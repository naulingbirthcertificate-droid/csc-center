"""Pydantic v2 models for the CSC directory portal.

Every model here has a hand-written TS mirror in frontend/src/lib/types.ts —
keep the two in sync in the same edit (nothing infers across the HTTP boundary).
"""

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    """Aware UTC now — store aware so Pydantic serialises with the offset."""
    return datetime.now(timezone.utc)


# ---- Directory link items: services / schemes / forms share this shape ----
class LinkItem(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    hindi: str = ""
    url: str = ""  # official government URL; empty → WhatsApp-channel enquiry
    is_new: bool = False
    sort_order: int = 0
    created_at: datetime = Field(default_factory=utcnow)


class LinkItemCreate(BaseModel):
    name: str
    hindi: str = ""
    url: str = ""
    is_new: bool = False
    sort_order: int = 0


# ---- Latest updates ----
class Update(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    url: str = ""
    date: str = ""  # YYYY-MM-DD, anchored server-side via lib.dates.today_iso
    is_active: bool = True
    created_at: datetime = Field(default_factory=utcnow)


class UpdateCreate(BaseModel):
    title: str
    url: str = ""
    is_active: bool = True


# ---- Important notices (marquee bar) ----
class Notice(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    body: str = ""
    is_active: bool = True
    created_at: datetime = Field(default_factory=utcnow)


class NoticeCreate(BaseModel):
    title: str
    body: str = ""
    is_active: bool = True


# ---- Site settings (key/value, single "site" document) ----
class SiteSettings(BaseModel):
    whatsapp_group_url: str = ""


# ---- Admin auth ----
class AdminUser(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    created_at: datetime = Field(default_factory=utcnow)


class LoginRequest(BaseModel):
    username: str
    password: str


class MeResponse(BaseModel):
    username: str


# ---- Search ----
class SearchResult(BaseModel):
    services: list[LinkItem] = []
    schemes: list[LinkItem] = []
    forms: list[LinkItem] = []
    updates: list[Update] = []
    """Admin session auth — httpOnly-cookie sessions stored in Mongo.

No tokens in JSON bodies: the session rides a same-origin httpOnly cookie,
`GET /api/auth/me` answers "who am I".
"""

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Request, Response
from passlib.hash import pbkdf2_sha256

from lib.db import db
from models.content import LoginRequest, MeResponse

router = APIRouter(prefix="/auth")

COOKIE_NAME = "csc_session"
SESSION_DAYS = 7


async def require_admin(request: Request) -> dict:
    """Dependency for write endpoints: 401 unless a live session cookie is present."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=401, detail="sign in required")
    session = await db.sessions.find_one({"token": token})
    if not session:
        raise HTTPException(status_code=401, detail="sign in required")
    expires_at = session.get("expires_at")
    if isinstance(expires_at, datetime):
        if expires_at.tzinfo is None:  # motor hands naive datetimes back
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            await db.sessions.delete_one({"token": token})
            raise HTTPException(status_code=401, detail="session expired")
    return session


@router.post("/login", response_model=MeResponse)
async def login(payload: LoginRequest, response: Response) -> MeResponse:
    admin = await db.admins.find_one({"username": payload.username})
    if not admin or not pbkdf2_sha256.verify(payload.password, admin.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="invalid username or password")
    token = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
    await db.sessions.insert_one(
        {"token": token, "admin_id": admin.get("id"), "expires_at": expires_at}
    )
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=SESSION_DAYS * 24 * 3600,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return MeResponse(username=admin["username"])


@router.post("/logout")
async def logout(request: Request, response: Response) -> dict:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        await db.sessions.delete_one({"token": token})
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me", response_model=MeResponse)
async def me(request: Request) -> MeResponse:
    session = await require_admin(request)
    admin = await db.admins.find_one({"id": session.get("admin_id")})
    if not admin:
        raise HTTPException(status_code=401, detail="sign in required")
    return MeResponse(username=admin["username"])
"""Public directory content + admin CRUD. Every route hangs off the /api router.

Reads (list/search/settings) are public; all writes require the admin session.
"""

import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pymongo import ASCENDING, DESCENDING

from lib.db import db
from lib.dates import today_iso
from models.content import (
    LinkItem,
    LinkItemCreate,
    Notice,
    NoticeCreate,
    SearchResult,
    SiteSettings,
    Update,
    UpdateCreate,
    utcnow,
)
from routers.auth import require_admin

router = APIRouter()

LINK_KINDS = ("services", "schemes", "forms")


def normalize_doc(doc: dict) -> dict:
    """Motor hands naive datetimes back — make them aware UTC before Pydantic serialises."""
    value = doc.get("created_at")
    if isinstance(value, datetime) and value.tzinfo is None:
        doc["created_at"] = value.replace(tzinfo=timezone.utc)
    return doc


# ---- Link items: services / schemes / forms (same shape, three collections) ----
# The loop registers a list/create/update/delete quartet per collection; default-arg
# binding (`kind: str = _kind`) captures each collection name per iteration.
for _kind in LINK_KINDS:

    async def _list(kind: str = _kind) -> list[LinkItem]:
        docs = (
            await db[kind]
            .find()
            .sort([("sort_order", ASCENDING), ("name", ASCENDING)])
            .to_list(500)
        )
        return [LinkItem(**normalize_doc(d)) for d in docs]

    async def _create(
        payload: LinkItemCreate, _admin: dict = Depends(require_admin), kind: str = _kind
    ) -> LinkItem:
        obj = LinkItem(**payload.model_dump())
        await db[kind].insert_one(obj.model_dump())
        return obj

    async def _update(
        id: str,
        payload: LinkItemCreate,
        _admin: dict = Depends(require_admin),
        kind: str = _kind,
    ) -> LinkItem:
        result = await db[kind].update_one({"id": id}, {"$set": payload.model_dump()})
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="item not found")
        doc = await db[kind].find_one({"id": id})
        return LinkItem(**normalize_doc(doc))

    async def _delete(
        id: str, _admin: dict = Depends(require_admin), kind: str = _kind
    ) -> dict:
        result = await db[kind].delete_one({"id": id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="item not found")
        return {"ok": True}

    router.get(f"/{_kind}", response_model=list[LinkItem])(_list)
    router.post(f"/{_kind}", response_model=LinkItem, status_code=201)(_create)
    router.put(f"/{_kind}/{{id}}", response_model=LinkItem)(_update)
    router.delete(f"/{_kind}/{{id}}")(_delete)


# ---- Latest updates ----
@router.get("/updates", response_model=list[Update])
async def list_updates() -> list[Update]:
    docs = (
        await db.updates.find()
        .sort([("date", DESCENDING), ("created_at", DESCENDING)])
        .to_list(100)
    )
    return [Update(**normalize_doc(d)) for d in docs]


@router.post("/updates", response_model=Update, status_code=201)
async def create_update(payload: UpdateCreate, _admin: dict = Depends(require_admin)) -> Update:
    obj = Update(**payload.model_dump(), date=today_iso())
    await db.updates.insert_one(obj.model_dump())
    return obj


@router.put("/updates/{id}", response_model=Update)
async def update_update(
    id: str, payload: UpdateCreate, _admin: dict = Depends(require_admin)
) -> Update:
    result = await db.updates.update_one(
        {"id": id}, {"$set": {**payload.model_dump(), "date": today_iso()}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="update not found")
    doc = await db.updates.find_one({"id": id})
    return Update(**normalize_doc(doc))


@router.delete("/updates/{id}")
async def delete_update(id: str, _admin: dict = Depends(require_admin)) -> dict:
    result = await db.updates.delete_one({"id": id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="update not found")
    return {"ok": True}


# ---- Important notices ----
@router.get("/notices", response_model=list[Notice])
async def list_notices() -> list[Notice]:
    docs = await db.notices.find().sort([("created_at", DESCENDING)]).to_list(100)
    return [Notice(**normalize_doc(d)) for d in docs]


@router.post("/notices", response_model=Notice, status_code=201)
async def create_notice(payload: NoticeCreate, _admin: dict = Depends(require_admin)) -> Notice:
    obj = Notice(**payload.model_dump())
    await db.notices.insert_one(obj.model_dump())
    return obj


@router.put("/notices/{id}", response_model=Notice)
async def update_notice(
    id: str, payload: NoticeCreate, _admin: dict = Depends(require_admin)
) -> Notice:
    result = await db.notices.update_one({"id": id}, {"$set": payload.model_dump()})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="notice not found")
    doc = await db.notices.find_one({"id": id})
    return Notice(**normalize_doc(doc))


@router.delete("/notices/{id}")
async def delete_notice(id: str, _admin: dict = Depends(require_admin)) -> dict:
    result = await db.notices.delete_one({"id": id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="notice not found")
    return {"ok": True}


# ---- Search across services / schemes / forms (and update titles) ----
@router.get("/search", response_model=SearchResult)
async def search(q: str) -> SearchResult:
    q = q.strip()
    if not q:
        return SearchResult()
    pattern = {"$regex": re.escape(q), "$options": "i"}
    result = SearchResult()
    for kind in LINK_KINDS:
        docs = (
            await db[kind]
            .find({"$or": [{"name": pattern}, {"hindi": pattern}]})
            .sort([("sort_order", ASCENDING), ("name", ASCENDING)])
            .to_list(20)
        )
        setattr(result, kind, [LinkItem(**normalize_doc(d)) for d in docs])
    udocs = await db.updates.find({"title": pattern}).to_list(20)
    result.updates = [Update(**normalize_doc(d)) for d in udocs]
    return result


# ---- Site settings (WhatsApp channel link etc.) ----
@router.get("/settings", response_model=SiteSettings)
async def get_settings() -> SiteSettings:
    doc = await db.settings.find_one({"key": "site"})
    return SiteSettings(whatsapp_group_url=(doc or {}).get("whatsapp_group_url", ""))


@router.put("/settings", response_model=SiteSettings)
async def update_settings(
    payload: SiteSettings, _admin: dict = Depends(require_admin)
) -> SiteSettings:
    await db.settings.update_one(
        {"key": "site"},
        {"$set": {"whatsapp_group_url": payload.whatsapp_group_url, "updated_at": utcnow()}},
        upsert=True,
    )
    return payload
# Feature routers — each module exports an APIRouter folded into /api here
from routers.auth import router as auth_router
from routers.content import router as content_router

api_router.include_router(auth_router)
api_router.include_router(content_router)

# Include the router in the main app
app.include_router(api_router)
"""One-shot idempotent seed for the Nauling CSC portal.

Run:  cd /app/backend && python seed.py

Creates the admin account, site settings, and the full starting directory
content (services / schemes / forms / updates / notices) when a collection is
empty. Never imported by server.py.
"""

import asyncio
import uuid
from datetime import datetime, timezone

from passlib.hash import pbkdf2_sha256

from lib.db import db, ensure_indexes
from lib.dates import today_iso

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Nauling@123"
WHATSAPP_CHANNEL_URL = "https://whatsapp.com/channel/0029VbEGAkEIyPtLLVHIg31u"

SERVICES = [
    {"name": "PAN Card Apply (New Application)", "hindi": "नया पैन कार्ड आवेदन", "url": "https://www.onlineservices.nsdl.com/paam/endUserRegisterContact.html", "is_new": True},
    {"name": "PAN Card Correction & Reprint", "hindi": "पैन कार्ड सुधार / रीप्रिंट", "url": "https://www.onlineservices.nsdl.com/paam/endUserRegisterContact.html", "is_new": False},
    {"name": "Ayushman Card (Ayushman Bharat Golden Card)", "hindi": "आयुष्मान कार्ड डाउनलोड / नया", "url": "https://beneficiary.nha.gov.in/", "is_new": True},
    {"name": "E-Shram Card", "hindi": "ई-श्रम कार्ड पंजीयन / अपडेट", "url": "https://eshram.gov.in/", "is_new": False},
    {"name": "Voter ID Apply", "hindi": "नया वोटर कार्ड आवेदन", "url": "https://voters.eci.gov.in/", "is_new": True},
    {"name": "Voter ID Correction", "hindi": "वोटर कार्ड सुधार / स्थानांतरण", "url": "https://voters.eci.gov.in/", "is_new": False},
    {"name": "Passport Application", "hindi": "पासपोर्ट सेवा ऑनलाइन आवेदन", "url": "https://www.passportindia.gov.in/", "is_new": False},
    {"name": "Driving Licence Services", "hindi": "ड्राइविंग लाइसेंस सेवा (सारथी)", "url": "https://sarathi.parivahan.gov.in/", "is_new": False},
    {"name": "Family Register Copy", "hindi": "परिवार रजिस्टर की नकल (उत्तराखण्ड)", "url": "https://eservices.uk.gov.in/", "is_new": True},
    {"name": "Printing and Scanning", "hindi": "दस्तावेज़ प्रिंटिंग व हाई-क्वालिटी स्कैनिंग", "url": "", "is_new": False},
    {"name": "Online Form Filling", "hindi": "समस्त ऑनलाइन सरकारी फॉर्म भराई", "url": "", "is_new": False},
    {"name": "Electricity Bill Payment", "hindi": "उत्तराखण्ड बिजली बिल भुगतान", "url": "https://www.upcl.org/", "is_new": False},
    {"name": "Digital Document Services", "hindi": "डिजिटल डॉक्यूमेंट व लेमिनेशन सेवा", "url": "", "is_new": False},
    {"name": "ABHA Card Services", "hindi": "आभा हेल्थ आईडी कार्ड बनाएं", "url": "https://abha.abdm.gov.in/", "is_new": True},
]

SCHEMES = [
    {"name": "PM Kisan Samman Nidhi", "hindi": "पीएम किसान सम्मान निधि ई-केवाईसी", "url": "https://pmkisan.gov.in/", "is_new": True},
    {"name": "Ayushman Bharat Yojana", "hindi": "आयुष्मान भारत योजना जानकारी", "url": "https://pmjay.gov.in/", "is_new": False},
    {"name": "E-Shram Yojana", "hindi": "ई-श्रम सामाजिक सुरक्षा योजना", "url": "https://eshram.gov.in/", "is_new": False},
    {"name": "Old Age Pension", "hindi": "वृद्धावस्था पेंशन योजना (समाज कल्याण)", "url": "https://ssp.uk.gov.in/", "is_new": True},
    {"name": "Widow Pension", "hindi": "विधवा पेंशन ऑनलाइन आवेदन", "url": "https://ssp.uk.gov.in/", "is_new": False},
    {"name": "Disability Pension", "hindi": "दिव्यांग पेंशन योजना उत्तराखण्ड", "url": "https://ssp.uk.gov.in/", "is_new": False},
    {"name": "Scholarship Schemes", "hindi": "राष्ट्रीय छात्रवृत्ति पोर्टल योजनाएं", "url": "https://scholarships.gov.in/", "is_new": True},
    {"name": "PM Awas Yojana", "hindi": "प्रधानमंत्री आवास योजना सूची", "url": "https://pmaymis.gov.in/", "is_new": False},
    {"name": "Jan Dhan Yojana", "hindi": "जन धन खाता एवं बीमा योजना", "url": "https://pmjdy.gov.in/", "is_new": False},
    {"name": "Government Scheme Information", "hindi": "उत्तराखण्ड राज्य सरकारी योजनाएं", "url": "https://uk.gov.in/", "is_new": False},
]

FORMS = [
    {"name": "Caste Certificate Application", "hindi": "जाति प्रमाण पत्र आवेदन", "url": "https://eservices.uk.gov.in/", "is_new": True},
    {"name": "Income Certificate Application", "hindi": "आय प्रमाण पत्र ऑनलाइन आवेदन", "url": "https://eservices.uk.gov.in/", "is_new": True},
    {"name": "Domicile Certificate Application", "hindi": "स्थाई निवास प्रमाण पत्र आवेदन", "url": "https://eservices.uk.gov.in/", "is_new": True},
    {"name": "Character Certificate Application", "hindi": "चरित्र प्रमाण पत्र ऑनलाइन", "url": "https://uttarakhandpolice.uk.gov.in/", "is_new": False},
    {"name": "Scholarship Online Form", "hindi": "छात्रवृत्ति ऑनलाइन आवेदन फॉर्म", "url": "https://scholarships.gov.in/", "is_new": True},
    {"name": "Pension Online Form", "hindi": "समाज कल्याण पेंशन नवीन फॉर्म", "url": "https://ssp.uk.gov.in/", "is_new": False},
    {"name": "Employment Registration", "hindi": "उत्तराखण्ड सेवायोजन पंजीकरण", "url": "https://rojgar.uk.gov.in/", "is_new": True},
    {"name": "School Admission Form", "hindi": "नवोदय / केन्द्रीय विद्यालय प्रवेश फॉर्म", "url": "https://navodaya.gov.in/", "is_new": False},
    {"name": "College Admission Form", "hindi": "कॉलेज व विश्वविद्यालय प्रवेश फॉर्म", "url": "", "is_new": False},
    {"name": "Government Job Online Forms", "hindi": "यूकेएसएसएससी व यूकेपीएससी भर्ती फॉर्म", "url": "https://psc.uk.gov.in/", "is_new": True},
    {"name": "Competitive Examination Forms", "hindi": "एसएससी / रेलवे / अग्निवीर भर्ती फॉर्म", "url": "https://ssc.gov.in/", "is_new": True},
    {"name": "Other Online Applications", "hindi": "अन्य समस्त ऑनलाइन आवेदन फॉर्म", "url": "", "is_new": False},
]

UPDATES = [
    {"title": "आयुष्मान कार्ड, ई-श्रम कार्ड व पैन कार्ड सेवाएं केंद्र पर उपलब्ध हैं", "url": ""},
    {"title": "PM किसान e-KYC अनिवार्य — सत्यापन के लिए केंद्र पर संपर्क करें", "url": "https://pmkisan.gov.in/"},
    {"title": "उत्तराखण्ड राशन कार्ड ई-केवाईसी केंद्र पर चालू है", "url": ""},
]

NOTICES = [
    {"title": "राशन कार्ड ई-केवाईसी एवं किसान सम्मान निधि सत्यापन केंद्र पर चालू है — कृपया आधार कार्ड के साथ पधारें।", "body": ""},
    {"title": "समस्त सरकारी योजनाओं के ऑनलाइन आवेदन व प्रमाण पत्र बनवाने हेतु केंद्र पर संपर्क करें।", "body": ""},
]


def _doc(item: dict, sort_order: int) -> dict:
    return {
        "id": str(uuid.uuid4()),
        **item,
        "sort_order": sort_order,
        "created_at": datetime.now(timezone.utc),
    }


async def _seed_collection(name: str, docs: list[dict]) -> None:
    if await db[name].count_documents({}) == 0:
        if docs:
            await db[name].insert_many(docs)
        print(f"seeded {name}: {len(docs)} docs")
    else:
        print(f"skipped {name}: already has data")


async def main() -> None:
    now = datetime.now(timezone.utc)

    # Admin account (only if none exists)
    if await db.admins.count_documents({}) == 0:
        await db.admins.insert_one(
            {
                "id": str(uuid.uuid4()),
                "username": ADMIN_USERNAME,
                "password_hash": pbkdf2_sha256.hash(ADMIN_PASSWORD),
                "created_at": now,
            }
        )
        print(f"seeded admin: {ADMIN_USERNAME}")
    else:
        print("skipped admin: already exists")

    # Site settings (upsert — always keep the WhatsApp channel link present)
    await db.settings.update_one(
        {"key": "site"},
        {"$set": {"whatsapp_group_url": WHATSAPP_CHANNEL_URL}},
        upsert=True,
    )
    print("seeded settings: site")

    await _seed_collection("services", [_doc(s, i) for i, s in enumerate(SERVICES)])
    await _seed_collection("schemes", [_doc(s, i) for i, s in enumerate(SCHEMES)])
    await _seed_collection("forms", [_doc(f, i) for i, f in enumerate(FORMS)])
    await _seed_collection(
        "updates",
        [
            {"id": str(uuid.uuid4()), **u, "date": today_iso(), "is_active": True,
             "created_at": now + timedelta_seconds(i)}
            for i, u in enumerate(UPDATES)
        ],
    )
    await _seed_collection(
        "notices",
        [
            {"id": str(uuid.uuid4()), **n, "is_active": True, "created_at": now + timedelta_seconds(i)}
            for i, n in enumerate(NOTICES)
        ],
    )

    await ensure_indexes()
    print("done")


def timedelta_seconds(i: int) -> "object":
    from datetime import timedelta

    return timedelta(seconds=i)


if __name__ == "__main__":
    asyncio.run(main())
INDEXES: dict[str, list[IndexModel]] = {
    "status_checks": [IndexModel([("timestamp", DESCENDING)], name="timestamp_desc")],
    # Directory link items — listed by (sort_order, name)
    **{
        kind: [
            IndexModel([("id", ASCENDING)], name="id", unique=True),
            IndexModel([("sort_order", ASCENDING), ("name", ASCENDING)], name="sort_name"),
        ]
        for kind in ("services", "schemes", "forms")
    },
    "updates": [
        IndexModel([("id", ASCENDING)], name="id", unique=True),
        IndexModel([("date", DESCENDING), ("created_at", DESCENDING)], name="date_desc"),
    ],
    "notices": [
        IndexModel([("id", ASCENDING)], name="id", unique=True),
        IndexModel([("created_at", DESCENDING)], name="created_desc"),
    ],
    "sessions": [
        IndexModel([("token", ASCENDING)], name="token", unique=True),
        # TTL: Mongo drops the session doc as soon as expires_at passes
        IndexModel([("expires_at", ASCENDING)], name="expires_ttl", expireAfterSeconds=0),
    ],
    "admins": [
        IndexModel([("id", ASCENDING)], name="id", unique=True),
        IndexModel([("username", ASCENDING)], name="username", unique=True),
    ],
    "settings": [IndexModel([("key", ASCENDING)], name="key", unique=True)],
}
// Admin session helpers. Sessions are httpOnly cookies set by the backend —
// never tokens in JS. This module owns clearing the react-query cache so one
// account's data never leaks into the next login.
import { useQuery } from "@tanstack/react-query";
import type { QueryClient } from "@tanstack/react-query";
import { apiGet, apiPost } from "@/lib/api";
import type { Me } from "@/lib/types";

// "Who am I?" — 401 (ApiError) when not signed in.
export function useAdmin() {
  return useQuery({
    queryKey: ["me"],
    queryFn: () => apiGet<Me>("/auth/me"),
    retry: false,
  });
}

// Call after a successful login/signup; refetches auth-gated queries.
export async function beginSession(queryClient: QueryClient, username: string, password: string) {
  const me = await apiPost<Me>("/auth/login", { username, password });
  await queryClient.invalidateQueries({ queryKey: ["me"] });
  return me;
}

// Every sign-out control must go through here — clearing only the server
// session would leak the previous account's cached data to the next login.
export async function endSession(queryClient: QueryClient) {
  try {
    await apiPost("/auth/logout");
  } finally {
    queryClient.clear();
  }
}
import type { Notice } from "@/lib/types";

// Amber marquee bar scrolling the active Important Notices (bilingual copy).
// Hidden entirely when there is nothing active — never a blank strip.
export default function NoticeBar({ notices }: { notices: Notice[] | undefined }) {
  const active = (notices ?? []).filter((n) => n.is_active);
  if (active.length === 0) return null;
  const text = active.map((n) => n.title).join("   ✦   ");

  return (
    <div
      className="border-b border-amber-200 bg-[#FEF3C7] text-[#92400E]"
      data-testid="notice-bar"
    >
      <div className="mx-auto flex max-w-7xl items-stretch">
        <span className="shrink-0 bg-[#B45309] px-3 py-1.5 text-xs font-bold text-white">
          महत्वपूर्ण सूचना
        </span>
        <div className="relative flex-1 overflow-hidden py-1.5">
          <div className="notice-marquee whitespace-nowrap text-sm font-medium">
            <span className="pr-12">{text}</span>
            <span className="pr-12" aria-hidden="true">
              {text}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
import { SiWhatsapp } from "@icons-pack/react-simple-icons";
import { SITE } from "@/lib/site";

// Contact panel shared by the home page and the Contact Us page.
// Deliberately NO phone number anywhere — CSC ID, email, address, WhatsApp channel only.
export default function ContactInfo({ whatsappUrl }: { whatsappUrl: string }) {
  return (
    <section className="mt-4 border border-[#AB0A0A] bg-white" data-testid="contact-section">
      <header className="bg-[#AB0A0A] px-3 py-2 text-center text-white">
        <h2 className="text-base font-bold uppercase tracking-wide md:text-lg">Contact Us</h2>
        <p className="mt-0.5 text-xs text-red-100">संपर्क करें</p>
      </header>
      <div className="p-4 md:p-5">
        <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
          <div data-testid="contact-name">
            <dt className="font-bold text-gray-900">Centre Name</dt>
            <dd className="text-gray-700">{SITE.name}</dd>
          </div>
          <div data-testid="contact-csc-id">
            <dt className="font-bold text-gray-900">CSC ID</dt>
            <dd className="font-mono text-gray-700">{SITE.cscId}</dd>
          </div>
          <div data-testid="contact-email">
            <dt className="font-bold text-gray-900">Email</dt>
            <dd>
              <a
                href={`mailto:${SITE.email}`}
                className="font-medium text-[#0056B3] underline transition-colors duration-150 hover:text-[#003366]"
              >
                {SITE.email}
              </a>
            </dd>
          </div>
          <div data-testid="contact-address">
            <dt className="font-bold text-gray-900">Address</dt>
            <dd className="text-gray-700">{SITE.address}</dd>
          </div>
        </dl>
        {whatsappUrl && (
          <a
            href={whatsappUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-4 inline-flex items-center gap-1.5 bg-[#15803D] px-3 py-2 text-sm font-bold text-white transition-colors duration-150 hover:bg-[#166534]"
            data-testid="contact-whatsapp-button"
          >
            <SiWhatsapp size={18} />
            Join our WhatsApp Channel
          </a>
        )}
      </div>
    </section>
  );
}
"""One-shot idempotent seed for the Nauling CSC portal.

Run:  cd /app/backend && python seed.py

Creates the admin account, site settings, and the full starting directory
content (services / schemes / forms / updates / notices) when a collection is
empty. Never imported by server.py.
"""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from passlib.hash import pbkdf2_sha256

from lib.db import db, ensure_indexes
from lib.dates import today_iso

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Nauling@123"
WHATSAPP_CHANNEL_URL = "https://whatsapp.com/channel/0029VbEGAkEIyPtLLVHIg31u"

SERVICES = [
    {"name": "PAN Card Apply (New Application)", "hindi": "नया पैन कार्ड आवेदन", "url": "https://www.onlineservices.nsdl.com/paam/endUserRegisterContact.html", "is_new": True},
    {"name": "PAN Card Correction & Reprint", "hindi": "पैन कार्ड सुधार / रीप्रिंट", "url": "https://www.onlineservices.nsdl.com/paam/endUserRegisterContact.html", "is_new": False},
    {"name": "Ayushman Card (Ayushman Bharat Golden Card)", "hindi": "आयुष्मान कार्ड डाउनलोड / नया", "url": "https://beneficiary.nha.gov.in/", "is_new": True},
    {"name": "E-Shram Card", "hindi": "ई-श्रम कार्ड पंजीयन / अपडेट", "url": "https://eshram.gov.in/", "is_new": False},
    {"name": "Voter ID Apply", "hindi": "नया वोटर कार्ड आवेदन", "url": "https://voters.eci.gov.in/", "is_new": True},
    {"name": "Voter ID Correction", "hindi": "वोटर कार्ड सुधार / स्थानांतरण", "url": "https://voters.eci.gov.in/", "is_new": False},
    {"name": "Passport Application", "hindi": "पासपोर्ट सेवा ऑनलाइन आवेदन", "url": "https://www.passportindia.gov.in/", "is_new": False},
    {"name": "Driving Licence Services", "hindi": "ड्राइविंग लाइसेंस सेवा (सारथी)", "url": "https://sarathi.parivahan.gov.in/", "is_new": False},
    {"name": "Family Register Copy", "hindi": "परिवार रजिस्टर की नकल (उत्तराखण्ड)", "url": "https://eservices.uk.gov.in/", "is_new": True},
    {"name": "Printing and Scanning", "hindi": "दस्तावेज़ प्रिंटिंग व हाई-क्वालिटी स्कैनिंग", "url": "", "is_new": False},
    {"name": "Online Form Filling", "hindi": "समस्त ऑनलाइन सरकारी फॉर्म भराई", "url": "", "is_new": False},
    {"name": "Electricity Bill Payment", "hindi": "उत्तराखण्ड बिजली बिल भुगतान", "url": "https://www.upcl.org/", "is_new": False},
    {"name": "Digital Document Services", "hindi": "डिजिटल डॉक्यूमेंट व लेमिनेशन सेवा", "url": "", "is_new": False},
    {"name": "ABHA Card Services", "hindi": "आभा हेल्थ आईडी कार्ड बनाएं", "url": "https://abha.abdm.gov.in/", "is_new": True},
]

SCHEMES = [
    {"name": "PM Kisan Samman Nidhi", "hindi": "पीएम किसान सम्मान निधि ई-केवाईसी", "url": "https://pmkisan.gov.in/", "is_new": True},
    {"name": "Ayushman Bharat Yojana", "hindi": "आयुष्मान भारत योजना जानकारी", "url": "https://pmjay.gov.in/", "is_new": False},
    {"name": "E-Shram Yojana", "hindi": "ई-श्रम सामाजिक सुरक्षा योजना", "url": "https://eshram.gov.in/", "is_new": False},
    {"name": "Old Age Pension", "hindi": "वृद्धावस्था पेंशन योजना (समाज कल्याण)", "url": "https://ssp.uk.gov.in/", "is_new": True},
    {"name": "Widow Pension", "hindi": "विधवा पेंशन ऑनलाइन आवेदन", "url": "https://ssp.uk.gov.in/", "is_new": False},
    {"name": "Disability Pension", "hindi": "दिव्यांग पेंशन योजना उत्तराखण्ड", "url": "https://ssp.uk.gov.in/", "is_new": False},
    {"name": "Scholarship Schemes", "hindi": "राष्ट्रीय छात्रवृत्ति पोर्टल योजनाएं", "url": "https://scholarships.gov.in/", "is_new": True},
    {"name": "PM Awas Yojana", "hindi": "प्रधानमंत्री आवास योजना सूची", "url": "https://pmaymis.gov.in/", "is_new": False},
    {"name": "Jan Dhan Yojana", "hindi": "जन धन खाता एवं बीमा योजना", "url": "https://pmjdy.gov.in/", "is_new": False},
    {"name": "Government Scheme Information", "hindi": "उत्तराखण्ड राज्य सरकारी योजनाएं", "url": "https://uk.gov.in/", "is_new": False},
]

FORMS = [
    {"name": "Caste Certificate Application", "hindi": "जाति प्रमाण पत्र आवेदन", "url": "https://eservices.uk.gov.in/", "is_new": True},
    {"name": "Income Certificate Application", "hindi": "आय प्रमाण पत्र ऑनलाइन आवेदन", "url": "https://eservices.uk.gov.in/", "is_new": True},
    {"name": "Domicile Certificate Application", "hindi": "स्थाई निवास प्रमाण पत्र आवेदन", "url": "https://eservices.uk.gov.in/", "is_new": True},
    {"name": "Character Certificate Application", "hindi": "चरित्र प्रमाण पत्र ऑनलाइन", "url": "https://uttarakhandpolice.uk.gov.in/", "is_new": False},
    {"name": "Scholarship Online Form", "hindi": "छात्रवृत्ति ऑनलाइन आवेदन फॉर्म", "url": "https://scholarships.gov.in/", "is_new": True},
    {"name": "Pension Online Form", "hindi": "समाज कल्याण पेंशन नवीन फॉर्म", "url": "https://ssp.uk.gov.in/", "is_new": False},
    {"name": "Employment Registration", "hindi": "उत्तराखण्ड सेवायोजन पंजीकरण", "url": "https://rojgar.uk.gov.in/", "is_new": True},
    {"name": "School Admission Form", "hindi": "नवोदय / केन्द्रीय विद्यालय प्रवेश फॉर्म", "url": "https://navodaya.gov.in/", "is_new": False},
    {"name": "College Admission Form", "hindi": "कॉलेज व विश्वविद्यालय प्रवेश फॉर्म", "url": "", "is_new": False},
    {"name": "Government Job Online Forms", "hindi": "यूकेएसएसएससी व यूकेपीएससी भर्ती फॉर्म", "url": "https://psc.uk.gov.in/", "is_new": True},
    {"name": "Competitive Examination Forms", "hindi": "एसएससी / रेलवे / अग्निवीर भर्ती फॉर्म", "url": "https://ssc.gov.in/", "is_new": True},
    {"name": "Other Online Applications", "hindi": "अन्य समस्त ऑनलाइन आवेदन फॉर्म", "url": "", "is_new": False},
]

UPDATES = [
    {"title": "आयुष्मान कार्ड, ई-श्रम कार्ड व पैन कार्ड सेवाएं केंद्र पर उपलब्ध हैं", "url": ""},
    {"title": "PM किसान e-KYC अनिवार्य — सत्यापन के लिए केंद्र पर संपर्क करें", "url": "https://pmkisan.gov.in/"},
    {"title": "उत्तराखण्ड राशन कार्ड ई-केवाईसी केंद्र पर चालू है", "url": ""},
]

NOTICES = [
    {"title": "राशन कार्ड ई-केवाईसी एवं किसान सम्मान निधि सत्यापन केंद्र पर चालू है — कृपया आधार कार्ड के साथ पधारें।", "body": ""},
    {"title": "समस्त सरकारी योजनाओं के ऑनलाइन आवेदन व प्रमाण पत्र बनवाने हेतु केंद्र पर संपर्क करें।", "body": ""},
]


def _doc(item: dict, sort_order: int) -> dict:
    return {
        "id": str(uuid.uuid4()),
        **item,
        "sort_order": sort_order,
        "created_at": datetime.now(timezone.utc),
    }


async def _seed_collection(name: str, docs: list[dict]) -> None:
    if await db[name].count_documents({}) == 0:
        if docs:
            await db[name].insert_many(docs)
        print(f"seeded {name}: {len(docs)} docs")
    else:
        print(f"skipped {name}: already has data")


async def main() -> None:
    now = datetime.now(timezone.utc)

    # Admin account (only if none exists)
    if await db.admins.count_documents({}) == 0:
        await db.admins.insert_one(
            {
                "id": str(uuid.uuid4()),
                "username": ADMIN_USERNAME,
                "password_hash": pbkdf2_sha256.hash(ADMIN_PASSWORD),
                "created_at": now,
            }
        )
        print(f"seeded admin: {ADMIN_USERNAME}")
    else:
        print("skipped admin: already exists")

    # Site settings (upsert — always keep the WhatsApp channel link present)
    await db.settings.update_one(
        {"key": "site"},
        {"$set": {"whatsapp_group_url": WHATSAPP_CHANNEL_URL}},
        upsert=True,
    )
    print("seeded settings: site")

    await _seed_collection("services", [_doc(s, i) for i, s in enumerate(SERVICES)])
    await _seed_collection("schemes", [_doc(s, i) for i, s in enumerate(SCHEMES)])
    await _seed_collection("forms", [_doc(f, i) for i, f in enumerate(FORMS)])
    await _seed_collection(
        "updates",
        [
            {
                "id": str(uuid.uuid4()),
                **u,
                "date": today_iso(),
                "is_active": True,
                "created_at": now + timedelta(seconds=i),
            }
            for i, u in enumerate(UPDATES)
        ],
    )
    await _seed_collection(
        "notices",
        [
            {
                "id": str(uuid.uuid4()),
                **n,
                "is_active": True,
                "created_at": now + timedelta(seconds=i),
            }
            for i, n in enumerate(NOTICES)
        ],
    )

    await ensure_indexes()
    print("done")


if __name__ == "__main__":
    asyncio.run(main())
import { SiWhatsapp } from "@icons-pack/react-simple-icons";

// Floating bottom-right WhatsApp channel button (hidden when no link is set).
export default function WhatsAppFab({ url }: { url: string }) {
  if (!url) return null;
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      aria-label="Join our WhatsApp channel (opens in a new tab)"
      data-testid="whatsapp-fab"
      className="fixed bottom-5 right-5 z-50 flex h-14 w-14 items-center justify-center rounded-full bg-[#25D366] text-white shadow-lg transition-transform duration-150 hover:scale-105"
    >
      <SiWhatsapp size={30} />
    </a>
  );
}
// Small inline tricolor CSC badge — no external image dependency.
export function CSCLogo({ size = 44 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      role="img"
      aria-label="CSC Centre logo"
      data-testid="csc-logo"
      className="shrink-0"
    >
      <circle cx="24" cy="24" r="22.5" fill="#FFFFFF" stroke="#D1D5DB" strokeWidth="1" />
      <path d="M5.5 24 a18.5 18.5 0 0 1 37 0" fill="none" stroke="#FF9933" strokeWidth="4" />
      <path d="M5.5 24 a18.5 18.5 0 0 0 37 0" fill="none" stroke="#138808" strokeWidth="4" />
      <text
        x="24"
        y="28.5"
        textAnchor="middle"
        fontSize="12"
        fontWeight="700"
        fill="#AB0A0A"
        fontFamily="Arial, Helvetica, sans-serif"
        letterSpacing="0.5"
      >
        CSC
      </text>
      <text
        x="24"
        y="36"
        textAnchor="middle"
        fontSize="5"
        fill="#374151"
        fontFamily="Arial, Helvetica, sans-serif"
      >
        DIGITAL SEVA
      </text>
    </svg>
  );
}
import type { LinkItem } from "@/lib/types";

interface LinkColumnProps {
  title: string;
  hindi: string;
  kind: string;
  items: LinkItem[] | undefined;
  isLoading: boolean;
  whatsappUrl: string;
}

// One Sarkari-Result-style column: solid red heading bar, thin red border,
// black bullets, blue underlined links. Items without an official URL fall
// back to the WhatsApp channel enquiry link.
export default function LinkColumn({
  title,
  hindi,
  kind,
  items,
  isLoading,
  whatsappUrl,
}: LinkColumnProps) {
  return (
    <section className="border border-[#AB0A0A] bg-white" data-testid={`${kind}-column`}>
      <header className="bg-[#AB0A0A] px-3 py-2 text-center text-white">
        <h2 className="text-base font-bold uppercase tracking-wide md:text-lg">{title}</h2>
        <p className="mt-0.5 text-xs text-red-100">{hindi}</p>
      </header>
      <ul className="max-h-[760px] divide-y divide-red-100/70 overflow-y-auto p-2.5 md:p-3">
        {isLoading && (
          <li className="px-1.5 py-2 text-sm text-gray-500">लोड हो रहा है… (loading…)</li>
        )}
        {!isLoading && items !== undefined && items.length === 0 && (
          <li className="px-1.5 py-2 text-sm text-gray-500">सूची उपलब्ध नहीं है</li>
        )}
        {items?.map((item, index) => {
          const href = item.url || whatsappUrl;
          return (
            <li
              key={item.id}
              className="group flex items-start gap-2 px-1.5 py-1.5 text-sm leading-snug transition-colors duration-150 hover:bg-red-50/60"
              data-testid={`${kind}-link-${index + 1}`}
            >
              <span className="mt-0.5 select-none text-base font-bold leading-none text-black">
                •
              </span>
              {href ? (
                <a
                  href={href}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={`${item.name} (opens in a new tab)`}
                  className="font-medium text-[#0056B3] underline transition-colors duration-150 hover:text-[#003366]"
                >
                  {item.name}
                  {item.is_new && (
                    <span className="ml-1.5 inline-block bg-red-600 px-1 py-0.5 align-middle text-[10px] font-bold uppercase text-white">
                      New
                    </span>
                  )}
                  {item.hindi && (
                    <span className="block text-xs font-normal text-gray-500">{item.hindi}</span>
                  )}
                </a>
              ) : (
                <span className="font-medium text-[#0056B3]">
                  {item.name}
                  {item.hindi && (
                    <span className="block text-xs font-normal text-gray-500">{item.hindi}</span>
                  )}
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
import { SITE } from "@/lib/site";

export default function SiteFooter() {
  return (
    <footer className="mt-6 bg-[#1E293B] text-[#CBD5E1]" data-testid="site-footer">
      <div className="mx-auto max-w-7xl px-4 py-6 text-center text-sm">
        <p className="text-base font-bold text-white">{SITE.name}</p>
        <p className="mt-1">{SITE.hindiName}</p>
        <p className="mt-2">
          CSC ID:{" "}
          <span className="font-semibold text-[#38BDF8]" data-testid="footer-csc-id">
            {SITE.cscId}
          </span>
        </p>
        <p className="mt-1">
          Email:{" "}
          <a
            href={`mailto:${SITE.email}`}
            className="text-[#38BDF8] underline transition-colors duration-150 hover:text-white"
            data-testid="footer-email-link"
          >
            {SITE.email}
          </a>
        </p>
        <p className="mt-1">{SITE.address}</p>
        <p className="mt-3 border-t border-slate-600 pt-3 text-xs text-slate-400">
          © {new Date().getFullYear()} {SITE.name}. All rights reserved.
        </p>
      </div>
    </footer>
  );
}
// Site-wide constants for the Nauling CSC portal.
// NOTE: no phone number anywhere — contact is CSC ID + email + WhatsApp channel only.
export const SITE = {
  name: "Nauling Mobile CSC Center Ganai Gangoli",
  hindiName: "नौलिंग मोबाइल सीएससी सेंटर गणाई गंगोली, पिथौरागढ़ (उत्तराखण्ड)",
  cscId: "628898270014",
  email: "naulingmobilecsc@gmail.com",
  address: "Ganai Gangoli, Pithoragarh, Uttarakhand, India",
  tagline: "CSC Services · Government Schemes · Online Forms",
} as const;
import type { LinkItem } from "@/lib/types";

interface LinkRowProps {
  item: LinkItem;
  whatsappUrl: string;
  testid: string;
}

// One directory row: black bullet + blue underlined link. Items with an
// official URL open it in a new tab; items without fall back to the
// WhatsApp channel enquiry link.
export default function LinkRow({ item, whatsappUrl, testid }: LinkRowProps) {
  const href = item.url || whatsappUrl;
  const label = (
    <>
      {item.name}
      {item.is_new && (
        <span className="ml-1.5 inline-block bg-red-600 px-1 py-0.5 align-middle text-[10px] font-bold uppercase text-white">
          New
        </span>
      )}
      {item.hindi && <span className="block text-xs font-normal text-gray-500">{item.hindi}</span>}
    </>
  );

  return (
    <li
      className="group flex items-start gap-2 px-1.5 py-1.5 text-sm leading-snug transition-colors duration-150 hover:bg-red-50/60"
      data-testid={testid}
    >
      <span className="mt-0.5 select-none text-base font-bold leading-none text-black">•</span>
      {href ? (
        <a
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={`${item.name} (opens in a new tab)`}
          className="font-medium text-[#0056B3] underline transition-colors duration-150 hover:text-[#003366]"
        >
          {label}
        </a>
      ) : (
        <span className="font-medium text-[#0056B3]">{label}</span>
      )}
    </li>
  );
}
import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/lib/api";
import type { LinkItem, SiteSettings } from "@/lib/types";
import LinkColumn from "@/components/LinkColumn";
import SiteFooter from "@/components/SiteFooter";
import SiteHeader from "@/components/SiteHeader";
import WhatsAppFab from "@/components/WhatsAppFab";

const CONFIG = {
  services: { title: "CSC Services", hindi: "सीएससी सेवाएं" },
  schemes: { title: "Government Schemes", hindi: "सरकारी योजनाएं" },
  forms: { title: "Online Forms", hindi: "ऑनलाइन फॉर्म" },
} as const;

export type CategoryKind = keyof typeof CONFIG;

// Full-list page for one directory column (nav: CSC Services / Government
// Schemes / Online Forms).
export default function CategoryPage({ kind }: { kind: CategoryKind }) {
  const config = CONFIG[kind];
  const { data: settings } = useQuery({
    queryKey: ["settings"],
    queryFn: () => apiGet<SiteSettings>("/settings"),
    retry: false,
  });
  const { data: items, isLoading } = useQuery({
    queryKey: [kind],
    queryFn: () => apiGet<LinkItem[]>(`/${kind}`),
    retry: false,
  });
  const whatsappUrl = settings?.whatsapp_group_url ?? "";

  return (
    <div className="min-h-svh bg-white text-gray-900">
      <SiteHeader whatsappUrl={whatsappUrl} />
      <main className="mx-auto max-w-3xl px-3 py-4 sm:px-4">
        <LinkColumn
          title={config.title}
          hindi={config.hindi}
          kind={kind}
          items={items}
          isLoading={isLoading}
          whatsappUrl={whatsappUrl}
        />
      </main>
      <SiteFooter />
      <WhatsAppFab url={whatsappUrl} />
    </div>
  );
}
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { apiDelete, apiGet, apiPost, apiPut } from "@/lib/api";
import { endSession, useAdmin } from "@/lib/session";
import { SITE } from "@/lib/site";
import type {
  LinkItem,
  LinkItemInput,
  LinkKind,
  Notice,
  NoticeInput,
  SiteSettings,
  UpdateInput,
  UpdateItem,
} from "@/lib/types";
import { Button } from "@/components/ui/button";
import { buttonVariants } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const errMsg = (e: unknown) => (e instanceof Error ? e.message : "request failed");

// Two-step delete (no window.confirm — automation and mobile friendly).
function DeleteButton({ onConfirm, testid }: { onConfirm: () => void; testid: string }) {
  const [armed, setArmed] = useState(false);
  return (
    <Button
      variant={armed ? "destructive" : "outline"}
      size="xs"
      onClick={() => (armed ? onConfirm() : setArmed(true))}
      onBlur={() => setArmed(false)}
      data-testid={testid}
    >
      {armed ? "Confirm?" : "Delete"}
    </Button>
  );
}

const EMPTY_ITEM: LinkItemInput = { name: "", hindi: "", url: "", is_new: false, sort_order: 0 };

// CRUD panel for one LinkItem collection (services / schemes / forms).
function LinkItemsAdmin({ kind, label }: { kind: LinkKind; label: string }) {
  const qc = useQueryClient();
  const { data: items, isLoading } = useQuery({
    queryKey: [kind],
    queryFn: () => apiGet<LinkItem[]>(`/${kind}`),
    retry: false,
  });
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<LinkItem | null>(null);
  const [form, setForm] = useState<LinkItemInput>(EMPTY_ITEM);

  const save = useMutation({
    mutationFn: (input: LinkItemInput) =>
      editing ? apiPut<LinkItem>(`/${kind}/${editing.id}`, input) : apiPost<LinkItem>(`/${kind}`, input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: [kind] });
      qc.invalidateQueries({ queryKey: ["search"] });
      setOpen(false);
      toast.success(editing ? `${label} item updated` : `${label} item added`);
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const remove = useMutation({
    mutationFn: (id: string) => apiDelete<{ ok: boolean }>(`/${kind}/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: [kind] });
      toast.success(`${label} item deleted`);
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const openAdd = () => {
    setEditing(null);
    setForm({ ...EMPTY_ITEM, sort_order: (items?.length ?? 0) + 1 });
    setOpen(true);
  };

  const openEdit = (item: LinkItem) => {
    setEditing(item);
    setForm({
      name: item.name,
      hindi: item.hindi,
      url: item.url,
      is_new: item.is_new,
      sort_order: item.sort_order,
    });
    setOpen(true);
  };

  return (
    <div className="mt-4 border border-[#E2E8F0] bg-white p-4" data-testid={`admin-${kind}-panel`}>
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-base font-bold text-gray-900">{label}</h2>
        <Button size="xs" onClick={openAdd} data-testid={`admin-${kind}-add-button`}>
          + Add {label} item
        </Button>
      </div>
      {isLoading ? (
        <p className="py-6 text-center text-sm text-gray-500">Loading…</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Hindi</TableHead>
              <TableHead>Official URL</TableHead>
              <TableHead>New</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items?.map((item) => (
              <TableRow key={item.id}>
                <TableCell className="font-medium">{item.name}</TableCell>
                <TableCell>{item.hindi}</TableCell>
                <TableCell className="max-w-48 truncate">{item.url || "—"}</TableCell>
                <TableCell>{item.is_new ? "New" : ""}</TableCell>
                <TableCell className="space-x-2 text-right">
                  <Button
                    variant="outline"
                    size="xs"
                    onClick={() => openEdit(item)}
                    data-testid={`item-edit-${item.id}`}
                  >
                    Edit
                  </Button>
                  <DeleteButton
                    onConfirm={() => remove.mutate(item.id)}
                    testid={`item-delete-${item.id}`}
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {editing ? "Edit" : "Add"} {label} item
            </DialogTitle>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="item-name">Name</Label>
              <Input
                id="item-name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                data-testid="item-name-input"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="item-hindi">Hindi name</Label>
              <Input
                id="item-hindi"
                value={form.hindi}
                onChange={(e) => setForm({ ...form, hindi: e.target.value })}
                data-testid="item-hindi-input"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="item-url">Official URL (leave empty → WhatsApp enquiry)</Label>
              <Input
                id="item-url"
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                placeholder="https://…"
                data-testid="item-url-input"
              />
            </div>
            <div className="flex items-center gap-4">
              <div className="grid gap-1.5">
                <Label htmlFor="item-sort">Order</Label>
                <Input
                  id="item-sort"
                  type="number"
                  value={form.sort_order}
                  onChange={(e) => setForm({ ...form, sort_order: Number(e.target.value) })}
                  className="w-24"
                  data-testid="item-sort-input"
                />
              </div>
              <label className="mt-4 flex items-center gap-2 text-sm">
                <Checkbox
                  checked={form.is_new}
                  onCheckedChange={(c) => setForm({ ...form, is_new: c === true })}
                  data-testid="item-is-new-checkbox"
                />
                Mark as New
              </label>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} data-testid="item-cancel-button">
              Cancel
            </Button>
            <Button
              onClick={() => save.mutate(form)}
              disabled={save.isPending || !form.name.trim()}
              data-testid="item-save-button"
            >
              {save.isPending ? "Saving…" : editing ? "Save changes" : "Add item"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// CRUD panel for Latest Updates.
function UpdatesAdmin() {
  const qc = useQueryClient();
  const { data: updates, isLoading } = useQuery({
    queryKey: ["updates"],
    queryFn: () => apiGet<UpdateItem[]>("/updates"),
    retry: false,
  });
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<UpdateItem | null>(null);
  const [form, setForm] = useState<UpdateInput>({ title: "", url: "", is_active: true });

  const save = useMutation({
    mutationFn: (input: UpdateInput) =>
      editing ? apiPut<UpdateItem>(`/updates/${editing.id}`, input) : apiPost<UpdateItem>("/updates", input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["updates"] });
      qc.invalidateQueries({ queryKey: ["search"] });
      setOpen(false);
      toast.success(editing ? "Update edited" : "Update published");
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const remove = useMutation({
    mutationFn: (id: string) => apiDelete<{ ok: boolean }>(`/updates/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["updates"] });
      toast.success("Update deleted");
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <div className="mt-4 border border-[#E2E8F0] bg-white p-4" data-testid="admin-updates-panel">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-base font-bold text-gray-900">Latest Updates</h2>
        <Button
          size="xs"
          onClick={() => {
            setEditing(null);
            setForm({ title: "", url: "", is_active: true });
            setOpen(true);
          }}
          data-testid="admin-updates-add-button"
        >
          + Publish update
        </Button>
      </div>
      {isLoading ? (
        <p className="py-6 text-center text-sm text-gray-500">Loading…</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Title</TableHead>
              <TableHead>URL</TableHead>
              <TableHead>Active</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {updates?.map((u) => (
              <TableRow key={u.id}>
                <TableCell className="font-medium">{u.title}</TableCell>
                <TableCell className="max-w-48 truncate">{u.url || "—"}</TableCell>
                <TableCell>{u.is_active ? "Yes" : "No"}</TableCell>
                <TableCell className="space-x-2 text-right">
                  <Button
                    variant="outline"
                    size="xs"
                    onClick={() => {
                      setEditing(u);
                      setForm({ title: u.title, url: u.url, is_active: u.is_active });
                      setOpen(true);
                    }}
                    data-testid={`update-edit-${u.id}`}
                  >
                    Edit
                  </Button>
                  <DeleteButton
                    onConfirm={() => remove.mutate(u.id)}
                    testid={`update-delete-${u.id}`}
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{editing ? "Edit" : "Publish"} update</DialogTitle>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="update-title">Title</Label>
              <Input
                id="update-title"
                value={form.title}
                onChange={(e) => setForm({ ...form, title: e.target.value })}
                data-testid="update-title-input"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="update-url">Link (optional)</Label>
              <Input
                id="update-url"
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                placeholder="https://…"
                data-testid="update-url-input"
              />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={form.is_active}
                onCheckedChange={(c) => setForm({ ...form, is_active: c === true })}
                data-testid="update-active-checkbox"
              />
              Active (show on website)
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} data-testid="update-cancel-button">
              Cancel
            </Button>
            <Button
              onClick={() => save.mutate(form)}
              disabled={save.isPending || !form.title.trim()}
              data-testid="update-save-button"
            >
              {save.isPending ? "Saving…" : "Save"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// CRUD panel for Important Notices.
function NoticesAdmin() {
  const qc = useQueryClient();
  const { data: notices, isLoading } = useQuery({
    queryKey: ["notices"],
    queryFn: () => apiGet<Notice[]>("/notices"),
    retry: false,
  });
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<Notice | null>(null);
  const [form, setForm] = useState<NoticeInput>({ title: "", body: "", is_active: true });

  const save = useMutation({
    mutationFn: (input: NoticeInput) =>
      editing ? apiPut<Notice>(`/notices/${editing.id}`, input) : apiPost<Notice>("/notices", input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notices"] });
      setOpen(false);
      toast.success(editing ? "Notice updated" : "Notice published");
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  const remove = useMutation({
    mutationFn: (id: string) => apiDelete<{ ok: boolean }>(`/notices/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notices"] });
      toast.success("Notice deleted");
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <div className="mt-4 border border-[#E2E8F0] bg-white p-4" data-testid="admin-notices-panel">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-base font-bold text-gray-900">Important Notices</h2>
        <Button
          size="xs"
          onClick={() => {
            setEditing(null);
            setForm({ title: "", body: "", is_active: true });
            setOpen(true);
          }}
          data-testid="admin-notices-add-button"
        >
          + Add notice
        </Button>
      </div>
      {isLoading ? (
        <p className="py-6 text-center text-sm text-gray-500">Loading…</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Title</TableHead>
              <TableHead>Active</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {notices?.map((n) => (
              <TableRow key={n.id}>
                <TableCell className="font-medium">{n.title}</TableCell>
                <TableCell>{n.is_active ? "Yes" : "No"}</TableCell>
                <TableCell className="space-x-2 text-right">
                  <Button
                    variant="outline"
                    size="xs"
                    onClick={() => {
                      setEditing(n);
                      setForm({ title: n.title, body: n.body, is_active: n.is_active });
                      setOpen(true);
                    }}
                    data-testid={`notice-edit-${n.id}`}
                  >
                    Edit
                  </Button>
                  <DeleteButton
                    onConfirm={() => remove.mutate(n.id)}
                    testid={`notice-delete-${n.id}`}
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{editing ? "Edit" : "Add"} notice</DialogTitle>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="notice-title">Title (shown in the marquee bar)</Label>
              <Input
                id="notice-title"
                value={form.title}
                onChange={(e) => setForm({ ...form, title: e.target.value })}
                data-testid="notice-title-input"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="notice-body">Details (optional)</Label>
              <Input
                id="notice-body"
                value={form.body}
                onChange={(e) => setForm({ ...form, body: e.target.value })}
                data-testid="notice-body-input"
              />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={form.is_active}
                onCheckedChange={(c) => setForm({ ...form, is_active: c === true })}
                data-testid="notice-active-checkbox"
              />
              Active (show on website)
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)} data-testid="notice-cancel-button">
              Cancel
            </Button>
            <Button
              onClick={() => save.mutate(form)}
              disabled={save.isPending || !form.title.trim()}
              data-testid="notice-save-button"
            >
              {save.isPending ? "Saving…" : "Save"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// WhatsApp channel link setting.
function SettingsAdmin() {
  const qc = useQueryClient();
  const { data } = useQuery({
    queryKey: ["settings"],
    queryFn: () => apiGet<SiteSettings>("/settings"),
    retry: false,
  });
  const [draft, setDraft] = useState<string | null>(null);
  const value = draft ?? data?.whatsapp_group_url ?? "";

  const save = useMutation({
    mutationFn: (v: string) => apiPut<SiteSettings>("/settings", { whatsapp_group_url: v }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["settings"] });
      toast.success("Settings saved");
    },
    onError: (e) => toast.error(errMsg(e)),
  });

  return (
    <div className="mt-4 border border-[#E2E8F0] bg-white p-4" data-testid="admin-settings-panel">
      <h2 className="text-base font-bold text-gray-900">Site Settings</h2>
      <div className="mt-3 grid max-w-xl gap-1.5">
        <Label htmlFor="settings-whatsapp">WhatsApp channel / group invite link</Label>
        <Input
          id="settings-whatsapp"
          value={value}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="https://whatsapp.com/channel/…"
          data-testid="settings-whatsapp-input"
        />
        <p className="text-xs text-gray-500">
          Used by the header button, floating button, contact section, and as the enquiry
          fallback for items without an official URL.
        </p>
      </div>
      <Button
        className="mt-3"
        size="sm"
        onClick={() => save.mutate(value)}
        disabled={save.isPending}
        data-testid="settings-save-button"
      >
        {save.isPending ? "Saving…" : "Save settings"}
      </Button>
    </div>
  );
}

export default function AdminDashboardPage() {
  const me = useAdmin();
  const qc = useQueryClient();
  const navigate = useNavigate();

  if (me.isLoading) {
    return (
      <div className="flex min-h-svh items-center justify-center text-sm text-gray-500">
        Loading…
      </div>
    );
  }

  if (me.isError || !me.data) {
    return (
      <div
        className="flex min-h-svh flex-col items-center justify-center gap-3 bg-gray-50 px-4 text-center text-gray-900"
        data-testid="admin-guard"
      >
        <p className="text-sm">Admin sign-in required.</p>
        <Link to="/admin" className={buttonVariants()} data-testid="admin-guard-login-link">
          Go to Login
        </Link>
      </div>
    );
  }

  return (
    <div className="min-h-svh bg-gray-50 text-gray-900">
      <header className="bg-[#AB0A0A] text-white">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-3 px-4 py-3">
          <h1 className="text-lg font-bold">Admin Panel</h1>
          <span className="hidden text-sm text-red-100 md:inline">{SITE.name}</span>
          <div className="ml-auto flex items-center gap-3">
            <span className="text-sm text-red-100" data-testid="admin-username">
              signed in: {me.data.username}
            </span>
            <Link to="/" className="text-sm font-bold underline" data-testid="admin-view-site-link">
              View site
            </Link>
            <Button
              variant="outline"
              size="xs"
              onClick={async () => {
                await endSession(qc);
                navigate("/admin");
              }}
              data-testid="admin-logout-button"
            >
              Logout
            </Button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-6">
        <Tabs defaultValue="services">
          <TabsList className="h-auto flex-wrap justify-start">
            <TabsTrigger value="services" data-testid="admin-tab-services">
              CSC Services
            </TabsTrigger>
            <TabsTrigger value="schemes" data-testid="admin-tab-schemes">
              Schemes
            </TabsTrigger>
            <TabsTrigger value="forms" data-testid="admin-tab-forms">
              Online Forms
            </TabsTrigger>
            <TabsTrigger value="updates" data-testid="admin-tab-updates">
              Updates
            </TabsTrigger>
            <TabsTrigger value="notices" data-testid="admin-tab-notices">
              Notices
            </TabsTrigger>
            <TabsTrigger value="settings" data-testid="admin-tab-settings">
              Settings
            </TabsTrigger>
          </TabsList>
          <TabsContent value="services">
            <LinkItemsAdmin kind="services" label="CSC Service" />
          </TabsContent>
          <TabsContent value="schemes">
            <LinkItemsAdmin kind="schemes" label="Government Scheme" />
          </TabsContent>
          <TabsContent value="forms">
            <LinkItemsAdmin kind="forms" label="Online Form" />
          </TabsContent>
          <TabsContent value="updates">
            <UpdatesAdmin />
          </TabsContent>
          <TabsContent value="notices">
            <NoticesAdmin />
          </TabsContent>
          <TabsContent value="settings">
            <SettingsAdmin />
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
@import "tailwindcss";
@import "tw-animate-css";
@import "shadcn/tailwind.css";

@custom-variant dark (&:is(.dark *));

@theme inline {
    --font-heading: var(--font-sans);
    --font-sans: Arial, Helvetica, 'Noto Sans Devanagari', 'Mangal', sans-serif;
    --color-sidebar-ring: var(--sidebar-ring);
    --color-sidebar-border: var(--sidebar-border);
    --color-sidebar-accent-foreground: var(--sidebar-accent-foreground);
    --color-sidebar-accent: var(--sidebar-accent);
    --color-sidebar-primary-foreground: var(--sidebar-primary-foreground);
    --color-sidebar-primary: var(--sidebar-primary);
    --color-sidebar-foreground: var(--sidebar-foreground);
    --color-sidebar: var(--sidebar);
    --color-chart-5: var(--chart-5);
    --color-chart-4: var(--chart-4);
    --color-chart-3: var(--chart-3);
    --color-chart-2: var(--chart-2);
    --color-chart-1: var(--chart-1);
    --color-ring: var(--ring);
    --color-input: var(--input);
    --color-border: var(--border);
    --color-destructive: var(--destructive);
    --color-accent-foreground: var(--accent-foreground);
    --color-accent: var(--accent);
    --color-muted-foreground: var(--muted-foreground);
    --color-muted: var(--muted);
    --color-secondary-foreground: var(--secondary-foreground);
    --color-secondary: var(--secondary);
    --color-primary-foreground: var(--primary-foreground);
    --color-primary: var(--primary);
    --color-popover-foreground: var(--popover-foreground);
    --color-popover: var(--popover);
    --color-card-foreground: var(--card-foreground);
    --color-card: var(--card);
    --color-foreground: var(--foreground);
    --color-background: var(--background);
    --radius-sm: calc(var(--radius) * 0.6);
    --radius-md: calc(var(--radius) * 0.8);
    --radius-lg: var(--radius);
    --radius-xl: calc(var(--radius) * 1.4);
    --radius-2xl: calc(var(--radius) * 1.8);
    --radius-3xl: calc(var(--radius) * 2.2);
    --radius-4xl: calc(var(--radius) * 2.6);
}

/* Sarkari-portal light theme: white surfaces, red accent, square corners. */
:root {
    --background: #ffffff;
    --foreground: #111827;
    --card: #ffffff;
    --card-foreground: #111827;
    --popover: #ffffff;
    --popover-foreground: #111827;
    --primary: #ab0a0a;
    --primary-foreground: #ffffff;
    --secondary: #f8fafc;
    --secondary-foreground: #0f172a;
    --muted: #f1f5f9;
    --muted-foreground: #4b5563;
    --accent: #fef2f2;
    --accent-foreground: #7f1d1d;
    --destructive: #dc2626;
    --border: #e5e7eb;
    --input: #cbd5e1;
    --ring: #b91c1c;
    --chart-1: #ab0a0a;
    --chart-2: #b45309;
    --chart-3: #15803d;
    --chart-4: #1e40af;
    --chart-5: #1e293b;
    --radius: 0rem;
    --sidebar: #f8fafc;
    --sidebar-foreground: #111827;
    --sidebar-primary: #ab0a0a;
    --sidebar-primary-foreground: #ffffff;
    --sidebar-accent: #fef2f2;
    --sidebar-accent-foreground: #7f1d1d;
    --sidebar-border: #e5e7eb;
    --sidebar-ring: #b91c1c;
}

.dark {
    --background: #0f172a;
    --foreground: #f8fafc;
    --card: #1e293b;
    --card-foreground: #f8fafc;
    --popover: #1e293b;
    --popover-foreground: #f8fafc;
    --primary: #ef4444;
    --primary-foreground: #ffffff;
    --secondary: #334155;
    --secondary-foreground: #f8fafc;
    --muted: #334155;
    --muted-foreground: #94a3b8;
    --accent: #334155;
    --accent-foreground: #fecaca;
    --destructive: #7f1d1d;
    --border: #ffffff1a;
    --input: #ffffff26;
    --ring: #ef4444;
    --chart-1: #f87171;
    --chart-2: #fbbf24;
    --chart-3: #4ade80;
    --chart-4: #60a5fa;
    --chart-5: #94a3b8;
    --sidebar: #1e293b;
    --sidebar-foreground: #f8fafc;
    --sidebar-primary: #ef4444;
    --sidebar-primary-foreground: #ffffff;
    --sidebar-accent: #334155;
    --sidebar-accent-foreground: #fecaca;
    --sidebar-border: #ffffff1a;
    --sidebar-ring: #ef4444;
}

@layer base {
  * {
    @apply border-border outline-ring/50;
    }
  body {
    @apply bg-background text-foreground;
    font-size: 15px;
    }
  html {
    @apply font-sans;
    }
}

/* Important-notice marquee — horizontal scroll, disabled under reduced motion. */
@keyframes notice-marquee {
  from { transform: translateX(0); }
  to { transform: translateX(-50%); }
}
.notice-marquee {
  display: inline-block;
  width: max-content;
  animation: notice-marquee 40s linear infinite;
}
@media (prefers-reduced-motion: reduce) {
  .notice-marquee {
    animation: none;
  }
}
import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { SiWhatsapp } from "@icons-pack/react-simple-icons";
import { CSCLogo } from "@/components/CSCLogo";
import { SITE } from "@/lib/site";

const NAV = [
  { to: "/", label: "Home", testid: "nav-link-home" },
  { to: "/services", label: "CSC Services", testid: "nav-link-services" },
  { to: "/schemes", label: "Government Schemes", testid: "nav-link-schemes" },
  { to: "/forms", label: "Online Forms", testid: "nav-link-forms" },
  { to: "/contact", label: "Contact Us", testid: "nav-link-contact" },
];

interface SiteHeaderProps {
  whatsappUrl: string;
}

export default function SiteHeader({ whatsappUrl }: SiteHeaderProps) {
  const [q, setQ] = useState("");
  const navigate = useNavigate();

  const submitSearch = (e: FormEvent) => {
    e.preventDefault();
    const term = q.trim();
    navigate(term ? `/search?q=${encodeURIComponent(term)}` : "/search");
  };

  return (
    <header data-testid="site-header">
      {/* Identity row */}
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-3 px-3 py-3 sm:px-4">
        <Link to="/" className="flex items-center gap-3" data-testid="header-home-link">
          <CSCLogo />
          <span>
            <span className="block text-lg font-bold leading-tight text-[#AB0A0A] md:text-xl">
              {SITE.name}
            </span>
            <span className="block text-xs text-gray-600 md:text-sm">{SITE.hindiName}</span>
          </span>
        </Link>
        <div className="ml-auto flex items-center gap-2">
          {whatsappUrl && (
            <a
              href={whatsappUrl}
              target="_blank"
              rel="noopener noreferrer"
              aria-label="Join our WhatsApp channel (opens in a new tab)"
              className="inline-flex items-center gap-1.5 bg-[#15803D] px-3 py-2 text-sm font-bold text-white transition-colors duration-150 hover:bg-[#166534]"
              data-testid="whatsapp-header-button"
            >
              <SiWhatsapp size={18} />
              WhatsApp
            </a>
          )}
        </div>
      </div>

      {/* Red navigation strip with search box */}
      <nav className="bg-[#AB0A0A]" aria-label="Main navigation">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-4 gap-y-1.5 px-3 py-2 sm:px-4">
          {NAV.map((item) => (
            <Link
              key={item.to}
              to={item.to}
              className="text-sm font-bold text-white transition-colors duration-150 hover:text-yellow-200 md:text-[15px]"
              data-testid={item.testid}
            >
              {item.label}
            </Link>
          ))}
          <form
            className="ml-auto flex"
            onSubmit={submitSearch}
            role="search"
            data-testid="header-search-form"
          >
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search services / forms…"
              aria-label="Search services, schemes and forms"
              className="w-40 border border-red-900 bg-white px-2 py-1 text-sm text-gray-900 outline-none placeholder:text-gray-400 focus:border-yellow-400 md:w-60"
              data-testid="header-search-input"
            />
            <button
              type="submit"
              className="bg-[#7F1D1D] px-3 py-1 text-sm font-bold text-white transition-colors duration-150 hover:bg-[#991B1B]"
              data-testid="header-search-submit"
            >
              Search
            </button>
          </form>
        </div>
      </nav>
    </header>
  );
}
# Test credentials

## Admin panel
- URL: `/admin` (login) → `/admin/dashboard`
- Username: `admin`
- Password: `Nauling@123`
- Seeded by `backend/seed.py`; sign-in sets the httpOnly cookie `csc_session`.

No other accounts exist. There is no phone-number login anywhere (owner removed
all phone numbers from the site by request).
import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/lib/api";
import type { LinkItem, Notice, SiteSettings, UpdateItem } from "@/lib/types";
import ContactInfo from "@/components/ContactInfo";
import LinkColumn from "@/components/LinkColumn";
import NoticeBar from "@/components/NoticeBar";
import SiteFooter from "@/components/SiteFooter";
import SiteHeader from "@/components/SiteHeader";
import UpdatesSection from "@/components/UpdatesSection";
import WhatsAppFab from "@/components/WhatsAppFab";

const loadServices = () => apiGet<LinkItem[]>("/services");
const loadSchemes = () => apiGet<LinkItem[]>("/schemes");
const loadForms = () => apiGet<LinkItem[]>("/forms");
const loadUpdates = () => apiGet<UpdateItem[]>("/updates");
const loadNotices = () => apiGet<Notice[]>("/notices");
const loadSettings = () => apiGet<SiteSettings>("/settings");

// The three-column Sarkari Result homepage. Shell and copy render
// unconditionally — only the data regions show loading/empty states.
export default function Home() {
  const { data: services, isLoading: loadingServices } = useQuery({
    queryKey: ["services"],
    queryFn: loadServices,
    retry: false,
  });
  const { data: schemes, isLoading: loadingSchemes } = useQuery({
    queryKey: ["schemes"],
    queryFn: loadSchemes,
    retry: false,
  });
  const { data: forms, isLoading: loadingForms } = useQuery({
    queryKey: ["forms"],
    queryFn: loadForms,
    retry: false,
  });
  const { data: updates } = useQuery({
    queryKey: ["updates"],
    queryFn: loadUpdates,
    retry: false,
  });
  const { data: notices } = useQuery({
    queryKey: ["notices"],
    queryFn: loadNotices,
    retry: false,
  });
  const { data: settings } = useQuery({
    queryKey: ["settings"],
    queryFn: loadSettings,
    retry: false,
  });

  const whatsappUrl = settings?.whatsapp_group_url ?? "";

  return (
    <div className="min-h-svh bg-white text-gray-900">
      <NoticeBar notices={notices} />
      <SiteHeader whatsappUrl={whatsappUrl} />
      <main className="mx-auto max-w-7xl px-3 py-4 sm:px-4">
        <div className="grid grid-cols-1 items-start gap-4 md:grid-cols-3" data-testid="three-columns">
          <LinkColumn
            title="CSC Services"
            hindi="सीएससी सेवाएं"
            kind="services"
            items={services}
            isLoading={loadingServices}
            whatsappUrl={whatsappUrl}
          />
          <LinkColumn
            title="Government Schemes"
            hindi="सरकारी योजनाएं"
            kind="schemes"
            items={schemes}
            isLoading={loadingSchemes}
            whatsappUrl={whatsappUrl}
          />
          <LinkColumn
            title="Online Forms"
            hindi="ऑनलाइन फॉर्म"
            kind="forms"
            items={forms}
            isLoading={loadingForms}
            whatsappUrl={whatsappUrl}
          />
        </div>
        <UpdatesSection updates={updates} />
        <ContactInfo whatsappUrl={whatsappUrl} />
      </main>
      <SiteFooter />
      <WhatsAppFab url={whatsappUrl} />
    </div>
  );
}
import { Navigate, Route, Routes } from "react-router-dom";
import { Toaster } from "@/components/ui/sonner";
import Home from "@/pages/Home";
import CategoryPage from "@/pages/CategoryPage";
import SearchPage from "@/pages/SearchPage";
import ContactPage from "@/pages/ContactPage";
import AdminLoginPage from "@/pages/AdminLoginPage";
import AdminDashboardPage from "@/pages/AdminDashboardPage";

// One <Route> per page in src/pages; BrowserRouter already wraps this in main.tsx.
export default function App() {
  return (
    <>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/services" element={<CategoryPage kind="services" />} />
        <Route path="/schemes" element={<CategoryPage kind="schemes" />} />
        <Route path="/forms" element={<CategoryPage kind="forms" />} />
        <Route path="/search" element={<SearchPage />} />
        <Route path="/contact" element={<ContactPage />} />
        <Route path="/admin" element={<AdminLoginPage />} />
        <Route path="/admin/dashboard" element={<AdminDashboardPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      <Toaster richColors />
    </>
  );
}
import { Navigate, Route, Routes } from "react-router-dom";
import { Toaster } from "@/components/ui/sonner";
import Home from "@/pages/Home";
import CategoryPage from "@/pages/CategoryPage";
import SearchPage from "@/pages/SearchPage";
import ContactPage from "@/pages/ContactPage";
import AdminLoginPage from "@/pages/AdminLoginPage";
import AdminDashboardPage from "@/pages/AdminDashboardPage";

// One <Route> per page in src/pages; BrowserRouter already wraps this in main.tsx.
export default function App() {
  return (
    <>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/services" element={<CategoryPage kind="services" />} />
        <Route path="/schemes" element={<CategoryPage kind="schemes" />} />
        <Route path="/forms" element={<CategoryPage kind="forms" />} />
        <Route path="/search" element={<SearchPage />} />
        <Route path="/contact" element={<ContactPage />} />
        <Route path="/admin" element={<AdminLoginPage />} />
        <Route path="/admin/dashboard" element={<AdminDashboardPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      <Toaster richColors />
    </>
  );
}
<!doctype html>
<html lang="en">
  <!-- <html lang="en" class="dark"> — uncomment for dark-by-default (replace the tag above; `dark` is a Tailwind variant, never `@apply` it) -->
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="icon" href="/favicon.ico" sizes="any" />
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png" />
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png" />
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Nauling Mobile CSC Center Ganai Gangoli — CSC Services, Government Schemes & Online Forms</title>
    <meta
      name="description"
      content="Nauling Mobile CSC Center Ganai Gangoli (Pithoragarh, Uttarakhand) — PAN card, Ayushman card, E-Shram card, voter ID, passport, driving licence, pension, scholarship, certificates and all online government form services. CSC ID 628898270014."
    />
    <meta
      name="keywords"
      content="CSC Ganai Gangoli, Nauling Mobile CSC Center, Pithoragarh CSC, PAN card apply, Ayushman card, E-Shram card, voter ID, pension yojana, scholarship form, online form Uttarakhand"
    />
    <meta name="theme-color" content="#AB0A0A" />
    <script type="application/ld+json">
      {
        "@context": "https://schema.org",
        "@type": "LocalBusiness",
        "name": "Nauling Mobile CSC Center Ganai Gangoli",
        "email": "naulingmobilecsc@gmail.com",
        "address": {
          "@type": "PostalAddress",
          "addressLocality": "Ganai Gangoli",
          "addressRegion": "Uttarakhand",
          "addressCountry": "IN"
        },
        "identifier": "CSC 628898270014",
        "description": "Common Service Centre offering CSC services, government schemes and online form filling in Ganai Gangoli, Pithoragarh, Uttarakhand."
      }
    </script>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
import type { LinkItem } from "@/lib/types";
import LinkRow from "@/components/LinkRow";

interface LinkColumnProps {
  title: string;
  hindi: string;
  kind: string;
  items: LinkItem[] | undefined;
  isLoading: boolean;
  whatsappUrl: string;
}

// One Sarkari-Result-style column: solid red heading bar, thin red border,
// black bullets, blue underlined links.
export default function LinkColumn({
  title,
  hindi,
  kind,
  items,
  isLoading,
  whatsappUrl,
}: LinkColumnProps) {
  return (
    <section className="border border-[#AB0A0A] bg-white" data-testid={`${kind}-column`}>
      <header className="bg-[#AB0A0A] px-3 py-2 text-center text-white">
        <h2 className="text-base font-bold uppercase tracking-wide md:text-lg">{title}</h2>
        <p className="mt-0.5 text-xs text-red-100">{hindi}</p>
      </header>
      <ul className="max-h-[760px] divide-y divide-red-100/70 overflow-y-auto p-2.5 md:p-3">
        {isLoading && (
          <li className="px-1.5 py-2 text-sm text-gray-500">लोड हो रहा है… (loading…)</li>
        )}
        {!isLoading && items !== undefined && items.length === 0 && (
          <li className="px-1.5 py-2 text-sm text-gray-500">सूची उपलब्ध नहीं है</li>
        )}
        {items?.map((item, index) => (
          <LinkRow
            key={item.id}
            item={item}
            whatsappUrl={whatsappUrl}
            testid={`${kind}-link-${index + 1}`}
          />
        ))}
      </ul>
    </section>
  );
}
import { useQuery } from "@tanstack/react-query";
import { apiGet } from "@/lib/api";
import type { SiteSettings } from "@/lib/types";
import ContactInfo from "@/components/ContactInfo";
import SiteFooter from "@/components/SiteFooter";
import SiteHeader from "@/components/SiteHeader";
import WhatsAppFab from "@/components/WhatsAppFab";

export default function ContactPage() {
  const { data: settings } = useQuery({
    queryKey: ["settings"],
    queryFn: () => apiGet<SiteSettings>("/settings"),
    retry: false,
  });
  const whatsappUrl = settings?.whatsapp_group_url ?? "";

  return (
    <div className="min-h-svh bg-white text-gray-900">
      <SiteHeader whatsappUrl={whatsappUrl} />
      <main className="mx-auto max-w-3xl px-3 py-4 sm:px-4">
        <ContactInfo whatsappUrl={whatsappUrl} />
      </main>
      <SiteFooter />
      <WhatsAppFab url={whatsappUrl} />
    </div>
  );
}
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { apiGet } from "@/lib/api";
import type { LinkItem, Notice, SearchResult, SiteSettings } from "@/lib/types";
import LinkRow from "@/components/LinkRow";
import NoticeBar from "@/components/NoticeBar";
import SiteFooter from "@/components/SiteFooter";
import SiteHeader from "@/components/SiteHeader";
import WhatsAppFab from "@/components/WhatsAppFab";

const loadSettings = () => apiGet<SiteSettings>("/settings");
const loadNotices = () => apiGet<Notice[]>("/notices");

interface ResultGroupProps {
  title: string;
  hindi: string;
  kind: string;
  items: LinkItem[];
  whatsappUrl: string;
}

function ResultGroup({ title, hindi, kind, items, whatsappUrl }: ResultGroupProps) {
  return (
    <div className="border border-[#AB0A0A] bg-white" data-testid={`search-group-${kind}`}>
      <div className="bg-[#AB0A0A] px-3 py-1.5 text-sm font-bold text-white">
        {title}
        <span className="ml-1 font-normal text-red-100" data-testid={`search-count-${kind}`}>
          ({items.length})
        </span>
        <span className="ml-2 text-xs font-normal text-red-100">{hindi}</span>
      </div>
      <ul className="divide-y divide-red-100/70 p-2">
        {items.length === 0 && (
          <li className="px-1.5 py-2 text-sm text-gray-500">कोई मेल नहीं (no matches)</li>
        )}
        {items.map((item, index) => (
          <LinkRow
            key={item.id}
            item={item}
            whatsappUrl={whatsappUrl}
            testid={`search-${kind}-result-${index + 1}`}
          />
        ))}
      </ul>
    </div>
  );
}

// Instant search — the backend answers a case-insensitive regex across
// services / schemes / forms / updates on every keystroke.
export default function SearchPage() {
  const [params] = useSearchParams();
  const [q, setQ] = useState(params.get("q") ?? "");
  const term = q.trim();

  const { data: settings } = useQuery({ queryKey: ["settings"], queryFn: loadSettings, retry: false });
  const { data: notices } = useQuery({ queryKey: ["notices"], queryFn: loadNotices, retry: false });
  const { data, isFetching } = useQuery({
    queryKey: ["search", term],
    queryFn: () => apiGet<SearchResult>(`/search?q=${encodeURIComponent(term)}`),
    enabled: term.length > 0,
    retry: false,
  });
  const whatsappUrl = settings?.whatsapp_group_url ?? "";

  return (
    <div className="min-h-svh bg-white text-gray-900">
      <NoticeBar notices={notices} />
      <SiteHeader whatsappUrl={whatsappUrl} />
      <main className="mx-auto max-w-7xl px-3 py-4 sm:px-4">
        <section className="border border-[#AB0A0A] bg-white" data-testid="search-panel">
          <header className="bg-[#AB0A0A] px-3 py-2 text-center text-white">
            <h2 className="text-base font-bold uppercase tracking-wide md:text-lg">Search Results</h2>
            <p className="mt-0.5 text-xs text-red-100">खोज परिणाम</p>
          </header>
          <div className="p-3 md:p-4">
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Type to search services, schemes, forms… (सेवा / योजना / फॉर्म खोजें)"
              autoFocus
              aria-label="Search services, schemes and forms"
              className="w-full border border-gray-300 bg-[#F8FAFC] px-3 py-2 text-sm text-gray-900 outline-none transition-colors duration-150 placeholder:text-gray-400 focus:border-[#B91C1C]"
              data-testid="search-page-input"
            />
            {term.length === 0 ? (
              <p className="mt-3 text-sm text-gray-500">
                उपर बॉक्स में टाइप करें — start typing above to search across all services,
                schemes and forms.
              </p>
            ) : isFetching && !data ? (
              <p className="mt-3 text-sm text-gray-500">खोजा जा रहा है… (searching…)</p>
            ) : data ? (
              <>
                <div className="mt-3 grid grid-cols-1 items-start gap-4 md:grid-cols-3">
                  <ResultGroup
                    title="CSC Services"
                    hindi="सीएससी सेवाएं"
                    kind="services"
                    items={data.services}
                    whatsappUrl={whatsappUrl}
                  />
                  <ResultGroup
                    title="Government Schemes"
                    hindi="सरकारी योजनाएं"
                    kind="schemes"
                    items={data.schemes}
                    whatsappUrl={whatsappUrl}
                  />
                  <ResultGroup
                    title="Online Forms"
                    hindi="ऑनलाइन फॉर्म"
                    kind="forms"
                    items={data.forms}
                    whatsappUrl={whatsappUrl}
                  />
                </div>
                {data.updates.length > 0 && (
                  <div className="mt-4 border border-[#AB0A0A] bg-white" data-testid="search-updates">
                    <div className="bg-[#AB0A0A] px-3 py-1.5 text-sm font-bold text-white">
                      Latest Updates
                      <span className="ml-1 font-normal text-red-100">
                        ({data.updates.length} match{data.updates.length === 1 ? "" : "es"})
                      </span>
                    </div>
                    <ul className="divide-y divide-red-100/70 p-2">
                      {data.updates.map((u) => (
                        <li key={u.id} className="px-1.5 py-2 text-sm" data-testid={`search-update-${u.id}`}>
                          <span className="mr-2 font-mono text-xs text-gray-500">{u.date}</span>
                          {u.url ? (
                            <a
                              href={u.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-medium text-[#0056B3] underline transition-colors duration-150 hover:text-[#003366]"
                            >
                              {u.title}
                            </a>
                          ) : (
                            <span className="text-gray-900">{u.title}</span>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </>
            ) : null}
          </div>
        </section>
      </main>
      <SiteFooter />
      <WhatsAppFab url={whatsappUrl} />
    </div>
  );
}
# Nauling Mobile CSC Center Ganai Gangoli — App Spec

Sarkari Result-style three-column CSC directory for a Common Service Centre in
Ganai Gangoli, Pithoragarh, Uttarakhand. FastAPI + Mongo backend, Vite + React 19
frontend (this repo: `farm-ts` template).

**Important owner constraint:** NO phone number anywhere on the site (owner
explicitly removed it) — contact surface is CSC ID, email, and the WhatsApp
channel link only. No Call Now button, no tel: links, no wa.me/<number>.

## Data model (Mongo `app` db; ids are uuid strings, aware-UTC datetimes)
- `services` / `schemes` / `forms` — LinkItem: `{id, name, hindi, url, is_new, sort_order, created_at}`. `url: ""` → frontend falls back to the WhatsApp channel link.
- `updates` — `{id, title, url, date (YYYY-MM-DD, server-anchored), is_active, created_at}`
- `notices` — `{id, title, body, is_active, created_at}`
- `settings` — single doc `{key: "site", whatsapp_group_url}` (WhatsApp channel invite URL)
- `admins` — `{id, username, password_hash (passlib pbkdf2_sha256), created_at}`
- `sessions` — `{token, admin_id, expires_at}` + TTL index on `expires_at`; httpOnly cookie `csc_session` (samesite=lax, path=/)

## Endpoints (all on api_router under /api)
Public reads:
- `GET /api/services` | `/api/schemes` | `/api/forms` — sorted (sort_order, name)
- `GET /api/updates` | `/api/notices` — full list; frontend filters `is_active` for display
- `GET /api/search?q=` — grouped `{services, schemes, forms, updates}` case-insensitive regex (422 if q missing)
- `GET /api/settings` — `{whatsapp_group_url}`

Auth (httpOnly cookie sessions — never tokens in JSON):
- `POST /api/auth/login` {username, password} → sets `csc_session` cookie; 401 on bad creds
- `POST /api/auth/logout` → clears server session + cookie
- `GET /api/auth/me` → `{username}` or 401

Admin writes (require session; 401 otherwise):
- `POST /api/{services|schemes|forms}` · `PUT /api/{kind}/{id}` · `DELETE /api/{kind}/{id}`
- `POST /api/updates` · `PUT /api/updates/{id}` · `DELETE /api/updates/{id}`
- `POST /api/notices` · `PUT /api/notices/{id}` · `DELETE /api/notices/{id}`
- `PUT /api/settings`

## Seed
`cd /app/backend && python seed.py` — idempotent (skips non-empty collections).
Seeds: admin account (credentials in memory/test_credentials.md), settings with
WhatsApp channel URL, 14 services, 10 schemes, 12 forms, 3 updates, 2 notices
(bilingual English/Hindi).

## Frontend pages
- `/` — notice marquee bar, header (logo, nav, search box, WhatsApp button),
  three red-bordered columns (CSC Services / Government Schemes / Online Forms),
  Latest Updates panel, Contact panel, footer, floating WhatsApp FAB
- `/services` `/schemes` `/forms` — full-list CategoryPage
- `/search?q=` — instant grouped search results with counts
- `/contact` — contact panel
- `/admin` — login; `/admin/dashboard` — tabs: Services / Schemes / Forms /
  Updates / Notices / Settings (WhatsApp link)

## Design rules (user-pinned)
White bg, red `#AB0A0A` heading bars (white text), 1px red borders, blue
underlined links, black bullets, Arial, square corners. NO dashboards, hero
banners, or card-based layouts. Items without an official URL open the WhatsApp
channel link; official URLs open in a new tab (`rel="noopener noreferrer"`).
  if (!me.isLoading && (!me.data || !me.data.username)) {              signed in: {admin.username}
   const admin = me.data;

  if (me.isLoading) {
    return (
      <div className="flex min-h-svh items-center justify-center text-sm text-gray-500">
        Loading…
      </div>
    );
  }

  if (!admin || !admin.username) {    onError: (e) => toast.error(errMsg(e)),
  });

  // Render the form only once settings exist — prevents saving an empty value
  // over the real WhatsApp link while the query is still loading.
  if (isLoading || !data) {
    return (
      <div className="mt-4 border border-[#E2E8F0] bg-white p-4" data-testid="admin-settings-panel">
        <h2 className="text-base font-bold text-gray-900">Site Settings</h2>
        <p className="py-6 text-center text-sm text-gray-500">Loading…</p>
      </div>
    );
  }

  const value = draft ?? data.whatsapp_group_url;

  return (
    <div className="mt-4 border border-[#E2E8F0] bg-white p-4" data-testid="admin-settings-panel">
      <h2 className="text-base font-bold text-gray-900">Site Settings</h2>
  const { data, isLoading } = useQuery({
    queryKey: ["settings"],
    queryFn: () => apiGet<SiteSettings>("/settings"),
    retry: false,
  });
  const [draft, setDraft] = useState<string | null>(null);
