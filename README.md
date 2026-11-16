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
