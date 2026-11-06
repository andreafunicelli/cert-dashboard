"""Replaceable logo state machine (``docs/ui/branding.md`` "Persistence, serving, cleanup").

A preview is staged in the database, tied to one authenticated session and addressed by a random
256-bit token; only the token's SHA-256 is stored. Save and reset are compare-and-set against the
current revision, so two administrators can never overwrite each other silently. Every entry point
opportunistically purges expired drafts and old receipts (A2-D6); the daily cleanup handler does
the same when no one visits the page.

The web layer owns CSRF, gates and rendering. This module returns typed refusals so the route can
map them to the exact status codes and copy without inspecting strings.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import and_, delete, func, or_, select, text
from sqlalchemy.orm import Session

from app.models import BrandingAsset, BrandingDraft, UserSession
from app.services.audit import Actor, record
from app.services.branding_image import validate_logo

DRAFT_TTL = timedelta(minutes=30)
RECEIPT_TTL = timedelta(minutes=30)
MAX_PENDING_BYTES = 16 * 1024 * 1024
DEFAULT_REVISION = "default"
AUDIT_TARGET = "logo"

__all__ = [
    "DEFAULT_REVISION",
    "DRAFT_TTL",
    "MAX_PENDING_BYTES",
    "BrandingDraftExpired",
    "BrandingDraftNotFound",
    "BrandingRevisionMismatch",
    "BrandingStorageUnavailable",
    "CurrentBranding",
    "ResetOutcome",
    "SaveOutcome",
    "StagedDraft",
    "current_asset",
    "current_revision",
    "discard_draft",
    "draft_image",
    "find_draft",
    "purge_branding_drafts",
    "reset_branding",
    "save_draft",
    "stage_draft",
]


class BrandingDraftNotFound(Exception):
    """Unknown token, or a token that belongs to another session (404, never revealing which)."""


class BrandingDraftExpired(Exception):
    """The draft or its session expired or was revoked (410)."""


class BrandingRevisionMismatch(Exception):
    """Someone else saved or reset branding since the page was opened (409)."""


class BrandingStorageUnavailable(Exception):
    """The pending-draft cap or the store refused the write (503)."""


@dataclass(frozen=True)
class CurrentBranding:
    revision: str
    mime: str
    width: int
    height: int
    display_filename: str
    content: bytes
    updated_at: datetime


@dataclass(frozen=True)
class StagedDraft:
    token: str
    mime: str
    width: int
    height: int
    sha256: str
    byte_size: int
    display_filename: str
    base_revision: str
    expires_at: datetime


@dataclass(frozen=True)
class SaveOutcome:
    revision: str
    already_saved: bool


@dataclass(frozen=True)
class ResetOutcome:
    changed: bool


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# One stable transaction-scoped key serializes save/reset across sessions. The singleton row may
# not exist yet, so it cannot be the lock: without this, two default-state saves could both pass
# the compare-and-set and race on the insert.
_ASSET_LOCK_KEY = 1_650_000_001


def _lock_asset(db: Session) -> None:
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _ASSET_LOCK_KEY})


def current_asset(db: Session) -> CurrentBranding | None:
    row = db.get(BrandingAsset, 1)
    if row is None:
        return None
    return CurrentBranding(
        revision=row.sha256,
        mime=row.mime,
        width=row.width,
        height=row.height,
        display_filename=row.display_filename,
        content=bytes(row.content),
        updated_at=row.updated_at,
    )


def current_revision(db: Session) -> str:
    asset = db.get(BrandingAsset, 1)
    return DEFAULT_REVISION if asset is None else asset.sha256


def purge_branding_drafts(db: Session, now: datetime) -> int:
    """Delete expired drafts and consumed receipts older than 30 minutes (A2-D6)."""
    result = db.execute(
        delete(BrandingDraft).where(
            or_(
                BrandingDraft.expires_at <= now,
                and_(
                    BrandingDraft.consumed_at.is_not(None),
                    BrandingDraft.consumed_at <= now - RECEIPT_TTL,
                ),
            )
        )
    )
    return result.rowcount or 0


def _delete_open_draft(db: Session, session_id: str) -> None:
    db.execute(
        delete(BrandingDraft).where(
            BrandingDraft.session_id == session_id,
            BrandingDraft.consumed_at.is_(None),
        )
    )


def stage_draft(
    db: Session,
    *,
    session_id: str,
    filename: str,
    content_type: str | None,
    data: bytes,
    now: datetime,
) -> StagedDraft:
    """Validate and stage one preview, replacing this session's previous draft.

    An invalid or oversized upload deliberately clears the previous candidate so an old selection
    can never be saved by accident. Raises ``BrandingImageError`` or ``BrandingStorageUnavailable``.
    """
    purge_branding_drafts(db, now)
    _delete_open_draft(db, session_id)
    image = validate_logo(filename, content_type, data)
    pending = db.scalar(
        select(func.coalesce(func.sum(BrandingDraft.byte_size), 0)).where(
            BrandingDraft.consumed_at.is_(None)
        )
    )
    if (pending or 0) + len(image.content) > MAX_PENDING_BYTES:
        raise BrandingStorageUnavailable
    token = secrets.token_urlsafe(32)
    draft = BrandingDraft(
        token_sha256=_token_hash(token),
        session_id=session_id,
        content=image.content,
        mime=image.mime,
        width=image.width,
        height=image.height,
        sha256=image.sha256,
        byte_size=len(image.content),
        display_filename=image.display_filename,
        base_revision=current_revision(db),
        expires_at=now + DRAFT_TTL,
    )
    db.add(draft)
    db.flush()
    return StagedDraft(
        token=token,
        mime=image.mime,
        width=image.width,
        height=image.height,
        sha256=image.sha256,
        byte_size=len(image.content),
        display_filename=image.display_filename,
        base_revision=draft.base_revision,
        expires_at=draft.expires_at,
    )


def _session_is_usable(db: Session, session_id: str, now: datetime) -> bool:
    session = db.get(UserSession, session_id)
    return (
        session is not None
        and session.revoked_at is None
        and session.expires_at > now
    )


def find_draft(
    db: Session, *, session_id: str, token: str, now: datetime, for_update: bool = False
) -> BrandingDraft | None:
    """Return this session's draft (including a consumed receipt) or ``None``.

    The row is looked up before the housekeeping purge so an expired token is still recognized as
    expired (410) rather than silently becoming "unknown" (404). A token that belongs to another
    session is indistinguishable from an unknown token. An expired draft or a revoked/expired
    session raises ``BrandingDraftExpired`` and deletes the bytes.
    """
    query = select(BrandingDraft).where(BrandingDraft.token_sha256 == _token_hash(token))
    if for_update:
        query = query.with_for_update()
    draft = db.scalar(query)
    if draft is not None and draft.session_id == session_id:
        if not _session_is_usable(db, session_id, now) or draft.expires_at <= now:
            db.delete(draft)
            db.flush()
            raise BrandingDraftExpired
        purge_branding_drafts(db, now)
        return draft
    purge_branding_drafts(db, now)
    return None


def draft_image(db: Session, *, session_id: str, token: str, now: datetime) -> tuple[StagedDraft, bytes]:
    """The validated bytes of a live, unconsumed draft (A2b's protected image URL)."""
    draft = find_draft(db, session_id=session_id, token=token, now=now)
    if draft is None or draft.consumed_at is not None or draft.content is None:
        raise BrandingDraftNotFound
    return (
        StagedDraft(
            token=token,
            mime=draft.mime or "",
            width=draft.width or 0,
            height=draft.height or 0,
            sha256=draft.sha256 or "",
            byte_size=draft.byte_size or 0,
            display_filename=draft.display_filename or "",
            base_revision=draft.base_revision,
            expires_at=draft.expires_at,
        ),
        bytes(draft.content),
    )


def save_draft(
    db: Session,
    *,
    session_id: str,
    token: str,
    base_revision: str,
    actor: Actor,
    now: datetime,
) -> SaveOutcome:
    """Apply one validated draft atomically; retrying the same token is a successful no-op."""
    _lock_asset(db)
    draft = find_draft(db, session_id=session_id, token=token, now=now, for_update=True)
    if draft is None:
        raise BrandingDraftNotFound
    if draft.consumed_at is not None:
        # The 30-minute receipt makes a double submit redirect to the same success state, with no
        # second asset write and no second audit row.
        return SaveOutcome(revision=draft.sha256 or current_revision(db), already_saved=True)
    revision = current_revision(db)
    if base_revision != revision or draft.base_revision != revision:
        raise BrandingRevisionMismatch
    asset = db.scalar(select(BrandingAsset).where(BrandingAsset.id == 1).with_for_update())
    if asset is None:
        asset = BrandingAsset(id=1)
        db.add(asset)
    asset.mime = draft.mime or ""
    asset.content = draft.content or b""
    asset.width = draft.width or 0
    asset.height = draft.height or 0
    asset.sha256 = draft.sha256 or ""
    asset.display_filename = draft.display_filename or ""
    asset.updated_by = actor.user_id
    draft.consumed_at = now
    draft.content = None
    draft.byte_size = None
    db.flush()
    record(
        db,
        actor,
        "branding.save",
        "branding",
        AUDIT_TARGET,
        {
            "width": asset.width,
            "height": asset.height,
            "mime": asset.mime,
            "revision": asset.sha256,
        },
    )
    return SaveOutcome(revision=asset.sha256, already_saved=False)


def discard_draft(db: Session, *, session_id: str, token: str, now: datetime) -> bool:
    """Delete this session's draft; an unknown or foreign token is a harmless no-op."""
    purge_branding_drafts(db, now)
    draft = db.scalar(
        select(BrandingDraft)
        .where(BrandingDraft.token_sha256 == _token_hash(token))
        .with_for_update()
    )
    if draft is None or draft.session_id != session_id:
        return False
    db.delete(draft)
    db.flush()
    return True


def reset_branding(
    db: Session, *, session_id: str, base_revision: str, actor: Actor, now: datetime
) -> ResetOutcome:
    """Remove the custom asset and this session's draft atomically; default is a no-op."""
    purge_branding_drafts(db, now)
    _lock_asset(db)
    asset = db.scalar(select(BrandingAsset).where(BrandingAsset.id == 1).with_for_update())
    revision = DEFAULT_REVISION if asset is None else asset.sha256
    if base_revision != revision:
        raise BrandingRevisionMismatch
    _delete_open_draft(db, session_id)
    if asset is None:
        db.flush()
        return ResetOutcome(changed=False)
    record(
        db,
        actor,
        "branding.reset",
        "branding",
        AUDIT_TARGET,
        {
            "width": asset.width,
            "height": asset.height,
            "mime": asset.mime,
            "revision": asset.sha256,
        },
    )
    db.delete(asset)
    db.flush()
    return ResetOutcome(changed=True)
