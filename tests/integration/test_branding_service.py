"""Branding draft/asset state machine against PostgreSQL (``docs/ui/branding.md``).

Covers the preview lifecycle, revision compare-and-set, expiry/revocation/cross-session refusals,
the pending cap, double-save idempotency and the audit shape. HTTP status mapping is A2b; these
tests assert the typed service outcomes.
"""

import hashlib
import struct
import zlib
from datetime import timedelta

import pytest
from sqlalchemy import func, select, text

from app.models import AuditLog, BrandingAsset, BrandingDraft, UserSession
from app.services.branding import (
    MAX_PENDING_BYTES,
    BrandingDraftExpired,
    BrandingDraftNotFound,
    BrandingRevisionMismatch,
    BrandingStorageUnavailable,
    current_asset,
    discard_draft,
    find_draft,
    purge_branding_drafts,
    reset_branding,
    save_draft,
    stage_draft,
)
from app.services.branding_image import BrandingImageError

SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
    b'<path d="M0 0 L10 10 Z" fill="#4cd7f6"/></svg>'
)
OTHER_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 24">'
    b'<rect width="48" height="24" fill="#006579"/></svg>'
)


def png(width: int, height: int, seed: int = 0) -> bytes:
    rows = b"".join(b"\x00" + bytes([(seed + row) % 256]) * (width * 4) for row in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(rows))
        + _chunk(b"IEND", b"")
    )


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


@pytest.fixture
def session_row(db, actor, now):
    row = UserSession(
        id="a" * 64,
        user_id=actor.user_id,
        csrf_token="c" * 64,
        last_seen_at=now,
        expires_at=now + timedelta(hours=1),
    )
    db.add(row)
    db.flush()
    return row


def stage(db, session, now, data=SVG, filename="logo.svg", content_type="image/svg+xml"):
    return stage_draft(
        db,
        session_id=session.id,
        filename=filename,
        content_type=content_type,
        data=data,
        now=now,
    )


def audits(db, action):
    return list(db.scalars(select(AuditLog).where(AuditLog.action == action)))


def test_stage_save_discard_reset_round_trip(db, actor, session_row, now):
    staged = stage(db, session_row, now)
    assert staged.base_revision == "default"
    assert staged.mime == "image/svg+xml" and (staged.width, staged.height) == (24, 24)
    draft = db.get(BrandingDraft, hashlib.sha256(staged.token.encode()).hexdigest())
    assert draft is not None and draft.content and draft.display_filename == "logo.svg"
    assert draft.token_sha256 != staged.token  # only the hash is stored
    assert current_asset(db) is None

    saved = save_draft(db, session_id=session_row.id, token=staged.token, base_revision="default", actor=actor, now=now)
    assert saved.already_saved is False
    asset = current_asset(db)
    assert asset is not None and asset.revision == saved.revision and asset.mime == "image/svg+xml"
    assert asset.content.startswith(b"<svg")
    assert [(row.action, row.target_type, row.target_id) for row in audits(db, "branding.save")] == [
        ("branding.save", "branding", "logo")
    ]

    second = stage(db, session_row, now, data=OTHER_SVG)
    assert second.base_revision == asset.revision
    assert discard_draft(db, session_id=session_row.id, token=second.token, now=now) is True
    assert find_draft(db, session_id=session_row.id, token=second.token, now=now) is None
    assert current_asset(db).revision == asset.revision

    reset = reset_branding(db, session_id=session_row.id, base_revision=asset.revision, actor=actor, now=now)
    assert reset.changed is True
    assert current_asset(db) is None
    assert len(audits(db, "branding.reset")) == 1


def test_double_save_is_idempotent_and_writes_one_asset_and_one_audit(db, actor, session_row, now):
    staged = stage(db, session_row, now)
    first = save_draft(db, session_id=session_row.id, token=staged.token, base_revision="default", actor=actor, now=now)
    second = save_draft(
        db, session_id=session_row.id, token=staged.token, base_revision="default", actor=actor, now=now
    )
    assert second.already_saved is True and second.revision == first.revision
    assert db.scalar(select(func.count()).select_from(BrandingAsset)) == 1
    assert len(audits(db, "branding.save")) == 1


def test_second_preview_replaces_the_draft_and_an_invalid_preview_clears_it(db, session_row, now):
    first = stage(db, session_row, now)
    second = stage(db, session_row, now, data=OTHER_SVG)
    assert second.token != first.token
    assert db.scalar(select(func.count()).select_from(BrandingDraft).where(BrandingDraft.consumed_at.is_(None))) == 1
    assert db.get(BrandingDraft, hashlib.sha256(first.token.encode()).hexdigest()) is None
    with pytest.raises(BrandingImageError):
        stage(db, session_row, now, data=b"not a png", filename="logo.png", content_type="image/png")
    assert db.scalar(select(func.count()).select_from(BrandingDraft)) == 0


def test_revision_mismatch_refuses_save_and_reset(db, actor, session_row, now):
    staged = stage(db, session_row, now)
    with pytest.raises(BrandingRevisionMismatch):
        save_draft(db, session_id=session_row.id, token=staged.token, base_revision="stale", actor=actor, now=now)
    assert current_asset(db) is None
    # The candidate survives a conflict so the page can show it with "Preview again"/"Discard".
    assert db.get(BrandingDraft, hashlib.sha256(staged.token.encode()).hexdigest()).content
    save_draft(db, session_id=session_row.id, token=staged.token, base_revision="default", actor=actor, now=now)
    revision = current_asset(db).revision
    with pytest.raises(BrandingRevisionMismatch):
        reset_branding(db, session_id=session_row.id, base_revision="default", actor=actor, now=now)
    assert current_asset(db).revision == revision


def test_expired_draft_returns_410_and_deletes_its_bytes(db, actor, session_row, now):
    staged = stage(db, session_row, now)
    later = now + timedelta(minutes=31)
    with pytest.raises(BrandingDraftExpired):
        save_draft(db, session_id=session_row.id, token=staged.token, base_revision="default", actor=actor, now=later)
    assert db.scalar(select(func.count()).select_from(BrandingDraft)) == 0


def test_cross_session_draft_is_not_found_and_is_not_deleted(db, actor, session_row, now):
    staged = stage(db, session_row, now)
    with pytest.raises(BrandingDraftNotFound):
        save_draft(
            db,
            session_id="b" * 64,
            token=staged.token,
            base_revision="default",
            actor=actor,
            now=now,
        )
    assert find_draft(db, session_id="b" * 64, token=staged.token, now=now) is None
    assert db.get(BrandingDraft, hashlib.sha256(staged.token.encode()).hexdigest()) is not None


def test_revoked_session_makes_the_draft_unusable(db, actor, session_row, now):
    staged = stage(db, session_row, now)
    session_row.revoked_at = now
    db.flush()
    with pytest.raises(BrandingDraftExpired):
        save_draft(db, session_id=session_row.id, token=staged.token, base_revision="default", actor=actor, now=now)
    assert db.scalar(select(func.count()).select_from(BrandingDraft)) == 0


def test_pending_cap_refuses_a_new_preview(db, actor, session_row, now):
    from app.models import User

    for index in range(64):
        user = User(username=f"cap-user-{index}", email=f"cap-{index}@example.test")
        db.add(user)
        db.flush()
        session_id = f"{index:02d}" * 32
        db.add(
            UserSession(
                id=session_id,
                user_id=user.id,
                csrf_token="c" * 64,
                last_seen_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
        # No ORM relationship exists between the two mappers, so flush the session before the
        # draft that references it instead of relying on unit-of-work ordering.
        db.flush()
        db.add(
            BrandingDraft(
                token_sha256=f"{index:03d}" + "0" * 61,
                session_id=session_id,
                byte_size=262_144,
                base_revision="default",
                expires_at=now + timedelta(minutes=30),
            )
        )
    db.flush()
    assert db.scalar(select(func.sum(BrandingDraft.byte_size))) == MAX_PENDING_BYTES
    with pytest.raises(BrandingStorageUnavailable):
        stage(db, session_row, now, data=png(2, 2), filename="logo.png", content_type="image/png")
    assert db.scalar(select(func.count()).select_from(BrandingDraft)) == 64


def test_purge_removes_expired_drafts_and_old_receipts_but_not_live_ones(db, actor, session_row, now):
    from app.models import User

    def extra_session(name: str) -> UserSession:
        user = User(username=f"purge-{name}", email=f"purge-{name}@example.test")
        db.add(user)
        db.flush()
        row = UserSession(
            id=name * 64,
            user_id=user.id,
            csrf_token="c" * 64,
            last_seen_at=now,
            expires_at=now + timedelta(hours=1),
        )
        db.add(row)
        db.flush()
        return row

    expired = stage(db, extra_session("e"), now)
    receipt_session = extra_session("r")
    receipt = stage(db, receipt_session, now, data=OTHER_SVG)
    save_draft(db, session_id=receipt_session.id, token=receipt.token, base_revision="default", actor=actor, now=now)
    live = stage(db, session_row, now)
    # Make the receipt look older than 30 minutes without expiring it yet.
    row = db.get(BrandingDraft, hashlib.sha256(receipt.token.encode()).hexdigest())
    row.consumed_at = now - timedelta(minutes=31)
    row.expires_at = now + timedelta(minutes=10)
    expired_row = db.get(BrandingDraft, hashlib.sha256(expired.token.encode()).hexdigest())
    expired_row.expires_at = now - timedelta(seconds=1)
    db.flush()
    assert purge_branding_drafts(db, now) == 2
    assert find_draft(db, session_id=session_row.id, token=live.token, now=now) is not None
    assert db.scalar(select(func.count()).select_from(BrandingDraft)) == 1


def test_audit_details_never_contain_bytes_or_the_display_filename(db, actor, session_row, now):
    staged = stage(db, session_row, now, filename="confidential-rebrand.svg")
    save_draft(db, session_id=session_row.id, token=staged.token, base_revision="default", actor=actor, now=now)
    (entry,) = audits(db, "branding.save")
    assert set(entry.details) == {"width", "height", "mime", "revision"}
    rendered = str(entry.details)
    assert "confidential-rebrand" not in rendered and "svg xmlns" not in rendered
    assert entry.details["revision"] == hashlib.sha256(current_asset(db).content).hexdigest()


def test_default_reset_is_a_harmless_no_op_without_audit(db, actor, session_row, now):
    result = reset_branding(db, session_id=session_row.id, base_revision="default", actor=actor, now=now)
    assert result.changed is False
    assert audits(db, "branding.reset") == []
    assert db.scalar(text("SELECT count(*) FROM branding_asset")) == 0
