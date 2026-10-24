"""Transactional key custody; public certificate inventory services extend this."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.crypto.keyring import Keyring, KeyUnwrapError, WrappedSecret, unwrap, wrap
from app.crypto.keys import PrivateKeyObject, load_private_key, private_key_pem, public_key_sha256
from app.models import PrivateKey, User
from app.services.audit import Actor, record


def store_key(
    db: Session,
    keyring: Keyring,
    key: PrivateKeyObject,
    origin: str,
    actor: Actor,
) -> PrivateKey:
    fingerprint = public_key_sha256(key.public_key())
    existing = db.scalar(select(PrivateKey).where(PrivateKey.public_key_sha256 == fingerprint))
    if existing is not None:
        return existing
    # Sequence reservation avoids ever inserting a partially encrypted row.
    key_id = db.scalar(select(func.nextval(func.pg_get_serial_sequence("private_key", "id"))))
    aad = f"private_key:{key_id}:{keyring.active}"
    plaintext = private_key_pem(key)
    try:
        encrypted = wrap(keyring, plaintext, aad)
    finally:
        del plaintext
    curve = None
    if isinstance(key, ec.EllipticCurvePrivateKey):
        curve = "prime256v1" if isinstance(key.curve, ec.SECP256R1) else "secp384r1"
    statement = (
        insert(PrivateKey)
        .values(
            id=key_id,
            key_type="ecdsa" if curve else "rsa",
            key_size=key.key_size,
            curve=curve,
            ciphertext=encrypted.ciphertext,
            nonce=encrypted.nonce,
            aad=aad,
            master_key_version=encrypted.version,
            public_key_sha256=fingerprint,
            public_key_pem=key.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode("ascii"),
            created_by=actor.user_id,
            origin=origin,
        )
        .on_conflict_do_nothing(index_elements=["public_key_sha256"])
        .returning(PrivateKey)
    )
    row = db.scalar(statement)
    if row is None:
        # READ COMMITTED: the winning insert has committed before ON CONFLICT
        # returns, so this new statement sees its complete row.
        return db.scalars(select(PrivateKey).where(PrivateKey.public_key_sha256 == fingerprint)).one()
    record(
        db,
        actor,
        "key.create",
        "private_key",
        str(row.id),
        {
            "origin": origin,
            "key_type": row.key_type,
            "key_size": row.key_size,
            "public_key_sha256": fingerprint,
            "master_key_version": row.master_key_version,
        },
    )
    return row


def unwrap_key(row: PrivateKey, keyring: Keyring) -> PrivateKeyObject:
    expected_aad = f"private_key:{row.id}:{row.master_key_version}"
    if row.aad != expected_aad:
        raise KeyUnwrapError()
    plaintext = unwrap(
        keyring, WrappedSecret(row.ciphertext, row.nonce, row.master_key_version), expected_aad
    )
    try:
        key = load_private_key(plaintext)
        if public_key_sha256(key.public_key()) != row.public_key_sha256:
            raise KeyUnwrapError()
        return key
    except (ValueError, TypeError):
        raise KeyUnwrapError() from None
    finally:
        del plaintext


def missing_master_key_versions(db: Session, keyring: Keyring) -> set[int]:
    versions = set(db.scalars(select(PrivateKey.master_key_version).distinct()))
    versions.update(
        db.scalars(
            select(User.totp_secret_version)
            .where(User.totp_secret_ciphertext.is_not(None), User.totp_secret_version.is_not(None))
            .distinct()
        )
    )
    return versions - set(keyring.keys)


def stale_master_key_rows(db: Session, keyring: Keyring) -> int:
    return db.scalar(
        select(func.count()).select_from(PrivateKey).where(PrivateKey.master_key_version != keyring.active)
    ) + db.scalar(
        select(func.count())
        .select_from(User)
        .where(
            User.totp_secret_ciphertext.is_not(None),
            User.totp_secret_version.is_distinct_from(keyring.active),
        )
    )


def _rewrap(keyring: Keyring, wrapped: WrappedSecret, old_aad: str, new_aad: str) -> WrappedSecret:
    # Keep raw bytes in this one-row helper, never in the batch's ORM collection.
    # Dropping references is not a claim of secure Python-heap zeroization.
    plaintext = unwrap(keyring, wrapped, old_aad)
    try:
        return wrap(keyring, plaintext, new_aad)
    finally:
        del plaintext


def rotate_master_key(db: Session, keyring: Keyring, actor: Actor, batch_size: int = 100) -> int:
    if type(batch_size) is not int or batch_size < 1:
        raise ValueError("batch_size must be a positive integer")
    keys = db.scalars(
        select(PrivateKey)
        .where(PrivateKey.master_key_version != keyring.active)
        .order_by(PrivateKey.id)
        .limit(batch_size)
        .with_for_update()
    ).all()
    for row in keys:
        old_aad = f"private_key:{row.id}:{row.master_key_version}"
        if row.aad != old_aad:
            raise KeyUnwrapError()
        new_aad = f"private_key:{row.id}:{keyring.active}"
        encrypted = _rewrap(
            keyring, WrappedSecret(row.ciphertext, row.nonce, row.master_key_version), old_aad, new_aad
        )
        row.ciphertext, row.nonce = encrypted.ciphertext, encrypted.nonce
        row.aad, row.master_key_version = new_aad, encrypted.version
    users = []
    if len(keys) < batch_size:
        users = db.scalars(
            select(User)
            .where(
                User.totp_secret_ciphertext.is_not(None),
                User.totp_secret_version.is_distinct_from(keyring.active),
            )
            .order_by(User.id)
            .limit(batch_size - len(keys))
            .with_for_update()
        ).all()
    for user in users:
        encrypted = _rewrap(
            keyring,
            WrappedSecret(user.totp_secret_ciphertext, user.totp_secret_nonce, user.totp_secret_version),
            f"user:{user.id}:totp:{user.totp_secret_version}",
            f"user:{user.id}:totp:{keyring.active}",
        )
        user.totp_secret_ciphertext, user.totp_secret_nonce = encrypted.ciphertext, encrypted.nonce
        user.totp_secret_version = encrypted.version
    db.flush()
    remaining = stale_master_key_rows(db, keyring)
    if keys or users:
        record(
            db,
            actor,
            "master_key.rotate",
            "master_key",
            str(keyring.active),
            {
                "keys_rotated": len(keys),
                "users_rotated": len(users),
                "version": keyring.active,
                "remaining": remaining,
            },
        )
    return remaining
