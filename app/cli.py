"""Operator commands: key generation is independent of application/DB startup."""

import argparse
import base64
import hashlib
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from cryptography import x509
from sqlalchemy.exc import SQLAlchemyError

from app.config import ConfigurationError, load_settings
from app.crypto.keyring import KeyUnwrapError, load_keyring
from app.crypto.keys import public_key_sha256
from app.db import assert_database_ready, create_session_factory, transaction
from app.models import Certificate, PrivateKey
from app.services.audit import Actor
from app.services.certificates import missing_master_key_versions, rotate_master_key, unwrap_key


def _positive(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a positive version or ID") from None
    if number < 1:
        raise argparse.ArgumentTypeError("expected a positive version or ID")
    return number


def _generate(version: int, merge: Path | None) -> None:
    keys = {}
    if merge is not None:
        try:
            keys = dict(load_keyring(merge.read_bytes()).keys)
        except OSError:
            raise ConfigurationError(
                "master_key: cannot read merge file; check path and permissions"
            ) from None
    if keys and version <= max(keys):
        raise ConfigurationError("master_key: new version must be greater than all merged versions")
    if len(keys) >= 2:
        raise ConfigurationError(
            "master_key: live limit of 2 versions; finish rotation before generating another"
        )
    keys[version] = os.urandom(32)
    data = {"active": version, "keys": {str(k): base64.b64encode(v).decode("ascii") for k, v in keys.items()}}
    raw = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    print("sha256=" + hashlib.sha256(raw).hexdigest(), file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate-master-key")
    generate.add_argument("--version", type=_positive, required=True)
    generate.add_argument("--merge", type=Path)
    commands.add_parser("rotate-master-key")
    verify = commands.add_parser("verify-key")
    verify.add_argument("--certificate-id", type=_positive, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "generate-master-key":
            _generate(args.version, args.merge)
            return 0
        settings = load_settings("cli", os.environ, Path(os.environ.get("SECRETS_DIR", "/run/secrets")))
        factory = create_session_factory(settings)
        engine = factory.kw["bind"]
        try:
            assert_database_ready(engine)
            if args.command == "rotate-master-key":
                with transaction(factory) as db:
                    missing = missing_master_key_versions(db, settings.keyring)
                if missing:
                    raise ConfigurationError(
                        "master_key: missing referenced versions: " + ",".join(map(str, sorted(missing)))
                    )
                while True:
                    with transaction(factory) as db:
                        remaining = rotate_master_key(db, settings.keyring, Actor(None, "system"))
                    print(f"remaining={remaining}")
                    if remaining == 0:
                        break
            else:
                with transaction(factory) as db:
                    cert = db.get(Certificate, args.certificate_id)
                    if cert is None:
                        raise ValueError("certificate not found")
                    row = db.get(PrivateKey, cert.key_id) if cert.key_id is not None else None
                    if row is None:
                        raise ValueError("certificate has no private key")
                    key = unwrap_key(row, settings.keyring)
                    try:
                        leaf = x509.load_pem_x509_certificate(cert.pem.encode("ascii"))
                        fingerprint = public_key_sha256(key.public_key())
                        if public_key_sha256(leaf.public_key()) != fingerprint:
                            raise ValueError("certificate public key does not match")
                    finally:
                        del key
                    print(f"verified certificate_id={cert.id} public_key_sha256={fingerprint}")
        finally:
            engine.dispose()
        return 0
    except (ConfigurationError, KeyUnwrapError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except SQLAlchemyError:
        print("database operation failed; check connectivity and configured schema", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
