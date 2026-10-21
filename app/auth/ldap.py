"""Reserved directory backend; v1 never falls back to local authentication."""

from app.auth.base import AuthResult, Failure, UserRecord


class LDAPAuthBackend:
    name = "ldap"

    def authenticate(self, username: str, password: str) -> AuthResult:
        return Failure("not_supported")

    def lookup(self, username: str) -> UserRecord | None:
        return None

    def supports_password_change(self) -> bool:
        return False
