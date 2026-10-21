from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable


@dataclass(frozen=True)
class Success:
    user_key: str
    display_name: str
    email: str


@dataclass(frozen=True)
class Failure:
    reason: Literal["invalid_credentials", "locked", "inactive", "backend_unavailable", "not_supported"]

    @property
    def message(self) -> str:
        # Reasons are for trusted control flow/audit, never account-enumerating UI text.
        return "Invalid credentials."


AuthResult = Success | Failure


@dataclass(frozen=True)
class UserRecord:
    user_key: str
    username: str
    display_name: str
    email: str
    backend: str
    is_active: bool


@runtime_checkable
class AuthBackend(Protocol):
    name: str

    def authenticate(self, username: str, password: str) -> AuthResult: ...
    def lookup(self, username: str) -> UserRecord | None: ...
    def supports_password_change(self) -> bool: ...
