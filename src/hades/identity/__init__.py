"""Users, roles, clearance, and JWT auth for the Aperture lab."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt

from hades.config import get_settings
from hades.policy import Classification, Role, ROLE_CLEARANCE


@dataclass(frozen=True)
class User:
    username: str
    display_name: str
    role: Role
    clearance: Classification
    password: str = "password"  # lab-only synthetic credentials


# Synthetic Aperture workforce used across attacks and utility tasks.
USERS: dict[str, User] = {
    "alice": User("alice", "Alice Chen", Role.ENGINEER, ROLE_CLEARANCE[Role.ENGINEER]),
    "bob": User("bob", "Bob Okonkwo", Role.HR, ROLE_CLEARANCE[Role.HR]),
    "carol": User("carol", "Carol Mendes", Role.FINANCE, ROLE_CLEARANCE[Role.FINANCE]),
    "dave": User("dave", "Dave Park", Role.EXECUTIVE, ROLE_CLEARANCE[Role.EXECUTIVE]),
    "eve": User("eve", "Eve Rossi", Role.SALES, ROLE_CLEARANCE[Role.SALES]),
    "frank": User("frank", "Frank Nguyen", Role.SECURITY, ROLE_CLEARANCE[Role.SECURITY]),
}


@dataclass
class AuthContext:
    username: str
    role: Role
    clearance: Classification
    display_name: str

    @property
    def user(self) -> User:
        return USERS[self.username]


def authenticate(username: str, password: str) -> Optional[User]:
    user = USERS.get(username.lower())
    if user is None or user.password != password:
        return None
    return user


def issue_token(user: User) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.username,
        "name": user.display_name,
        "role": user.role.value,
        "clearance": user.clearance.value,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.jwt_ttl_seconds)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> AuthContext:
    settings = get_settings()
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    username = payload["sub"]
    user = USERS.get(username)
    if user is None:
        raise jwt.InvalidTokenError("unknown user")
    return AuthContext(
        username=user.username,
        role=user.role,
        clearance=user.clearance,
        display_name=user.display_name,
    )


def context_for_username(username: str) -> AuthContext:
    user = USERS[username.lower()]
    return AuthContext(
        username=user.username,
        role=user.role,
        clearance=user.clearance,
        display_name=user.display_name,
    )
