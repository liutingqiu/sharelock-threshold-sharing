"""Session binding and constant-time comparison.

A share set is only meaningful inside the session it was created for. Binding the
session identifier into every leaf stops a share from one ritual being replayed
into another, and the constant-time equality check stops verification from
leaking how close a forged share came to matching.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class Session:
    identifier: bytes
    purpose: str

    @classmethod
    def create(cls, purpose: str) -> "Session":
        if not purpose:
            raise ValueError("purpose must not be empty")
        return cls(identifier=secrets.token_bytes(16), purpose=purpose)

    @property
    def label(self) -> str:
        return self.identifier.hex()


def constant_time_equal(left: bytes, right: bytes) -> bool:
    """Compare without early exit."""
    return hmac.compare_digest(left, right)


def require_session(expected: Session, presented: bytes) -> None:
    """Reject a share presented outside its session."""
    if not constant_time_equal(expected.identifier, presented):
        raise PermissionError("share presented outside its session")
