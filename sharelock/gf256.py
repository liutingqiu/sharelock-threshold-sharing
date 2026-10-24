"""Arithmetic in GF(2^8) with the AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).

Byte-oriented field: every element is a single byte, which lets a secret be split
byte by byte without any padding or length leakage beyond the secret's own length.
"""

from __future__ import annotations

POLYNOMIAL = 0x11B

_EXP = [0] * 512
_LOG = [0] * 256


def _build_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        # multiply x by the generator 3 = x + 1
        x ^= (x << 1) ^ (POLYNOMIAL if x & 0x80 else 0)
        x &= 0xFF
        if x == 0:  # pragma: no cover - generator order is 255 by construction
            raise AssertionError("generator left the multiplicative group")
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def mul(a: int, b: int) -> int:
    """Multiply two field elements."""
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def inv(a: int) -> int:
    """Multiplicative inverse; zero has none and is rejected."""
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^8)")
    return _EXP[255 - _LOG[a]]


def div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(2^8)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def add(a: int, b: int) -> int:
    """Addition is XOR."""
    return a ^ b


def sub(a: int, b: int) -> int:
    """Subtraction is addition in characteristic two."""
    return a ^ b


def pow_(a: int, e: int) -> int:
    if e == 0:
        return 1
    if a == 0:
        return 0
    return _EXP[(_LOG[a] * e) % 255]
