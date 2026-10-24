"""Threshold secret sharing over GF(2^8).

A secret is a byte string. For each byte s, a random polynomial

    f_s(x) = s + a_1 x + ... + a_{t-1} x^{t-1}

is drawn with every a_i uniform in GF(2^8). Share i is the vector
(f_s(x_i))_s over all bytes, evaluated at the non-zero point x_i.

With fewer than t shares, every candidate secret is equally likely: given t-1
points there is exactly one polynomial of degree <= t-1 through them and any
chosen value at zero, so the posterior equals the prior. That is the whole
security argument, and section 3 of the report states it as a theorem.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from . import gf256


@dataclass(frozen=True)
class Share:
    """One shareholder's piece: an evaluation point and one byte per secret byte."""

    x: int
    y: bytes

    def __post_init__(self) -> None:
        if not 1 <= self.x <= 255:
            raise ValueError("share coordinate must be a non-zero field element")


def split(secret: bytes, threshold: int, shares: int, *, rng=secrets.token_bytes) -> list[Share]:
    """Split a secret into shares, any threshold of which reconstruct it."""
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if shares < threshold:
        raise ValueError("share count must be at least the threshold")
    if shares > 255:
        raise ValueError("GF(2^8) has only 255 non-zero evaluation points")
    if not secret:
        raise ValueError("secret must not be empty")

    coefficients = []
    for _ in range(threshold - 1):
        coefficients.append(rng(len(secret)))

    result: list[Share] = []
    for index in range(1, shares + 1):
        x = index
        y = bytearray(secret)
        power = x
        for coeff in coefficients:
            for position in range(len(secret)):
                y[position] ^= gf256.mul(coeff[position], power)
            power = gf256.mul(power, x)
        result.append(Share(x=x, y=bytes(y)))
    return result


def _lagrange_coefficients(xs: list[int]) -> list[int]:
    """Coefficients that evaluate the interpolant at zero: sum(lambda_i * y_i)."""
    lambdas: list[int] = []
    for i, xi in enumerate(xs):
        numerator = 1
        denominator = 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            numerator = gf256.mul(numerator, xj)
            denominator = gf256.mul(denominator, gf256.sub(xi, xj))
        lambdas.append(gf256.div(numerator, denominator))
    return lambdas


def combine(shares: list[Share]) -> bytes:
    """Reconstruct the secret from any t shares."""
    if not shares:
        raise ValueError("no shares supplied")
    xs = [share.x for share in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share coordinates")
    lengths = {len(share.y) for share in shares}
    if len(lengths) != 1:
        raise ValueError("shares disagree on secret length")

    lambdas = _lagrange_coefficients(xs)
    length = lengths.pop()
    secret = bytearray(length)
    for coefficient, share in zip(lambdas, shares):
        for position in range(length):
            secret[position] ^= gf256.mul(coefficient, share.y[position])
    return bytes(secret)


def interpolate_at(points: list[tuple[int, bytes]], x_target: int) -> bytes:
    """Evaluate the interpolating polynomial at an arbitrary field point.

    Used by the security tests and by the report's construction: given t-1 real
    shares plus a hypothetical value at x=0, this returns what the resulting
    polynomial predicts for any other coordinate. Two different hypotheses at
    zero predict different values elsewhere, while both agree with every observed
    share - which is exactly why the observed shares carry no information about
    the secret.
    """
    if not points:
        raise ValueError("no points supplied")
    xs = [x for x, _ in points]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate coordinates")
    lengths = {len(y) for _, y in points}
    if len(lengths) != 1:
        raise ValueError("points disagree on length")
    length = lengths.pop()

    lambdas: list[int] = []
    for i, xi in enumerate(xs):
        numerator = 1
        denominator = 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            numerator = gf256.mul(numerator, gf256.sub(x_target, xj))
            denominator = gf256.mul(denominator, gf256.sub(xi, xj))
        lambdas.append(gf256.div(numerator, denominator))

    out = bytearray(length)
    for coefficient, (_, y) in zip(lambdas, points):
        for position in range(length):
            out[position] ^= gf256.mul(coefficient, y[position])
    return bytes(out)
