"""Verifiable sharing: Merkle commitments over the share set.

Why not Feldman or Pedersen? Both need a group with hard discrete logarithms and
both only tell you *that* the reconstruction is inconsistent, not *which* share
is wrong. A dealer who hands out a bad share survives a Feldman check with a
flag, not an identity.

This module commits to every share individually and to the set as a whole:

    leaf_i = H(domain || session || i || x_i || y_i)
    root   = Merkle root over leaves

The root is published with the share set. A receiver can then check any single
share against the root with a proof of length O(log n), and when several shares
disagree the verification identifies exactly which ones fail - tamper
localisation that Feldman-style checks do not provide.

Scope, stated honestly: the commitment protects integrity and attribution, not
confidentiality. Shares still travel over a confidential channel; hashing a
share does not hide it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .shamir import Share

DOMAIN = b"sharelock/v1/share"


def _leaf(session: bytes, share: Share) -> bytes:
    digest = hashlib.sha256()
    digest.update(DOMAIN)
    digest.update(len(session).to_bytes(2, "big"))
    digest.update(session)
    digest.update(bytes([share.x]))
    digest.update(len(share.y).to_bytes(4, "big"))
    digest.update(share.y)
    return digest.digest()


def _pair(left: bytes, right: bytes) -> bytes:
    digest = hashlib.sha256()
    digest.update(b"sharelock/v1/node")
    digest.update(left)
    digest.update(right)
    return digest.digest()


@dataclass(frozen=True)
class Proof:
    """Merkle path for one share, plus the index it was built for."""

    index: int
    siblings: tuple[bytes, ...]
    directions: tuple[bool, ...]


@dataclass(frozen=True)
class Commitment:
    root: bytes
    size: int
    session: bytes


def _tree(leaves: list[bytes]) -> list[list[bytes]]:
    levels = [leaves]
    while len(levels[-1]) > 1:
        current = levels[-1]
        nxt = []
        for i in range(0, len(current), 2):
            if i + 1 < len(current):
                nxt.append(_pair(current[i], current[i + 1]))
            else:
                nxt.append(_pair(current[i], current[i]))
        levels.append(nxt)
    return levels


def commit(session: bytes, shares: list[Share]) -> tuple[Commitment, list[Proof]]:
    """Build the commitment and one proof per share, in the order supplied."""
    if not shares:
        raise ValueError("nothing to commit")
    leaves = [_leaf(session, share) for share in shares]
    levels = _tree(leaves)

    proofs: list[Proof] = []
    for index in range(len(leaves)):
        siblings: list[bytes] = []
        directions: list[bool] = []
        position = index
        for level in levels[:-1]:
            sibling_index = position ^ 1
            if sibling_index >= len(level):
                sibling_index = position
            siblings.append(level[sibling_index])
            directions.append(bool(position & 1))
            position //= 2
        proofs.append(Proof(index=index, siblings=tuple(siblings), directions=tuple(directions)))
    return Commitment(root=levels[-1][0], size=len(shares), session=session), proofs


def verify(session: bytes, share: Share, proof: Proof, commitment: Commitment) -> bool:
    """Check one share against the published root."""
    if commitment.session != session:
        return False
    if proof.index >= commitment.size:
        return False
    current = _leaf(session, share)
    for sibling, direction in zip(proof.siblings, proof.directions):
        current = _pair(sibling, current) if direction else _pair(current, sibling)
    return current == commitment.root


def locate(
    session: bytes,
    shares: list[Share],
    proofs: list[Proof],
    commitment: Commitment,
) -> list[int]:
    """Return the indices of shares that fail verification.

    An empty list means every share checked out. A non-empty list names the bad
    ones, which is the property Feldman-style checks lack.
    """
    if len(shares) != len(proofs):
        raise ValueError("shares and proofs must align")
    return [
        index
        for index, (share, proof) in enumerate(zip(shares, proofs))
        if not verify(session, share, proof, commitment)
    ]
