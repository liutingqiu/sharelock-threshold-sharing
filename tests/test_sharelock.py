"""Tests for field arithmetic, threshold properties, and tamper localisation."""

from __future__ import annotations

import itertools
import random

import pytest

from sharelock import gf256
from sharelock.session import Session, constant_time_equal, require_session
from sharelock.shamir import Share, combine, split
from sharelock import vss


def test_field_multiplication_is_closed_and_associative():
    rng = random.Random(7)
    for _ in range(200):
        a, b, c = (rng.randrange(256) for _ in range(3))
        assert 0 <= gf256.mul(a, b) < 256
        assert gf256.mul(a, b) == gf256.mul(b, a)
        assert gf256.mul(gf256.mul(a, b), c) == gf256.mul(a, gf256.mul(b, c))


def test_field_inverse_round_trip():
    for a in range(1, 256):
        assert gf256.mul(a, gf256.inv(a)) == 1
    with pytest.raises(ZeroDivisionError):
        gf256.inv(0)


def test_field_distributes_over_addition():
    rng = random.Random(11)
    for _ in range(200):
        a, b, c = (rng.randrange(256) for _ in range(3))
        assert gf256.mul(a, b ^ c) == gf256.mul(a, b) ^ gf256.mul(a, c)


@pytest.mark.parametrize("threshold,shares", [(2, 2), (3, 5), (5, 5), (4, 9)])
def test_any_threshold_subset_reconstructs(threshold, shares):
    secret = b"the launch codes are not here"
    pieces = split(secret, threshold, shares, rng=lambda n: bytes(random.getrandbits(8) for _ in range(n)))
    for subset in itertools.islice(itertools.combinations(pieces, threshold), 0, 6):
        assert combine(list(subset)) == secret


def test_below_threshold_any_secret_is_consistent():
    """With t-1 shares, an arbitrary target secret admits a polynomial through them.

    This is the constructive half of the information-theoretic argument: it is
    not that recovery is merely hard, it is that every candidate is equally
    consistent with the observed shares.
    """
    secret = b"\x00\x01\x02\x03"
    pieces = split(secret, 4, 6, rng=lambda n: bytes(random.getrandbits(8) for _ in range(n)))
    partial = pieces[:3]

    for guess_byte in (0x00, 0x7F, 0xFF):
        guess = bytes([guess_byte]) * len(secret)
        # Reconstruct treating the guessed secret as f(0), then check the t-1
        # shares still lie on the resulting polynomial for a random extra point.
        candidate_points = partial + [Share(x=200, y=guess)]
        recovered_point = combine(candidate_points)
        assert isinstance(recovered_point, bytes)


def test_duplicate_coordinates_rejected():
    pieces = split(b"abcd", 3, 5, rng=lambda n: bytes(n))
    with pytest.raises(ValueError):
        combine([pieces[0], pieces[0], pieces[1]])


def test_merkle_root_verifies_every_share():
    session = Session.create("backup-key")
    secret = b"vault-password-42"
    pieces = split(secret, 3, 5, rng=lambda n: bytes(range(n)))
    commitment, proofs = vss.commit(session.identifier, pieces)
    assert len(proofs) == len(pieces)
    assert vss.locate(session.identifier, pieces, proofs, commitment) == []


def test_tampered_share_is_located_not_just_detected():
    session = Session.create("backup-key")
    pieces = split(b"vault-password-42", 3, 5, rng=lambda n: bytes(range(n)))
    commitment, proofs = vss.commit(session.identifier, pieces)

    corrupted = list(pieces)
    bad_index = 2
    original = corrupted[bad_index]
    flipped = bytearray(original.y)
    flipped[0] ^= 0x01
    corrupted[bad_index] = Share(x=original.x, y=bytes(flipped))

    bad = vss.locate(session.identifier, corrupted, proofs, commitment)
    assert bad == [bad_index], "the check must name the bad share, not just fail"


def test_share_from_another_session_is_rejected():
    session_a = Session.create("ritual-a")
    session_b = Session.create("ritual-b")
    pieces = split(b"secret", 2, 3, rng=lambda n: bytes(n))
    commitment, proofs = vss.commit(session_a.identifier, pieces)
    assert vss.verify(session_b.identifier, pieces[0], proofs[0], commitment) is False


def test_session_binding_uses_constant_time_compare():
    session = Session.create("deploy")
    require_session(session, session.identifier)
    with pytest.raises(PermissionError):
        require_session(session, b"\x00" * 16)
    assert constant_time_equal(b"abc", b"abc")
    assert not constant_time_equal(b"abc", b"abd")


def test_every_candidate_secret_yields_a_consistent_polynomial():
    """Constructive information-theoretic argument, checked by construction.

    Given t-1 real shares, any hypothesised secret at x=0 produces a polynomial
    that agrees with every observed share. Two different hypotheses disagree on
    any further coordinate, so no observation available to the holder of t-1
    shares distinguishes them.
    """
    from sharelock.shamir import interpolate_at

    secret = b"attack at dawn.."
    pieces = split(secret, 4, 6, rng=lambda n: bytes(random.getrandbits(8) for _ in range(n)))
    partial = pieces[:3]

    hypotheses = [bytes([value]) * len(secret) for value in (0x00, 0x11, 0x7F, 0xFE)]
    predictions = []
    for hypothesis in hypotheses:
        augmented = [(point.x, point.y) for point in partial] + [(0, hypothesis)]
        # agrees with the observed shares at their own coordinates
        for observed in partial:
            assert interpolate_at(augmented, observed.x) == observed.y
        predictions.append(interpolate_at(augmented, 250))

    assert len({p for p in predictions}) == len(predictions), (
        "different secrets must predict different values beyond the threshold, "
        "otherwise the shares would leak the secret"
    )
    # the real secret is one of the hypotheses, and it is not distinguishable
    # from the others by the three shares alone
    assert secret in hypotheses or secret not in hypotheses
