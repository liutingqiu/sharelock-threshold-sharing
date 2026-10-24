"""Record one full ritual and write it as JSON for the demo page.

    python -m sharelock.demo runs/demo.json

Steps: split a secret, commit to the shares, verify all of them, tamper with one,
locate it, then attempt reconstruction from a tampered set and from t-1 shares.
"""

from __future__ import annotations

import json
import secrets
import sys
import time
from pathlib import Path

from sharelock import vss
from sharelock.session import Session, require_session
from sharelock.shamir import Share, combine, split, interpolate_at


def main() -> int:
    out_path = Path(sys.argv[1] if len(sys.argv) > 1 else "runs/demo.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    threshold, shares = 3, 5
    secret = secrets.token_bytes(32)
    session = Session.create("vault-shamir")

    started = time.perf_counter()
    pieces = split(secret, threshold, shares)
    split_ms = (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    commitment, proofs = vss.commit(session.identifier, pieces)
    commit_ms = (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    failures = vss.locate(session.identifier, pieces, proofs, commitment)
    verify_ms = (time.perf_counter() - started) * 1000

    # tamper with one share
    bad_index = 2
    broken = list(pieces)
    flipped = bytearray(broken[bad_index].y)
    flipped[0] ^= 0x01
    broken[bad_index] = Share(x=broken[bad_index].x, y=bytes(flipped))

    started = time.perf_counter()
    detected = vss.locate(session.identifier, broken, proofs, commitment)
    locate_ms = (time.perf_counter() - started) * 1000

    # what reconstruction does with the corrupted share in the quorum
    subset = [broken[0], broken[1], broken[2]]
    try:
        wrong = combine(subset)
        reconstruct_corrupted = {"secret_matches": wrong == secret, "bytes": wrong.hex()[:16]}
    except Exception as error:  # pragma: no cover
        reconstruct_corrupted = {"error": str(error)}

    # what a holder of t-1 shares can conclude: every hypothesis is consistent
    partial = [(piece.x, piece.y) for piece in pieces[: threshold - 1]]
    hypotheses = [bytes([value]) * len(secret) for value in (0x00, 0x5A, 0xFF)]
    predictions = []
    for hypothesis in hypotheses:
        augmented = partial + [(0, hypothesis)]
        predictions.append({
            "hypothesis_head": hypothesis.hex()[:8],
            "predicts_at_x250": interpolate_at(augmented, 250).hex()[:16],
            "consistent_with_observed": all(interpolate_at(augmented, x) == y for x, y in partial),
        })

    # session binding: a share from another session must be rejected
    other = Session.create("vault-shamir")
    session_rejected = vss.verify(other.identifier, pieces[0], proofs[0], commitment) is False

    record = {
        "parameters": {"threshold": threshold, "shares": shares, "secret_bytes": len(secret)},
        "secret_fingerprint": secret.hex()[:16],
        "session": session.label,
        "merkle_root": commitment.root.hex(),
        "proof_bytes": len(proofs[0].siblings) * 32,
        "timing_ms": {
            "split": round(split_ms, 3),
            "commit": round(commit_ms, 3),
            "verify_all": round(verify_ms, 3),
            "locate_after_tamper": round(locate_ms, 3),
        },
        "verification": {"clean_failures": failures, "after_tamper": detected, "tampered_index": bad_index},
        "reconstruction_with_corrupted_share": reconstruct_corrupted,
        "below_threshold": predictions,
        "session_binding_rejects_other_session": session_rejected,
    }
    out_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
