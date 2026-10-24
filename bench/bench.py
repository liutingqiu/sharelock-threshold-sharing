"""Timing and size measurements for the report. Run: python -m bench.bench"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

from sharelock import vss
from sharelock.session import Session
from sharelock.shamir import combine, split


def timed(fn, repeats=20):
    samples = []
    for _ in range(repeats):
        started = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - started) * 1000.0)
    samples.sort()
    return {"p50_ms": round(samples[len(samples) // 2], 3), "max_ms": round(samples[-1], 3)}


def main() -> int:
    secret = secrets.token_bytes(32)
    rows = []
    for threshold, shares in [(2, 3), (3, 5), (5, 5), (4, 10)]:
        pieces = split(secret, threshold, shares)
        size = sum(len(piece.y) + 1 for piece in pieces)
        session = Session.create("benchmark")
        commitment, proofs = vss.commit(session.identifier, pieces)
        subset = pieces[:threshold]

        rows.append(
            {
                "threshold": threshold,
                "shares": shares,
                "total_share_bytes": size,
                "expansion_vs_secret": round(size / len(secret), 3),
                "split": timed(lambda: split(secret, threshold, shares)),
                "combine": timed(lambda: combine(subset)),
                "commit": timed(lambda: vss.commit(session.identifier, pieces)),
                "verify_one": timed(lambda: vss.verify(session.identifier, pieces[0], proofs[0], commitment)),
                "locate_all": timed(lambda: vss.locate(session.identifier, pieces, proofs, commitment)),
                "proof_bytes": len(proofs[0].siblings) * 32,
                "root_hex": commitment.root.hex()[:16],
            }
        )

    out = {"secret_bytes": len(secret), "runs": rows}
    Path("runs").mkdir(exist_ok=True)
    Path("runs/bench.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
