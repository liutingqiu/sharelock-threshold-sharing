## Inspiration

Threshold secret sharing hides a secret but cannot tell you that a share was corrupted. Verifiable variants (Feldman, Pedersen) can detect inconsistency, but they need a discrete-log group and they only report that *something* in the quorum is wrong. Accountability - knowing which shareholder handed you a bad share - is missing from all three.

## What it does

ShareLock splits a secret over GF(2^8) and commits to every share individually under a Merkle root bound to a session identifier:

- **Confidentiality** - Shamir sharing per byte; any t shares reconstruct, any t-1 reveal nothing (Theorem 1, proved by construction: for every candidate secret s′ there exists a degree ≤ t-1 polynomial consistent with the observed shares and with f(0) = s′).
- **Localisation** - verification of a tampered share fails, and *only* that index fails, because each leaf commits to one share and the Merkle path covers only siblings (Theorem 2).
- **Session binding** - a share lifted from another session fails the binding check, with constant-time comparison (Theorem 3).

A proof is log₂ n · 32 bytes (96 bytes at n=5) and verifying one share costs 0.003-0.004 ms. No group assumption is needed, which matters where byte-field arithmetic already exists in hardware (AES).

## How we built it

- `sharelock/gf256.py` - GF(2^8) with the AES modulus, log/exp tables generated from the primitive element 3.
- `sharelock/shamir.py` - split / combine / interpolate_at over the byte field, with duplicate-coordinate and length checks.
- `sharelock/vss.py` - SHA-256 leaves, Merkle root, O(log n) proofs, `locate()` returning the exact failing indices.
- `sharelock/session.py` - session-bound verification with `hmac.compare_digest`.
- `docs/report.tex` - the paper: three theorems with proofs, an attack-surface section, a comparison table against Shamir/Feldman/Pedersen, and measurements. `docs/report.pdf` is prebuilt for reviewers without TeX.

## Challenges we ran into

The interesting part was not implementing Shamir, it was finding a construction that localises without a group. Feldman checks a linear relation over a group, so one bad share breaks the relation for the whole set and the identity of the culprit is lost. Committing per share and structuring the commitments as a tree turns "is this quorum consistent" into "which index is wrong" at O(log n) cost.

The second problem was honesty about scope: the scheme commits to the sharing, not the secret, so a malicious dealer is undetected. That is stated in the paper rather than hidden.

## Accomplishments that we are proud of

- 14 tests, including a constructive check that t-1 shares are consistent with *any* candidate secret (three different guesses produce three different polynomials, all agreeing with the observations).
- Tamper localisation verified end to end: flipping one bit in share 2 yields `after_tamper: [2]`, and reconstruction over a quorum containing it returns a different secret.
- A recorded ritual: 32-byte secret, (3,5), split 0.06 ms, commit 0.076 ms, locate 0.018 ms, proof 96 bytes.

## What we learned

Cryptographic claims deserve the same treatment as benchmarks: either there is a proof or the claim does not belong in the README.

## What is next

A commitment to the secret itself so a lying dealer is detectable, share refresh without changing the secret (proactive secret sharing), and a constant-time implementation in a systems language.
