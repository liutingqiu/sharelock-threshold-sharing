# ShareLock

Threshold secret sharing over GF(2^8) where a corrupted share is **named**, not merely detected.

| | |
| --- | --- |
| Scheme | Shamir sharing in GF(2^8) + per-share Merkle commitment bound to a session |
| Guarantees | confidentiality (Theorem 1), localisation (Theorem 2), session binding (Theorem 3) |
| Mechanics | SHA-256 leaves, O(log n) proofs (64 B at n=3, 96 B at n=5), no group assumption |
| Measured | 32-byte secret, (3,5): split 0.037 ms, combine 0.013 ms, verify-all 0.021 ms |
| Tests | 14, no third-party dependencies |

Run record: https://liutingqiu.github.io/sharelock-threshold-sharing/  
Paper: [docs/report.pdf](docs/report.pdf) · LaTeX source [docs/report.tex](docs/report.tex)

## Why it exists

Shamir sharing hides a secret but cannot tell you that a share was tampered with. Feldman and
Pedersen verified sharing can, at the cost of a discrete-logarithm group, and even then they only
report that the quorum is inconsistent - not which share broke it.

ShareLock stays in the byte field. Each share is hashed into a Merkle tree whose root is published
with a session identifier:

- a share that was altered fails verification, and **only that index fails**;
- a share lifted from another session fails the binding check;
- the check costs O(log n) hashes and 32 bytes per level.

## Quick start

~~~bash
python -m pytest -q                        # 14 tests
python -m sharelock.demo runs/demo.json    # records the page's data
python -m bench.bench                      # timings from the paper

pdflatex docs/report.tex && pdflatex docs/report.tex   # build the paper
~~~

Python 3.13, standard library only.

## Layout

~~~
sharelock/gf256.py     field arithmetic with the AES modulus
sharelock/shamir.py    split / combine / interpolate_at
sharelock/vss.py       Merkle commitment, proofs, tamper localisation
sharelock/session.py   session binding, constant-time comparison
sharelock/demo.py      one recorded ritual -> JSON
bench/bench.py         timings used in the paper
docs/report.tex        paper with the three theorems
docs/report.pdf        prebuilt
tests/                 14 tests
~~~

## What this does not do

It does not protect against a malicious dealer (the root commits to the sharing, not to the
secret), it does not hide shares (a hash commits without concealing), and the Python code is not
side-channel hardened. The report states these in section 8 rather than leaving them implied.
