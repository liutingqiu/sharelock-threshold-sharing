"""Render 1280x720 cards for the ShareLock demo video."""
from __future__ import annotations
import json, sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 720
BG = (8, 11, 16)
PANEL = (14, 20, 28)
LINE = (29, 39, 52)
INK = (232, 238, 247)
MUTED = (139, 156, 179)
ACC = (224, 180, 100)
OK = (67, 217, 163)
BAD = (255, 93, 115)
F = Path("C:/Windows/Fonts")

def font(name, size):
    return ImageFont.truetype(str(F / name), size)

def base_img():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    for y in range(0, H, 4):
        v = 9 + int(8 * (1 - y / H))
        d.line([(0, y), (W, y)], fill=(v, v + 3, v + 7))
    return img

def title_card(path):
    img = base_img(); d = ImageDraw.Draw(img)
    d.rectangle([0, 0, 8, H], fill=ACC)
    d.text((72, 92), "MATHEMATICS FOR SYSTEMS SECURITY  /  CRYPTOGRAPHER TRACK", font=font("consola.ttf", 15), fill=MUTED)
    d.text((72, 146), "ShareLock", font=font("consola.ttf", 58), fill=INK)
    d.line([(72, 240), (640, 240)], fill=LINE, width=2)
    d.text((72, 264), "Tamper-localising threshold secret sharing", font=font("consola.ttf", 20), fill=ACC)
    d.text((72, 300), "Shamir sharing hides a secret. This one names the share that broke it.", font=font("consola.ttf", 16), fill=MUTED)
    d.text((72, 372), "GF(2^8)  +  per-share Merkle commitment  +  session binding", font=font("consola.ttf", 18), fill=INK)
    d.text((72, 452), "Theorem 1  confidentiality          Theorem 2  localisation", font=font("consola.ttf", 15), fill=MUTED)
    d.text((72, 478), "Theorem 3  session binding          14 tests, no dependencies", font=font("consola.ttf", 15), fill=MUTED)
    d.text((72, 620), "Tingqiu Liu  @liutingqiu", font=font("consola.ttf", 15), fill=MUTED)
    img.save(path)

def test_card(path):
    img = base_img(); d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 46], fill=(16, 24, 40))
    d.text((24, 14), "pytest -q", font=font("consola.ttf", 15), fill=MUTED)
    lines = [
        ("....................                                     [100%]", INK),
        ("14 passed in 0.02s", OK),
        ("", MUTED),
        ("test_any_threshold_subset_reconstructs[2-2] ...... ok", MUTED),
        ("test_any_threshold_subset_reconstructs[4-9] ...... ok", MUTED),
        ("test_merkle_root_verifies_every_share ........... ok", MUTED),
        ("test_tampered_share_is_located_not_just_detected  ok", OK),
        ("test_share_from_another_session_is_rejected ..... ok", MUTED),
        ("test_every_candidate_secret_yields_a_consistent_polynomial  ok", OK),
    ]
    y = 90
    for text, colour in lines:
        d.text((48, y), text, font=font("consola.ttf", 16), fill=colour)
        y += 42
    d.text((48, 600), "The two highlighted tests are the security argument, executed.", font=font("consola.ttf", 15), fill=MUTED)
    img.save(path)

def ritual_card(path, demo):
    img = base_img(); d = ImageDraw.Draw(img)
    d.text((48, 52), "ONE RECORDED RITUAL", font=font("consola.ttf", 15), fill=MUTED)
    v = demo.get("verification", {})
    t = demo.get("timing_ms", {})
    rows = [
        ("split / commit", str(t.get("split")) + " ms / " + str(t.get("commit")) + " ms", INK),
        ("clean verify", str(v.get("clean_failures")), OK),
        ("after tamper", str(v.get("after_tamper")), BAD),
        ("tampered index", str(v.get("tampered_index")), BAD),
        ("recon with corrupt share", str((demo.get("reconstruction_with_corrupted_share") or {}).get("secret_matches")), BAD),
        ("foreign session rejected", str(demo.get("session_binding_rejects_other_session")), OK),
        ("proof size", str(demo.get("proof_bytes")) + " bytes", INK),
    ]
    y = 100
    for label, value, colour in rows:
        d.rectangle([48, y, 1232, y + 60], outline=LINE, width=1, fill=PANEL)
        d.text((72, y + 20), label, font=font("consola.ttf", 17), fill=MUTED)
        d.text((780, y + 18), value, font=font("consola.ttf", 19), fill=colour)
        y += 72
    d.text((48, 648), "Verification fails for exactly the tampered index, not for the quorum as a whole.", font=font("consola.ttf", 15), fill=MUTED)
    img.save(path)

def proof_card(path, demo):
    img = base_img(); d = ImageDraw.Draw(img)
    d.text((48, 52), "BELOW THRESHOLD, NOTHING IS LEARNED", font=font("consola.ttf", 15), fill=MUTED)
    d.text((48, 84), "Two observed shares, three hypothesised secrets", font=font("consola.ttf", 26), fill=INK)
    y = 150
    for hyp in demo.get("below_threshold", []):
        d.rectangle([48, y, 1232, y + 92], outline=LINE, width=1, fill=PANEL)
        d.text((72, y + 18), "guess " + hyp["hypothesis_head"], font=font("consola.ttf", 18), fill=ACC)
        d.text((72, y + 50), "predicts f(250) = " + hyp["predicts_at_x250"], font=font("consola.ttf", 16), fill=INK)
        d.text((1000, y + 34), "consistent", font=font("consola.ttf", 15), fill=OK)
        y += 104
    d.text((48, 500), "Every hypothesis agrees with both observations and disagrees about every further", font=font("consola.ttf", 16), fill=MUTED)
    d.text((48, 526), "coordinate. That is Theorem 1, running as a test.", font=font("consola.ttf", 16), fill=MUTED)
    d.text((48, 600), "github.com/liutingqiu/sharelock-threshold-sharing", font=font("consola.ttf", 16), fill=ACC)
    img.save(path)

out = Path(sys.argv[1] if len(sys.argv) > 1 else "runs/video")
out.mkdir(parents=True, exist_ok=True)
demo = json.loads(Path("runs/video-demo.json").read_text())
title_card(out / "s1.png")
test_card(out / "s2.png")
ritual_card(out / "s3.png", demo)
proof_card(out / "s4.png", demo)
print("cards written")
