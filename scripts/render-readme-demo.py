#!/usr/bin/env python3
"""Render an explicitly labelled result summary from readme-demo.mjs output.

Requires Pillow. Uses installed fonts; override DEMO_SANS_FONT/DEMO_MONO_FONT
for another platform. This is an illustration of captured results, not a
screen recording or a claim that the proposed tool commands were executed.
"""
import json
import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "docs" / "assets"
RUN = json.loads((ASSETS / "readme-demo-run.json").read_text())
STEPS = {step["name"]: step for step in RUN["steps"]}
RESULTS = {name: json.loads(step["stdout"]) for name, step in STEPS.items()}
assert RESULTS["allow_read"]["allowed"] is True
assert RESULTS["deny_force_push"]["allowed"] is False
assert RESULTS["sign_allow"]["signed"] and RESULTS["sign_deny"]["signed"]
assert RESULTS["verify_chain"]["verified"] == 2
assert RESULTS["verify_chain"]["chainBreaks"] == 0
assert RESULTS["reject_tamper"]["error"] == "invalid_signature"
assert RESULTS["reject_embedded_key"]["error"] == "embedded_key_rejected"

def font_path(variable, candidates):
    override = os.environ.get(variable)
    if override:
        return override
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    raise SystemExit(f"Set {variable} to an installed font file.")

SANS = font_path("DEMO_SANS_FONT", [
    "/System/Library/Fonts/SFNS.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
])
MONO = font_path("DEMO_MONO_FONT", [
    "/System/Library/Fonts/SFNSMono.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
])
def sans(size): return ImageFont.truetype(SANS, size)
def mono(size): return ImageFont.truetype(MONO, size)

W, H = 1280, 834
BG, PANEL, BORDER = "#0A1020", "#111B2D", "#25324A"
WHITE, MUTED, FAINT = "#ECF2FB", "#AAB8CE", "#71829D"
BLUE, GREEN, RED = "#85B7FF", "#77E4B1", "#FF9B9B"
allow, deny, chain = RESULTS["allow_read"], RESULTS["deny_force_push"], RESULTS["verify_chain"]
rule = deny["reason"].split(":")[1].strip()
cards = [
    ("01", "EVALUATE A PROPOSED READ", "Read · README.md", f'allowed: {str(allow["allowed"]).lower()}', GREEN),
    ("02", "EVALUATE A PROPOSED FORCE-PUSH", "Bash · git push --force origin main", f'allowed: {str(deny["allowed"]).lower()}  ·  {rule}', RED),
    ("03", "SIGN BOTH DECISIONS", "allow + deny → receipt log", 'signed: true  ·  2 decision receipts', BLUE),
    ("04", "VERIFY WITH A SEPARATELY SUPPLIED PUBLIC KEY", "verify --replay-chain … --key …", f'verified: {chain["verified"]}  ·  chainBreaks: {chain["chainBreaks"]}', GREEN),
    ("05", "CHANGE THE SIGNED DENY TO ALLOW", "verify tampered.json --key …", f'error: {RESULTS["reject_tamper"]["error"]}', RED),
]

def render(revealed, final=False):
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((1, 1, W-2, H-2), radius=22, outline=BORDER, width=2)
    for i, color in enumerate(["#FF827C", "#E6BD6C", "#7CCFA3"]):
        d.ellipse((30+i*24, 26, 42+i*24, 38), fill=color)
    d.text((118, 21), "protect-mcp", font=mono(20), fill=WHITE)
    d.text((W-435, 22), "Result summary · real local run", font=sans(20), fill=MUTED)
    d.line((24, 57, W-24, 57), fill=BORDER, width=1)
    d.text((35, 79), "Allow. Deny. Verify.", font=sans(42), fill=WHITE)
    versions = f'protect-mcp {RUN["packages"]["protect-mcp"]["version"]}  /  verify {RUN["packages"]["@veritasacta/verify"]["version"]}'
    d.text((36, 132), versions, font=mono(19), fill=MUTED)
    for index, (number, label, command, outcome, color) in enumerate(cards):
        y = 179 + index*111
        ready = index < revealed
        active = ready and (index == revealed-1 or final)
        d.rounded_rectangle((26, y, W-27, y+100), radius=12, fill=PANEL, outline=color if active else BORDER, width=2 if active else 1)
        d.text((44, y+18), number, font=mono(24), fill=color if ready else FAINT)
        d.text((97, y+12), label, font=sans(15), fill=MUTED if ready else FAINT)
        d.text((97, y+35), command, font=mono(23), fill=WHITE if ready else FAINT)
        d.text((97, y+68), outcome if ready else "…", font=mono(19), fill=color if ready else FAINT)
    d.text((36, 752), "Proposals evaluated only. No tool or force-push was executed.", font=sans(21), fill=MUTED)
    d.text((36, 787), "Checks supplied records; does not prove execution or complete coverage.", font=sans(18), fill=FAINT)
    return im

ASSETS.mkdir(parents=True, exist_ok=True)
still = render(5, final=True)
still.save(ASSETS / "readme-demo.png", optimize=True)
frames = [render(step) for step in range(1, 6)] + [still]
# One shared palette keeps colors steady and makes the GIF small.
palette = still.quantize(colors=64, method=Image.Quantize.MEDIANCUT)
frames = [frame.quantize(palette=palette, dither=Image.Dither.NONE) for frame in frames]
frames[0].save(ASSETS / "readme-demo.gif", save_all=True, append_images=frames[1:],
               duration=[1600, 1600, 1600, 1800, 1800, 5600], loop=0, optimize=True, disposal=1)
with Image.open(ASSETS / "readme-demo.gif") as gif:
    total = 0
    for frame in range(gif.n_frames):
        gif.seek(frame)
        total += gif.info["duration"]
    assert gif.n_frames == 6
    assert total == 14000
assert (ASSETS / "readme-demo.gif").stat().st_size < 1_000_000
print(f"Rendered {W}×{H}: six frames, {total / 1000:g}s, {(ASSETS / 'readme-demo.gif').stat().st_size:,} bytes")
