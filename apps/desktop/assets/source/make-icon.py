#!/usr/bin/env python3
"""Recreate the Lliam-GOV navy 'LG / LLIAM-GOV' monogram app icon at 1024x1024."""
from PIL import Image, ImageDraw, ImageFont

SZ = 1024
NAVY = (22, 36, 63, 255)        # deep navy
NAVY_HI = (52, 70, 104, 255)    # subtle lighter inner border
WHITE = (245, 247, 250, 255)
GOLD = (198, 164, 92, 255)      # accent for the wordmark underline

img = Image.new("RGBA", (SZ, SZ), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# Rounded-square background (macOS-ish squircle), near-full tile
m = 36
d.rounded_rectangle([m, m, SZ - m, SZ - m], radius=208, fill=NAVY)
# subtle inner frame
d.rounded_rectangle([m + 26, m + 26, SZ - m - 26, SZ - m - 26], radius=184,
                    outline=NAVY_HI, width=4)

SERIF = "/System/Library/Fonts/Supplemental/Georgia Bold.ttf"
SANS = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"  # upright, clean

# --- "LG" monogram, large serif, centered upper-middle ---
lg_font = ImageFont.truetype(SERIF, 460)
lg = "LG"
bb = d.textbbox((0, 0), lg, font=lg_font)
lg_w = bb[2] - bb[0]
lg_x = (SZ - lg_w) / 2 - bb[0]
lg_y = 290 - bb[1]
d.text((lg_x, lg_y), lg, font=lg_font, fill=WHITE)

# --- "LLIAM-GOV" wordmark, letter-spaced caps below (baseline-aligned) ---
wm = "LLIAM-GOV"
wm_font = ImageFont.truetype(SANS, 110)
tracking = 16
# advance width per char (use bbox width + a little), draw on a common baseline
widths = [d.textlength(c, font=wm_font) for c in wm]
total = sum(widths) + tracking * (len(wm) - 1)
x = (SZ - total) / 2
baseline = 850
for c, w in zip(wm, widths):
    d.text((x, baseline), c, font=wm_font, fill=WHITE, anchor="ls")
    x += w + tracking

# --- thin gold rule under the wordmark ---
rule_w = int(total * 0.62)
rx = (SZ - rule_w) / 2
d.rectangle([rx, 905, rx + rule_w, 911], fill=GOLD)

img.save("/tmp/lliam_icon_master.png")
print("wrote /tmp/lliam_icon_master.png", img.size)
