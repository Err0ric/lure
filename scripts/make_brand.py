"""Build the brand images in docs/assets/ from the logo mark. Pillow only.

    python scripts/make_brand.py [--font PATH] [--only NAME ...]

Outputs (all in docs/assets/):

| File | Size | Contents |
| --- | --- | --- |
| social-preview.png | 1280x640 | Logo left, wordmark and tagline right |
| banner.png | 1200x400 | README banner, same layout |
| favicon.png | 32x32 | Drawn glyph: horns, eyes, terminal bar |
| favicon-16.png | 16x16 | Same glyph |
| avatar.png | 512x512 | Face and horns |

It also writes two report partials in lure/report/templates/, as base64
data URIs so reports stay single-file and work offline: _favicon.html.j2
(the favicons) and _avatar.html.j2 (the avatar for the page header).

The default font is Menlo Bold (macOS), to match the logo's terminal text.
"""

import argparse
import base64
import io
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ASSETS = Path(__file__).resolve().parent.parent / "docs" / "assets"
LOGO = ASSETS / "lure-logo-mark.png"
TEMPLATES = ASSETS.parent.parent / "lure" / "report" / "templates"
FAVICON_PARTIAL = TEMPLATES / "_favicon.html.j2"
AVATAR_PARTIAL = TEMPLATES / "_avatar.html.j2"
# Header avatar: shown at 28px, stored at 2x for sharp high-DPI screens.
AVATAR_CSS_PX = 28

BG = (0x10, 0x05, 0x1F)
WORDMARK = (0xC0, 0x84, 0xFC)  # the logo's horn outline purple
TAGLINE = (0xC9, 0xBE, 0xDD)  # the logo's terminal text lavender
RULE = (0x6B, 0x3F, 0xA0)
HORN = (0xA9, 0x70, 0xFF)
EYE = (0xFF, 0x3B, 0x5C)

DEFAULT_FONT = "/System/Library/Fonts/Menlo.ttc"
MENLO_BOLD = 1  # face index in Menlo.ttc

# Face and horns in the 1024x957 logo, ending above the terminal's top
# border. The top runs past the image edge and is padded with BG.
FACE_BOX = (250, -35, 780, 495)
# Red ember on the hair at the avatar's bottom left, painted over.
AVATAR_EMBER = (411, 477, 429, 493)


def font(path, size):
    index = MENLO_BOLD if path.endswith("Menlo.ttc") else 0
    return ImageFont.truetype(path, size, index=index)


def fade_edges(img, margin):
    """Blend the logo's own background into BG over `margin` px at each edge."""
    w, h = img.size
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).rectangle((margin, margin, w - margin, h - margin), fill=255)
    mask = mask.filter(ImageFilter.GaussianBlur(margin / 2))
    out = Image.new("RGB", (w, h), BG)
    out.paste(img, (0, 0), mask)
    return out


def lockup(logo, size, logo_h, word_px, tag_px, font_path):
    """Logo on the left, "LURE" and the tagline stacked on the right."""
    w, h = size
    canvas = Image.new("RGB", size, BG)
    scaled = logo.resize(
        (round(logo.width * logo_h / logo.height), logo_h), Image.LANCZOS
    )
    scaled = fade_edges(scaled, max(4, logo_h // 40))
    pad = (h - logo_h) // 2
    x_logo = round(w * 0.06)
    canvas.paste(scaled, (x_logo, pad))

    draw = ImageDraw.Draw(canvas)
    word_font = font(font_path, word_px)
    tag_font = font(font_path, tag_px)
    word, tag = "LURE", "Agent security harness"
    wb = draw.textbbox((0, 0), word, font=word_font)
    tb = draw.textbbox((0, 0), tag, font=tag_font)
    gap = round(tag_px * 0.9)
    rule_h = max(2, word_px // 40)
    block_h = (wb[3] - wb[1]) + gap + rule_h + gap + (tb[3] - tb[1])
    block_w = max(wb[2] - wb[0], tb[2] - tb[0])

    text_left = x_logo + scaled.width + round(w * 0.05)
    x = text_left + (w - round(w * 0.05) - text_left - block_w) // 2
    y = (h - block_h) // 2
    draw.text((x - wb[0], y - wb[1]), word, font=word_font, fill=WORDMARK)
    y += (wb[3] - wb[1]) + gap
    draw.rectangle((x, y, x + block_w, y + rule_h - 1), fill=RULE)
    y += rule_h + gap
    draw.text((x - tb[0], y - tb[1]), tag, font=tag_font, fill=TAGLINE)
    return canvas


def avatar(logo, px):
    """Square crop of FACE_BOX, padded with BG where it runs past the logo."""
    logo = logo.copy()
    x0, y0, x1, y1 = AVATAR_EMBER
    hair = logo.getpixel((x0 - 2, (y0 + y1) // 2))
    ImageDraw.Draw(logo).ellipse(AVATAR_EMBER, fill=hair)
    x0, y0, x1, y1 = FACE_BOX
    crop = Image.new("RGB", (x1 - x0, y1 - y0), BG)
    crop.paste(logo, (-x0, -y0))
    return crop.resize((px, px), Image.LANCZOS)


def bezier(p0, c, p1, steps=24):
    """Points on the quadratic Bezier from p0 to p1 with control point c."""
    pts = []
    for i in range(steps + 1):
        t = i / steps
        pts.append(
            (
                (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * c[0] + t**2 * p1[0],
                (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * c[1] + t**2 * p1[1],
            )
        )
    return pts


def glyph():
    """The favicon glyph at 256px. Drawn at 4x, then downsampled to smooth
    the edges, since Pillow does not anti-alias polygons."""
    k = 4

    def sc(points):
        return [(x * k, y * k) for x, y in points]

    def mirror(points):
        return [(256 - x, y) for x, y in points]

    size = 256 * k
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    ImageDraw.Draw(img).rounded_rectangle((0, 0, size - 1, size - 1), 56 * k, fill=BG)

    # Left horn: a crescent from a base on the brow, sweeping out and up to
    # a tip that curls back in. The right horn mirrors it.
    horn = bezier((64, 132), (14, 64), (72, 18)) + bezier(
        (72, 18), (42, 80), (106, 116)
    )
    # Left eye: a slanted almond, its inner corner lower, for a narrowed look.
    eye = bezier((58, 146), (92, 132), (122, 172)) + bezier(
        (122, 172), (82, 178), (58, 146)
    )
    bar = (60 * k, 208 * k, 196 * k, 220 * k)

    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    for shape in (eye, mirror(eye)):
        gd.polygon(sc(shape), fill=EYE + (255,))
    glow = glow.filter(ImageFilter.GaussianBlur(10 * k))
    for _ in range(3):
        img = Image.alpha_composite(img, glow)

    draw = ImageDraw.Draw(img)
    for shape in (horn, mirror(horn)):
        draw.polygon(sc(shape), fill=HORN)
    for shape in (eye, mirror(eye)):
        draw.polygon(sc(shape), fill=EYE)
    draw.rounded_rectangle(bar, 6 * k, fill=HORN)

    # Keep the glow inside the rounded square.
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size - 1, size - 1), 56 * k, fill=255)
    img.putalpha(Image.composite(img.getchannel("A"), mask, mask))
    return img.resize((256, 256), Image.LANCZOS)


def build(font_path):
    logo = Image.open(LOGO).convert("RGB")
    return {
        "social-preview.png": lambda: lockup(
            logo, (1280, 640), 540, 150, 36, font_path
        ),
        "banner.png": lambda: lockup(logo, (1200, 400), 340, 110, 30, font_path),
        "favicon.png": lambda: glyph().resize((32, 32), Image.LANCZOS),
        "favicon-16.png": lambda: glyph().resize((16, 16), Image.LANCZOS),
        "avatar.png": lambda: avatar(logo, 512),
    }


def write_favicon_partial():
    links = []
    for name, px in (("favicon.png", 32), ("favicon-16.png", 16)):
        data = base64.b64encode((ASSETS / name).read_bytes()).decode("ascii")
        links.append(
            f'<link rel="icon" type="image/png" sizes="{px}x{px}" '
            f'href="data:image/png;base64,{data}">'
        )
    head = "{# Generated by scripts/make_brand.py from docs/assets/favicon*.png. #}"
    # Jinja drops one trailing newline from an include; the second keeps the
    # next tag on its own line.
    FAVICON_PARTIAL.write_text("\n".join([head, *links]) + "\n\n")
    print(f"Wrote {FAVICON_PARTIAL.relative_to(ASSETS.parent.parent)}")


def write_avatar_partial():
    img = Image.open(ASSETS / "avatar.png").convert("RGB")
    img = img.resize((AVATAR_CSS_PX * 2, AVATAR_CSS_PX * 2), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    data = base64.b64encode(buf.getvalue()).decode("ascii")
    head = "{# Generated by scripts/make_brand.py from docs/assets/avatar.png. #}"
    tag = (
        f'<img class="avatar" alt="" width="{AVATAR_CSS_PX}" height="{AVATAR_CSS_PX}" '
        f'src="data:image/png;base64,{data}">'
    )
    # Trailing newlines as in write_favicon_partial.
    AVATAR_PARTIAL.write_text(f"{head}\n{tag}\n\n")
    print(f"Wrote {AVATAR_PARTIAL.relative_to(ASSETS.parent.parent)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--font", default=DEFAULT_FONT, help="TrueType font for the wordmark"
    )
    parser.add_argument(
        "--only", nargs="+", metavar="NAME", help="build only these files"
    )
    args = parser.parse_args()
    for name, make in build(args.font).items():
        if args.only and name not in args.only:
            continue
        img = make()
        img.save(ASSETS / name, optimize=True)
        print(f"Wrote docs/assets/{name}: {img.width}x{img.height}")
    if not args.only or {"favicon.png", "favicon-16.png"} & set(args.only):
        write_favicon_partial()
    if not args.only or "avatar.png" in args.only:
        write_avatar_partial()


if __name__ == "__main__":
    main()
