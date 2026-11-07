"""
Generates the SiteLimiter tray/app icons (original artwork, drawn from geometry).

    python tools/make_icon.py        # writes src/SiteLimiter/Assets/*.ico (+ preview.png)

Design: a speedometer gauge (rounded arc, three ticks, teardrop needle) with the letters
M and G in the top corners. Everything is stroke-based so it stays crisp at 16 px.
Tray: dark glyph (for light taskbars) and light glyph (for dark taskbars), transparent.
App (exe, terminal, browser tab): black glyph on a white rounded square, always visible.
"""
import io, math, struct, pathlib
from PIL import Image, ImageDraw

SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]
SS = 16  # supersampling factor
OUT = pathlib.Path(__file__).resolve().parent.parent / "src" / "SiteLimiter" / "Assets"

# ---- geometry in a 100x100 design space (y down) ----
GC, GR = (50.0, 96.0), 45.0           # gauge centre (on the baseline) and arc radius
FOOT = 9.0                           # length of the inward feet at the arc ends
TICK_IN = 33.0                        # ticks run from this radius out to the arc
PIVOT, PIVOT_R = (51.0, 88.0), 6.0    # needle bulb
NEEDLE_ANGLE, NEEDLE_LEN = 64.7, 27.0     # aimed at the centre of the G
M_BOX = (3.0, 3.0, 31.0, 37.0)        # x0, y0, x1, y1
G_BOX = (66.0, 3.0, 97.0, 37.0)


def stroke_width(size: int) -> float:
    # ~7% of the icon, but never thinner than ~1.25 px at tiny sizes
    return max(7.0, 1.25 * 100.0 / size)


def arc_points(c, r, a0, a1, steps=90):
    """Points on a circle, angles in degrees, math convention (counter-clockwise, y up)."""
    pts = []
    for i in range(steps + 1):
        t = math.radians(a0 + (a1 - a0) * i / steps)
        pts.append((c[0] + r * math.cos(t), c[1] - r * math.sin(t)))
    return pts


def render(size: int, color) -> Image.Image:
    big = size * SS
    k = big / 100.0
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    sw = stroke_width(size)
    w = max(1, round(sw * k))

    def P(p):
        return (p[0] * k, p[1] * k)

    def polyline(pts):
        pts = [P(p) for p in pts]
        d.line(pts, fill=color, width=w, joint="curve")
        for x, y in (pts[0], pts[-1]):  # round caps
            d.ellipse((x - w / 2, y - w / 2, x + w / 2, y + w / 2), fill=color)

    inset = sw / 2  # keep strokes inside the canvas

    # gauge: left foot -> arc over the top -> right foot
    cx, cy = GC
    by = cy - inset
    r = GR
    arc = arc_points((cx, by), r, 180, 0)
    polyline([(cx - r + FOOT, by)] + arc + [(cx + r - FOOT, by)])

    # ticks at 45 / 90 / 135 degrees (dropped at 16 px where they would blur into the arc)
    if size >= 20:
        for a in (135, 90, 45):
            t = math.radians(a)
            polyline([(cx + TICK_IN * math.cos(t), by - TICK_IN * math.sin(t)),
                      (cx + (r - 1) * math.cos(t), by - (r - 1) * math.sin(t))])

    # needle: filled teardrop from the bulb to the tip
    px, py = PIVOT[0], PIVOT[1] - inset
    br = max(PIVOT_R, sw * 0.8)
    t = math.radians(NEEDLE_ANGLE)
    tip = (px + NEEDLE_LEN * math.cos(t), py - NEEDLE_LEN * math.sin(t))
    dist = math.hypot(tip[0] - px, tip[1] - py)
    base = math.atan2(-(tip[1] - py), tip[0] - px)            # math angle of the tip direction
    spread = math.acos(min(1.0, br / dist))                   # tangent points on the bulb
    bulb = arc_points((px, py), br, math.degrees(base + spread), math.degrees(base - spread) + 360, 60)
    tip_r = sw * 0.28
    d.polygon([P(tip)] + [P(p) for p in bulb], fill=color)
    tx, ty = P(tip)
    d.ellipse((tx - tip_r * k, ty - tip_r * k, tx + tip_r * k, ty + tip_r * k), fill=color)

    # M
    x0, y0, x1, y1 = M_BOX
    x0 += inset; x1 -= inset; y0 += inset; y1 -= inset
    polyline([(x0, y1), (x0, y0), ((x0 + x1) / 2, y0 + (y1 - y0) * 0.58), (x1, y0), (x1, y1)])

    # G: open ring from upper-right, round the left, back to the right, then the bar inward
    gx0, gy0, gx1, gy1 = G_BOX
    # Same box height as M (G_BOX shares M_BOX's y range); slightly oval so their outer edges line up.
    gcx, gcy = (gx0 + gx1) / 2, (gy0 + gy1) / 2
    # at 16 px the round top anti-aliases into the row above M's flat top; pull it in ~0.35 px
    rx, ry = (gx1 - gx0) / 2 - inset, (gy1 - gy0) / 2 - inset - (35.0 / size if size <= 16 else 0.0)
    ring = []
    for i in range(81):
        t = math.radians(52 + (360 - 52) * i / 80)
        ring.append((gcx + rx * math.cos(t), gcy - ry * math.sin(t)))
    polyline(ring + [(gcx + rx * 0.05, gcy)])

    return img.resize((size, size), Image.LANCZOS)


def render_app(size: int) -> Image.Image:
    """App/exe/browser-tab icon: black glyph on a white rounded square, visible on any background."""
    big = size * SS
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    ImageDraw.Draw(img).rounded_rectangle((0, 0, big - 1, big - 1), radius=big * 0.2, fill=(255, 255, 255, 255))
    img = img.resize((size, size), Image.LANCZOS)
    # small sizes can't afford padding: the glyph's own stroke inset is the margin
    inner = size if size <= 20 else size - 2 if size <= 32 else round(size * 0.84)
    glyph = render(inner, (0, 0, 0, 255))
    off = (size - inner) // 2
    img.alpha_composite(glyph, (off, off))
    return img


def write_ico(path: pathlib.Path, images):
    """Multi-size .ico with PNG-compressed entries (Windows Vista+)."""
    blobs = []
    for im in images:
        buf = io.BytesIO()
        im.save(buf, "PNG", optimize=True)
        blobs.append(buf.getvalue())
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    for im, blob in zip(images, blobs):
        s = im.size[0]
        entries += struct.pack("<BBBBHHII", s if s < 256 else 0, s if s < 256 else 0, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    path.write_bytes(header + entries + b"".join(blobs))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    variants = {"tray-dark": (27, 27, 27, 255), "tray-light": (255, 255, 255, 255)}
    rendered = {}
    for name, color in variants.items():
        rendered[name] = [render(s, color) for s in SIZES]
        write_ico(OUT / f"{name}.ico", rendered[name])

    app = [render_app(s) for s in SIZES]
    write_ico(OUT / "app.ico", app)
    rendered["app"] = app

    # preview: each size at 1x and enlarged 8x (nearest), on a light and a dark taskbar colour
    show = [16, 20, 24, 32, 48]
    cell = 8 * 48 + 24
    sheet = Image.new("RGBA", (cell * len(show), cell * 3 + 160), (255, 255, 255, 255))
    for row, (bg, name) in enumerate([((243, 243, 243, 255), "tray-dark"), ((32, 32, 32, 255), "tray-light"),
                                      ((32, 32, 32, 255), "app")]):
        for col, s in enumerate(show):
            im = rendered[name][SIZES.index(s)]
            x, y = col * cell, row * cell
            tile = Image.new("RGBA", (cell, cell), bg)
            tile.alpha_composite(im.resize((s * 8, s * 8), Image.NEAREST), (12, 12))
            tile.alpha_composite(im, (cell - s - 12, cell - s - 12))
            sheet.alpha_composite(tile, (x, y))
    big = rendered["tray-dark"][SIZES.index(256)]
    strip = Image.new("RGBA", (sheet.width, 160), (255, 255, 255, 255))
    strip.alpha_composite(big.resize((150, 150), Image.LANCZOS), (5, 5))
    sheet.alpha_composite(strip, (0, cell * 3))
    sheet.save(OUT / "preview.png")
    print("wrote", ", ".join(sorted(p.name for p in OUT.iterdir())))


if __name__ == "__main__":
    main()
