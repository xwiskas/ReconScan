"""The ReconScan icon, drawn in code.

Windows shortcuts want a .ico, Linux desktop entries want a .png, and neither
should mean adding an image library to a project that otherwise has none. Both
formats are simple enough to write by hand, so this draws the mark - a radar
sweep in the app's blue - at several sizes and packs the bytes itself.
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

ACCENT = (0x2F, 0x5F, 0xD0)     # the same blue as the dot in the sidebar
WHITE = (0xFF, 0xFF, 0xFF)
SIZES = (16, 32, 48, 64, 128, 256)
SS = 3                          # supersampling factor, for smooth edges


def _pixel(x: float, y: float, size: int) -> tuple[int, int, int, int]:
    """Colour of one sample point: a blue disc with two rings and a centre dot."""
    c = size / 2.0
    dx, dy = x - c, y - c
    dist = (dx * dx + dy * dy) ** 0.5
    r = size / 2.0 - max(0.5, size * 0.02)

    if dist > r:
        return (0, 0, 0, 0)                       # transparent outside the disc

    unit = dist / r                               # 0 at centre, 1 at the edge
    ring = max(0.055, 1.2 / size)                 # ring thickness, scaled

    # Two concentric rings and a dot in the middle: reads as "radar" even at 16px.
    if unit < 0.16:
        return (*WHITE, 255)
    if abs(unit - 0.46) < ring or abs(unit - 0.76) < ring:
        return (*WHITE, 255)

    # A faint sweep wedge in the upper right, so the mark is not perfectly static.
    if dx > 0 and dy < 0 and abs(dy) < dx * 1.1:
        return (0x5A, 0x86, 0xE8, 255)
    return (*ACCENT, 255)


def render(size: int) -> list[list[tuple[int, int, int, int]]]:
    """Rows of RGBA pixels, top row first, supersampled for smooth edges."""
    rows = []
    for py in range(size):
        row = []
        for px in range(size):
            r = g = b = a = 0
            for sy in range(SS):
                for sx in range(SS):
                    x = px + (sx + 0.5) / SS
                    y = py + (sy + 0.5) / SS
                    pr, pg, pb, pa = _pixel(x, y, size)
                    r += pr * pa
                    g += pg * pa
                    b += pb * pa
                    a += pa
            n = SS * SS
            if a == 0:
                row.append((0, 0, 0, 0))
            else:
                row.append((r // a, g // a, b // a, a // n))
        rows.append(row)
    return rows


# --- ICO --------------------------------------------------------------------
def _ico_image(rows: list[list[tuple[int, int, int, int]]]) -> bytes:
    """One BMP-style image inside an ICO: header, BGRA bottom-up, empty AND mask."""
    size = len(rows)
    header = struct.pack(
        "<IiiHHIIiiII",
        40,             # header size
        size,           # width
        size * 2,       # height: XOR bitmap plus AND mask, as ICO requires
        1,              # planes
        32,             # bits per pixel
        0, 0, 0, 0, 0, 0,
    )
    pixels = bytearray()
    for row in reversed(rows):                    # BMP rows run bottom to top
        for (r, g, b, a) in row:
            pixels += bytes((b, g, r, a))         # BGRA
    mask_row = (size + 31) // 32 * 4              # 1bpp, padded to 4 bytes
    mask = bytes(mask_row * size)                 # all zero: alpha does the work
    return header + bytes(pixels) + mask


def write_ico(path: Path, sizes: tuple[int, ...] = SIZES) -> Path:
    images = [(s, _ico_image(render(s))) for s in sizes]
    count = len(images)
    out = bytearray(struct.pack("<HHH", 0, 1, count))
    offset = 6 + 16 * count
    for size, blob in images:
        out += struct.pack(
            "<BBBBHHII",
            0 if size >= 256 else size,           # 0 means 256 in the ICO format
            0 if size >= 256 else size,
            0, 0, 1, 32, len(blob), offset,
        )
        offset += len(blob)
    for _size, blob in images:
        out += blob
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(out))
    return path


# --- PNG --------------------------------------------------------------------
def _chunk(tag: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


def write_png(path: Path, size: int = 256) -> Path:
    rows = render(size)
    raw = bytearray()
    for row in rows:
        raw.append(0)                             # filter type 0 for each scanline
        for (r, g, b, a) in row:
            raw += bytes((r, g, b, a))
    png = (b"\x89PNG\r\n\x1a\n"
           + _chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
           + _chunk(b"IDAT", zlib.compress(bytes(raw), 9))
           + _chunk(b"IEND", b""))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png)
    return path


# The shortcut icon needs the big sizes Windows shows in large-icon views; a
# favicon never renders above 48px, and the .ico format stores raw uncompressed
# bitmaps, so shipping one file for both would mean a 370 KB favicon.
FAVICON_SIZES = (16, 32, 48)


def write_all(web_dir: Path) -> None:
    write_ico(web_dir / "reconscan.ico")                       # shortcut / desktop
    write_ico(web_dir / "favicon.ico", FAVICON_SIZES)          # browser tab
    write_png(web_dir / "reconscan.png")                       # Linux .desktop


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    write_all(here / "web")
    for f in sorted((here / "web").glob("*.ico")) + sorted((here / "web").glob("*.png")):
        print(f"{f.name:20s} {f.stat().st_size:>8,} bytes")
