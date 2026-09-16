"""A small, dependency-free PDF writer.

Enough to lay out a report: headings, paragraphs, bullets, key/value rows and
monospaced evidence blocks, with wrapping and pagination. Uses the 14 standard
PDF fonts, so no font files are embedded and the output opens anywhere.

This exists so that "export as PDF" works offline on a stock Kali install
without pulling in a rendering stack.
"""
from __future__ import annotations

import textwrap
from dataclasses import dataclass

PAGE_W, PAGE_H = 595.28, 841.89          # A4 in points
MARGIN = 56
CONTENT_W = PAGE_W - 2 * MARGIN


@dataclass
class Block:
    kind: str          # h1 | h2 | h3 | p | bullet | kv | mono | rule | space
    text: str = ""
    key: str = ""


STYLES = {
    "h1": ("F2", 20, 26, 16, 8),      # font, size, leading, space_before, space_after
    "h2": ("F2", 14, 19, 14, 6),
    "h3": ("F2", 11, 15, 10, 4),
    "p": ("F1", 10, 14, 0, 7),
    "bullet": ("F1", 10, 14, 0, 3),
    "kv": ("F1", 10, 14, 0, 2),
    "mono": ("F3", 8, 10, 4, 6),
}

_ESCAPE = {"\\": r"\\", "(": r"\(", ")": r"\)"}


def _esc(s: str) -> str:
    return "".join(_ESCAPE.get(c, c) for c in s)


def _ascii(s: str) -> str:
    """WinAnsi-safe text: replace the typographic characters our copy uses."""
    repl = {"’": "'", "‘": "'", "“": '"', "”": '"',
            "–": "-", "—": "-", "…": "...", "·": "-",
            "→": "->", "✓": "v", "⚠": "!", " ": " "}
    for k, v in repl.items():
        s = s.replace(k, v)
    return "".join(c if 32 <= ord(c) < 127 else "?" for c in s)


def _wrap(text: str, font: str, size: float, width: float) -> list[str]:
    # Helvetica averages ~0.5 em per character, Courier is exactly 0.6.
    per_char = size * (0.6 if font == "F3" else 0.5)
    cols = max(8, int(width / per_char))
    out: list[str] = []
    for para in text.split("\n"):
        out.extend(textwrap.wrap(para, cols) or [""])
    return out


class Writer:
    def __init__(self) -> None:
        self.blocks: list[Block] = []

    def h1(self, t: str) -> None: self.blocks.append(Block("h1", t))
    def h2(self, t: str) -> None: self.blocks.append(Block("h2", t))
    def h3(self, t: str) -> None: self.blocks.append(Block("h3", t))
    def p(self, t: str) -> None: self.blocks.append(Block("p", t))
    def bullet(self, t: str) -> None: self.blocks.append(Block("bullet", t))
    def kv(self, k: str, v: str) -> None: self.blocks.append(Block("kv", v, k))
    def mono(self, t: str) -> None: self.blocks.append(Block("mono", t))
    def rule(self) -> None: self.blocks.append(Block("rule"))
    def space(self, h: str = "8") -> None: self.blocks.append(Block("space", h))

    # --- layout -------------------------------------------------------------
    def _lay_out(self) -> list[list[tuple]]:
        pages: list[list[tuple]] = []
        ops: list[tuple] = []
        y = PAGE_H - MARGIN

        def newpage() -> None:
            nonlocal ops, y
            if ops:
                pages.append(ops)
            ops = []
            y = PAGE_H - MARGIN

        for b in self.blocks:
            if b.kind == "space":
                y -= float(b.text or 8)
                continue
            if b.kind == "rule":
                if y < MARGIN + 20:
                    newpage()
                y -= 6
                ops.append(("rule", y))
                y -= 10
                continue

            font, size, leading, before, after = STYLES[b.kind]
            y -= before
            indent = 0.0
            if b.kind == "bullet":
                indent = 14.0
            if b.kind == "kv":
                indent = 0.0

            if b.kind == "kv":
                body = f"{b.key}: {b.text}"
                lines = _wrap(body, font, size, CONTENT_W)
            else:
                lines = _wrap(b.text, font, size, CONTENT_W - indent)

            for i, line in enumerate(lines):
                if y - leading < MARGIN:
                    newpage()
                y -= leading
                prefix = ""
                if b.kind == "bullet" and i == 0:
                    ops.append(("text", "F1", size, MARGIN, y, "-"))
                ops.append(("text", font, size, MARGIN + indent, y, prefix + line))
            y -= after
        if ops:
            pages.append(ops)
        return pages or [[]]

    # --- PDF assembly -------------------------------------------------------
    def render(self, title: str = "ReconScan report") -> bytes:
        pages = self._lay_out()
        streams: list[bytes] = []
        for ops in pages:
            parts: list[str] = []
            for op in ops:
                if op[0] == "rule":
                    _, y = op
                    parts.append(f"0.75 w 0.8 0.8 0.82 RG {MARGIN} {y:.2f} m "
                                 f"{PAGE_W - MARGIN} {y:.2f} l S")
                else:
                    _, font, size, x, y, text = op
                    parts.append(f"BT /{font} {size} Tf {x:.2f} {y:.2f} Td "
                                 f"({_esc(_ascii(text))}) Tj ET")
            streams.append("\n".join(parts).encode("latin-1", "replace"))

        objects: list[bytes] = []

        def add(body: bytes) -> int:
            objects.append(body)
            return len(objects)

        font_objs = {
            "F1": add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                      b"/Encoding /WinAnsiEncoding >>"),
            "F2": add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                      b"/Encoding /WinAnsiEncoding >>"),
            "F3": add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier "
                      b"/Encoding /WinAnsiEncoding >>"),
        }
        pages_obj_num = len(objects) + 1 + 2 * len(streams) + 1
        page_nums: list[int] = []
        for s in streams:
            content_num = add(b"<< /Length " + str(len(s)).encode() + b" >>\nstream\n"
                              + s + b"\nendstream")
            res = ("<< /Font << " + " ".join(
                f"/{k} {v} 0 R" for k, v in font_objs.items()) + " >> >>").encode()
            page_nums.append(add(
                b"<< /Type /Page /Parent " + str(pages_obj_num).encode() +
                b" 0 R /MediaBox [0 0 " + f"{PAGE_W:.2f} {PAGE_H:.2f}".encode() +
                b"] /Resources " + res + b" /Contents " + str(content_num).encode() + b" 0 R >>"))

        kids = " ".join(f"{n} 0 R" for n in page_nums).encode()
        pages_num = add(b"<< /Type /Pages /Kids [" + kids + b"] /Count "
                        + str(len(page_nums)).encode() + b" >>")
        info_num = add(b"<< /Title (" + _esc(_ascii(title)).encode("latin-1", "replace")
                       + b") /Producer (ReconScan) >>")
        catalog_num = add(b"<< /Type /Catalog /Pages " + str(pages_num).encode() + b" 0 R >>")

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for i, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
        xref_at = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for off in offsets[1:]:
            out += f"{off:010d} 00000 n \n".encode()
        out += (f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_num} 0 R "
                f"/Info {info_num} 0 R >>\nstartxref\n{xref_at}\n%%EOF\n").encode()
        return bytes(out)
