"""Render captured terminal output as a terminal-style PNG.

The text is drawn exactly as captured (ANSI colour codes removed); only
colour is added, by keyword, to make PASSED / FAILED / ALERT readable. The
raw text is saved beside every image so the screenshot can be checked
against it.
"""
from __future__ import annotations

import re
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONT = r"C:\Windows\Fonts\consola.ttf"
FONT_B = r"C:\Windows\Fonts\consolab.ttf"
SIZE, LINE, PAD, WRAP, MAX_LINES = 15, 21, 22, 118, 46
BG, BAR, TITLE, PROMPT, TEXT = "#0d1117", "#161b22", "#8b949e", "#79c0ff", "#c9d1d9"
COLOURS = [
    (re.compile(r"\b(PASSED|passed|PASS|OK|ok|benign_ok|detected|Holds|met|significant|accepted)\b"), "#3fb950"),
    (re.compile(r"\b(FAILED|failed|FAIL|ALERT|alert|false_alarm|error|ERROR|NOT met|residue_alert)\b"), "#f85149"),
    (re.compile(r"\b(WARNING|warning|watch|WATCH|pending|skipped)\b"), "#d29922"),
]
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _segments(line: str):
    """Split a line into (text, colour) runs by keyword."""
    marks = []
    for rx, colour in COLOURS:
        for m in rx.finditer(line):
            marks.append((m.start(), m.end(), colour))
    marks.sort()
    out, pos = [], 0
    for a, b, colour in marks:
        if a < pos:
            continue
        if a > pos:
            out.append((line[pos:a], TEXT))
        out.append((line[a:b], colour))
        pos = b
    if pos < len(line):
        out.append((line[pos:], TEXT))
    return out


def _wrap(text: str) -> list[str]:
    lines = []
    for raw in ANSI.sub("", text).replace("\r", "").split("\n"):
        raw = raw.expandtabs(4)
        lines.extend(textwrap.wrap(raw, WRAP, replace_whitespace=False, drop_whitespace=False) or [""])
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def render(title: str, command: str, text: str, out: Path) -> list[Path]:
    """Write one PNG per page of output; returns the files written."""
    font, bold = ImageFont.truetype(FONT, SIZE), ImageFont.truetype(FONT_B, SIZE)
    lines = _wrap(text)
    pages = [lines[i:i + MAX_LINES] for i in range(0, max(len(lines), 1), MAX_LINES)] or [[]]
    files = []
    cmd_lines = _wrap("> " + command) if command else []
    for n, page in enumerate(pages, 1):
        name = out if len(pages) == 1 else out.with_name(f"{out.stem}_part{n}{out.suffix}")
        head = cmd_lines if n == 1 else [f"(continued, part {n} of {len(pages)})"]
        width = max(820, PAD * 2 + 9 * max([len(l) for l in head + page] + [40]))
        height = 44 + PAD + LINE * (len(head) + len(page)) + PAD
        img = Image.new("RGB", (width, height), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, width, 40], fill=BAR)
        for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
            d.ellipse([16 + i * 22, 13, 30 + i * 22, 27], fill=c)
        page_title = title if len(pages) == 1 else f"{title}  ({n}/{len(pages)})"
        d.text((90, 11), page_title, font=font, fill=TITLE)
        y = 44 + PAD // 2
        for l in head:
            d.text((PAD, y), l, font=bold, fill=PROMPT if n == 1 else TITLE)
            y += LINE
        for l in page:
            x = PAD
            for seg, colour in _segments(l):
                d.text((x, y), seg, font=font, fill=colour)
                x += d.textlength(seg, font=font)
            y += LINE
        name.parent.mkdir(parents=True, exist_ok=True)
        img.save(name)
        files.append(name)
    return files
