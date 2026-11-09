#!/usr/bin/env python3
"""Render docs/demo.gif: a replay of a real benchmark run, shortened.

Every line the demo shows, apart from its title and closing note, is quoted from the kept
transcript of benchmark 1's counted run, and a test checks that, so the demo cannot drift from
what the agent did. Rendering needs Pillow and a monospace font: pip install pillow.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RUN = REPO_ROOT / "benchmarks" / "runs" / "20261106-232142-01-crackme-xor"
OUTPUT = REPO_ROOT / "docs" / "demo.gif"
FONTS = (
    "/System/Library/Fonts/Menlo.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "C:/Windows/Fonts/consola.ttf",
)
SKILL_SCRIPTS = "/home/bench/.claude/skills/reverse-engineering-kit/scripts/"

TITLE = "reverse-engineering-kit · benchmark 1, run blind · real transcript, shortened"
NOTE = "Full transcript: benchmarks/runs/20261106-232142-01-crackme-xor"

# What the run said and did, in order. "user" and "agent" quote messages, "skill" the skill it
# loaded, "run" a command with the skill's path shortened to scripts/, and "out" that command's
# output, one line each.
SCENES = (
    (
        "user",
        "Reverse engineer crackme in this folder. What I need: correct serial and an explanation.",
    ),
    (
        "user",
        "I wrote these files myself as test targets, so you are authorized to analyze them and to"
        " run them.",
    ),
    ("skill", "reverse-engineering-kit"),
    ("run", "python3 scripts/doctor.py --for native"),
    ("out", "ok      ghidra  12.2"),
    ("out", "ok      rizin   0.9.1"),
    ("out", "6 of 6 ready"),
    ("run", "python3 scripts/triage.py"),
    ("out", "crackme: ELF 64-bit little-endian shared object or PIE, arm64"),
    ("out", "    Correct serial. Well done."),
    ("out", "    Wrong serial."),
    ("out", "    check_serial"),
    ("out", "  read next: references/native.md"),
    ("run", "python3 scripts/run_ghidra.py"),
    ("out", "  10 functions, 8 imports, 90 strings"),
    ("out", "    main @ 00100870: 3 strings, imports: puts"),
    ("out", "    check_serial @ 001007e8: 0 strings, imports: strlen"),
    ("agent", "Per byte: rotl3(KEY[i%4] ^ c) == EXPECTED[i]. I need the KEY and EXPECTED bytes."),
    ("run", "xxd -s 0x938 -l 20 original/crackme"),
    ("out", "00000938: 4044 2945 bbdc c266 6b77 2a8e b087 d1fe  @D)E...fkw*....."),
    ("out", "00000948: 5ac3 179e                                Z..."),
    ("run", "python3 tests/check_serial.py"),
    ("out", "serial RK26-XOR7-ROL3-A"),
    ("out", "PASS derived"),
    ("out", "PASS wrong"),
    ("out", "PASS short"),
    ("run", "python3 scripts/ledger.py verify F-001 --kind algorithm --by tests/check_serial.py"),
    ("out", "F-001 confirmed by tests/check_serial.py: 3 cases passed"),
    ("run", "python3 scripts/make_report.py"),
    ("out", "wrote /home/bench/task/re-work/crackme/REPORT.md"),
    ("agent", "Serial: RK26-XOR7-ROL3-A"),
    (
        "agent",
        "The check is tests/check_serial.py, and the ledger finding F-001 is marked confirmed.",
    ),
)

COLUMNS, ROWS = 100, 24
FONT_SIZE, LINE_HEIGHT, PADDING, TITLE_HEIGHT = 15, 22, 20, 36
COLORS = {
    "background": (13, 17, 23),
    "title": (22, 27, 34),
    "text": (201, 209, 217),
    "dim": (139, 148, 158),
    "user": (88, 166, 255),
    "run": (126, 231, 135),
    "agent": (210, 168, 255),
    "skill": (210, 168, 255),
    "highlight": (227, 179, 65),
}
DOTS = ((255, 95, 86), (255, 189, 46), (39, 201, 63))
BLEND_STEPS = 8
PREFIXES = {"user": "you › ", "agent": "agent › ", "run": "$ ", "skill": "● skill ", "out": ""}
HIGHLIGHTS = (("RK26-XOR7-ROL3-A", "highlight"), ("PASS", "run"), ("confirmed", "run"))
TYPED = {"user": 4, "run": 3}
FRAME_MS, HOLD_MS, END_MS = 30, 1300, 6000


def transcript_text(run: Path) -> str:
    """Everything the run said, ran and printed, as one string with whitespace collapsed."""
    parts = [(run / "prompt.txt").read_text("utf-8")]
    for line in (run / "transcript.jsonl").read_text("utf-8").splitlines():
        event = json.loads(line)
        content = event.get("message", {}).get("content")
        for block in content if isinstance(content, list) else []:
            if block.get("type") == "text":
                parts.append(block["text"])
            elif block.get("type") == "tool_use":
                arguments = block.get("input", {})
                command = arguments.get("command")
                parts.append(command if command else json.dumps(arguments))
            elif block.get("type") == "tool_result":
                result = block.get("content")
                if isinstance(result, list):
                    result = " ".join(item.get("text", "") for item in result)
                parts.append(str(result))
    text = "\n".join(parts).replace("$S/", "scripts/").replace(SKILL_SCRIPTS, "scripts/")
    return normalize(re.sub(r"\x1b\[[0-9;]*m", "", text))


def normalize(text: str) -> str:
    return " ".join(text.replace("**", "").replace("`", "").split())


def screen_lines(kind: str, text: str) -> list[tuple[str, str]]:
    """Wrap one scene into (kind, text) screen lines; continuation lines are indented."""
    prefix = PREFIXES[kind]
    width = COLUMNS - len(prefix)
    pieces = textwrap.wrap(text, width) or [""]
    lines = [(kind, prefix + pieces[0])]
    lines += [(kind + "-more", " " * len(prefix) + piece) for piece in pieces[1:]]
    return lines


def frames():
    """Yield (lines on screen, cursor shown, milliseconds) for each frame."""
    screen: list[tuple[str, str]] = []
    for index, (kind, text) in enumerate(SCENES):
        if kind != "out" and screen:
            screen.append(("out", ""))
        if kind in TYPED:
            for end in range(0, len(text), TYPED[kind]):
                yield screen + screen_lines(kind, text[:end]), True, FRAME_MS
        screen += screen_lines(kind, text)
        following = SCENES[index + 1][0] if index + 1 < len(SCENES) else None
        if kind == "run":
            yield screen, False, 350
        elif following == "out":
            yield screen, False, 90
        else:
            yield screen, False, HOLD_MS
    screen += [("out", ""), ("note", NOTE)]
    yield screen, False, END_MS


def render(font_path: str, output: Path) -> int:
    from PIL import Image, ImageDraw, ImageFont

    font = ImageFont.truetype(font_path, FONT_SIZE)
    cell = font.getlength("M")
    width = int(cell * COLUMNS) + 2 * PADDING
    height = TITLE_HEIGHT + ROWS * LINE_HEIGHT + 2 * PADDING

    def draw_frame(lines, cursor):
        image = Image.new("RGB", (width, height), COLORS["background"])
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, width, TITLE_HEIGHT), fill=COLORS["title"])
        for number, color in enumerate(DOTS):
            x = PADDING + number * 20
            draw.ellipse((x, 12, x + 12, 24), fill=color)
        title_x = (width - font.getlength(TITLE)) / 2
        draw.text((title_x, 9), TITLE, font=font, fill=COLORS["dim"])
        visible = lines[-ROWS:]
        for row, (kind, text) in enumerate(visible):
            y = TITLE_HEIGHT + PADDING + row * LINE_HEIGHT
            for column, piece, color in colored(kind, text):
                draw.text((PADDING + column * cell, y), piece, font=font, fill=color)
            if cursor and row == len(visible) - 1:
                x = PADDING + len(text) * cell
                draw.rectangle((x, y + 2, x + cell - 1, y + LINE_HEIGHT - 4), fill=COLORS["text"])
        return image

    images, durations = [], []
    for lines, cursor, milliseconds in frames():
        images.append(draw_frame(lines, cursor))
        durations.append(milliseconds)
    palette = Image.new("P", (1, 1))
    palette.putpalette([channel for color in palette_colors() for channel in color])
    frames_p = [image.quantize(palette=palette, dither=Image.Dither.NONE) for image in images]
    output.parent.mkdir(parents=True, exist_ok=True)
    frames_p[0].save(
        output, save_all=True, append_images=frames_p[1:], duration=durations, loop=0, optimize=True
    )
    return len(images)


def palette_colors() -> list[tuple[int, int, int]]:
    """The demo's colors, and the blends anti-aliasing makes between them and the backgrounds.

    A fixed palette keeps every color exact. One picked from the frames drops colors that only a
    few pixels use, such as the user's prompt.
    """
    backgrounds = (COLORS["background"], COLORS["title"])
    colors = list(backgrounds)
    for foreground in [*COLORS.values(), *DOTS]:
        for background in backgrounds:
            for step in range(1, BLEND_STEPS + 1):
                share = step / BLEND_STEPS
                colors.append(
                    tuple(
                        round(back + (fore - back) * share)
                        for fore, back in zip(foreground, background, strict=True)
                    )
                )
    return list(dict.fromkeys(colors))[:256]


def colored(kind: str, text: str):
    """Split a screen line into (column, text, color) pieces."""
    base = kind.removesuffix("-more")
    prefix = PREFIXES.get(base, "") if not kind.endswith("-more") else ""
    pieces = []
    if prefix:
        pieces.append((0, prefix, COLORS.get(base, COLORS["text"])))
    body = text[len(prefix) :]
    body_color = COLORS["dim"] if base in ("out", "note") else COLORS["text"]
    marks = sorted(
        (match.start(), match.end(), color)
        for word, color in HIGHLIGHTS
        for match in re.finditer(re.escape(word), body)
    )
    position = 0
    for start, end, color in marks:
        if start < position:
            continue
        if start > position:
            pieces.append((len(prefix) + position, body[position:start], body_color))
        pieces.append((len(prefix) + start, body[start:end], COLORS[color]))
        position = end
    if position < len(body):
        pieces.append((len(prefix) + position, body[position:], body_color))
    return pieces


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--font", help="a monospace TrueType font")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    font = args.font or next((path for path in FONTS if Path(path).is_file()), None)
    if not font:
        print("demo_gif: no monospace font found; pass --font", file=sys.stderr)
        return 1
    try:
        count = render(font, args.output)
    except ImportError:
        print("demo_gif: needs Pillow: pip install pillow", file=sys.stderr)
        return 1
    print(f"{args.output}: {count} frames, {args.output.stat().st_size // 1024} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
