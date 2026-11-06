#!/usr/bin/env python3
"""Build the marketplace zip: one top-level folder named after the skill, text files only.

With --blind, build the copy that benchmark runs load instead: the worked examples describe the
benchmarks and quote their answers, so that copy leaves them out.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = REPO_ROOT / "skills" / "reverse-engineering-kit"
OUTPUT = REPO_ROOT / "dist" / "reverse-engineering-kit.zip"
BLIND_OUTPUT = REPO_ROOT / "dist" / "reverse-engineering-kit-blind.zip"
WORKED_EXAMPLE = "## Worked example"
EXAMPLES_DIR = "examples"

JUNK_NAMES = {".DS_Store", "Thumbs.db", ".gitkeep"}
JUNK_DIRS = {"__pycache__", ".pytest_cache", ".ruff_cache"}
# Fixed so the same tree always produces the same bytes, whatever the checkout's mtimes are.
ZIP_TIMESTAMP = (2026, 1, 1, 0, 0, 0)


class PackageError(Exception):
    pass


def iter_skill_files(skill_dir: Path):
    for path in sorted(skill_dir.rglob("*")):
        relative = path.relative_to(skill_dir)
        if path.is_symlink():
            raise PackageError(f"symlink not allowed in the package: {relative}")
        if path.is_dir() or path.name in JUNK_NAMES or JUNK_DIRS.intersection(relative.parts):
            continue
        yield path


def read_text_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PackageError(f"binary file not allowed in the package: {path.name}") from error
    if b"\0" in data:
        raise PackageError(f"binary file not allowed in the package: {path.name}")
    return data


def without_worked_examples(text: str) -> str:
    """Drop each worked example section, and each paragraph that links into examples/."""
    kept, skipping, fenced = [], False, False
    for line in text.splitlines(keepends=True):
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced and line.startswith("## "):
            skipping = line.rstrip() == WORKED_EXAMPLE
        if not skipping:
            kept.append(line)
    paragraphs = "".join(kept).split("\n\n")
    kept_paragraphs = [part for part in paragraphs if f"]({EXAMPLES_DIR}/" not in part]
    return "\n\n".join(kept_paragraphs).rstrip("\n") + "\n"


def build(skill_dir: Path, output: Path, blind: bool = False) -> None:
    """Write the zip. Exec bits come from shebangs, since Windows checkouts do not keep them."""
    if not (skill_dir / "SKILL.md").is_file():
        raise PackageError(f"no SKILL.md in {skill_dir}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in iter_skill_files(skill_dir):
            relative = path.relative_to(skill_dir)
            if blind and relative.parts[0] == EXAMPLES_DIR:
                continue
            data = read_text_bytes(path)
            if blind and path.suffix == ".md":
                data = without_worked_examples(data.decode("utf-8")).encode("utf-8")
            name = f"{skill_dir.name}/{relative.as_posix()}"
            info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if data.startswith(b"#!") else 0o644
            info.external_attr = (0o100000 | mode) << 16
            archive.writestr(info, data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--blind", action="store_true", help="build the copy for benchmark runs")
    args = parser.parse_args()
    output = BLIND_OUTPUT if args.blind else OUTPUT
    try:
        build(SKILL_DIR, output, blind=args.blind)
    except PackageError as error:
        print(f"build_zip: {error}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
