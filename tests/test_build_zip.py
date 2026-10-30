"""Agensi's zip structure check: one named folder, text only, no symlinks, no junk."""

import os
import stat
import zipfile

import pytest
from conftest import SKILL_DIR

from build_zip import PackageError, build


@pytest.fixture
def archive(tmp_path):
    output = tmp_path / "skill.zip"
    build(SKILL_DIR, output)
    with zipfile.ZipFile(output) as opened:
        yield opened


def mode_of(archive, name):
    return archive.getinfo(name).external_attr >> 16


def test_zip_has_one_top_level_folder_named_after_the_skill(archive):
    assert {name.split("/")[0] for name in archive.namelist()} == {SKILL_DIR.name}


def test_skill_md_sits_at_the_root_of_that_folder(archive):
    assert f"{SKILL_DIR.name}/SKILL.md" in archive.namelist()


def test_zip_carries_the_license(archive):
    assert f"{SKILL_DIR.name}/LICENSE.txt" in archive.namelist()


def test_zip_leaves_out_junk(tmp_path):
    skill = tmp_path / "demo"
    (skill / "__pycache__").mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: demo\n---\n")
    (skill / ".DS_Store").write_text("junk")
    (skill / "__pycache__" / "x.txt").write_text("junk")
    output = tmp_path / "demo.zip"
    build(skill, output)
    with zipfile.ZipFile(output) as opened:
        assert opened.namelist() == ["demo/SKILL.md"]


def test_scripts_are_executable_and_documents_are_not(archive):
    scripts = f"{SKILL_DIR.name}/scripts"
    assert stat.S_IMODE(mode_of(archive, f"{scripts}/doctor.py")) == 0o755
    assert stat.S_IMODE(mode_of(archive, f"{scripts}/run_ghidra.sh")) == 0o755
    assert stat.S_IMODE(mode_of(archive, f"{SKILL_DIR.name}/SKILL.md")) == 0o644


def test_build_is_reproducible(tmp_path):
    first, second = tmp_path / "a.zip", tmp_path / "b.zip"
    build(SKILL_DIR, first)
    build(SKILL_DIR, second)
    assert first.read_bytes() == second.read_bytes()


def test_binary_files_are_rejected(tmp_path):
    skill = tmp_path / "demo"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: demo\n---\n")
    (skill / "target.bin").write_bytes(b"\x7fELF\x00\x01")
    with pytest.raises(PackageError, match="binary"):
        build(skill, tmp_path / "demo.zip")


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks needs privileges on Windows")
def test_symlinks_are_rejected(tmp_path):
    skill = tmp_path / "demo"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: demo\n---\n")
    (skill / "link.md").symlink_to(skill / "SKILL.md")
    with pytest.raises(PackageError, match="symlink"):
        build(skill, tmp_path / "demo.zip")
