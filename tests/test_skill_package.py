"""Marketplace rules: the Agent Skills spec plus Agensi's SKILL.md validity check."""

import json
import re

import jsonschema
import pytest
import yaml
from conftest import REPO_ROOT, SKILL_DIR

SKILL_MD = SKILL_DIR / "SKILL.md"
NAME_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def frontmatter() -> dict:
    match = re.match(r"^---\n(.*?)\n---\n", SKILL_MD.read_text(encoding="utf-8"), re.DOTALL)
    assert match, "SKILL.md must start with YAML frontmatter"
    return yaml.safe_load(match.group(1))


def test_name_follows_spec_and_matches_folder():
    name = frontmatter()["name"]
    assert len(name) <= 64
    assert NAME_PATTERN.match(name)
    assert name == SKILL_DIR.name


def test_description_fits_spec():
    assert 1 <= len(frontmatter()["description"]) <= 1024


def test_compatibility_fits_spec():
    assert 1 <= len(frontmatter()["compatibility"]) <= 500


def test_metadata_maps_strings_to_strings():
    metadata = frontmatter()["metadata"]
    assert all(isinstance(value, str) for value in metadata.values())


def test_skill_md_stays_under_500_lines():
    assert len(SKILL_MD.read_text(encoding="utf-8").splitlines()) < 500


def test_skill_md_only_points_at_files_that_exist():
    text = SKILL_MD.read_text(encoding="utf-8")
    paths = set(re.findall(r"\b(?:references|scripts|templates|examples)/[\w./-]+\.\w+", text))
    assert paths
    missing = [path for path in sorted(paths) if not (SKILL_DIR / path).is_file()]
    assert not missing


def test_bundled_license_matches_repo_license():
    bundled = (SKILL_DIR / "LICENSE.txt").read_text(encoding="utf-8")
    assert bundled == (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")


def finding(**overrides) -> dict:
    return {
        "id": "F-012",
        "claim": "Login sends credentials to /v1/auth",
        "location": "sources/com/app/Api.java:88",
        "evidence": "line reference and OkHttp post() call",
        "confidence": "inferred",
        "verified_by": None,
        "hypothesis": "H3",
        "ts": "2026-11-02T10:14:00Z",
    } | overrides


@pytest.fixture
def validator():
    schema = json.loads((SKILL_DIR / "templates" / "findings.schema.json").read_text("utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_schema_accepts_inferred_finding(validator):
    validator.validate(finding())


def test_schema_accepts_confirmed_finding_with_verification(validator):
    validator.validate(finding(confidence="confirmed", verified_by="tests/test_auth.py"))


@pytest.mark.parametrize("verified_by", [None, ""])
def test_schema_rejects_confirmed_finding_without_verification(validator, verified_by):
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(finding(confidence="confirmed", verified_by=verified_by))


def test_all_ten_benchmarks_declare_their_expected_result():
    entries = sorted((REPO_ROOT / "benchmarks").glob("*/expected.json"))
    assert len(entries) == 10
    for path in entries:
        entry = json.loads(path.read_text(encoding="utf-8"))
        assert {"id", "target", "deliverable", "status", "expected"} <= entry.keys()
