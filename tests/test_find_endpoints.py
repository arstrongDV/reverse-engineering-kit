"""find_endpoints.py: what it finds, what it hides as library noise, and that it masks secrets."""

import json

from conftest import run_script

from find_endpoints import Findings, scan_line

# Built from pieces, so no complete credential-shaped string sits in this repository.
AWS_KEY = "AKIA" + "Q" * 16
GOOGLE_KEY = "AIza" + "x" * 35


def findings_of(line):
    findings = Findings()
    scan_line(findings, line, "a.js:1", False)
    return {kind: [item["value"] for item in items] for kind, items in findings.as_dict().items()}


def test_finds_urls_paths_and_calls():
    found = findings_of(
        'const r = await fetch(`https://api.demo.test/v3${p}`); go("/orders?limit=5")'
    )
    assert found["urls"] == ["https://api.demo.test/v3"]
    assert found["paths"] == ["/orders?limit=5"]
    assert found["calls"][0].startswith("fetch:")


def test_reads_retrofit_annotations():
    found = findings_of('@POST("v2/session") Call<Token> login(@Body Login body);')
    assert found["calls"][0].startswith("retrofit:")


def test_ip_addresses_only_in_quotes_so_versions_do_not_count():
    assert findings_of('connect("10.20.0.1:7500")')["ip_addresses"] == ["10.20.0.1"]
    assert "ip_addresses" not in findings_of("version = 1.2.3.4;")


def test_auth_headers():
    found = findings_of('conn.setRequestProperty("X-App-Key", key); h["Authorization"] = t')
    assert found["headers"] == ["X-App-Key", "Authorization"]


def test_secrets_are_masked():
    line = f'const config = {{ apiKey: "{GOOGLE_KEY}", aws: "{AWS_KEY}", password: "hunter22x" }};'
    secrets = findings_of(line)["secrets"]
    joined = " ".join(secrets)
    assert GOOGLE_KEY not in joined and AWS_KEY not in joined and "hunter22x" not in joined
    assert "aws-access-key: AKIA... (20 characters)" in secrets
    assert "password: hunt... (9 characters)" in secrets


def test_scans_a_whole_project_and_saves_the_result(work):
    sources = work / "decompiled" / "jadx" / "sources"
    (sources / "com" / "demo").mkdir(parents=True)
    (sources / "com" / "demo" / "Api.java").write_text(
        'String base = "https://api.demo.test/v1";\nString key = "' + AWS_KEY + '";\n', "utf-8"
    )
    (sources / "androidx" / "core").mkdir(parents=True)
    (sources / "androidx" / "core" / "Lib.java").write_text(
        'String u = "https://lib.test/x";', "utf-8"
    )
    (sources / "Schema.java").write_text(
        'String s = "http://schemas.android.com/apk/res/android";', "utf-8"
    )
    (work / "decompiled" / "blob.bin").write_bytes(b"\0https://hidden.test/in-binary")
    result = run_script("find_endpoints.py", "--work", str(work))
    assert result.returncode == 0
    assert AWS_KEY not in result.stdout
    assert "https://api.demo.test/v1" in result.stdout
    assert "https://lib.test/x" not in result.stdout
    assert "urls: 1 in the app, 2 in libraries or standard schemas" in result.stdout
    saved = json.loads((work / "decompiled" / "endpoints.json").read_text("utf-8"))
    urls = {item["value"]: item for item in saved["findings"]["urls"]}
    assert urls["https://lib.test/x"]["library"] is True
    assert urls["http://schemas.android.com/apk/res/android"]["noise"] is True
    assert "https://hidden.test/in-binary" not in urls
    assert AWS_KEY not in json.dumps(saved)


def test_a_second_run_does_not_count_its_own_output(work):
    (work / "decompiled").mkdir()
    (work / "decompiled" / "a.js").write_text('fetch("https://api.demo.test/x")', "utf-8")
    run_script("find_endpoints.py", "--work", str(work))
    run_script("find_endpoints.py", "--work", str(work))
    saved = json.loads((work / "decompiled" / "endpoints.json").read_text("utf-8"))
    assert saved["findings"]["urls"][0]["count"] == 1


def test_a_minified_line_is_scanned_to_its_end(work):
    (work / "decompiled").mkdir()
    line = "var a=1;" * 20_000 + 'fetch("https://end.demo.test/last")'
    (work / "decompiled" / "bundle.js").write_text(line, "utf-8")
    result = run_script("find_endpoints.py", "--work", str(work), "--json")
    urls = [item["value"] for item in json.loads(result.stdout)["findings"]["urls"]]
    assert urls == ["https://end.demo.test/last"]


def test_needs_something_to_scan(work):
    assert run_script("find_endpoints.py", "--work", str(work)).returncode == 1
