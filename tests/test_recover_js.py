"""recover_js.py: safe asar extraction, source maps, webcrack and the Electron IPC map."""

import base64
import json
import struct

import pytest
import samples
from conftest import path_with, python_tool, run_script

from recover_js import extract_asar

FAKE_WEBCRACK = """
import sys
from pathlib import Path
out = Path(sys.argv[sys.argv.index("-o") + 1])
out.mkdir(parents=True)
(out / "deobfuscated.js").write_text("// readable\\n" + Path(sys.argv[1]).read_text())
"""
MAIN = """
const { app, BrowserWindow, ipcMain } = require("electron");
const win = new BrowserWindow({ webPreferences: { preload: path.join(__dirname, "preload.js"),
  nodeIntegration: true, contextIsolation: false } });
ipcMain.handle("files:read", (event, name) => read(name));
ipcMain.on("window:close", () => win.close());
"""
PRELOAD = """
contextBridge.exposeInMainWorld("api", { read: (n) => ipcRenderer.invoke("files:read", n),
  shell: (c) => ipcRenderer.send("shell:run", c) });
"""


def raw_asar(entries, body):
    """An asar with a hand-written file table, for entries the real tool would never write."""
    header = json.dumps({"files": entries}).encode()
    padded = header + b"\0" * (-len(header) % 4)
    pickle = struct.pack("<II", len(padded) + 4, len(header)) + padded
    return struct.pack("<II", 4, len(pickle)) + pickle + body


def test_extracts_an_asar_archive(tmp_path):
    archive = tmp_path / "app.asar"
    archive.write_bytes(samples.asar({"package.json": b"{}", "src/main.js": b"main();"}))
    written, skipped = extract_asar(archive, tmp_path / "out")
    assert written == 2 and skipped == []
    assert (tmp_path / "out" / "src" / "main.js").read_bytes() == b"main();"


@pytest.mark.parametrize("name", ["..", "../evil.js", "/etc/x", "a\\..\\b", "c:evil", ""])
def test_an_entry_cannot_leave_the_folder(tmp_path, name):
    archive = tmp_path / "app.asar"
    archive.write_bytes(
        raw_asar({name: {"size": 4, "offset": "0"}, "ok.js": {"size": 4, "offset": "0"}}, b"evil")
    )
    written, skipped = extract_asar(archive, tmp_path / "out" / "inner")
    assert written == 1
    assert len(skipped) == 1
    assert sorted(path.name for path in (tmp_path / "out").rglob("*") if path.is_file()) == [
        "ok.js"
    ]


def test_the_folder_check_holds_even_if_the_name_filter_fails(tmp_path, monkeypatch):
    """Two layers: names are filtered, and every destination is checked against the folder."""
    import recover_js

    monkeypatch.setattr(recover_js, "safe_parts", lambda name: name.split("/"))
    archive = tmp_path / "app.asar"
    archive.write_bytes(raw_asar({"../escape.js": {"size": 4, "offset": "0"}}, b"evil"))
    written, skipped = extract_asar(archive, tmp_path / "out")
    assert written == 0
    assert "outside the folder" in skipped[0]
    assert not (tmp_path / "escape.js").exists()


def test_links_are_not_followed(tmp_path):
    archive = tmp_path / "app.asar"
    archive.write_bytes(raw_asar({"link.js": {"link": "../../../etc/passwd"}}, b""))
    written, skipped = extract_asar(archive, tmp_path / "out")
    assert written == 0 and "link not followed" in skipped[0]


def test_an_entry_beyond_the_file_is_skipped(tmp_path):
    archive = tmp_path / "app.asar"
    archive.write_bytes(raw_asar({"big.js": {"size": 10**9, "offset": "0"}}, b"tiny"))
    assert extract_asar(archive, tmp_path / "out")[0] == 0


def test_unpacked_files_come_from_the_folder_beside_the_archive(tmp_path):
    archive = tmp_path / "app.asar"
    archive.write_bytes(raw_asar({"addon.node": {"size": 3, "unpacked": True}}, b""))
    (tmp_path / "app.asar.unpacked").mkdir()
    (tmp_path / "app.asar.unpacked" / "addon.node").write_bytes(b"bin")
    extract_asar(archive, tmp_path / "out")
    assert (tmp_path / "out" / "addon.node").read_bytes() == b"bin"


@pytest.fixture
def electron(work):
    (work / "original" / "target.bin").unlink()
    files = {"package.json": b'{"name": "demo", "main": "main.js"}', "main.js": MAIN.encode()}
    files["preload.js"] = PRELOAD.encode()
    (work / "original" / "app.asar").write_bytes(samples.asar(files))
    return work


def recover(work, environment=None, *args):
    result = run_script("recover_js.py", "--work", str(work), "--json", *args, env=environment)
    return result, json.loads(result.stdout)


def test_maps_an_electron_app(electron, tmp_path):
    result, summary = recover(electron, path_with(tmp_path / "empty"))
    assert result.returncode == 0, result.stdout
    app = summary["electron"]
    assert app["name"] == "demo"
    assert app["preloads"] == ["preload.js"]
    assert app["bridges"] == ["api"]
    assert set(app["ipc_main"]) == {"files:read", "window:close"}
    assert app["unhandled_channels"] == ["shell:run"]
    assert any("nodeIntegration" in item for item in app["risky"])
    assert any("contextIsolation" in item for item in app["risky"])


def write_bundle(work, text, name="main.js"):
    (work / "original" / "target.bin").unlink(missing_ok=True)
    path = work / "original" / name
    path.write_text(text, "utf-8")
    return path


SOURCE_MAP = {
    "version": 3,
    "sources": ["webpack:///./src/api.js", "webpack:///../../../etc/evil.js", "no-content.js"],
    "sourcesContent": ["export const api = 1;", "stolen", None],
    "mappings": "AAAA",
}


def test_writes_sources_from_a_map_beside_the_bundle(work, tmp_path):
    write_bundle(work, "var a=1;\n//# sourceMappingURL=main.js.map\n")
    (work / "original" / "main.js.map").write_text(json.dumps(SOURCE_MAP), "utf-8")
    result, summary = recover(
        work, path_with(tmp_path / "empty"), str(work / "original" / "main.js")
    )
    assert result.returncode == 0, result.stdout
    assert summary["source_maps"][0]["sources"] == 2
    files = (path for path in (work / "decompiled").rglob("*.js") if path.is_file())
    written = sorted(path.relative_to(work).as_posix() for path in files)
    assert written == [
        "decompiled/js/sources/main.js/etc/evil.js",
        "decompiled/js/sources/main.js/src/api.js",
    ]


def test_reads_an_inline_source_map(work, tmp_path):
    inline = base64.b64encode(json.dumps(SOURCE_MAP).encode()).decode()
    write_bundle(work, f"var a=1;\n//# sourceMappingURL=data:application/json;base64,{inline}\n")
    _, summary = recover(work, path_with(tmp_path / "empty"))
    assert summary["source_maps"][0]["map"] == "inline"


def test_never_fetches_a_remote_source_map(work, tmp_path):
    write_bundle(work, "var a=1;\n//# sourceMappingURL=https://cdn.demo.test/main.js.map\n")
    _, summary = recover(work, path_with(tmp_path / "empty"))
    assert summary["source_maps"][0]["map"].startswith("remote, not fetched")


def test_a_minified_bundle_goes_through_webcrack(work, tmp_path):
    python_tool(tmp_path / "bin", "webcrack", FAKE_WEBCRACK)
    write_bundle(work, "var a=" + "1+" * 400 + "1;")
    result, summary = recover(work, path_with(tmp_path / "bin"))
    assert result.returncode == 0, result.stdout
    output = work / summary["webcrack"][0]["output"]
    assert output.read_text("utf-8").startswith("// readable")


def test_without_webcrack_the_result_is_partial(work, tmp_path):
    write_bundle(work, "var a=" + "1+" * 400 + "1;")
    result, summary = recover(work, path_with(tmp_path / "empty"))
    assert result.returncode == 2
    assert "webcrack@2.16.0" in summary["warnings"][0]


def test_a_native_binary_is_unsupported(work, tmp_path):
    (work / "original" / "target.bin").write_bytes(samples.elf())
    result, _ = recover(work, path_with(tmp_path / "empty"), str(work / "original" / "target.bin"))
    assert result.returncode == 3
