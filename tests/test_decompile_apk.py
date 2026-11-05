"""decompile_apk.py against fake jadx and apktool: the manifest summary, XAPK and failures."""

import io
import json
import zipfile
from xml.etree import ElementTree

import pytest
import samples
from conftest import path_with, python_tool, run_script

from decompile_apk import ANDROID_NS, describe_component

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo.app">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <application android:name=".DemoApp" android:debuggable="true" android:allowBackup="true"
      android:networkSecurityConfig="@xml/network_security_config">
    <activity android:name=".Main">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".Link">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="demo" android:host="open"/>
      </intent-filter>
    </activity>
    <activity android:name=".Hidden" android:exported="false"/>
    <service android:name="com.demo.app.Sync" android:exported="true"
        android:permission="com.demo.SYNC"/>
    <provider android:name=".Files" android:authorities="com.demo.files"/>
  </application>
</manifest>
"""
NETWORK_CONFIG = """<network-security-config>
  <base-config><trust-anchors><certificates src="user"/></trust-anchors></base-config>
  <domain-config cleartextTrafficPermitted="true"><domain>legacy.demo.test</domain></domain-config>
  <domain-config><domain>api.demo.test</domain>
    <pin-set expiration="2027-01-01">
      <pin digest="SHA-256">AAAA</pin><pin digest="SHA-256">BBBB</pin>
    </pin-set>
  </domain-config>
</network-security-config>
"""
FAKE_JADX = f"""
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
(Path(__file__).parent / "jadx_calls.jsonl").open("a").write(json.dumps(args) + "\\n")
out = Path(args[args.index("-d") + 1])
if os.environ.get("FAKE_JADX_EMPTY"):
    sys.exit(0)
(out / "sources/com/demo/app").mkdir(parents=True)
(out / "sources/com/demo/app/Main.java").write_text("class Main {{}}")
(out / "resources").mkdir()
(out / "resources/AndroidManifest.xml").write_text({MANIFEST!r})
print("INFO  - done")
"""
FAKE_APKTOOL = f"""
import sys
from pathlib import Path
args = sys.argv[1:]
out = Path(args[args.index("-o") + 1])
(out / "res/xml").mkdir(parents=True)
(out / "AndroidManifest.xml").write_text({MANIFEST!r})
(out / "res/xml/network_security_config.xml").write_text({NETWORK_CONFIG!r})
(out / "apktool.yml").write_text("sdkInfo:\\n  minSdkVersion: '21'\\n  targetSdkVersion: '28'\\n"
    "versionInfo:\\n  versionCode: '7'\\n  versionName: 2.4.1\\n")
"""


@pytest.fixture
def tools(tmp_path):
    folder = tmp_path / "bin"
    python_tool(folder, "jadx", FAKE_JADX)
    python_tool(folder, "apktool", FAKE_APKTOOL)
    return folder


@pytest.fixture
def apk(work):
    (work / "original" / "target.bin").unlink()
    names = (
        "AndroidManifest.xml",
        "classes.dex",
        "lib/arm64-v8a/libflutter.so",
        "lib/arm64-v8a/libapp.so",
    )
    (work / "original" / "demo.apk").write_bytes(samples.zipped(*names))
    return work


def decompile(work, environment, *args):
    result = run_script("decompile_apk.py", "--work", str(work), "--json", *args, env=environment)
    return result, json.loads(result.stdout)


def test_summarizes_what_the_manifest_exposes(apk, tools):
    result, summary = decompile(apk, path_with(tools))
    assert result.returncode == 0, result.stdout
    manifest = summary["manifest"]
    assert manifest["package"] == "com.demo.app"
    assert manifest["version"] == "2.4.1"
    assert manifest["sdk"] == {"min": 21, "target": 28}
    assert manifest["application"]["debuggable"] == "true"
    assert manifest["permissions"] == ["android.permission.CAMERA", "android.permission.INTERNET"]
    exported = {item["name"]: item for item in manifest["components"] if item["exported"]}
    assert set(exported) == {"com.demo.app.Main", "com.demo.app.Link", "com.demo.app.Sync"}
    assert exported["com.demo.app.Main"]["launcher"] is True
    assert exported["com.demo.app.Link"]["deep_links"] == ["demo://open"]
    assert exported["com.demo.app.Sync"]["permission"] == "com.demo.SYNC"


def test_reads_the_network_security_config(apk, tools):
    _, summary = decompile(apk, path_with(tools))
    config = summary["manifest"]["network_security_config"]
    assert config["cleartext"] == ["legacy.demo.test"]
    assert config["pins"] == [{"pins": 2, "expiration": "2027-01-01"}]
    assert config["user_certificates"] is True


def test_names_frameworks_and_native_libraries(apk, tools):
    _, summary = decompile(apk, path_with(tools))
    assert any(label.startswith("Flutter") for label in summary["frameworks"])
    assert summary["native_libraries"] == {"arm64-v8a": ["libflutter.so", "libapp.so"]}
    assert (apk / "decompiled" / "android.json").is_file()


def test_unpacks_an_xapk_and_gives_jadx_the_apks_inside(work, tools):
    (work / "original" / "target.bin").unlink()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("manifest.json", "{}")
        archive.writestr("base.apk", samples.zipped("AndroidManifest.xml"))
        archive.writestr("../../evil.apk", samples.zipped("AndroidManifest.xml"))
    (work / "original" / "app.xapk").write_bytes(buffer.getvalue())
    result, _ = decompile(work, path_with(tools))
    assert result.returncode == 0, result.stdout
    call = json.loads((tools / "jadx_calls.jsonl").read_text("utf-8").splitlines()[0])
    inputs = call[call.index("-d") + 2 :]
    assert [name.replace("\\", "/").rsplit("/", 1)[1] for name in inputs] == [
        "base.apk",
        "evil.apk",
    ]
    assert list(work.parent.parent.rglob("evil.apk")) == [work / "decompiled" / "xapk" / "evil.apk"]
    assert all(
        (work / "decompiled" / "xapk").as_posix() in name.replace("\\", "/") for name in inputs
    )


def test_without_jadx_it_exits_2(apk, tmp_path):
    result, summary = decompile(apk, path_with(tmp_path / "empty"))
    assert result.returncode == 2
    assert "jadx-1.5.6" in summary["message"]


def test_without_apktool_the_jadx_manifest_is_used(apk, tmp_path):
    folder = tmp_path / "only-jadx"
    python_tool(folder, "jadx", FAKE_JADX)
    result, summary = decompile(apk, path_with(folder))
    assert result.returncode == 2
    assert summary["status"] == "partial"
    assert summary["manifest"]["package"] == "com.demo.app"


def test_jadx_writing_no_code_is_an_error(apk, tools):
    result, _ = decompile(apk, path_with(tools) | {"FAKE_JADX_EMPTY": "1"})
    assert result.returncode == 1


def test_a_native_binary_is_unsupported(work, tools):
    path = work / "original" / "lib.so"
    path.write_bytes(samples.elf())
    result, _ = decompile(work, path_with(tools), str(path))
    assert result.returncode == 3


@pytest.mark.parametrize(
    "target_sdk,exported", [(30, True), (31, False)], ids=["before-31", "from-31"]
)
def test_an_intent_filter_exports_a_component_only_before_api_31(target_sdk, exported):
    element = ElementTree.fromstring(
        f'<activity xmlns:android="{ANDROID_NS[1:-1]}" android:name=".A">'
        '<intent-filter><action android:name="x"/></intent-filter></activity>'
    )
    assert describe_component(element, "activity", "p", target_sdk)["exported"] is exported
