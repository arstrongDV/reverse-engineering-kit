#!/usr/bin/env python3
"""Decompile an Android package with jadx and apktool into decompiled/, and summarize what its
manifest exposes: components, permissions, network security settings and frameworks."""

from __future__ import annotations

import json
import re
import shutil
import xml.etree.ElementTree as ElementTree
import zipfile
from pathlib import Path

from _common import (
    EXIT_MISSING_TOOL,
    EXIT_OK,
    EXIT_UNSUPPORTED,
    EXIT_USAGE,
    SAFE_NAME,
    KitError,
    add_work_flag,
    build_parser,
    emit,
    fail,
    require_tool,
    resolve_work_dir,
    run_tool,
    stage_input,
    tail,
    write_atomic,
)
from doctor import TOOLS, this_os
from triage import HEAD_SIZE, clean, identify

ANDROID = ("apk", "xapk", "aab", "aar", "dex")
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")
TIMEOUT = 1800
SHOWN = 15
# Since API 31 an exported flag is required; before it, an intent filter meant exported.
IMPLICIT_EXPORT_UNTIL = 31
PROVIDER_PRIVATE_FROM = 17
FRAMEWORKS = (
    (re.compile(r"lib/[^/]+/libflutter\.so$"), "Flutter: the Dart code is in lib/<abi>/libapp.so"),
    (
        re.compile(r"assets/index\.android\.bundle$"),
        "React Native: the app logic is in assets/index.android.bundle",
    ),
    (re.compile(r"lib/[^/]+/libmonodroid\.so$|^assemblies/"), ".NET (Xamarin or MAUI)"),
    (re.compile(r"lib/[^/]+/libil2cpp\.so$"), "Unity IL2CPP"),
    (
        re.compile(r"assets/(?:www|public)/index\.html$"),
        "web app (Cordova or Capacitor) in assets/",
    ),
)


def hint_for(name: str) -> str:
    return next(tool.hints[this_os()] for tool in TOOLS if tool.name == name)


def pick_target(work: Path, given: str | None) -> Path:
    candidates = [Path(given)] if given else sorted((work / "original").glob("*"))
    found = []
    for path in candidates:
        if not path.is_file():
            continue
        with path.open("rb") as file:
            kind = identify(path, file.read(HEAD_SIZE))["type"]
        if kind in ANDROID:
            found.append((path, kind))
        elif given:
            raise KitError(f"{path.name} is {kind}, not an Android package", EXIT_UNSUPPORTED)
    if given and not found:
        raise KitError(f"{given} is not a file")
    if len(found) != 1:
        names = ", ".join(path.name for path, _ in found) or "none"
        raise KitError(
            f"name the package to decompile (Android files in original/: {names})", EXIT_USAGE
        )
    return found[0]


def unpack_xapk(path: Path, work: Path) -> list[Path]:
    """jadx accepts an XAPK and then writes no code, so the APKs inside go to it one by one."""
    folder = work / "decompiled" / "xapk"
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    apks = []
    with zipfile.ZipFile(path) as archive:
        for index, entry in enumerate(archive.infolist()):
            if not entry.filename.endswith(".apk"):
                continue
            # Only the base name is kept, so an entry cannot write outside this folder.
            name = Path(entry.filename).name
            name = name if SAFE_NAME.fullmatch(name) else f"split_{index}.apk"
            with archive.open(entry) as source, (folder / name).open("wb") as target:
                shutil.copyfileobj(source, target)
            apks.append(folder / name)
    if not apks:
        raise KitError(f"{path.name} holds no APK files", EXIT_UNSUPPORTED)
    return apks


def run_jadx(inputs: list[Path], output: Path) -> list[str]:
    jadx = require_tool("jadx", hint_for("jadx"))
    shutil.rmtree(output, ignore_errors=True)
    command = [jadx, "--show-bad-code", "-d", str(output), *map(str, inputs)]
    done = run_tool(command, TIMEOUT)
    if not any((output / "sources").rglob("*.java")):
        raise KitError(f"jadx wrote no Java sources:\n{tail(done.stdout)}")
    errors = re.search(r"finished with errors, count: (\d+)", done.stdout)
    return (
        [f"jadx could not decompile {errors[1]} methods: see the comments in the code"]
        if errors
        else []
    )


def run_apktool(apk: Path, output: Path) -> list[str]:
    apktool = shutil.which("apktool")
    if not apktool:
        missing = "apktool is not installed, so there is no smali or decoded resources."
        return [f"{missing} {hint_for('apktool')}"]
    shutil.rmtree(output, ignore_errors=True)
    done = run_tool([apktool, "d", "-f", "-o", str(output), str(apk)], TIMEOUT)
    if not (output / "AndroidManifest.xml").is_file():
        return [f"apktool failed, so only jadx output exists:\n{tail(done.stdout, 8)}"]
    return []


def attribute(element, name: str) -> str | None:
    return element.get(ANDROID_NS + name)


def app_version(manifest_root, apktool_dir: Path) -> str:
    """apktool moves versionName out of the manifest and into apktool.yml."""
    settings = apktool_dir / "apktool.yml"
    if settings.is_file():
        text = settings.read_text("utf-8", errors="replace")
        match = re.search(r"versionName:\s*'?([^'\n]+)", text)
        if match:
            return match[1].strip()
    return manifest_root.get(ANDROID_NS + "versionName") or ""


def sdk_versions(manifest_root, apktool_dir: Path) -> dict:
    versions = {}
    uses_sdk = manifest_root.find("uses-sdk")
    if uses_sdk is not None:
        versions = {
            "min": attribute(uses_sdk, "minSdkVersion"),
            "target": attribute(uses_sdk, "targetSdkVersion"),
        }
    settings = apktool_dir / "apktool.yml"
    if settings.is_file():
        text = settings.read_text("utf-8", errors="replace")
        for key, field in (("min", "minSdkVersion"), ("target", "targetSdkVersion")):
            match = re.search(rf"{field}:\s*'?(\d+)", text)
            if match:
                versions[key] = match[1]
    return {key: int(value) for key, value in versions.items() if value and value.isdigit()}


def describe_component(element, tag: str, package: str, target_sdk: int) -> dict:
    name = attribute(element, "name") or attribute(element, "targetActivity") or "?"
    if name.startswith("."):
        name = package + name
    filters = element.findall("intent-filter")
    actions = [attribute(item, "name") for f in filters for item in f.findall("action")]
    categories = [attribute(item, "name") for f in filters for item in f.findall("category")]
    explicit = attribute(element, "exported")
    if explicit is not None:
        exported = explicit == "true"
    elif tag == "provider":
        exported = target_sdk < PROVIDER_PRIVATE_FROM
    else:
        exported = bool(filters) and target_sdk < IMPLICIT_EXPORT_UNTIL
    links = []
    for item in filters:
        if any(
            attribute(c, "name") == "android.intent.category.BROWSABLE"
            for c in item.findall("category")
        ):
            for data in item.findall("data"):
                scheme, host = attribute(data, "scheme"), attribute(data, "host")
                if scheme:
                    links.append(f"{scheme}://{host or '*'}{attribute(data, 'pathPrefix') or ''}")
    return {
        "type": tag,
        "name": clean(name),
        "exported": exported,
        "permission": attribute(element, "permission"),
        "launcher": "android.intent.action.MAIN" in actions
        and "android.intent.category.LAUNCHER" in categories,
        "actions": [clean(action) for action in actions if action][:10],
        "deep_links": [clean(link) for link in links][:10],
    }


def network_config(manifest_root, resources: Path | None) -> dict | None:
    application = manifest_root.find("application")
    reference = attribute(application, "networkSecurityConfig") if application is not None else None
    if not reference or not reference.startswith("@xml/") or resources is None:
        return {"file": reference} if reference else None
    path = resources / "xml" / f"{reference[5:]}.xml"
    if not path.is_file():
        return {"file": reference, "warning": "the file is not in the decoded resources"}
    root = ElementTree.parse(path).getroot()
    config = {"file": reference, "cleartext": [], "pins": [], "user_certificates": False}
    for element in root.iter():
        if element.get("cleartextTrafficPermitted") == "true":
            domains = [clean(d.text or "") for d in element.findall("domain")]
            config["cleartext"].append(", ".join(domains) or element.tag)
        if element.tag == "pin-set":
            config["pins"].append(
                {"pins": len(element.findall("pin")), "expiration": element.get("expiration")}
            )
        if element.tag == "certificates" and element.get("src") == "user":
            config["user_certificates"] = True
        if element.tag == "debug-overrides":
            config["debug_overrides"] = True
    return config


def frameworks(packages: list[Path]) -> tuple[list[str], dict]:
    found, libraries = [], {}
    for package in packages:
        try:
            with zipfile.ZipFile(package) as archive:
                names = archive.namelist()
        except (zipfile.BadZipFile, OSError):
            continue
        for pattern, label in FRAMEWORKS:
            if any(pattern.search(name) for name in names) and label not in found:
                found.append(label)
        for name in names:
            match = re.fullmatch(r"lib/([\w-]+)/([^/]+\.so)", name)
            if match:
                libraries.setdefault(match[1], []).append(clean(match[2]))
    return found, libraries


def summarize_manifest(manifest: Path, apktool_dir: Path, jadx_dir: Path) -> dict:
    root = ElementTree.parse(manifest).getroot()
    package = root.get("package", "")
    sdk = sdk_versions(root, apktool_dir)
    target_sdk = sdk.get("target", sdk.get("min", 1))
    application = root.find("application")
    application = application if application is not None else ElementTree.Element("application")
    components = [
        describe_component(element, tag, package, target_sdk)
        for tag in COMPONENTS
        for element in application.findall(tag)
    ]
    flags = {
        name: attribute(application, name)
        for name in ("debuggable", "allowBackup", "usesCleartextTraffic", "name")
        if attribute(application, name) is not None
    }
    resources = (
        apktool_dir / "res" if (apktool_dir / "res").is_dir() else jadx_dir / "resources" / "res"
    )
    return {
        "package": clean(package),
        "version": clean(app_version(root, apktool_dir)),
        "sdk": sdk,
        "application": {key: clean(value) for key, value in flags.items()},
        "permissions": sorted(
            clean(attribute(item, "name") or "") for item in root.findall("uses-permission")
        ),
        "components": components,
        "network_security_config": network_config(root, resources if resources.is_dir() else None),
    }


def find_manifest(apktool_dir: Path, jadx_dir: Path) -> Path | None:
    for path in (
        apktool_dir / "AndroidManifest.xml",
        jadx_dir / "resources" / "AndroidManifest.xml",
    ):
        if path.is_file():
            return path
    return None


def render(summary: dict) -> str:
    manifest = summary.get("manifest") or {}
    package = f"{manifest.get('package', 'no manifest')} {manifest.get('version', '')}"
    lines = [f"{summary['target']}: {package.rstrip()}"]
    if manifest:
        lines.append(f"  sdk: {manifest['sdk']}, application: {manifest['application']}")
        lines.append(f"  permissions: {', '.join(manifest['permissions'][:SHOWN]) or 'none'}")
        exported = [c for c in manifest["components"] if c["exported"]]
        lines.append(f"  components: {len(manifest['components'])}, exported: {len(exported)}")
        for item in exported[:SHOWN]:
            extra = " (launcher)" if item["launcher"] else ""
            guard = f", needs {item['permission']}" if item["permission"] else ""
            lines.append(f"    {item['type']} {item['name']}{extra}{guard}")
        links = [link for c in manifest["components"] for link in c["deep_links"]]
        if links:
            lines.append(f"  deep links: {', '.join(links[:SHOWN])}")
        if manifest["network_security_config"]:
            lines.append(f"  network security config: {manifest['network_security_config']}")
    for label in summary["frameworks"]:
        lines.append(f"  framework: {label}")
    if summary["native_libraries"]:
        lines.append(f"  native libraries: {summary['native_libraries']}")
    lines += [f"  warning: {text}" for text in summary["warnings"]]
    lines += [f"  {name}: {path}/" for name, path in summary["outputs"].items()]
    return "\n".join(lines)


def main() -> int:
    parser = build_parser(__doc__)
    add_work_flag(parser)
    parser.add_argument("target", nargs="?", help="the package (default: the one in original/)")
    args = parser.parse_args()
    try:
        work = resolve_work_dir(args.work)
        path, kind = pick_target(work, args.target)
        staged = stage_input(path, work)
        inputs = unpack_xapk(staged, work) if kind == "xapk" else [staged]
        decompiled = work / "decompiled"
        jadx_dir, apktool_dir = decompiled / "jadx", decompiled / "apktool"
        warnings = run_jadx(inputs, jadx_dir)
        apks = [item for item in inputs if item.suffix == ".apk" or kind == "apk"]
        if apks:
            warnings += run_apktool(apks[0], apktool_dir)
        else:
            warnings.append(f"apktool does not read {kind} files, so there is no smali")
        manifest = find_manifest(apktool_dir, jadx_dir)
        found, libraries = frameworks(inputs)
    except (KitError, OSError, ElementTree.ParseError, zipfile.BadZipFile) as error:
        return fail(error if isinstance(error, KitError) else KitError(str(error)), args.json)
    summary = {
        "status": "partial" if any("not installed" in text for text in warnings) else "ok",
        "target": clean(path.name),
        "type": kind,
        "manifest": summarize_manifest(manifest, apktool_dir, jadx_dir) if manifest else None,
        "frameworks": found,
        "native_libraries": libraries,
        "outputs": {
            name: folder.relative_to(work).as_posix()
            for name, folder in (("jadx", jadx_dir), ("apktool", apktool_dir))
            if folder.is_dir()
        },
        "warnings": warnings,
    }
    write_atomic(decompiled / "android.json", json.dumps(summary, indent=2) + "\n")
    emit(summary, render(summary), args.json)
    return EXIT_MISSING_TOOL if summary["status"] == "partial" else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
