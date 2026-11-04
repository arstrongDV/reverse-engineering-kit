"""doctor.py: it finds tools, tells working from broken, and only ever prints advice."""

import json
import os
import platform
import stat

import pytest
from conftest import SCRIPTS_DIR, run_script

import doctor
from doctor import GHIDRA_PLATFORMS, TOOLS


def fake_tool(folder, name, output="1.2.3", code=0, stream=1):
    """A tool that prints a version. Windows gets a .bat, the same wrapper jadx really uses."""
    if os.name == "nt":
        target = " 1>&2" if stream == 2 else ""
        lines = f"@echo off\r\necho {output}{target}\r\nexit /b {code}\r\n"
        (folder / f"{name}.bat").write_text(lines, "utf-8")
        return
    path = folder / name
    target = " >&2" if stream == 2 else ""
    path.write_text(f"#!/bin/sh\necho '{output}'{target}\nexit {code}\n", "utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def tools(tmp_path):
    folder = tmp_path / "bin"
    folder.mkdir()
    return folder


@pytest.fixture
def environment(tools):
    keep = {k: v for k, v in os.environ.items() if k != "GHIDRA_INSTALL_DIR"}
    return keep | {"PATH": str(tools)}


def ask(environment, *args):
    result = run_script("doctor.py", "--json", *args, env=environment)
    return result, {item["name"]: item for item in json.loads(result.stdout)["tools"]}


def current_decompiler():
    return GHIDRA_PLATFORMS[(platform.system(), platform.machine())]


def fake_ghidra(root, decompilers=(), built=(), java_minimum="21", version="12.2"):
    (root / "Ghidra").mkdir(parents=True)
    properties = f"application.version={version}\napplication.java.min={java_minimum}\n"
    (root / "Ghidra" / "application.properties").write_text(properties, "utf-8")
    feature = root / "Ghidra" / "Features" / "Decompiler"
    for name, folder in [(n, feature / "os") for n in decompilers] + [
        (n, feature / "build" / "os") for n in built
    ]:
        (folder / name).mkdir(parents=True)
        path = folder / name / ("decompile.exe" if name.startswith("win") else "decompile")
        path.write_bytes(b"\0")
        path.chmod(0o755)
    return root


def test_every_tool_has_an_install_hint_for_every_os():
    for tool in TOOLS:
        assert tool.hints.keys() == {"macos", "linux", "windows"}, tool.name
        assert all(hint.strip() for hint in tool.hints.values())


def test_every_hint_names_a_version_or_a_pinned_release():
    for tool in TOOLS:
        for hint in tool.hints.values():
            assert any(character.isdigit() for character in hint), f"{tool.name}: {hint}"


def test_hints_are_never_piped_into_a_shell():
    for tool in TOOLS:
        assert not any("|" in hint for hint in tool.hints.values()), tool.name


def test_a_missing_tool_gets_a_hint_and_exit_2(environment):
    result, found = ask(environment, "--for", "android")
    assert result.returncode == 2
    assert found["jadx"]["status"] == "missing"
    assert "1.5.6" in found["jadx"]["hint"]


def test_a_working_tool_reports_its_version(tools, environment):
    fake_tool(tools, "jadx", "1.5.6")
    _, found = ask(environment, "--for", "android")
    assert found["jadx"]["status"] == "ok"
    assert found["jadx"]["version"] == "1.5.6"
    assert found["jadx"]["hint"] is None


def test_all_ready_exits_0(tools, environment):
    fake_tool(tools, "frida", "17.25.0")
    result, found = ask(environment, "--for", "dynamic")
    assert result.returncode == 0
    assert set(found) == {"python", "frida"}


def test_a_tool_that_fails_is_broken_not_ok(tools, environment):
    """macOS ships a java command that only prints an error until a JDK is installed."""
    fake_tool(tools, "java", "Unable to locate a Java Runtime.", code=1, stream=2)
    result, found = ask(environment, "--for", "android")
    assert result.returncode == 2
    assert found["java"]["status"] == "broken"
    assert found["java"]["hint"]


def test_a_tool_that_prints_a_version_and_then_fails_is_broken(tools, environment):
    fake_tool(tools, "jadx", "1.5.6", code=1)
    _, found = ask(environment, "--for", "android")
    assert found["jadx"]["status"] == "broken"
    assert "exit code 1" in found["jadx"]["problem"]


def test_reads_the_java_version_from_stderr(tools, environment):
    output = "Picked up JAVA_TOOL_OPTIONS: -Xmx2g"
    fake_tool(tools, "java", f'{output} openjdk version "25.0.4.1" 2026-08-18', stream=2)
    _, found = ask(environment, "--for", "android")
    assert found["java"]["version"] == "25.0.4.1"


@pytest.mark.parametrize(
    "version,major", [("25.0.4.1", 25), ("25", 25), ("21.0.2", 21), ("1.8.0_292", 8)]
)
def test_java_major_versions(version, major):
    assert doctor.java_major(version) == major


def test_goals_limit_what_is_checked(environment):
    _, found = ask(environment, "--for", "js")
    assert set(found) == {"python", "node", "webcrack", "asar"}


def test_goals_can_be_combined(environment):
    _, found = ask(environment, "--for", "js", "--for", "dynamic")
    assert "frida" in found
    assert "node" in found


def test_an_unknown_goal_is_a_usage_error(environment):
    assert run_script("doctor.py", "--for", "firmware", env=environment).returncode == 64


def test_text_output_shows_the_hint(environment):
    result = run_script("doctor.py", "--for", "android", env=environment)
    assert result.returncode == 2
    assert "missing jadx" in " ".join(result.stdout.split())
    assert "jadx-1.5.6.zip" in result.stdout


class TestGhidra:
    @pytest.fixture
    def installed(self, tmp_path, tools, environment):
        fake_tool(tools, "java", 'openjdk version "25.0.1" 2026-01-20', stream=2)

        def install(**kwargs):
            root = fake_ghidra(tmp_path / "ghidra", **kwargs)
            return environment | {"GHIDRA_INSTALL_DIR": str(root)}

        return install

    def test_a_release_decompiler_is_found(self, installed):
        _, found = ask(installed(decompilers=[current_decompiler()]), "--for", "native")
        assert found["ghidra"]["status"] == "ok"
        assert found["ghidra"]["version"] == "12.2"

    def test_a_built_decompiler_is_found(self, installed):
        _, found = ask(installed(built=[current_decompiler()]), "--for", "native")
        assert found["ghidra"]["status"] == "ok"

    def test_it_is_broken_without_a_decompiler_for_this_machine(self, installed):
        """The trap: Ghidra starts and reports 12.2 here, but it can never decompile."""
        others = {"linux_x86_64", "win_x86_64", "linux_arm_64"} - {current_decompiler()}
        result, found = ask(installed(decompilers=sorted(others)), "--for", "native")
        assert result.returncode == 2
        assert found["ghidra"]["status"] == "broken"
        assert found["ghidra"]["version"] == "12.2"
        assert "cannot decompile" in found["ghidra"]["problem"]
        assert "buildNatives" in found["ghidra"]["hint"]

    def test_the_hint_names_the_install_it_found(self, installed, tmp_path):
        _, found = ask(installed(), "--for", "native")
        assert str(tmp_path / "ghidra") in found["ghidra"]["hint"]

    def test_an_old_jdk_makes_it_broken(self, installed):
        environment = installed(decompilers=[current_decompiler()], java_minimum="99")
        _, found = ask(environment, "--for", "native")
        assert found["ghidra"]["status"] == "broken"
        assert "JDK 99" in found["ghidra"]["problem"]

    def test_no_jdk_at_all_makes_it_broken(self, tools, installed):
        environment = installed(decompilers=[current_decompiler()])
        for path in tools.iterdir():
            path.unlink()
        _, found = ask(environment, "--for", "native")
        assert found["ghidra"]["status"] == "broken"
        assert "found none" in found["ghidra"]["problem"]

    def test_a_folder_without_ghidra_in_it_is_missing(self, tmp_path, environment):
        environment = environment | {"GHIDRA_INSTALL_DIR": str(tmp_path)}
        _, found = ask(environment, "--for", "native")
        assert found["ghidra"]["status"] == "missing"

    @pytest.mark.skipif(
        os.name == "nt", reason="needs a privilege Windows does not grant by default"
    )
    def test_it_is_found_through_a_link_on_path(self, tmp_path, tools, environment):
        root = fake_ghidra(tmp_path / "ghidra", decompilers=[current_decompiler()])
        (root / "support").mkdir()
        launcher = root / "support" / "analyzeHeadless"
        launcher.write_text("#!/bin/sh\n", "utf-8")
        launcher.chmod(0o755)
        (tools / "analyzeHeadless").symlink_to(launcher)
        fake_tool(tools, "java", 'openjdk version "25" 2026-01-20', stream=2)
        _, found = ask(environment, "--for", "native")
        assert found["ghidra"]["status"] == "ok"

    def test_an_unknown_machine_is_reported(self, tmp_path, monkeypatch):
        root = fake_ghidra(tmp_path / "ghidra")
        monkeypatch.setattr(doctor.platform, "machine", lambda: "sparc")
        problem, _ = doctor.check_decompiler(root, "25")
        assert "no known Ghidra decompiler" in problem

    @pytest.mark.parametrize(
        "machine,folder",
        [
            (("Darwin", "arm64"), "mac_arm_64"),
            (("Linux", "aarch64"), "linux_arm_64"),
        ],
    )
    def test_arm_machines_need_a_build_even_with_a_full_release(
        self, tmp_path, monkeypatch, machine, folder
    ):
        root = fake_ghidra(tmp_path / "ghidra", decompilers=["linux_x86_64", "win_x86_64"])
        monkeypatch.setattr(doctor.platform, "system", lambda: machine[0])
        monkeypatch.setattr(doctor.platform, "machine", lambda: machine[1])
        problem, hint = doctor.check_decompiler(root, "25")
        assert folder in problem
        assert "buildNatives" in hint


def test_lief_is_reported(environment):
    _, found = ask(environment, "--for", "native")
    assert found["lief"]["status"] == "ok"


def test_doctor_installs_nothing():
    source = (SCRIPTS_DIR / "doctor.py").read_text("utf-8")
    assert "check_call" not in source
    assert source.count("subprocess.run(") == 1
