"""_common.py: how kit scripts start analysis tools, and what they refuse to pass to one."""

import os
import sys
import time

import pytest

from _common import KitError, run_tool, safe_file_name, stage_input


@pytest.mark.parametrize("argument", ["a&calc", "x|y", "100%", 'q"uote', "a^b", "<in", "out>"])
def test_shell_syntax_never_reaches_a_batch_file(argument):
    with pytest.raises(KitError) as error:
        run_tool(["C:/tools/jadx.bat", "-d", argument], timeout=5)
    assert error.value.exit_code == 3


def test_plain_paths_pass_to_a_batch_file_check():
    command = [sys.executable, "-c", "print('ran')"]
    assert run_tool(command, timeout=30).stdout.strip() == "ran"


def test_a_plain_name_is_used_as_it_is(tmp_path):
    target = tmp_path / "app-1.2.apk"
    target.write_bytes(b"x")
    assert stage_input(target, tmp_path) == target


@pytest.mark.parametrize("name", ["a&b.apk", "x y.apk", "$(id).apk", "-rf.apk", "ünï.apk"])
def test_a_name_with_shell_syntax_is_copied_to_a_plain_one(tmp_path, name):
    target = tmp_path / name
    target.write_bytes(b"payload")
    staged = stage_input(target, tmp_path)
    assert staged.name == "target.apk"
    assert staged.read_bytes() == b"payload"
    assert staged.parent == tmp_path / "decompiled" / "input"


@pytest.mark.parametrize("name", ["../../etc/passwd", "a/b\\c", "..", "", "x" * 300])
def test_safe_file_names_stay_in_one_folder(name):
    cleaned = safe_file_name(name)
    assert "/" not in cleaned and "\\" not in cleaned
    assert cleaned not in ("", ".", "..")
    assert len(cleaned) <= 80


def test_a_tool_that_overruns_is_stopped():
    started = time.monotonic()
    with pytest.raises(KitError, match="did not finish"):
        run_tool([sys.executable, "-c", "import time; time.sleep(60)"], timeout=1)
    assert time.monotonic() - started < 30


@pytest.mark.skipif(os.name == "nt", reason="checks a POSIX process group")
def test_an_overrun_also_stops_the_tools_own_children(tmp_path):
    """Ghidra and jadx run a JVM as a child, which must not outlive the timeout."""
    pid_file = tmp_path / "child.pid"
    code = (
        "import subprocess, sys, time; "
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
        f"open({str(pid_file)!r}, 'w').write(str(child.pid)); time.sleep(60)"
    )
    started = time.monotonic()
    with pytest.raises(KitError):
        run_tool([sys.executable, "-c", code], timeout=2)
    # A surviving child keeps the output pipe open, so the call would wait for it to exit.
    assert time.monotonic() - started < 20
    child = int(pid_file.read_text())
    time.sleep(0.5)
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)


def test_a_missing_tool_is_exit_2():
    with pytest.raises(KitError) as error:
        run_tool(["/no/such/tool"], timeout=5)
    assert error.value.exit_code == 2


def test_output_is_text_even_when_a_tool_prints_bad_bytes():
    command = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'ok\\xff\\xfe')"]
    assert run_tool(command, timeout=30).stdout.startswith("ok")


def test_stdin_is_closed_so_a_prompting_tool_cannot_hang():
    command = [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"]
    done = run_tool(command, timeout=30)
    assert done.stdout.strip() == "''"
