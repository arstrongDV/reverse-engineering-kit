"""Drive GhidraMCP and r2mcp over stdio, as an agent would, and check their answers on benchmark 1.

The expected values come from run_ghidra.py on the same build, so the servers must agree with the
kit's own scripts. Exits 1 on the first answer that does not match.
"""

import asyncio
import hashlib
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(sys.argv[1])
CRACKME = ROOT / "work" / "crackme"
GHIDRA = [
    "--headless",
    "--binary",
    str(CRACKME),
    "--ghidra-install-dir",
    "/opt/re-kit/ghidra",
    "--extension-jar",
    str(ROOT / "extension" / "GhidraMCP" / "lib" / "GhidraMCP.jar"),
    "--ready-timeout",
    "600",
]


class Mismatch(Exception):
    pass


def expect(condition, what):
    if not condition:
        raise Mismatch(what)
    print(f"  ok: {what}")


async def session_for(command, args, steps):
    params = StdioServerParameters(command=command, args=args)
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            await session.initialize()
            tools = {tool.name for tool in (await session.list_tools()).tools}

            async def call(tool, /, **arguments):
                result = await session.call_tool(tool, arguments)
                return "\n".join(getattr(part, "text", "") for part in result.content)

            await steps(tools, call)


async def ghidra(tools, call):
    expect({"decompile_function", "read_memory", "get_program_info"} <= tools, "tools are listed")
    info = json.loads(await call("get_program_info"))
    digest = hashlib.sha256(CRACKME.read_bytes()).hexdigest()
    expect(info["sha256"] == digest, "the loaded program is the file given with --binary")
    found = json.loads(await call("search_functions_by_name", query="check_serial"))
    expect(found["items"][0]["address"] == "001007e8", "check_serial is at 001007e8")
    code = json.loads(await call("decompile_function", name="check_serial"))["code"]
    expect("strlen(param_1)" in code and "&KEY" in code and "&EXPECTED" in code, "it decompiles")
    memory = json.loads(await call("read_memory", address="00100948", length=4))
    expect(memory["hex"] == "5a c3 17 9e", "KEY reads 5a c3 17 9e, as run_ghidra.py --bytes")


async def r2(tools, call):
    expect({"open_file", "analyze", "decompile_function"} <= tools, "tools are listed")
    expect("successfully" in await call("open_file", file_path=str(CRACKME)), "it opens the file")
    await call("analyze", level=2)
    expect("sym.check_serial" in await call("list_functions"), "it finds check_serial")
    code = await call("decompile_function", address="sym.check_serial")
    expect("obj.KEY" in code and "obj.EXPECTED" in code, "it decompiles")
    memory = await call("hexdump", address="obj.KEY", length=4)
    expect("5ac3 179e" in memory, "KEY reads 5a c3 17 9e")
    refused = await call("open_file", file_path="/etc/passwd")
    expect("Failed" in refused, "the sandbox refuses a file outside the work folder")


async def r2_readonly(tools, call):
    # mcp-setup.md says -R cannot open a file over stdio. If this starts to pass, update it.
    expect("open_file" not in tools, "read-only mode hides open_file")
    answer = await call("list_functions")
    expect("No file is currently open" in answer, "read-only mode has no file to work on")


async def main():
    suites = [
        ("GhidraMCP headless", str(ROOT / "ghidra-mcp" / "bin" / "ghidra-mcp"), GHIDRA, ghidra),
        ("r2mcp, sandboxed", "r2mcp", ["-s", str(CRACKME.parent)], r2),
        ("r2mcp, read-only", "r2mcp", ["-R", "-c", f"o {CRACKME}"], r2_readonly),
    ]
    for name, command, args, steps in suites:
        print(name)
        await asyncio.wait_for(session_for(command, args, steps), timeout=900)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Mismatch as error:
        print(f"  MISMATCH: {error}")
        sys.exit(1)
    print("MCP checks passed")
