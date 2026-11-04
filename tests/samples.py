"""Build small but valid target files, so tests need no compiler and no binaries in the repo."""

import gzip
import io
import json
import struct
import tarfile
import zipfile

CODE = bytes(range(256)) * 2
EM_X86_64 = 62
EM_AARCH64 = 183
MZ_STUB = b"MZ" + b"\0" * 58 + struct.pack("<I", 64)


def _table(names):
    """A NUL-separated string table, and the offset of each name in it."""
    table = b"\0"
    offsets = {}
    for name in names:
        offsets[name] = len(table)
        table += name.encode() + b"\0"
    return table, offsets


def elf(
    machine=EM_X86_64,
    sections=((".text", CODE),),
    imports=("puts",),
    exports=("check_serial",),
    libraries=("libc.so.6",),
    symtab=False,
):
    """A 64-bit little-endian shared object with a real dynamic symbol table."""
    base = 0x400000
    dynstr, offsets = _table([*libraries, *imports, *exports])
    entries = [(tag, offsets[name]) for tag, name in ((1, n) for n in libraries)]
    headers = 64 + 56 * 2
    names = [name for name, _ in sections] + [".dynsym", ".dynstr", ".dynamic", ".shstrtab"]
    names += [".symtab"] if symtab else []
    shstrtab, shnames = _table(names)

    blobs = []
    cursor = headers
    placed = {}
    for name, data in sections:
        placed[name] = cursor
        blobs.append(data)
        cursor += len(data)
    first_section = placed[sections[0][0]]

    symbol_count = 1 + len(imports) + len(exports)
    placed[".dynsym"] = cursor
    cursor += 24 * symbol_count
    placed[".dynstr"] = cursor
    cursor += len(dynstr)
    placed[".dynamic"] = cursor
    entries += [
        (5, base + placed[".dynstr"]),
        (6, base + placed[".dynsym"]),
        (10, len(dynstr)),
        (11, 24),
        (0, 0),
    ]
    dynamic = b"".join(struct.pack("<QQ", tag, value) for tag, value in entries)
    cursor += len(dynamic)
    placed[".shstrtab"] = cursor
    cursor += len(shstrtab)
    table_at = cursor

    symbols = b"\0" * 24
    for name in imports:
        symbols += struct.pack("<IBBHQQ", offsets[name], 0x12, 0, 0, 0, 0)
    for name in exports:
        value = base + first_section
        symbols += struct.pack("<IBBHQQ", offsets[name], 0x12, 0, 1, value, 16)

    def section_header(name, kind, flags, offset, size, link=0, info=0, entry=0):
        address = base + offset if flags else 0
        return struct.pack(
            "<IIQQQQIIQQ", shnames[name], kind, flags, address, offset, size, link, info, 1, entry
        )

    count = len(sections)
    table = b"\0" * 64
    for name, data in sections:
        table += section_header(name, 1, 6, placed[name], len(data))
    table += section_header(".dynsym", 11, 2, placed[".dynsym"], len(symbols), count + 2, 1, 24)
    table += section_header(".dynstr", 3, 2, placed[".dynstr"], len(dynstr))
    table += section_header(".dynamic", 6, 3, placed[".dynamic"], len(dynamic), count + 2, 0, 16)
    table += section_header(".shstrtab", 3, 0, placed[".shstrtab"], len(shstrtab))
    if symtab:
        table += section_header(".symtab", 2, 0, placed[".dynsym"], len(symbols), count + 2, 1, 24)
    section_count = len(table) // 64

    header = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header += struct.pack(
        "<HHIQQQIHHHHHH",
        3,
        machine,
        1,
        base + first_section,
        64,
        table_at,
        0,
        64,
        56,
        2,
        64,
        section_count,
        count + 4,
    )
    size = table_at + len(table)
    load = struct.pack("<IIQQQQQQ", 1, 7, 0, base, base, size, size, 0x1000)
    dynamic_header = struct.pack(
        "<IIQQQQQQ",
        2,
        6,
        placed[".dynamic"],
        base + placed[".dynamic"],
        base + placed[".dynamic"],
        len(dynamic),
        len(dynamic),
        8,
    )
    body = b"".join(blobs) + symbols + dynstr + dynamic + shstrtab
    return header + load + dynamic_header + body + table


def elf_header(bits=64, big=False, kind=2, machine=EM_X86_64):
    """Only the identity bytes and the type fields, for the many ELF variants."""
    order = ">" if big else "<"
    ident = b"\x7fELF" + bytes([bits // 32, 2 if big else 1, 1]) + b"\0" * 9
    return ident + struct.pack(f"{order}HHI", kind, machine, 1) + b"\0" * 48


def pe(
    machine=0x8664,
    sections=((".text", CODE),),
    imports=(("KERNEL32.dll", ("Sleep",)),),
    exports=(),
    dll=False,
    clr=False,
):
    """A PE32+ file with a real import table and, if asked, a real export table."""
    file_align = 0x200
    section_align = 0x1000
    built = [(name, data) for name, data in sections]
    rva = section_align * (len(built) + 1)
    import_rva = rva
    import_data = _pe_imports(imports, import_rva)
    built.append((".idata", import_data))
    export_rva = rva + section_align
    export_data = _pe_exports(exports, export_rva) if exports else b""
    if export_data:
        built.append((".edata", export_data))

    headers = 64 + 4 + 20 + 240 + 40 * len(built)
    raw = (headers + file_align - 1) // file_align * file_align
    table = b""
    body = b""
    for index, (name, data) in enumerate(built):
        padded = data + b"\0" * (-len(data) % file_align)
        flags = 0x60000020 if index == 0 else 0xC0000040
        table += name.encode().ljust(8, b"\0")[:8]
        table += struct.pack(
            "<IIIIIIHHI",
            len(data),
            section_align * (index + 1),
            len(padded),
            raw + len(body),
            0,
            0,
            0,
            0,
            flags,
        )
        body += padded

    image_size = section_align * (len(built) + 1)
    directories = [(0, 0)] * 16
    directories[1] = (import_rva, len(import_data))
    if export_data:
        directories[0] = (export_rva, len(export_data))
    if clr:
        directories[14] = (0x1000, 72)
    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,
        14,
        0,
        len(body),
        0,
        0,
        section_align,
        section_align,
        0x140000000,
        section_align,
        file_align,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        image_size,
        raw,
        0,
        3,
        0x8160,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional += b"".join(struct.pack("<II", *pair) for pair in directories)
    flags = 0x2022 if dll else 0x0022
    coff = struct.pack("<HHIIIHH", machine, len(built), 0, 0, 0, len(optional), flags)
    return (MZ_STUB + b"PE\0\0" + coff + optional + table).ljust(raw, b"\0") + body


def _pe_imports(imports, rva):
    table_size = 20 * (len(imports) + 1)
    thunks = b""
    names = b""
    descriptors = b""
    thunk_rva = rva + table_size
    total_thunks = sum(len(functions) + 1 for _, functions in imports)
    name_rva = thunk_rva + total_thunks * 8
    for library, functions in imports:
        first = thunk_rva + len(thunks)
        for function in functions:
            thunks += struct.pack("<Q", name_rva + len(names))
            names += b"\0\0" + function.encode() + b"\0"
        thunks += b"\0" * 8
        library_rva = name_rva + len(names)
        names += library.encode() + b"\0"
        descriptors += struct.pack("<IIIII", first, 0, 0, library_rva, first)
    return descriptors + b"\0" * 20 + thunks + names


def _pe_exports(exports, rva):
    count = len(exports)
    addresses_at = rva + 40
    names_at = addresses_at + 4 * count
    ordinals_at = names_at + 4 * count
    strings_at = ordinals_at + 2 * count
    strings = b"sample.dll\0"
    pointers = b""
    for name in exports:
        pointers += struct.pack("<I", strings_at + len(strings))
        strings += name.encode() + b"\0"
    directory = struct.pack(
        "<IIHHIIIIIII",
        0,
        0,
        0,
        0,
        strings_at,
        1,
        count,
        count,
        addresses_at,
        names_at,
        ordinals_at,
    )
    addresses = struct.pack("<I", 0x1000) * count
    ordinals = b"".join(struct.pack("<H", index) for index in range(count))
    return directory + addresses + pointers + ordinals + strings


CPU_ARM64 = 0x0100000C
CPU_X86_64 = 0x01000007


def macho(cpu=CPU_ARM64, imports=("_puts",), exports=("_check_serial",), code=CODE):
    """A 64-bit Mach-O executable with a real symbol table."""
    strings, offsets = _table([*imports, *exports])
    segment_size = 72 + 80
    symtab_size = 24
    dysymtab_size = 80
    library = b"/usr/lib/libSystem.B.dylib\0"
    library += b"\0" * (-(24 + len(library)) % 8)
    dylib_size = 24 + len(library)
    commands = segment_size + symtab_size + dysymtab_size + dylib_size
    code_at = 32 + commands
    symbols_at = code_at + len(code)
    symbols = b""
    for name in exports:
        symbols += struct.pack("<IBBHQ", offsets[name], 0x0F, 1, 0, 0x100000000 + code_at)
    for name in imports:
        symbols += struct.pack("<IBBHQ", offsets[name], 0x01, 0, 0x100, 0)
    strings_at = symbols_at + len(symbols)
    address = 0x100000000
    size = strings_at + len(strings)
    segment = struct.pack(
        "<II16sQQQQIIII",
        0x19,
        segment_size,
        b"__TEXT",
        address,
        size,
        0,
        size,
        7,
        5,
        1,
        0,
    )
    segment += struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text",
        b"__TEXT",
        address + code_at,
        len(code),
        code_at,
        0,
        0,
        0,
        0x80000400,
        0,
        0,
        0,
    )
    count = len(symbols) // 16
    symtab = struct.pack("<IIIIII", 2, 24, symbols_at, count, strings_at, len(strings))
    dysymtab = struct.pack(
        "<20I",
        0xB,
        80,
        0,
        0,
        0,
        len(exports),
        len(exports),
        len(imports),
        *[0] * 12,
    )
    dylib = struct.pack("<IIIIII", 0xC, dylib_size, 24, 0, 0, 0) + library
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, cpu, 0, 2, 4, commands, 0x200000, 0)
    return header + segment + symtab + dysymtab + dylib + code + symbols + strings


def fat(*slices):
    """A universal binary holding (cpu, data) slices."""
    align = 0x1000
    header = struct.pack(">II", 0xCAFEBABE, len(slices))
    offset = align
    body = b""
    for cpu, data in slices:
        header += struct.pack(">IIIII", cpu, 0, offset, len(data), 12)
        padded = data + b"\0" * (-len(data) % align)
        body += padded
        offset += len(padded)
    return header.ljust(align, b"\0") + body


def java_class(major=61):
    return b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, major) + b"\0\x01" * 8


def dex():
    return b"dex\n039\0" + b"\0" * 104


def wasm():
    return b"\0asm\x01\0\0\0" + b"\x01\x04\x01\x60\0\0"


def pcap(big=False, nanoseconds=False, link=1):
    order = ">" if big else "<"
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    return struct.pack(f"{order}IHHiIII", magic, 2, 4, 0, 0, 65535, link)


def pcapng():
    block = struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1)
    return block + struct.pack("<I", 28)


def asar(files):
    """files maps a path to its contents, in the layout Electron's asar tool writes."""
    tree = {"files": {}}
    body = b""
    for path, data in files.items():
        folder = tree
        *parents, name = path.split("/")
        for parent in parents:
            folder = folder["files"].setdefault(parent, {"files": {}})
        folder["files"][name] = {"size": len(data), "offset": str(len(body))}
        body += data
    header = json.dumps(tree, separators=(",", ":")).encode()
    padded = header + b"\0" * (-len(header) % 4)
    pickle = struct.pack("<II", len(padded) + 4, len(header)) + padded
    return struct.pack("<II", 4, len(pickle)) + pickle + body


def zipped(*names):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, b"content")
    return buffer.getvalue()


def tar():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        entry = tarfile.TarInfo("a.txt")
        entry.size = 2
        archive.addfile(entry, io.BytesIO(b"hi"))
    return buffer.getvalue()


def gzipped():
    return gzip.compress(b"payload", mtime=0)


# The module runtime of a minified webpack 5 bundle: older releases used var, 5.112 uses const.
MINIFIED_WEBPACK = (
    '(()=>{"use strict";var e={},r={};function t(o){var n=r[o];if(void 0!==n)return n.exports;'
    "var i=r[o]={exports:{}};return e[o](i,i.exports,t),i.exports}"
    + ";console.log(t(1))" * 40
    + "})();"
)
MINIFIED_WEBPACK_5_112 = (
    '(()=>{"use strict";var t={10(t,e,o){o.d(e,{i:()=>r})}};const e={};'
    "function o(n){const r=e[n];if(void 0!==r)return r.exports;const s=e[n]={exports:{}};"
    "return t[n](s,s.exports,o),s.exports}" + ";var n=o(10)" * 40 + "})();"
)
OBFUSCATED_JS = (
    "var _0x1a2b=['log','hello'];"
    + "".join(
        f"function _0x{index:04x}(_0xabcd){{return _0x1a2b[_0xabcd];}}\n" for index in range(30)
    )
    + "while(!![]){switch(_0x1a2b[0]){case'0':break;}break;}"
)
SOURCE_MAP = json.dumps(
    {"version": 3, "sources": ["a.ts", "b.ts"], "names": [], "mappings": "AAAA"}
).encode()
HAR = json.dumps(
    {"log": {"version": "1.2", "entries": [{"request": {}}, {"request": {}}]}}
).encode()
