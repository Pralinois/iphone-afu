"""Fixtures binaires synthétiques pour les tests v2 (Mach-O, ObjC, cookies, IPA)."""

import plistlib
import struct
import zipfile
from pathlib import Path

MH_PIE = 0x200000
ARM64 = 0x0100000C
ARM64E = 0x0100000C


def seg64(segname: str, vmaddr: int, vmsize: int, fileoff: int, filesize: int,
          sections: list) -> bytes:
    """LC_SEGMENT_64 avec sections [(sectname, segname, addr, size, offset)]."""
    sec_size = 80
    cmdsize = 72 + len(sections) * sec_size
    body = struct.pack("<II16sQQQQIIII", 0x19, cmdsize, segname.encode().ljust(16, b"\0"),
                       vmaddr, vmsize, fileoff, filesize, 7, 7, len(sections), 0)
    for (sect, seg, addr, size, offset) in sections:
        body += struct.pack("<16s16sQQIIIIIIII", sect.encode().ljust(16, b"\0"),
                            seg.encode().ljust(16, b"\0"), addr, size, offset,
                            4, 0, 0, 0, 0, 0, 0)
    return body


def lc_rpath(path: str) -> bytes:
    raw = path.encode() + b"\0"
    raw += b"\0" * ((8 - len(raw) % 8) % 8)
    return struct.pack("<II", 0x1C | 0x80000000, 8 + len(raw)) + raw


def lc_encryption64(cryptid: int) -> bytes:
    # LC_ENCRYPTION_INFO_64 = 24 octets : cmd, cmdsize, cryptoff, cryptsize, cryptid, pad
    return struct.pack("<IIIIII", 0x2C, 24, 0, 4096, cryptid, 0)


def lc_code_signature(dataoff: int, datasize: int) -> bytes:
    return struct.pack("<IIII", 0x1D, 16, dataoff, datasize)


def lc_symtab(symoff: int, nsyms: int, stroff: int, strsize: int) -> bytes:
    return struct.pack("<IIIIII", 0x2, 24, symoff, nsyms, stroff, strsize)


def cs_blob(entitlements: dict) -> bytes:
    """SuperBlob LC_CODE_SIGNATURE contenant un blob entitlements XML (type 5)."""
    xml = plistlib.dumps(entitlements)
    inner = struct.pack(">II", 0xFADE7171, 8 + len(xml)) + xml
    idx = struct.pack(">II", 5, 20)
    return struct.pack(">III", 0xFADE0CC0, 12 + 8 + len(inner), 1) + idx + inner


def mach_header(ncmds: int, sizeofcmds: int, flags: int = MH_PIE,
                cputype: int = ARM64, cpusubtype: int = 0) -> bytes:
    return struct.pack("<IIIIIIII", 0xFEEDFACF, cputype, cpusubtype, 2,
                       ncmds, sizeofcmds, flags, 0)


def make_macho(*, pie=True, cryptid=None, entitlements=None, rpath=True,
               restrict=True, canary=True, arc=True, anti_debug=True) -> bytes:
    """Mach-O 64 synthétique avec protections configurables (thème + données)."""
    cmds = b""
    ncmds = 0
    cmds += seg64("__TEXT", 0x100000000, 0x1000, 0, 0x1000,
                  [("__text", "__TEXT", 0x100000300, 0x200, 0x300)])
    ncmds += 1
    if restrict:
        cmds += seg64("__RESTRICT", 0x100002000, 0x1000, 0x2000, 0x10,
                      [("__restrict", "__RESTRICT", 0x100002000, 0x10, 0x2000)])
        ncmds += 1
    cmds += seg64("__DATA", 0x100001000, 0x1000, 0x1000, 0x1000,
                  [("__data", "__DATA", 0x100001000, 0x400, 0x1000)])
    ncmds += 1
    if rpath:
        cmds += lc_rpath("@executable_path/Frameworks")
        ncmds += 1
    if cryptid is not None:
        cmds += lc_encryption64(cryptid)
        ncmds += 1

    strings = b""
    if canary:
        strings += b"___stack_chk_guard\x00"
    if arc:
        strings += b"objc_release\x00objc_retain\x00"
    if anti_debug:
        strings += b"ptrace\x00sysctl\x00task_get_exception_ports\x00"

    if entitlements is not None:
        blob = cs_blob(entitlements)
        cs_off = 0x1800
        cmds += lc_code_signature(cs_off, len(blob))
        ncmds += 1
        file_size = 0x2000 + len(blob)
    else:
        blob = b""
        file_size = max(0x2000, 0x300 + len(strings))

    hdr = mach_header(ncmds, len(cmds), MH_PIE if pie else 0)
    buf = bytearray(max(file_size, len(hdr) + len(cmds) + len(strings) + 16))
    buf[0:len(hdr + cmds)] = hdr + cmds
    buf[0x300:0x300 + len(strings)] = strings
    if blob:
        buf[0x1800:0x1800 + len(blob)] = blob
    return bytes(buf)


def make_objc_macho(*, with_symtab=False, cryptid=None) -> bytes:
    """Mach-O avec __objc_classlist : MyBase (+proto, ivar, 2 méthodes abs) / MyChild (méthode relative)."""
    TEXT, DATA = 0x100000000, 0x100001000
    cmds = seg64("__TEXT", TEXT, 0x1000, 0, 0x1000,
                 [("__text", "__TEXT", TEXT + 0x300, 0x200, 0x300)])
    cmds += seg64("__DATA", DATA, 0x1000, 0x1000, 0x1000, [
        ("__objc_classlist", "__DATA", DATA, 0x10, 0x1000),
        ("__objc_data", "__DATA", DATA + 0x20, 0x2E0, 0x1020),
    ])
    ncmds = 2
    if cryptid is not None:
        cmds += lc_encryption64(cryptid)
        ncmds += 1

    symtab_cmds = b""
    if with_symtab:
        symtab_cmds = lc_symtab(0x1F00, 2, 0x1F40, 0x40)
        cmds += symtab_cmds
        ncmds += 1

    hdr = mach_header(ncmds, len(cmds))
    buf = bytearray(0x2000)

    def put(off: int, raw: bytes):
        buf[off:off + len(raw)] = raw

    put(0, hdr + cmds)

    def put_s(addr: int, s: str):
        put(addr - TEXT, s.encode() + b"\0")

    for i, s in enumerate(["MyBase", "MyChild", "doThing:", "sharedInstance",
                           "NSCopying", "childMethod", "instanceVar1"]):
        put_s(TEXT + 0x400 + i * 0x10, s)

    def put_ptrs(addr: int, ptrs: list):
        off = 0x1000 + (addr - DATA)
        for i, p in enumerate(ptrs):
            put(off + i * 8, struct.pack("<Q", p))

    put_ptrs(DATA + 0x00, [DATA + 0x40, DATA + 0x80])
    put_ptrs(DATA + 0x40, [0, 0, 0, 0, DATA + 0x100])
    put_ptrs(DATA + 0x80, [0, DATA + 0x40, 0, 0, DATA + 0x140])
    put_ptrs(DATA + 0x110, [TEXT + 0x400, DATA + 0x200, DATA + 0x260, DATA + 0x2C0])
    put_ptrs(DATA + 0x150, [TEXT + 0x410, DATA + 0x280, 0, 0])
    put(0x1000 + 0x200, struct.pack("<II", 24, 2))
    put_ptrs(DATA + 0x208, [TEXT + 0x420, 0, 0, TEXT + 0x430, 0, 0])
    put_ptrs(DATA + 0x260, [1, DATA + 0x2A0])
    put_ptrs(DATA + 0x2A0, [0, TEXT + 0x440])
    put(0x1000 + 0x280, struct.pack("<II", 3, 1))
    put(0x1000 + 0x288, struct.pack("<iii", (TEXT + 0x450) - (DATA + 0x288), 0, 0))
    put(0x1000 + 0x2C0, struct.pack("<II", 32, 1))
    put_ptrs(DATA + 0x2C8, [0, TEXT + 0x460, 0])
    put(0x1000 + 0x2D8, struct.pack("<II", 4, 8))

    if with_symtab:
        # nlist_64 ×2 : noms "_$s4Test3fooyyF" et "_plain_symbol"
        stroff_content = b"\x00_$s4Test3fooyyF\x00_plain_symbol\x00"
        put(0x1F40, stroff_content)
        put(0x1F00, struct.pack("<IBBHQ", 1, 0x0F, 1, 0, 0))
        put(0x1F10, struct.pack("<IBBHQ", 16, 0x0F, 1, 0, 0))
    return bytes(buf)


def make_ipa(tmp_path: Path, bin_data: bytes, info: dict, name="Test.ipa") -> Path:
    ipa = Path(tmp_path) / name
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps(info))
        zf.writestr("Payload/Test.app/Test", bin_data)
    return ipa


def default_info(**overrides) -> dict:
    info = {
        "CFBundleExecutable": "Test",
        "CFBundleIdentifier": "com.test.app",
        "CFBundleName": "TestApp",
        "CFBundleShortVersionString": "1.0",
        "MinimumOSVersion": "17.0",
    }
    info.update(overrides)
    return info


def make_cookies_binary() -> bytes:
    """Cookies.binarycookies synthétique (2 cookies, 1 page) — format cohérent avec le parser."""
    def record(name: str, value: str, domain: str, path: str, expires: float) -> bytes:
        url_b, name_b, path_b, value_b = (s.encode() + b"\0" for s in (domain, name, path, value))
        strings = url_b + name_b + path_b + value_b
        url_off = 0
        name_off = len(url_b)
        path_off = name_off + len(name_b)
        value_off = path_off + len(path_b)
        # 10 champs (40 o) + expires/creation (16 o) = en-tête 56 o, strings à 56
        header = struct.pack("<IIIIIIIIII", 0, 1, 0, 0, url_off, name_off, path_off,
                             value_off, 0, 0)
        header += struct.pack("<dd", expires, 0.0)
        size = len(header) + len(strings)
        return struct.pack("<I", size) + header[4:] + strings

    r1 = record("session", "abc123", ".test.com", "/", 1900000000.0)
    r2 = record("token", "eyJhbGciOiJIUzI1NiJ9.payload.sig", ".api.test.com", "/api", 0.0)
    recs = r1 + r2
    page_header = struct.pack("<II", 0x00000100, 2)
    off1 = len(page_header) + 8
    off2 = off1 + len(r1)
    page = page_header + struct.pack("<II", off1, off2) + recs
    return b"cook" + struct.pack(">I", 1) + struct.pack(">I", len(page)) + page


def make_syslog_text() -> str:
    return "\n".join([
        "Nov 10 12:00:01 iPhone kernel[0]: TCP ESTABLISHED 192.168.1.50:49152 <-> 93.184.216.34:443",
        "Nov 10 12:00:02 iPhone mDNSResponder[104]: dns_query api.target.com type=A",
        "Nov 10 12:00:03 iPhone mDNSResponder[104]: dns_query cdn.target.com type=A",
        "Nov 10 12:00:04 iPhone app[123]: GET https://api.target.com/v1/users HTTP/1.1",
        "Nov 10 12:00:05 iPhone app[123]: connecting to telemetry.example.net:443",
        "Nov 10 12:00:06 iPhone app[123]: peer 10.0.0.7:8080 active",
        "Nov 10 12:00:07 iPhone app[123]: upload to 203.0.113.99:8443",
    ])
