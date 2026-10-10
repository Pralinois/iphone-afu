# lang: Python 3.10+
# file: modules/macho_analyzer.py
# deps: macholib (pip install macholib)
# skill refs: binary-protection-bypass, anti-debugging-techniques

"""Analyse binaire Mach-O / IPA : protections, entitlements, APIs anti-debug, bypass vectors.

Importable :
    from modules.macho_analyzer import analyze_macho, render_macho_report

Runnable seul :
    python -m modules.macho_analyzer <ipa_or_binary> [--json out.json]
"""

import argparse
import json
import plistlib
import shutil
import sys
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from macholib.MachO import MachO

MH_PIE = 0x200000
LC_SEGMENT_64 = 0x19
LC_RPATH = 0x1C | 0x80000000
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_CODE_SIGNATURE = 0x1D
LC_SYMTAB = 0x2

ANTI_DEBUG_SYMBOLS = [
    "ptrace", "sysctl", "sysctlbyname",
    "task_get_exception_ports", "task_set_exception_ports",
    "catch_mach_exception_raise", "exc_server", "getppid",
    "dlopen", "dlsym",
]

CPU_NAMES = {12: "armv7", 0x01000007: "x86_64", 0x0100000C: "arm64"}


@dataclass
class MachOProtections:
    """Résultat d'analyse des protections d'un binaire Mach-O."""
    path:            str
    arch:            list[str] = field(default_factory=list)
    pie:             bool = False
    arc:             bool = False
    stack_canary:    bool = False
    encrypted:       bool = False
    cryptid:         int = 0
    restrict:        bool = False
    rpath_count:     int = 0
    get_task_allow:  bool = False
    entitlements:    dict = field(default_factory=dict)
    url_schemes:     list[str] = field(default_factory=list)
    ats_allows_http: bool = False
    ats_exceptions:  list[str] = field(default_factory=list)
    anti_debug_apis: list[str] = field(default_factory=list)
    bypass_vectors:  list[str] = field(default_factory=list)


def _bstr(val) -> str:
    if isinstance(val, bytes):
        return val.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return str(val)


def _cpu_name(cputype: int, cpusubtype: int) -> str:
    name = CPU_NAMES.get(cputype, hex(cputype))
    if name == "arm64" and cpusubtype & 0x80000000:
        name = "arm64e"
    return name


def _extract_entitlements(cs_blob: bytes) -> dict:
    """Entitlements XML depuis un SuperBlob LC_CODE_SIGNATURE (type 5)."""
    if not cs_blob or len(cs_blob) < 20:
        return {}
    if int.from_bytes(cs_blob[:4], "big") != 0xFADE0CC0:
        return {}
    count = int.from_bytes(cs_blob[8:12], "big")
    for i in range(min(count, 32)):
        base = 12 + i * 8
        if base + 8 > len(cs_blob):
            break
        btype = int.from_bytes(cs_blob[base:base + 4], "big")
        boff = int.from_bytes(cs_blob[base + 4:base + 8], "big")
        if btype == 5 and 0 < boff and boff + 8 <= len(cs_blob):
            blen = int.from_bytes(cs_blob[boff + 4:boff + 8], "big")
            if blen > 8 and boff + blen <= len(cs_blob):
                try:
                    parsed = plistlib.loads(cs_blob[boff + 8:boff + blen])
                    if isinstance(parsed, dict):
                        return parsed
                except Exception:
                    return {}
    return {}


def _read_code_signature(data: bytes, dataoff: int, datasize: int, slice_base: int) -> bytes:
    for start in (slice_base + dataoff, dataoff):
        if 0 < start < len(data) and start + 4 <= len(data):
            blob = data[start:start + datasize]
            if blob[:4] == b"\xfa\xde\x0c\xc0":
                return blob
    return b""


def _anti_debug_apis(data: bytes) -> list[str]:
    found: list[str] = []
    for sym in ANTI_DEBUG_SYMBOLS:
        if sym.encode() in data:
            found.append(sym)
    return found


def _scan_binary(data: bytes, slice_base: int, macho: MachO) -> dict:
    """Analyse une passe macholib : archs, pie, cryptid, restrict, rpath, entitlements, sections."""
    out: dict[str, Any] = {
        "archs": [], "pie": None, "cryptid": 0, "restrict": False,
        "rpath_count": 0, "entitlements": {},
        "sections": [], "segments": [],
    }
    for header in macho.headers:
        out["archs"].append(_cpu_name(header.header.cputype, header.header.cpusubtype))
        pie = bool(header.header.flags & MH_PIE)
        out["pie"] = pie if out["pie"] is None else (out["pie"] and pie)
        hdr_base = getattr(header, "offset", 0) or 0
        for lc, cmd, cdata in header.commands:
            if lc.cmd == LC_SEGMENT_64:
                seg = _bstr(getattr(cmd, "segname", b""))
                out["segments"].append((seg, cmd.vmaddr, cmd.vmsize, cmd.fileoff, cmd.filesize))
                for s in (cdata if isinstance(cdata, list) else []):
                    sname, gname = _bstr(s.sectname), _bstr(s.segname)
                    out["sections"].append((gname, sname, s.addr, s.size, s.offset))
                    if sname == "__restrict" or (gname == "__RESTRICT" and "restrict" in sname):
                        out["restrict"] = True
            elif lc.cmd == LC_RPATH:
                out["rpath_count"] += 1
            elif lc.cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                cryptid = getattr(cmd, "cryptid", 0)
                out["cryptid"] = max(out["cryptid"], int(cryptid))
            elif lc.cmd == LC_CODE_SIGNATURE and not out["entitlements"]:
                blob = _read_code_signature(data, cmd.dataoff, cmd.datasize, hdr_base)
                out["entitlements"] = _extract_entitlements(blob)
    return out


def _build_bypass_vectors(r: MachOProtections) -> list[str]:
    v = []
    if not r.pie:
        v.append("PIE absent → ASLR désactivé, adresses de code fixes : ROP/ret2* directs "
                 "(binary-protection-bypass §3)")
    if not r.stack_canary:
        v.append("Stack canary absent → overflow direct / stack spray viable "
                 "(binary-protection-bypass §6)")
    if r.encrypted:
        v.append("FairPlay actif (cryptid=%d) → déchiffrer l'IPA (frida-ios-dump / bagbag) "
                 "avant RE et patch" % r.cryptid)
    if r.get_task_allow:
        v.append("get-task-allow=true → debugger/Frida attachables directement, sans re-signature")
    if not r.restrict:
        v.append("Pas de __RESTRICT → DYLD_INSERT_LIBRARIES / dyld env vars utilisables "
                 "sur binaire re-signé")
    if r.rpath_count:
        v.append(f"{r.rpath_count} LC_RPATH → vérifier les chemins @loader_path/@executable_path "
                 "pour une injection dylib (écriture dans Frameworks/)")
    if r.anti_debug_apis:
        v.append("Anti-debug détecté (%s) → Frida Interceptor.replace des APIs, hook "
                 "ptrace(PT_DENY_ATTACH)→0, patch NOP (anti-debugging-techniques §1-3)"
                 % ", ".join(r.anti_debug_apis))
    if r.arc is False:
        v.append("ARC non détecté → gestion mémoire manuelle : patterns UAF/rétention "
                 "analysables (RE plus verbeuse)")
    if r.ats_allows_http:
        v.append("ATS permissif (NSAllowsArbitraryLoads) → trafic HTTP en clair observables, "
                 "proxy MITM facilité (ios-pentesting-tricks §8)")
    if r.url_schemes:
        v.append("Schémas URL (%s) → hijacking/interception de callbacks possibles "
                 "(ios-pentesting-tricks §3)" % ", ".join(r.url_schemes[:8]))
    groups = r.entitlements.get("keychain-access-groups") if r.entitlements else None
    if groups:
        v.append("keychain-access-groups (%s) → périmètre keychain de l'app à auditer "
                 "(ios-pentesting-tricks §2)" % ", ".join(map(str, groups[:4])))
    return v


def _materialize(path: Path) -> tuple[Path, dict, Optional[Path]]:
    """Retourne (chemin binaire, Info.plist, tempdir à nettoyer). IPA → extraction temp."""
    if path.suffix.lower() == ".ipa":
        tmp = Path(tempfile.mkdtemp(prefix="afu_macho_"))
        with zipfile.ZipFile(path) as zf:
            zf.extractall(tmp)
        plists = list((tmp / "Payload").glob("*.app/Info.plist"))
        if not plists:
            shutil.rmtree(tmp, ignore_errors=True)
            raise RuntimeError(f"Payload/*.app/Info.plist introuvable dans {path.name}")
        info = plistlib.loads(plists[0].read_bytes())
        app_dir = plists[0].parent
        exe = info.get("CFBundleExecutable") or app_dir.stem
        binary = app_dir / exe
        if not binary.exists():
            shutil.rmtree(tmp, ignore_errors=True)
            raise RuntimeError(f"binaire principal introuvable : {exe}")
        return binary, info, tmp
    if path.is_dir():
        plist = path / "Info.plist"
        info = plistlib.loads(plist.read_bytes()) if plist.exists() else {}
        exe = info.get("CFBundleExecutable") or path.stem
        return path / exe, info, None
    return path, {}, None


def analyze_macho(path: Path) -> MachOProtections:
    """Analyse un binaire Mach-O ou un IPA : protections, entitlements, bypass vectors."""
    path = Path(path)
    if not path.exists():
        raise RuntimeError(f"Chemin introuvable : {path}")

    binary, info, tmp = _materialize(path)
    try:
        data = binary.read_bytes()
        try:
            macho = MachO(str(binary))
        except Exception as e:
            raise RuntimeError(f"parse Mach-O impossible ({binary.name}) : {e}") from e

        scan = _scan_binary(data, getattr(macho.headers[0], "offset", 0) or 0, macho)
        ats = info.get("NSAppTransportSecurity") or {}
        ents = scan["entitlements"]
        r = MachOProtections(
            path=str(path),
            arch=scan["archs"],
            pie=bool(scan["pie"]),
            arc=b"objc_release" in data or b"objc_retain" in data,
            stack_canary=b"___stack_chk_guard" in data or b"__stack_chk_guard" in data,
            encrypted=scan["cryptid"] != 0,
            cryptid=scan["cryptid"],
            restrict=scan["restrict"],
            rpath_count=scan["rpath_count"],
            get_task_allow=bool(ents.get("get-task-allow")),
            entitlements=ents,
            url_schemes=[s for t in info.get("CFBundleURLTypes", [])
                         for s in t.get("CFBundleURLSchemes", [])],
            ats_allows_http=bool(ats.get("NSAllowsArbitraryLoads")),
            ats_exceptions=list((ats.get("NSExceptionDomains") or {}).keys()),
            anti_debug_apis=_anti_debug_apis(data),
        )
        r.bypass_vectors = _build_bypass_vectors(r)
        return r
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)


def render_macho_report(r: MachOProtections, json_out: Optional[Path] = None,
                        plain: bool = False) -> str:
    """Rapport texte (markup Rich si plain=False) + export JSON."""
    def mark(line: str) -> str:
        if plain:
            return line
        return line

    lines = []
    lines.append(mark("[bold]Mach-O Analysis[/bold]" if not plain else "Mach-O Analysis"))
    lines.append(f"  path      : {r.path}")
    lines.append(f"  arch      : {', '.join(r.arch) or '?'}")
    lines.append("")
    lines.append("Protections :")
    checks = [
        ("PIE (ASLR)", r.pie, "present" if r.pie else "ABSENT"),
        ("Stack canary", r.stack_canary, "present" if r.stack_canary else "ABSENT"),
        ("ARC (heuristique)", r.arc, "detecte" if r.arc else "non detecte"),
        ("FairPlay encryption", r.encrypted, f"cryptid={r.cryptid}"),
        ("__RESTRICT", r.restrict, "present" if r.restrict else "absent"),
        ("LC_RPATH", r.rpath_count > 0, str(r.rpath_count)),
        ("get-task-allow", r.get_task_allow, str(r.get_task_allow)),
        ("ATS HTTP clair", r.ats_allows_http, "autorise" if r.ats_allows_http else "bloque"),
    ]
    for name, ok, val in checks:
        flag = "OK " if ok else "!! "
        lines.append(f"  [{flag}] {name:22s} {val}")
    if r.ats_exceptions:
        lines.append(f"        ATS domaines : {', '.join(r.ats_exceptions[:6])}")
    if r.url_schemes:
        lines.append(f"        URL schemes  : {', '.join(r.url_schemes[:8])}")
    lines.append("")
    lines.append(f"Entitlements ({len(r.entitlements)}) :")
    for k in sorted(r.entitlements)[:20]:
        lines.append(f"  - {k}: {str(r.entitlements[k])[:70]}")
    if not r.entitlements:
        lines.append("  (aucun)")
    lines.append("")
    lines.append(f"APIs anti-debug ({len(r.anti_debug_apis)}) :")
    lines.append("  " + (", ".join(r.anti_debug_apis) if r.anti_debug_apis else "(aucune)"))
    lines.append("")
    lines.append(f"Bypass vectors ({len(r.bypass_vectors)}) :")
    for v in r.bypass_vectors:
        lines.append(f"  > {v}")

    if json_out:
        payload = asdict(r)
        payload["generated"] = datetime.now().isoformat(timespec="seconds")
        Path(json_out).write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                                  encoding="utf-8")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="macho_analyzer",
                                     description="Analyse Mach-O / IPA — protections + bypass vectors")
    parser.add_argument("target", help="Chemin vers .ipa ou binaire Mach-O")
    parser.add_argument("--json", dest="json_out", help="Écrit le rapport JSON")
    args = parser.parse_args(argv)
    try:
        r = analyze_macho(Path(args.target))
    except RuntimeError as e:
        print(f"[!] {e}")
        return 1
    print(render_macho_report(r, Path(args.json_out) if args.json_out else None, plain=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
