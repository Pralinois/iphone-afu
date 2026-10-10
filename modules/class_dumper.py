# lang: Python 3.10+
# file: modules/class_dumper.py
# deps: macholib (déjà dans requirements via TÂCHE A)
# skill refs: ios-pentesting-tricks §5, binary-protection-bypass

"""Dump statique des classes ObjC + symboles Swift depuis un Mach-O / IPA.

Importable :
    from modules.class_dumper import dump_objc_classes, extract_swift_symbols, render_class_dump

Runnable seul :
    python -m modules.class_dumper <ipa_or_binary> [--swift] [--filter regex] [--json out.json]
"""

import argparse
import json
import logging
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from macholib.MachO import MachO

log = logging.getLogger("afu.class_dumper")

LC_SEGMENT_64 = 0x19
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_SYMTAB = 0x2

PAC_MASK = (1 << 36) - 1
CLASS_DATA_MASK = 0x00007FFFFFFFF8
MAX_CLASSES = 5000
MAX_NAME = 512


@dataclass
class ObjCClass:
    name:       str
    methods:    list[str]
    protocols:  list[str]
    ivars:      list[str]
    superclass: Optional[str]


class _Slice:
    """Contexte d'une tranche Mach-O : segments + sections + data."""

    def __init__(self, data: bytes, base: int, header):
        self.data = data
        self.base = base
        self.segments: list[tuple[int, int, int, int]] = []    # vmaddr, vmsize, fileoff, filesize
        self.sections: list[tuple[str, str, int, int, int]] = []  # seg, sect, addr, size, offset
        self.symtab: Optional[tuple[int, int, int, int]] = None    # symoff, nsyms, stroff, strsize
        self.cryptid = 0
        for lc, cmd, cdata in header.commands:
            if lc.cmd == LC_SEGMENT_64:
                self.segments.append((cmd.vmaddr, cmd.vmsize, cmd.fileoff, cmd.filesize))
                for s in (cdata if isinstance(cdata, list) else []):
                    self.sections.append((_bstr(s.segname), _bstr(s.sectname),
                                          s.addr, s.size, s.offset))
            elif lc.cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                self.cryptid = max(self.cryptid, int(getattr(cmd, "cryptid", 0)))
            elif lc.cmd == LC_SYMTAB:
                self.symtab = (cmd.symoff, cmd.nsyms, cmd.stroff, cmd.strsize)

    def off_for_addr(self, addr: int) -> Optional[int]:
        """vmaddr → offset fichier absolu (masque PAC arm64e)."""
        addr &= PAC_MASK
        for vmaddr, vmsize, fileoff, filesize in self.segments:
            if vmaddr <= addr < vmaddr + vmsize:
                delta = addr - vmaddr
                if delta < filesize:
                    return self.base + fileoff + delta
        return None

    def read_u64(self, pos: int) -> Optional[int]:
        if pos is None or pos < 0 or pos + 8 > len(self.data):
            return None
        return int.from_bytes(self.data[pos:pos + 8], "little")

    def read_u32(self, pos: int) -> Optional[int]:
        if pos is None or pos < 0 or pos + 4 > len(self.data):
            return None
        return int.from_bytes(self.data[pos:pos + 4], "little")

    def read_i32(self, pos: int) -> Optional[int]:
        v = self.read_u32(pos)
        if v is None:
            return None
        return v - (1 << 32) if v & 0x80000000 else v

    def read_cstr(self, pos: Optional[int]) -> Optional[str]:
        if pos is None or pos < 0 or pos >= len(self.data):
            return None
        end = self.data.find(b"\x00", pos, pos + MAX_NAME)
        if end == -1:
            return None
        return self.data[pos:end].decode("utf-8", errors="replace")

    def ptr_at(self, pos: int) -> Optional[int]:
        """Lit un pointeur 8o à pos et retourne sa cible vmaddr (masquée PAC)."""
        v = self.read_u64(pos)
        if v is None:
            return None
        return v & PAC_MASK

    def section(self, sectname: str) -> Optional[tuple[int, int, int]]:
        for seg, sect, addr, size, offset in self.sections:
            if sect == sectname or sect.rstrip("\x00") == sectname:
                return addr, size, offset
        return None


def _bstr(val) -> str:
    if isinstance(val, bytes):
        return val.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return str(val)


def _vmaddr_of_file_pos(slice_ctx: _Slice, pos: int) -> Optional[int]:
    """Inverse de off_for_addr : retrouve la vmaddr d'une position fichier (pour les offsets relatifs)."""
    for vmaddr, vmsize, fileoff, filesize in slice_ctx.segments:
        start = slice_ctx.base + fileoff
        if start <= pos < start + filesize:
            return vmaddr + (pos - start)
    return None


def _class_name(slice_ctx: _Slice, class_addr: int) -> Optional[str]:
    """classe ObjC → nom via class_t.data → class_ro_t.name."""
    class_pos = slice_ctx.off_for_addr(class_addr)
    if class_pos is None:
        return None
    data_ptr = slice_ctx.ptr_at(class_pos + 32)
    if not data_ptr:
        return None
    ro_pos = slice_ctx.off_for_addr(data_ptr & CLASS_DATA_MASK)
    if ro_pos is None:
        return None
    name_ptr = slice_ctx.ptr_at(ro_pos + 16)
    if not name_ptr:
        return None
    return slice_ctx.read_cstr(slice_ctx.off_for_addr(name_ptr))


def _parse_method_list(slice_ctx: _Slice, list_addr: int) -> list[str]:
    pos = slice_ctx.off_for_addr(list_addr)
    if pos is None:
        return []
    entsize_flags = slice_ctx.read_u32(pos)
    count = slice_ctx.read_u32(pos + 4)
    if entsize_flags is None or count is None or count > 20000:
        return []
    relative = (entsize_flags & 0x3) == 0x3
    entries = pos + 8
    methods = []
    for i in range(count):
        entry = entries + i * (12 if relative else 24)
        if entry + 12 > len(slice_ctx.data):
            break
        if relative:
            name_off = slice_ctx.read_i32(entry)
            entry_vm = _vmaddr_of_file_pos(slice_ctx, entry)
            if name_off is None or entry_vm is None:
                continue
            name = slice_ctx.read_cstr(slice_ctx.off_for_addr(entry_vm + name_off))
        else:
            name_ptr = slice_ctx.ptr_at(entry)
            name = slice_ctx.read_cstr(slice_ctx.off_for_addr(name_ptr)) if name_ptr else None
        if name:
            methods.append(name)
    return methods


def _parse_protocol_list(slice_ctx: _Slice, list_addr: int) -> list[str]:
    pos = slice_ctx.off_for_addr(list_addr)
    if pos is None:
        return []
    count = slice_ctx.read_u64(pos)
    if count is None or count > 1000:
        return []
    names = []
    for i in range(count):
        ptr = slice_ctx.ptr_at(pos + 8 + i * 8)
        if not ptr:
            continue
        proto_pos = slice_ctx.off_for_addr(ptr)
        if proto_pos is None:
            continue
        name_ptr = slice_ctx.ptr_at(proto_pos + 8)
        name = slice_ctx.read_cstr(slice_ctx.off_for_addr(name_ptr)) if name_ptr else None
        if name:
            names.append(name)
    return names


def _parse_ivar_list(slice_ctx: _Slice, list_addr: int) -> list[str]:
    pos = slice_ctx.off_for_addr(list_addr)
    if pos is None:
        return []
    entsize = slice_ctx.read_u32(pos)
    count = slice_ctx.read_u32(pos + 4)
    if entsize is None or count is None or count > 5000:
        return []
    relative = (entsize & 0x3) == 0x3
    entry_size = 20 if relative else 32
    ivars = []
    for i in range(count):
        entry = pos + 8 + i * entry_size
        if entry + entry_size > len(slice_ctx.data):
            break
        name = None
        if relative:
            name_off = slice_ctx.read_i32(entry + 4)
            entry_vm = _vmaddr_of_file_pos(slice_ctx, entry)
            if name_off is not None and entry_vm is not None:
                name = slice_ctx.read_cstr(slice_ctx.off_for_addr(entry_vm + name_off))
        else:
            name_ptr = slice_ctx.ptr_at(entry + 8)
            name = slice_ctx.read_cstr(slice_ctx.off_for_addr(name_ptr)) if name_ptr else None
        if name:
            ivars.append(name)
    return ivars


def dump_objc_classes(binary_path: Path) -> list[ObjCClass]:
    """Parse __DATA,__objc_classlist (thin + fat). Binaire FairPlay → [] + warning."""
    data = Path(binary_path).read_bytes()
    try:
        macho = MachO(str(binary_path))
    except Exception as e:
        raise RuntimeError(f"parse Mach-O impossible : {e}") from e

    classes: dict[str, ObjCClass] = {}
    for header in macho.headers:
        base = getattr(header, "offset", 0) or 0
        ctx = _Slice(data, base, header)
        if ctx.cryptid != 0:
            log.warning("binaire chiffré FairPlay (cryptid=%d) — class-dump nécessite un IPA déchiffré",
                        ctx.cryptid)
            return []
        sect = ctx.section("__objc_classlist")
        if sect is None:
            continue
        addr, size, offset = sect
        n = min(size // 8, MAX_CLASSES)
        for i in range(n):
            class_addr = ctx.read_u64(base + offset + i * 8)
            if not class_addr:
                continue
            class_addr &= PAC_MASK
            pos = ctx.off_for_addr(class_addr)
            if pos is None:
                continue
            name = _class_name(ctx, class_addr)
            if not name or name in classes:
                continue
            super_ptr = ctx.ptr_at(pos + 8)
            super_name = _class_name(ctx, super_ptr) if super_ptr else None
            data_ptr = ctx.ptr_at(pos + 32)
            methods, protocols, ivars = [], [], []
            if data_ptr:
                ro = ctx.off_for_addr(data_ptr & CLASS_DATA_MASK)
                if ro is not None:
                    m_ptr = ctx.ptr_at(ro + 24)
                    p_ptr = ctx.ptr_at(ro + 32)
                    i_ptr = ctx.ptr_at(ro + 40)
                    if m_ptr:
                        methods = _parse_method_list(ctx, m_ptr)
                    if p_ptr:
                        protocols = _parse_protocol_list(ctx, p_ptr)
                    if i_ptr:
                        ivars = _parse_ivar_list(ctx, i_ptr)
            classes[name] = ObjCClass(name=name, methods=methods, protocols=protocols,
                                      ivars=ivars, superclass=super_name)
    return sorted(classes.values(), key=lambda c: c.name)


def extract_swift_symbols(binary_path: Path) -> list[str]:
    """Symboles Swift (mangling _$s) depuis LC_SYMTAB ; demangle si swift-demangle dispo."""
    data = Path(binary_path).read_bytes()
    raw: list[str] = []
    try:
        macho = MachO(str(binary_path))
    except Exception as e:
        raise RuntimeError(f"parse Mach-O impossible : {e}") from e

    for header in macho.headers:
        base = getattr(header, "offset", 0) or 0
        ctx = _Slice(data, base, header)
        if not ctx.symtab:
            continue
        symoff, nsyms, stroff, strsize = ctx.symtab
        for i in range(min(nsyms, 200000)):
            entry = base + symoff + i * 16
            if entry + 16 > len(data):
                break
            strx = int.from_bytes(data[entry:entry + 4], "little")
            if strx >= strsize:
                continue
            name = ctx.read_cstr(base + stroff + strx)
            if name and (name.startswith("_$s") or name.startswith("$s")):
                raw.append(name[1:] if name.startswith("_$") else name)
            if len(raw) >= 5000:
                break

    if raw and shutil.which("swift-demangle"):
        try:
            proc = subprocess.run(["swift-demangle"], input="\n".join(raw),
                                  capture_output=True, text=True, timeout=30)
            if proc.returncode == 0 and proc.stdout.strip():
                return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        except Exception as e:
            log.warning("swift-demangle échec : %s", e)
    return raw


def render_class_dump(classes: list[ObjCClass], swift_symbols: list[str],
                      output_path: Optional[Path] = None,
                      json_out: Optional[Path] = None) -> str:
    """Format texte style class-dump + export JSON structuré."""
    lines = [f"// classes ObjC : {len(classes)} | symboles Swift : {len(swift_symbols)}",
             "// types tronqués (dump statique, sans runtime)", ""]
    for c in classes:
        header = f"@interface {c.name}"
        if c.superclass:
            header += f" : {c.superclass}"
        if c.protocols:
            header += f" <{', '.join(c.protocols)}>"
        lines.append(header)
        for iv in c.ivars:
            lines.append(f"    @private {iv};")
        for m in c.methods:
            lines.append(f"    - (id){m};")
        lines.append("@end")
        lines.append("")

    if swift_symbols:
        lines.append(f"// --- symboles Swift ({len(swift_symbols)}) ---")
        lines.extend(f"// {s}" for s in swift_symbols[:500])

    text = "\n".join(lines)
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
    if json_out:
        payload = {
            "classes": [asdict(c) for c in classes],
            "swift_symbols": swift_symbols,
        }
        Path(json_out).write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                                  encoding="utf-8")
    return text


def _materialize(path: Path) -> tuple[Path, Optional[Path]]:
    if path.suffix.lower() == ".ipa":
        tmp = Path(tempfile.mkdtemp(prefix="afu_classdump_"))
        with zipfile.ZipFile(path) as zf:
            zf.extractall(tmp)
        plists = list((tmp / "Payload").glob("*.app/Info.plist"))
        if not plists:
            shutil.rmtree(tmp, ignore_errors=True)
            raise RuntimeError(f"Payload/*.app introuvable dans {path.name}")
        import plistlib
        info = plistlib.loads(plists[0].read_bytes())
        exe = info.get("CFBundleExecutable") or plists[0].parent.stem
        return plists[0].parent / exe, tmp
    if path.is_dir():
        import plistlib
        plist = path / "Info.plist"
        info = plistlib.loads(plist.read_bytes()) if plist.exists() else {}
        return path / (info.get("CFBundleExecutable") or path.stem), None
    return path, None


def materialize_binary(path: Path) -> tuple[Path, Optional[Path]]:
    """Résout un .ipa/.app/binaire → (fichier binaire, tempdir à nettoyer ou None)."""
    return _materialize(Path(path))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="class_dumper",
                                     description="Dump statique classes ObjC + symboles Swift")
    parser.add_argument("target", help=".ipa ou binaire Mach-O")
    parser.add_argument("--swift", action="store_true", help="Inclure les symboles Swift")
    parser.add_argument("--filter", help="Regex filtre sur les noms de classes")
    parser.add_argument("--json", dest="json_out", help="Sortie JSON structurée")
    parser.add_argument("-o", "--output", help="Fichier texte de sortie")
    args = parser.parse_args(argv)

    import logging as _logging
    _logging.basicConfig(level=_logging.WARNING, format="%(levelname)s %(message)s")

    target = Path(args.target)
    if not target.exists():
        print(f"[!] Chemin introuvable : {target}")
        return 1
    binary, tmp = _materialize(target)
    try:
        classes = dump_objc_classes(binary)
        swift = extract_swift_symbols(binary) if args.swift else []
    except RuntimeError as e:
        print(f"[!] {e}")
        return 1
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)

    if args.filter:
        rx = re.compile(args.filter)
        classes = [c for c in classes if rx.search(c.name)]
        swift = [s for s in swift if rx.search(s)]

    text = render_class_dump(classes, swift,
                             Path(args.output) if args.output else None,
                             Path(args.json_out) if args.json_out else None)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
