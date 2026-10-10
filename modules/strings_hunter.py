# lang: Python 3.10+
# file: modules/strings_hunter.py
# deps: stdlib seulement (re, struct, math, pathlib, json, csv)
# skill refs: code-obfuscation-deobfuscation, ios-pentesting-tricks §7

"""Secret hunting + score d'obfuscation.

Importable :
    from modules.strings_hunter import scan_directory, export_findings

Runnable seul :
    python -m modules.strings_hunter <path> [--entropy 4.5] [--obfuscation] [-o dir]
"""

import argparse
import csv
import json
import math
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator, Optional

SECRET_PATTERNS = {
    "jwt":          r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "bearer":       r"[Bb]earer\s+[a-zA-Z0-9\-._~+/]{20,}",
    "api_key":      r"(?i)(api[_-]?key|apikey|x-api-key)[=:\s\"']+([a-zA-Z0-9\-_]{16,})",
    "aws_key":      r"AKIA[0-9A-Z]{16}",
    "aws_secret":   r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "private_key":  r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "password":     r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]",
    "secret":       r"(?i)(secret|token|credential)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
    "url_creds":    r"https?://[a-zA-Z0-9_%-]+:[a-zA-Z0-9_%!@#$^&*-]+@",
    "firebase":     r"AIza[0-9A-Za-z-_]{35}",
    "google_oauth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "slack_token":  r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
    "ssh_key":      r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "pem_cert":     r"-----BEGIN CERTIFICATE-----",
}

SEVERITY_MAP = {
    "private_key": "HIGH",
    "ssh_key": "HIGH",
    "jwt": "HIGH",
    "aws_secret": "HIGH",
    "firebase": "HIGH",
    "slack_token": "HIGH",
    "api_key": "MEDIUM",
    "bearer": "MEDIUM",
    "password": "MEDIUM",
    "secret": "MEDIUM",
    "aws_key": "MEDIUM",
    "url_creds": "MEDIUM",
    "google_oauth": "MEDIUM",
    "pem_cert": "LOW",
}

DEFAULT_EXTS = [".db", ".sqlite", ".sqlite3", ".plist", ".json", ".txt", ".log",
                ".js", ".ts", ".swift", ".m", ".h"]

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
MAX_FILE_BYTES = 50 * 1024 * 1024
MIN_ENTROPY_LEN = 16


@dataclass
class StringFinding:
    file:     str
    offset:   int
    string:   str
    pattern:  str
    entropy:  float
    severity: str


def shannon_entropy(data: bytes) -> float:
    """Calcule l'entropie de Shannon (bits/octet) d'un bloc de bytes."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return -sum((f / length) * math.log2(f / length) for f in freq if f)


def extract_strings(path: Path, min_len: int = 6) -> Iterator[tuple[int, str]]:
    """Yield (offset, string) pour chaque séquence imprimable ≥ min_len (équiv. `strings`)."""
    data = path.read_bytes()
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    for m in pattern.finditer(data):
        yield m.start(), m.group().decode("ascii", errors="replace")


def _compiled_patterns() -> list[tuple[str, re.Pattern]]:
    return [(name, re.compile(rx)) for name, rx in SECRET_PATTERNS.items()]


def scan_file(path: Path, entropy_threshold: float = 4.5,
              patterns: Optional[list] = None) -> list[StringFinding]:
    """
    Scanne un fichier unique (binaire, plist, sqlite, db, txt).
    Matche les SECRET_PATTERNS + flag les strings à haute entropie.
    """
    patterns = patterns if patterns is not None else _compiled_patterns()
    findings: list[StringFinding] = []
    seen: set[tuple[str, str]] = set()

    for offset, s in extract_strings(path):
        ent = shannon_entropy(s.encode("ascii", errors="replace"))
        matched = False
        for name, rx in patterns:
            if rx.search(s):
                key = (name, s[:120])
                if key not in seen:
                    seen.add(key)
                    findings.append(StringFinding(
                        file=str(path), offset=offset, string=s[:200],
                        pattern=name, entropy=round(ent, 2),
                        severity=SEVERITY_MAP.get(name, "MEDIUM"),
                    ))
                matched = True
        if (not matched and entropy_threshold > 0
                and len(s) >= MIN_ENTROPY_LEN and ent >= entropy_threshold):
            key = ("entropy", s[:120])
            if key not in seen:
                seen.add(key)
                findings.append(StringFinding(
                    file=str(path), offset=offset, string=s[:200],
                    pattern="entropy", entropy=round(ent, 2),
                    severity="MEDIUM" if ent > 5.5 else "LOW",
                ))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return findings


def scan_directory(root: Path, entropy_threshold: float = 4.5,
                   extensions: Optional[list[str]] = None) -> list[StringFinding]:
    """Walk récursif (skip > 50 MB). Par défaut : extensions documentées + binaires sans extension."""
    if not root.exists():
        raise RuntimeError(f"Chemin introuvable : {root}")
    exts = [e.lower() if e.startswith(".") else "." + e.lower()
            for e in (extensions if extensions is not None else DEFAULT_EXTS)]
    findings: list[StringFinding] = []
    patterns = _compiled_patterns()
    files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    for p in files:
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        if p.is_file() and p.suffix.lower() not in exts and p.suffix != "":
            continue
        try:
            findings.extend(scan_file(p, entropy_threshold=entropy_threshold, patterns=patterns))
        except (OSError, PermissionError):
            continue
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file))
    return findings


def export_findings(findings: list[StringFinding], output_dir: Path,
                    formats: tuple = ("json", "csv", "txt")) -> dict:
    """Exporte findings.json, findings.csv, findings.txt (groupé par severity)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    written = {}
    if "json" in formats:
        p = output_dir / "findings.json"
        p.write_text(json.dumps([asdict(f) for f in findings], indent=2,
                                ensure_ascii=False), encoding="utf-8")
        written["json"] = str(p)
    if "csv" in formats:
        p = output_dir / "findings.csv"
        with p.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["severity", "pattern", "file",
                                                    "offset", "entropy", "string"])
            writer.writeheader()
            for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
                writer.writerow({"severity": f.severity, "pattern": f.pattern, "file": f.file,
                                 "offset": f.offset, "entropy": f.entropy, "string": f.string})
        written["csv"] = str(p)
    if "txt" in formats:
        p = output_dir / "findings.txt"
        lines = []
        for sev in ("HIGH", "MEDIUM", "LOW"):
            group = [f for f in findings if f.severity == sev]
            if not group:
                continue
            lines.append(f"=== {sev} ({len(group)}) ===")
            for f in group:
                lines.append(f"{f.severity} | {f.file}:{f.offset} | {f.pattern} | {f.string[:80]}")
            lines.append("")
        p.write_text("\n".join(lines) or "Aucun finding.\n", encoding="utf-8")
        written["txt"] = str(p)
    return written


def _has_symtab(data: bytes) -> bool:
    """Heuristique Mach-O : présence d'un LC_SYMTAB non vide."""
    for base in (0, 0x1000):
        if len(data) < base + 32:
            continue
        magic = int.from_bytes(data[base:base + 4], "little")
        if magic not in (0xFEEDFACF, 0xFEEDFACE):
            continue
        is64 = magic == 0xFEEDFACF
        ncmds = int.from_bytes(data[base + 16:base + 20], "little")
        off = base + (32 if is64 else 28)
        for _ in range(ncmds):
            if off + 8 > len(data):
                break
            cmd = int.from_bytes(data[off:off + 4], "little")
            cmdsize = int.from_bytes(data[off + 4:off + 8], "little")
            if cmdsize < 8:
                break
            if cmd == 0x2 and cmdsize >= 24:
                nsyms = int.from_bytes(data[off + 12:off + 16], "little")
                if nsyms > 0:
                    return True
            off += cmdsize
        return False
    return False


def compute_obfuscation_score(path: Path) -> dict:
    """Score d'obfuscation 0-100 : entropie globale, ratio imprimable, symtab, patterns XOR/packés."""
    data = path.read_bytes()[:MAX_FILE_BYTES]
    if not data:
        return {"score": 0, "verdict": "fichier vide", "indicators": []}
    indicators: list[str] = []
    score = 0

    ent = shannon_entropy(data[: 4 * 1024 * 1024])
    if ent > 7.2:
        score += 40
        indicators.append(f"entropie globale élevée ({ent:.2f}) — packé/chiffré probable")
    elif ent > 6.5:
        score += 25
        indicators.append(f"entropie globale modérée ({ent:.2f}) — compression ou encryption partielle")

    printable = sum(1 for b in data[: 1024 * 1024] if 0x20 <= b <= 0x7E)
    printable_ratio = printable / min(len(data), 1024 * 1024)
    if printable_ratio < 0.15:
        score += 20
        indicators.append(f"ratio imprimable faible ({printable_ratio:.2f}) — binaire fortement non-textuel")

    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") and not _has_symtab(data):
        score += 20
        indicators.append("Mach-O strippé (pas de LC_SYMTAB) — symboles supprimés")

    null_ratio = data[: 1024 * 1024].count(0) / min(len(data), 1024 * 1024)
    if null_ratio < 0.01 and ent > 5.5:
        score += 20
        indicators.append("quasi aucun octet nul + entropie haute — pattern XOR/pack détecté")

    score = max(0, min(100, score))
    if score < 25:
        verdict = "non obfusqué"
    elif score < 60:
        verdict = "partiellement obfusqué / packé"
    else:
        verdict = "fortement obfusqué / chiffré"
    return {"score": score, "verdict": verdict, "indicators": indicators}


def _print_report(findings: list[StringFinding], obf: Optional[dict]):
    if obf:
        print(f"[*] Score d'obfuscation : {obf['score']}/100 — {obf['verdict']}")
        for ind in obf["indicators"]:
            print(f"    - {ind}")
    if not findings:
        print("[+] Aucun secret détecté.")
        return
    for sev in ("HIGH", "MEDIUM", "LOW"):
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        print(f"[{sev}] {len(group)} finding(s)")
        for f in group[:60]:
            print(f"  {f.file}:{f.offset} [{f.pattern}] {f.string[:80]}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="strings_hunter",
                                     description="Secret hunting + score d'obfuscation")
    parser.add_argument("target", help="Fichier ou répertoire à scanner")
    parser.add_argument("--entropy", type=float, default=4.5, help="Seuil entropie Shannon (0 = désactivé)")
    parser.add_argument("--regex-only", action="store_true", help="Regex seulement, pas d'entropie")
    parser.add_argument("--obfuscation", action="store_true", help="Calculer le score d'obfuscation")
    parser.add_argument("-o", "--output", help="Répertoire de sortie pour les exports")
    parser.add_argument("--ext", help="Extensions à scanner, séparées par virgule")
    args = parser.parse_args(argv)

    root = Path(args.target)
    threshold = 0.0 if args.regex_only else args.entropy
    exts = args.ext.split(",") if args.ext else None
    findings = scan_directory(root, entropy_threshold=threshold, extensions=exts)

    obf = None
    if args.obfuscation and root.is_file():
        obf = compute_obfuscation_score(root)

    _print_report(findings, obf)
    if args.output:
        written = export_findings(findings, Path(args.output))
        for kind, p in written.items():
            print(f"[+] {kind}: {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
