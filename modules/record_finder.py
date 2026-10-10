# lang: Python 3.10+
# file: modules/record_finder.py
# deps: stdlib (plistlib, json), pymobiledevice3 (guardé)
# skill refs: ios-pentesting-tricks §1 (non-jailbreak setup), recon-and-methodology

"""Recherche, validation, test et installation de pairing records iOS.

Importable :
    from modules.record_finder import find_pairing_records, test_pairing_record

Runnable seul :
    python -m modules.record_finder [find|test|install] [args]
"""

import argparse
import json
import logging
import os
import plistlib
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("afu.record_finder")

try:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.afc import AfcService
    PMD3 = True
except ImportError:
    PMD3 = False

REQUIRED_FIELDS = ("DeviceCertificate", "HostCertificate",
                   "RootCertificate", "HostPrivateKey")

LOCKDOWN_PATHS = {
    "linux": [
        Path("/var/lib/lockdown/"),
        Path("/var/db/lockdown/"),
        Path.home() / ".config/lockdown/",
        Path.home() / ".local/share/lockdown/",
        # pymobiledevice3 / iphone-afu stockent parfois ici
        Path.home() / ".iphone_afu/",
    ],
    "darwin": [
        Path("/var/db/lockdown/"),
        Path.home() / "Library/Lockdown/",
        Path.home() / ".iphone_afu/",
    ],
    "windows": [
        Path(os.environ.get("ALLUSERSPROFILE", "C:/ProgramData")) / "Apple/Lockdown/",
        Path(os.environ.get("APPDATA", "")) / "Apple Computer/Lockdown/",
        Path(os.environ.get("APPDATA", "")) / "Apple/Lockdown/",
        # iTunes moderne (Microsoft Store)
        Path(os.environ.get("LOCALAPPDATA", "")) / "Apple/MobileSync/Lockdown/",
        # outils tiers (iMazing / 3uTools)
        Path(os.environ.get("APPDATA", "")) / "DigiDNA/iMazing/Lockdown/",
        Path(os.environ.get("APPDATA", "")) / "3uTools/Lockdown/",
        Path.home() / ".iphone_afu/",
    ],
}

PLATFORM_ALIASES = {"mac": "darwin", "macos": "darwin", "darwin": "darwin",
                    "windows": "windows", "win": "windows", "win32": "windows",
                    "linux": "linux"}


@dataclass
class PairingRecord:
    path:         Path
    udid:         str
    host_id:      str
    system_buid:  str
    device_cert:  bool
    host_cert:    bool
    root_cert:    bool
    host_private: bool
    wifi_mac:     Optional[str]
    valid:        bool
    error:        Optional[str] = None


def resolve_platform(platform: Optional[str] = None) -> str:
    """Normalise la plateforme : 'mac'→'darwin', None → auto (sys.platform)."""
    if platform:
        key = PLATFORM_ALIASES.get(platform.lower())
        if key is None:
            raise ValueError(f"plateforme inconnue : {platform}")
        return key
    return PLATFORM_ALIASES.get(sys.platform, "linux")


def search_paths(platform: Optional[str] = None) -> list[Path]:
    """Chemins de recherche des pairing records pour la plateforme donnée."""
    return list(LOCKDOWN_PATHS[resolve_platform(platform)])


def install_paths(platform: Optional[str] = None) -> list[Path]:
    """Chemins d'installation du pairing record (order = priorité)."""
    return {
        "linux": [
            Path("/var/lib/lockdown"),
            Path.home() / ".config/lockdown",
        ],
        "darwin": [
            Path("/var/db/lockdown"),
        ],
        "windows": [
            Path(os.environ.get("ALLUSERSPROFILE", "C:/ProgramData")) / "Apple/Lockdown",
        ],
    }[resolve_platform(platform)]


def _b(v) -> bool:
    return v is not None and v != b"" and v != ""


def _s(v) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="replace")
    return str(v) if v is not None else ""


def _load_record_file(path: Path) -> dict:
    """Charge un record .plist ou .json. Lève ValueError si illisible."""
    raw = path.read_bytes()
    if path.suffix.lower() == ".json" or raw.lstrip()[:1] in (b"{", b"["):
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except ValueError as e:
            raise ValueError(f"JSON invalide : {e}") from e
        if not isinstance(data, dict):
            raise ValueError("record JSON : dict attendu")
        return data
    try:
        data = plistlib.loads(raw)
    except Exception as e:
        raise ValueError(f"plist invalide : {e}") from e
    if not isinstance(data, dict):
        raise ValueError("record plist : dict attendu")
    return data


def validate_record(record_path: Path) -> PairingRecord:
    """Parse le record et vérifie les 4 champs requis (DeviceCertificate, HostCertificate, RootCertificate, HostPrivateKey)."""
    record_path = Path(record_path)
    base: dict[str, Any] = {
        "path": record_path, "udid": record_path.stem, "host_id": "",
        "system_buid": "", "device_cert": False, "host_cert": False,
        "root_cert": False, "host_private": False, "wifi_mac": None,
        "valid": False, "error": None,
    }
    try:
        data = _load_record_file(record_path)
    except (OSError, ValueError) as e:
        base["error"] = str(e)
        return PairingRecord(**base)

    base["device_cert"] = _b(data.get("DeviceCertificate"))
    base["host_cert"] = _b(data.get("HostCertificate"))
    base["root_cert"] = _b(data.get("RootCertificate"))
    base["host_private"] = _b(data.get("HostPrivateKey"))
    base["host_id"] = _s(data.get("HostID"))
    base["system_buid"] = _s(data.get("SystemBUID"))
    base["wifi_mac"] = _s(data.get("WiFiMACAddress")) or None
    udid = _s(data.get("UDID"))
    if udid:
        base["udid"] = udid
    base["valid"] = all(base[f] for f in
                        ("device_cert", "host_cert", "root_cert", "host_private"))
    missing = [name for name, key in (("DeviceCertificate", "device_cert"),
                                      ("HostCertificate", "host_cert"),
                                      ("RootCertificate", "root_cert"),
                                      ("HostPrivateKey", "host_private"))
               if not base[key]]
    if missing:
        base["error"] = "champs manquants : " + ", ".join(missing)
    return PairingRecord(**base)


def find_pairing_records(target_udid: Optional[str] = None,
                         platform: Optional[str] = None,
                         roots: Optional[list] = None) -> list[PairingRecord]:
    """Scanne les LOCKDOWN_PATHS (*.plist + *.json) et retourne les records (valides d'abord)."""
    paths = [Path(p) for p in roots] if roots is not None else search_paths(platform)
    records: list[PairingRecord] = []
    seen: set[Path] = set()
    for root in paths:
        if not root.is_dir():
            continue
        candidates = [p for p in sorted(root.glob("*.plist")) if p.is_file()]
        candidates += [p for p in sorted(root.glob("*.json")) if p.is_file()]
        for cand in candidates:
            if cand in seen or cand.name in ("debug.log",):
                continue
            seen.add(cand)
            rec = validate_record(cand)
            if target_udid and rec.udid.lower() != str(target_udid).lower():
                continue
            records.append(rec)
    records.sort(key=lambda r: (not r.valid, r.udid))
    log.debug("find_pairing_records: %d record(s) sur %d chemin(s)", len(records), len(paths))
    return records


def export_record(record: PairingRecord, output_path: Path) -> Path:
    """Copie le record vers output_path (répertoire → <UDID>.plist)."""
    output_path = Path(output_path)
    if output_path.is_dir() or not output_path.suffix:
        output_path.mkdir(parents=True, exist_ok=True)
        suffix = record.path.suffix or ".plist"
        output_path = output_path / f"{record.udid}{suffix}"
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(record.path, output_path)
    log.info("export_record: %s → %s", record.path, output_path)
    return output_path


def test_pairing_record(record_path: Path) -> dict:
    """
    Teste un pairing record contre le device actuellement branché (5 étapes).
    Retourne {step_1_parse, step_2_load, step_3_afu, step_4_afc, step_5_services,
              device_info, error}.
    """
    result = {
        "step_1_parse": False, "step_2_load": False, "step_3_afu": False,
        "step_4_afc": False, "step_5_services": [], "device_info": {},
        "error": None,
    }
    record_path = Path(record_path)

    # 1. parse + champs requis
    try:
        data = _load_record_file(record_path)
    except (OSError, ValueError) as e:
        result["error"] = f"parse : {e}"
        return result
    missing = [f for f in REQUIRED_FIELDS if not _b(data.get(f))]
    if missing:
        result["error"] = "record incomplet : " + ", ".join(missing)
        return result
    result["step_1_parse"] = True

    if not PMD3:
        result["error"] = "pymobiledevice3 non installé — pip install pymobiledevice3"
        return result

    # 2. LockdownClient
    try:
        ld = create_using_usbmux(pair_record=data)
    except Exception as e:
        result["error"] = f"lockdown : {e}"
        return result
    result["step_2_load"] = True

    # 3. AFU confirmé (les valeurs device répondent)
    try:
        product_version = ld.get_value(key="ProductVersion")
        result["step_3_afu"] = bool(product_version)
        result["device_info"] = {
            "name": getattr(ld, "display_name", None),
            "ios": product_version,
            "model": getattr(ld, "product_type", None),
            "udid": getattr(ld, "udid", None) or _s(data.get("UDID")),
        }
    except Exception as e:
        result["error"] = f"device injoignable (BFU ?) : {e}"
        return result

    # 4. AFC accessible
    if result["step_3_afu"]:
        try:
            entries = AfcService(ld).listdir("/")
            result["step_4_afc"] = entries is not None
        except Exception as e:
            result["error"] = f"AFC bloqué : {e}"

    # 5. services disponibles
    try:
        allv = getattr(ld, "all_values", None)
        services = []
        if isinstance(allv, dict):
            disc = allv.get("ServiceDiscovery") or allv.get("ServiceDiscoveryCache")
            if isinstance(disc, dict):
                services = sorted(str(k) for k in disc.keys())
        result["step_5_services"] = services[:80]
    except Exception as e:
        log.debug("test_pairing_record: services — %s", e)

    return result


def install_pairing_record(record_path: Path, *,
                           platform: Optional[str] = None,
                           roots: Optional[list] = None) -> dict:
    """Copie le record aux emplacements standard (multi-OS). Retourne {installed_paths, udid, error}."""
    record_path = Path(record_path)
    rec = validate_record(record_path)
    targets = [Path(r) for r in roots] if roots is not None else install_paths(platform)
    installed: list[str] = []
    errors: list[str] = []
    for target in targets:
        try:
            target.mkdir(parents=True, exist_ok=True)
            dest = target / f"{rec.udid}.plist"
            if record_path.suffix.lower() == ".plist":
                shutil.copy2(record_path, dest)
            else:
                # record JSON (format iphone-afu) → resérialisé en plist
                data = _load_record_file(record_path)
                with dest.open("wb") as fh:
                    plistlib.dump(data, fh)
            installed.append(str(dest))
            log.info("install_pairing_record: %s → %s", record_path, dest)
        except (OSError, PermissionError, ValueError) as e:
            errors.append(f"{target}: {e}")
    return {
        "installed_paths": installed,
        "udid": rec.udid,
        "error": None if installed else ("; ".join(errors) or "aucun chemin disponible"),
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="record_finder",
                                     description="Recherche/validation de pairing records iOS")
    sub = parser.add_subparsers(dest="cmd")
    p_find = sub.add_parser("find")
    p_find.add_argument("--udid")
    p_find.add_argument("--os", choices=["windows", "mac", "linux"])
    p_test = sub.add_parser("test")
    p_test.add_argument("record")
    p_install = sub.add_parser("install")
    p_install.add_argument("record")
    args = parser.parse_args(argv)

    if args.cmd == "find":
        records = find_pairing_records(args.udid, args.os)
        if not records:
            print("[!] Aucun pairing record — chemins scannés :")
            for p in search_paths(args.os):
                print(f"    {p}")
        for r in records:
            print(f"{'OK' if r.valid else 'INCOMPLET'} {r.udid} → {r.path}")
        return 0
    if args.cmd == "test":
        res = test_pairing_record(Path(args.record))
        for i, key in enumerate(("step_1_parse", "step_2_load", "step_3_afu", "step_4_afc"), 1):
            print(f"{'OK' if res[key] else 'FAIL'} étape {i}")
        if res["error"]:
            print(f"[!] {res['error']}")
        if res["device_info"]:
            print(f"    device: {res['device_info']}")
        return 0 if res["step_4_afc"] else 1
    if args.cmd == "install":
        res = install_pairing_record(Path(args.record))
        for p in res["installed_paths"]:
            print(f"[+] installé → {p}")
        if res["error"]:
            print(f"[!] {res['error']}")
            return 1
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
