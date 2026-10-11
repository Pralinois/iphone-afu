# lang: Python 3.10+
# file: modules/plist_extractor.py
# deps: stdlib (plistlib gère XML et binary plists), sqlite3
# skill refs: ios-pentesting-tricks §7

"""Extraction des 9 data storage locations iOS (backup dézippé / container AFC).

Importable :
    from modules.plist_extractor import extract_all_storage, extract_binary_cookies

Runnable seul :
    python -m modules.plist_extractor --backup <dir> [-b bundle] [-o plist_out]
"""

import argparse
import json
import logging
import plistlib
import shutil
import sqlite3
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("afu.plist_extractor")

try:
    from modules.pymd3_compat import run_maybe_async as _maybe
except ImportError:
    def _maybe(value):
        return value

STORAGE_LOCATIONS = {
    "NSUserDefaults":   "Library/Preferences/*.plist",
    "CoreData":         "Library/Application Support/*.sqlite*",
    "Cookies":          "Library/Cookies/Cookies.binarycookies",
    "Caches":           "Library/Caches/**/*",
    "Screenshots":      "Library/Caches/Snapshots/**/*.png",
    "KeyboardCache":    "Library/Keyboard/",
    "Pasteboard":       None,   # runtime only — via Objection
    "WebKitData":       "Library/WebKit/",
    "CoreDataStores":   "Library/Application Support/",
}

MAX_ROWS_PER_TABLE = 500
MAX_FILES_PER_LOCATION = 200


def extract_binary_cookies(path: Path) -> list[dict]:
    """Parse Cookies.binarycookies (NSHTTPCookieStorage) → liste de cookies."""
    data = Path(path).read_bytes()
    if len(data) < 8 or data[:4] != b"cook":
        raise ValueError(f"pas un Cookies.binarycookies valide : {path}")
    num_pages = struct.unpack(">I", data[4:8])[0]
    pos = 8 + 4 * num_pages
    page_sizes = [struct.unpack(">I", data[8 + 4 * i:12 + 4 * i])[0] for i in range(num_pages)]

    cookies: list[dict] = []
    for psize in page_sizes:
        page = data[pos:pos + psize]
        pos += psize
        if len(page) < 8:
            continue
        count = struct.unpack("<I", page[4:8])[0]
        offsets = []
        for i in range(count):
            if 8 + 4 * i + 4 > len(page):
                break
            offsets.append(struct.unpack("<I", page[8 + 4 * i:12 + 4 * i])[0])
        for off in offsets:
            rec = page[off:]
            if len(rec) < 56:
                continue
            flags = struct.unpack("<I", rec[8:12])[0]
            url_off = struct.unpack("<I", rec[16:20])[0]
            name_off = struct.unpack("<I", rec[20:24])[0]
            path_off = struct.unpack("<I", rec[24:28])[0]
            value_off = struct.unpack("<I", rec[28:32])[0]
            expires = struct.unpack("<d", rec[40:48])[0]

            def read_str(rel: int) -> str:
                start = 56 + rel
                if start >= len(rec):
                    return ""
                end = rec.find(b"\x00", start)
                return rec[start:end if end != -1 else len(rec)].decode("utf-8", errors="replace")

            def ts(val: float) -> Optional[str]:
                try:
                    if val <= 0:
                        return None
                    return datetime.fromtimestamp(val, tz=timezone.utc).isoformat(timespec="seconds")
                except (OverflowError, OSError, ValueError):
                    return None

            cookies.append({
                "name": read_str(name_off),
                "value": read_str(value_off),
                "domain": read_str(url_off),
                "path": read_str(path_off),
                "expires": ts(expires),
                "flags": flags,
            })
    return cookies


def extract_preferences(pref_dir: Path) -> dict:
    """Parse tous les .plist d'un répertoire Preferences → {bundle_id: {key: value}}."""
    out: dict = {}
    for p in sorted(Path(pref_dir).glob("*.plist")):
        try:
            parsed = plistlib.loads(p.read_bytes())
        except Exception as e:
            log.warning("plist illisible %s : %s", p.name, e)
            continue
        out[p.stem] = parsed
    return out


def extract_sqlite_tables(db_path: Path, max_rows: int = MAX_ROWS_PER_TABLE) -> dict:
    """Extrait toutes les tables d'une DB SQLite (≤ max_rows par table)."""
    uri = f"file:{Path(db_path).as_posix()}?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    con.row_factory = sqlite3.Row
    out: dict = {}
    try:
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for table in tables:
            try:
                # noms issus du schéma sqlite_master (pas d'input utilisateur) ; identifiant échappé
                safe_table = str(table).replace('"', '""')
                query = f'SELECT * FROM "{safe_table}" LIMIT ?'  # nosec B608 — identifiant issu du schéma, échappé
                rows = con.execute(query, (max_rows,)).fetchall()
                out[table] = [dict(r) for r in rows]
            except sqlite3.Error as e:
                out[table] = [{"_error": str(e)}]
    finally:
        con.close()
    return out


def _json_default(obj):
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def _copy_matches(source_dir: Path, pattern: str, dest_dir: Path) -> int:
    count = 0
    for p in sorted(source_dir.glob(pattern)):
        if not p.is_file() or count >= MAX_FILES_PER_LOCATION:
            break
        rel = p.relative_to(source_dir)
        target = dest_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(p, target)
            count += 1
        except OSError as e:
            log.warning("copie échouée %s : %s", p, e)
    return count


def extract_all_storage(source_dir: Path, output_dir: Path,
                        bundle_id: Optional[str] = None) -> dict:
    """Extrait les 9 locations dans output_dir/<location>/. Retourne le résumé."""
    source_dir = Path(source_dir)
    output_dir = Path(output_dir)
    if not source_dir.is_dir():
        raise RuntimeError(f"répertoire source introuvable : {source_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    summary: dict = {}

    if bundle_id:
        # containers de backup/app : les prefs portent le nom du bundle
        pref_glob = f"Library/Preferences/{bundle_id}.plist"
    else:
        pref_glob = STORAGE_LOCATIONS["NSUserDefaults"]

    for location, pattern in STORAGE_LOCATIONS.items():
        entry = {"found": False, "count": 0, "path": str(output_dir / location),
                 "detail": ""}
        if pattern is None:
            entry["detail"] = "runtime only — utiliser `objection --cmd pasteboard`"
            summary[location] = entry
            continue

        if location == "NSUserDefaults":
            target = output_dir / location
            target.mkdir(parents=True, exist_ok=True)
            glob = pref_glob if bundle_id else pattern
            files = [p for p in source_dir.glob(glob) if p.is_file()]
            if files:
                prefs = extract_preferences(files[0].parent)
                if bundle_id:
                    prefs = {k: v for k, v in prefs.items() if bundle_id in k}
                target.mkdir(parents=True, exist_ok=True)
                (target / "preferences.json").write_text(
                    json.dumps(prefs, indent=2, ensure_ascii=False, default=_json_default),
                    encoding="utf-8")
                for p in files[:MAX_FILES_PER_LOCATION]:
                    shutil.copy2(p, target / p.name)
                entry.update(found=True, count=len(files), detail=f"{len(prefs)} domaines parsés")
        elif location == "Cookies":
            src = source_dir / pattern
            if src.is_file():
                target = output_dir / location
                target.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, target / "Cookies.binarycookies")
                try:
                    cookies = extract_binary_cookies(src)
                    (target / "cookies.json").write_text(
                        json.dumps(cookies, indent=2, ensure_ascii=False), encoding="utf-8")
                    entry.update(found=True, count=len(cookies),
                                 detail=f"{len(cookies)} cookies parsés")
                except ValueError as e:
                    entry.update(found=True, count=1, detail=f"copié (parse: {e})")
        elif location in ("CoreData", "CoreDataStores"):
            target = output_dir / location
            target.mkdir(parents=True, exist_ok=True)
            count = _copy_matches(source_dir, pattern.replace("*.sqlite*", "*"), target)
            dbs = list(target.rglob("*.sqlite*"))[:5]
            for db in dbs:
                try:
                    tables = extract_sqlite_tables(db)
                    (db.parent / f"{db.name}.tables.json").write_text(
                        json.dumps(tables, indent=2, ensure_ascii=False, default=_json_default),
                        encoding="utf-8")
                except sqlite3.Error as e:
                    log.warning("sqlite %s : %s", db, e)
            if count:
                entry.update(found=True, count=count, detail=f"{len(dbs)} DB parsées")
        elif location == "KeyboardCache":
            target = output_dir / location
            target.mkdir(parents=True, exist_ok=True)
            count = _copy_matches(source_dir, pattern + "*", target)
            if count:
                entry.update(found=True, count=count)
        elif pattern.endswith("/"):
            target = output_dir / location
            target.mkdir(parents=True, exist_ok=True)
            count = _copy_matches(source_dir, pattern.rstrip("/") + "/**/*", target)
            if count:
                entry.update(found=True, count=count)
        else:
            target = output_dir / location
            target.mkdir(parents=True, exist_ok=True)
            count = _copy_matches(source_dir, pattern, target)
            if count:
                entry.update(found=True, count=count)

        summary[location] = entry

    (output_dir / "storage_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def extract_all_storage_afc(lockdown, output_dir: Path,
                            bundle_id: Optional[str] = None) -> dict:
    """Variante device : HouseArrest vendor container → même extraction sur copie locale."""
    if not bundle_id:
        raise RuntimeError("--bundle-id requis pour l'extraction AFC (container de l'app)")
    try:
        from pymobiledevice3.services.house_arrest import HouseArrestService
    except ImportError as e:
        raise RuntimeError(
            "HouseArrest indisponible dans cette version de pymobiledevice3 — "
            "utilise --backup (backup dézippé) à la place"
        ) from e
    try:
        # pymobiledevice3 ≥ 11 : factory async create(); anciennes versions : constructeur
        if hasattr(HouseArrestService, "create"):
            svc = _maybe(HouseArrestService.create(lockdown, bundle_id))
        else:
            # anciennes versions : __init__(lockdown, bundle_id)
            svc = HouseArrestService(lockdown, bundle_id)  # type: ignore[arg-type]
    except Exception as e:
        raise RuntimeError(f"HouseArrest refusé pour {bundle_id} : {e}") from e
    afc = getattr(svc, "afc", svc)

    staging = Path(output_dir) / "_afc_staging"
    staging.mkdir(parents=True, exist_ok=True)

    def walk(remote: str, local: Path, depth: int = 0):
        if depth > 6:
            return
        try:
            entries = _maybe(afc.listdir(remote))
        except Exception:
            return
        local.mkdir(parents=True, exist_ok=True)
        for entry in entries:
            if entry in (".", ".."):
                continue
            rpath = f"{remote}/{entry}"
            lpath = local / entry
            try:
                info = _maybe(afc.stat(rpath))
                if info.get("st_ifmt") == "S_IFDIR":
                    walk(rpath, lpath, depth + 1)
                else:
                    lpath.write_bytes(_maybe(afc.get_file_contents(rpath)))
            except Exception as e:
                log.warning("AFC %s : %s", rpath, e)

    for remote in ("Library/Preferences", "Library/Cookies", "Library/Caches",
                   "Library/Application Support", "Library/Keyboard", "Library/WebKit"):
        walk(remote, staging / remote)

    summary = extract_all_storage(staging, Path(output_dir), bundle_id=None)
    try:
        _maybe(svc.close())
    except Exception as e:
        log.debug("HouseArrest close: %s", e)
    shutil.rmtree(staging, ignore_errors=True)
    return summary


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="plist_extractor",
                                     description="Extrait les 9 locations de data storage iOS")
    parser.add_argument("--backup", help="Chemin vers backup dézippé")
    parser.add_argument("--afc", action="store_true", help="Extraire via AFC (device requis)")
    parser.add_argument("-b", "--bundle-id", dest="bundle_id", help="Filtrer par bundle ID")
    parser.add_argument("-o", "--output", default="./plist_out")
    args = parser.parse_args(argv)

    if args.backup:
        summary = extract_all_storage(Path(args.backup), Path(args.output),
                                      bundle_id=args.bundle_id)
    elif args.afc:
        print("[!] mode --afc nécessite un device — lance via: python iphone_afu.py plist-dump --afc -b <bundle>")
        return 1
    else:
        parser.print_help()
        return 1

    for location, entry in summary.items():
        state = "OK" if entry["found"] else "--"
        print(f"[{state}] {location:16s} count={entry['count']:4d} {entry['detail']}")
    print(f"[+] résumé → {Path(args.output) / 'storage_summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
