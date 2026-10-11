# lang: Python 3.10+
# file: modules/ptp_extractor.py
# deps: gphoto2 (pip install gphoto2), libgphoto2 système
# target: Linux natif / VM Linux
# skill ref: ios-pentesting-tricks (non-jailbreak extraction)

"""Extraction PTP via libgphoto2/python-gphoto2 — zéro trust, zéro pairing record.

Condition unique : iPhone déverrouillé + « Allow » tapé une fois.
Après le tap, la session survit au reverrouillage.

Importable :
    from modules.ptp_extractor import detect_camera, extract_files

Runnable seul :
    python -m modules.ptp_extractor -o ./photos [--wait] [--resume]
"""

import argparse
import csv
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

try:
    import gphoto2 as gp
    GPHOTO = True
except ImportError:
    gp = None
    GPHOTO = False

try:
    from PIL import Image
    PILLOW = True
except ImportError:
    PILLOW = False

log = logging.getLogger("afu.ptp")

MEDIA_EXTS = {"jpg", "jpeg", "heic", "heif", "mov", "mp4", "m4v",
              "png", "raw", "dng", "aae", "tif", "tiff"}
MAX_WALK_DEPTH = 4
RETRIES = 3
RETRY_DELAY = 2.0


@dataclass
class PtpFile:
    """Équivalent duck-typé de gp.CameraFilePath (folder + name)."""
    folder: str
    name: str


def _no_gphoto() -> RuntimeError:
    return RuntimeError(
        "gphoto2 manquant — pip install gphoto2 && sudo apt install libgphoto2-dev"
    )


def _make_file_path(folder: str, name: str):
    """Construit un gp.CameraFilePath si disponible, sinon PtpFile."""
    if gp is not None and hasattr(gp, "CameraFilePath"):
        try:
            fp = gp.CameraFilePath()
            fp.folder, fp.name = folder, name
            return fp
        except Exception as e:
            log.debug("CameraFilePath indisponible: %s", e)
    return PtpFile(folder=folder, name=name)


def _folder_name(folder) -> str:
    return str(getattr(folder, "name", folder)).strip("/")


def detect_camera(wait: bool = True, timeout: int = 60, emit: Optional[Callable] = None):
    """Détecte le premier device PTP (autodetect + init). None si absent."""
    if not GPHOTO:
        raise _no_gphoto()
    emit = emit or (lambda m: None)
    deadline = time.time() + (timeout if wait else 0)
    first = True
    while True:
        cameras = []
        try:
            cameras = gp.Camera.autodetect()
        except Exception as e:
            log.debug("autodetect: %s", e)
        if cameras:
            try:
                model, port = cameras[0][0], cameras[0][1]
            except Exception:
                model, port = (str(cameras[0]), "")
            try:
                camera = gp.Camera()
                port_info_list = gp.PortInfoList()
                port_info_list.load()
                idx = port_info_list.lookup_path(port)
                camera.set_port_info(port_info_list[idx])
                camera.init()
                emit(f"    Détecté : {model} ({port})")
                return camera
            except Exception as e:
                emit(f"    Device vu mais init échouée : {e}")
        if not wait or time.time() >= deadline:
            return None
        if first:
            emit("    État 1 — branche l'iPhone (déverrouillé) via USB…")
            first = False
        time.sleep(3)


def find_dcim_folder(camera, context, emit: Optional[Callable] = None) -> Optional[str]:
    """Localise le chemin DCIM du storage réel (None si verrouillé / Allow non tapé)."""
    emit = emit or (lambda m: None)
    try:
        root_folders = camera.folder_list_folders("/", context)
    except Exception as e:
        emit(f"    État 2/3 — storage inaccessible ({e})")
        return None
    for f in root_folders:
        name = _folder_name(f)
        candidate = f"/{name}/DCIM"
        try:
            camera.folder_list_files(candidate, context)
            return candidate
        except Exception:
            continue
    try:
        camera.folder_list_files("/DCIM", context)
        return "/DCIM"
    except Exception:
        return None


def check_storage_accessible(camera, context) -> bool:
    """True si le storage réel (DCIM) est accessible — pas 0xfeedface."""
    return find_dcim_folder(camera, context) is not None


def wait_for_unlock(camera, context, timeout: int = 120,
                    emit: Optional[Callable] = None) -> Optional[str]:
    """Attend le déverrouillage + « Allow » (retry 3s). Retourne le chemin DCIM ou None."""
    emit = emit or (lambda m: None)
    deadline = time.time() + timeout
    first = True
    while True:
        dcim = find_dcim_folder(camera, context)
        if dcim:
            emit(f"    État 4 — DCIM accessible ({dcim})")
            return dcim
        if time.time() >= deadline:
            return None
        if first:
            emit("    En attente du déverrouillage… déverrouille l'iPhone et tape « Allow »")
            first = False
        time.sleep(3)


def _walk(camera, context, folder: str, out: list, depth: int = 0) -> None:
    try:
        names = camera.folder_list_files(folder, context)
    except Exception as e:
        log.debug("list_files %s: %s", folder, e)
        names = []
    for name in names:
        ext = str(name).rsplit(".", 1)[-1].lower() if "." in str(name) else ""
        if ext in MEDIA_EXTS:
            out.append(_make_file_path(folder, str(name)))
    if depth >= MAX_WALK_DEPTH:
        return
    try:
        subfolders = camera.folder_list_folders(folder, context)
    except Exception:
        subfolders = []
    for f in subfolders:
        sub = _folder_name(f)
        _walk(camera, context, f"{folder.rstrip('/')}/{sub}", out, depth + 1)


def list_all_files(camera, context, folder: Optional[str] = None) -> list:
    """Walk récursif du filesystem PTP → médias filtrés. folder=None → DCIM auto."""
    if folder is None:
        folder = find_dcim_folder(camera, context) or "/"
    out: list = []
    _walk(camera, context, folder, out)
    return out


def _remote_size(camera, context, f) -> Optional[int]:
    try:
        info = camera.file_get_info(f.folder, f.name, context)
        size = getattr(getattr(info, "file", None), "size", None)
        return int(size) if size is not None else None
    except Exception:
        return None


def _relative_dest(output_dir: Path, f) -> Path:
    """Préserve la structure à partir de DCIM/ (sinon dossier seul)."""
    folder = str(f.folder).lstrip("/")
    idx = folder.find("DCIM")
    rel = folder[idx:] if idx >= 0 else folder
    return Path(output_dir) / rel / str(f.name)


def extract_files(
    camera,
    context,
    files: list,
    output_dir: Path,
    resume: bool = False,
    progress_cb: Optional[Callable] = None,
) -> dict:
    """Télécharge chaque fichier vers output_dir (structure DCIM préservée)."""
    stats: dict[str, Any] = {"copied": 0, "skipped": 0, "errors": 0,
                             "total_bytes": 0, "error_list": []}
    output_dir = Path(output_dir)
    total = len(files)
    for i, f in enumerate(files, 1):
        dest = _relative_dest(output_dir, f)
        remote_size = _remote_size(camera, context, f)

        if resume and dest.exists():
            if remote_size is not None and dest.stat().st_size == remote_size:
                stats["skipped"] += 1
                stats["total_bytes"] += dest.stat().st_size
                if progress_cb:
                    progress_cb(i, total, str(f.name), stats["total_bytes"])
                continue
            try:
                dest.unlink()
            except OSError:
                pass

        ok = False
        last_err = None
        t0 = time.time()
        for attempt in range(1, RETRIES + 1):
            try:
                camera_file = camera.file_get(f.folder, f.name,
                                              gp.GP_FILE_TYPE_NORMAL, context)
                dest.parent.mkdir(parents=True, exist_ok=True)
                camera_file.save(str(dest))
                ok = True
                break
            except Exception as e:
                last_err = e
                log.warning("extract %s/%s tentative %d/%d — %s",
                            f.folder, f.name, attempt, RETRIES, e)
                if attempt < RETRIES:
                    time.sleep(RETRY_DELAY)
        elapsed = time.time() - t0

        if ok:
            size = dest.stat().st_size if dest.exists() else 0
            stats["copied"] += 1
            stats["total_bytes"] += size
            if elapsed > 300:
                stats["error_list"].append({"file": str(f.name), "error":
                                            f"lent ({elapsed:.0f}s) — stall possible"})
        else:
            stats["errors"] += 1
            stats["error_list"].append({"file": f"{f.folder}/{f.name}",
                                        "error": str(last_err) or "échec"})
        if progress_cb:
            progress_cb(i, total, str(f.name), stats["total_bytes"])
    return stats


def _exif_date(path: Path) -> Optional[str]:
    if not PILLOW or path.suffix.lower() not in (".jpg", ".jpeg", ".heic", ".heif"):
        return None
    try:
        with Image.open(path) as img:
            raw = img.getexif().get(306)
            return str(raw) if raw else None
    except Exception:
        return None


def build_manifest(output_dir: Path) -> dict:
    """manifest.json + manifest.csv (mêmes champs que le manifest AFC)."""
    output_dir = Path(output_dir)
    entries: list[dict[str, Any]] = []
    for p in sorted(output_dir.rglob("*")):
        if not p.is_file() or p.name in ("manifest.json", "manifest.csv"):
            continue
        st = p.stat()
        entries.append({
            "path": p.relative_to(output_dir).as_posix(),
            "size_bytes": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            "ext": p.suffix.lower(),
            "exif_date": _exif_date(p),
        })
    entries.sort(key=lambda e: e["mtime"], reverse=True)
    (output_dir / "manifest.json").write_text(
        json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")
    with (output_dir / "manifest.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["path", "size_bytes", "mtime", "ext", "exif_date"])
        writer.writeheader()
        writer.writerows(entries)
    return {"files": len(entries), "manifest": str(output_dir / "manifest.json")}


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="ptp_extractor",
                                     description="Extraction PTP — zéro trust, zéro pairing record")
    parser.add_argument("-o", "--output", default="./iphone_ptp_out")
    parser.add_argument("--wait", action="store_true", help="Attendre le déverrouillage (timeout 120s)")
    parser.add_argument("--resume", action="store_true", help="Reprendre une extraction interrompue")
    parser.add_argument("--no-manifest", action="store_true", help="Ne pas générer manifest.json")
    parser.add_argument("--max", type=int, default=0, help="Nombre max de fichiers (0 = tous)")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    if not GPHOTO:
        print(f"[!] {_no_gphoto()}")
        return 1

    emit = print
    camera = detect_camera(wait=True, timeout=args.wait and 120 or 10, emit=emit)
    if camera is None:
        print("[!] Aucun device PTP détecté.")
        return 1
    context = gp.Context()
    dcim = find_dcim_folder(camera, context, emit=emit)
    if dcim is None and args.wait:
        dcim = wait_for_unlock(camera, context, timeout=120, emit=emit)
    if dcim is None:
        print("[!] DCIM inaccessible — déverrouille l'iPhone et tape « Allow ».")
        return 1

    files = list_all_files(camera, context, folder=dcim)
    if args.max:
        files = files[:args.max]
    print(f"[*] {len(files)} fichiers média — extraction → {args.output}")

    def cb(i, total, name, total_bytes):
        print(f"  [{i}/{total}] {name} ({total_bytes // 1024 // 1024} MB)")

    stats = extract_files(camera, context, files, Path(args.output),
                          resume=args.resume, progress_cb=cb)
    if not args.no_manifest:
        m = build_manifest(Path(args.output))
        print(f"[+] manifest : {m['files']} entrées → {m['manifest']}")
    print(f"[+] Terminé — {stats['copied']} copiés, {stats['skipped']} skippés, "
          f"{stats['errors']} erreurs, {stats['total_bytes'] / 1024 / 1024:.1f} MB")
    return 0 if stats["errors"] == 0 else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
