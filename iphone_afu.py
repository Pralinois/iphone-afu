#!/usr/bin/env python3
# lang: Python 3.10+
# file: iphone_afu.py
# target: Linux natif / VM Linux sur Windows
# deps: pymobiledevice3, rich, textual, frida-tools

"""
iPhone AFU Extraction Tool
CLI: python iphone_afu.py <command> [options]
TUI: python iphone_afu.py tui
"""

import argparse
import asyncio
import csv
import json
import logging
import os
import plistlib
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# ─── logging structuré (fichier rotatif + console WARNING+) ──────────────────
LOG_PATH = Path.home() / ".iphone_afu" / "debug.log"

# Consoles non-UTF8 (Windows cp1252, locale C des VM) : ne jamais crasher sur l'encodage
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="backslashreplace")
    except (AttributeError, ValueError):
        pass

_fmt = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(funcName)s — %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("iphone_afu")
log.setLevel(logging.DEBUG)
log.propagate = False

try:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _fh = RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    _fh.setFormatter(_fmt)
    _fh.setLevel(logging.DEBUG)
    log.addHandler(_fh)
except OSError:
    pass  # home non inscriptible — pas de log fichier

_ch = logging.StreamHandler()
_ch.setFormatter(_fmt)
_ch.setLevel(logging.WARNING)   # console : WARNING+ seulement
log.addHandler(_ch)

# ─── cryptography (pairing record chiffré) ───────────────────────────────────
try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    CRYPTO = True
except ImportError:
    CRYPTO = False

# ─── Pillow (EXIF du manifest — optionnel) ───────────────────────────────────
try:
    from PIL import Image
    PILLOW = True
except ImportError:
    PILLOW = False

# ─── rich (affichage CLI) ────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.panel import Panel
    from rich.text import Text
    from rich import print as rprint
    RICH = True
except ImportError:
    RICH = False
    print("[!] rich manquant — pip install rich")

# ─── textual (TUI) ───────────────────────────────────────────────────────────
try:
    from textual.app import App, ComposeResult
    from textual.widgets import Header, Footer, Button, Static, Log, ProgressBar, Label, Input
    from textual.containers import Horizontal, Vertical, ScrollableContainer
    from textual.reactive import reactive
    from textual.screen import ModalScreen
    TEXTUAL = True
except ImportError:
    TEXTUAL = False

# ─── pymobiledevice3 ─────────────────────────────────────────────────────────
try:
    from pymobiledevice3.usbmux import list_devices
    from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
    from pymobiledevice3.services.afc import AfcService
    from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
    from pymobiledevice3.services.os_trace import OsTraceService
    from pymobiledevice3.services.installation_proxy import InstallationProxyService
    PMD3 = True
except ImportError:
    PMD3 = False

console = Console() if RICH else None


# ═══════════════════════════════════════════════════════════════════════════════
# CORE — fonctions bas niveau
# ═══════════════════════════════════════════════════════════════════════════════

def check_deps() -> dict:
    """Vérifie toutes les dépendances système et Python."""
    results = {
        "usbmuxd":        shutil.which("usbmuxd") is not None,
        "idevice_id":     shutil.which("idevice_id") is not None,
        "frida":          shutil.which("frida") is not None,
        "pymobiledevice3": PMD3,
        "rich":           RICH,
        "textual":        TEXTUAL,
    }
    log.debug(f"check_deps: {results}")
    return results


def get_connected_devices() -> list[dict]:
    """Retourne la liste des devices connectés avec leurs infos."""
    log.debug("get_connected_devices: début")
    devices = []
    if not PMD3:
        log.debug("get_connected_devices: pymobiledevice3 indisponible — 0 device")
        return devices
    try:
        raw = list_devices()
        for d in raw:
            try:
                ld = create_using_usbmux(serial=d.serial)
                info = {
                    "udid":       d.serial,
                    "name":       ld.display_name or "Unknown",
                    "ios":        ld.product_version or "Unknown",
                    "model":      ld.product_type or "Unknown",
                    "trusted":    True,
                    "lockdown":   ld,
                }
                devices.append(info)
                log.debug(f"get_connected_devices: {d.serial} trusted ({info['name']}, iOS {info['ios']})")
            except Exception as e:
                devices.append({
                    "udid":    d.serial,
                    "name":    "NOT TRUSTED",
                    "ios":     "—",
                    "model":   "—",
                    "trusted": False,
                    "lockdown": None,
                })
                log.debug(f"get_connected_devices: {d.serial} not trusted — {e}")
    except Exception as e:
        log.error(f"get_connected_devices: list_devices échoué — {e}")
    log.debug(f"get_connected_devices: {len(devices)} device(s)")
    return devices


def wait_for_trust(udid: Optional[str] = None, timeout: int = 60) -> Optional[object]:
    """
    Attend que le trust soit établi (dialog 'Faire confiance' accepté).
    Retourne le LockdownClient ou None si timeout.
    """
    log.debug(f"wait_for_trust: udid={udid} timeout={timeout}s")
    deadline = time.time() + timeout
    while time.time() < deadline:
        devs = get_connected_devices()
        for d in devs:
            if d["trusted"] and (udid is None or d["udid"] == udid):
                log.info(f"wait_for_trust: trust établi ({d['udid']})")
                return d["lockdown"]
        time.sleep(2)
    log.warning(f"wait_for_trust: timeout {timeout}s — trust non établi")
    return None


def _encrypted_record_path(output_path: Path) -> Path:
    """Ajoute le suffixe .enc si absent (mon_iphone.json → mon_iphone.json.enc)."""
    if output_path.suffix == ".enc":
        return output_path
    return output_path.with_suffix(output_path.suffix + ".enc")


def encrypt_pairing_record(data: dict, password: str) -> bytes:
    """
    Chiffre un pairing record en AES-256-GCM avec clé dérivée par scrypt.
    Format : salt(32) || nonce(12) || ciphertext
    """
    if not CRYPTO:
        raise RuntimeError("cryptography non installé — pip install cryptography")
    # scrypt : N=2^17, r=8, p=1 — calibré pour ~1s sur laptop moyen
    salt = secrets.token_bytes(32)
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    key = kdf.derive(password.encode())
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(data).encode(), None)
    return salt + nonce + ct


def decrypt_pairing_record(blob: bytes, password: str) -> dict:
    """
    Déchiffre un blob produit par encrypt_pairing_record.
    Lève ValueError si le mot de passe est mauvais (tag GCM invalide).
    """
    if not CRYPTO:
        raise RuntimeError("cryptography non installé — pip install cryptography")
    salt, nonce, ct = blob[:32], blob[32:44], blob[44:]
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    key = kdf.derive(password.encode())
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, None)
    except (InvalidTag, ValueError) as e:
        raise ValueError("Mot de passe incorrect ou record corrompu") from e
    return json.loads(plaintext)


def save_pairing_record(lockdown: object, output_path: Path, password: Optional[str] = None) -> bool:
    """Sauvegarde le pairing record (chiffré AES-GCM si password + cryptography)."""
    try:
        record = lockdown.pair_record
        if password and CRYPTO:
            output_path = _encrypted_record_path(output_path)
            output_path.write_bytes(encrypt_pairing_record(record, password))
            log.info(f"save_pairing_record: chiffré → {output_path}")
        elif password and not CRYPTO:
            log.warning("save_pairing_record: cryptography absent — record écrit en clair")
            output_path.write_text(json.dumps(record, indent=2))
        else:
            output_path.write_text(json.dumps(record, indent=2))
            log.info(f"save_pairing_record: → {output_path}")
        return True
    except Exception as e:
        log.error(f"save_pairing_record({output_path}): {e}")
        return False


def load_pairing_record(record_path: Path, password: Optional[str] = None) -> Optional[object]:
    """Charge un pairing record (.enc chiffré accepté) et retourne un LockdownClient."""
    try:
        if record_path.suffix == ".enc":
            if not CRYPTO:
                log.error("load_pairing_record: record .enc mais cryptography absent")
                return None
            if not password:
                raise ValueError(f"Record chiffré {record_path.name} : --password requis")
            record = decrypt_pairing_record(record_path.read_bytes(), password)
        else:
            record = json.loads(record_path.read_text())
        ld = create_using_usbmux(pair_record=record)
        log.info(f"load_pairing_record: {record_path} chargé")
        return ld
    except ValueError:
        raise  # mot de passe / format : remonté proprement à l'appelant
    except Exception as e:
        log.error(f"load_pairing_record({record_path}): {e}")
        return None


def tunnel_is_active() -> bool:
    """Détection best-effort du tunnel RemoteXPC (process start-tunnel vivant)."""
    pgrep = shutil.which("pgrep")
    if pgrep:
        try:
            probe = subprocess.run(
                [pgrep, "-f", "remote start-tunnel"],
                capture_output=True, text=True, timeout=5
            )
            return probe.returncode == 0 and bool(probe.stdout.strip())
        except Exception as e:
            log.debug(f"tunnel_is_active: pgrep — {e}")
    # Pas de pgrep : sonde rapide pymobiledevice3 (device joignable = tunnel présumé)
    if not PMD3:
        return False
    try:
        ld = create_using_usbmux(autopair=False)
        ld.get_value(domain="com.apple.mobile.lockdown", key="ProductVersion")
        return True
    except Exception as e:
        log.debug(f"tunnel_is_active: probe lockdown — {e}")
        return False


_tunnel_warned = False


def _warn_if_tunnel_missing():
    """Avertit une seule fois si le tunnel RemoteXPC n'est pas détecté."""
    global _tunnel_warned
    if _tunnel_warned or tunnel_is_active():
        return
    _tunnel_warned = True
    msg = "⚠ Tunnel RemoteXPC non détecté — lance: sudo python iphone_afu.py tunnel"
    log.warning(msg)
    if RICH:
        console.print(f"[yellow]{msg}[/yellow]")
    else:
        print(f"[!] {msg}")


def start_tunnel_daemon(udid: Optional[str] = None) -> subprocess.Popen:
    """
    Lance pymobiledevice3 remote start-tunnel en arrière-plan.
    Retourne le Popen pour kill propre à la sortie.
    Nécessite sudo — lève PermissionError si non-root.
    """
    if getattr(os, "geteuid", None) is None or os.geteuid() != 0:
        raise PermissionError("start-tunnel nécessite sudo — relance: sudo python iphone_afu.py tunnel")
    cmd = ["pymobiledevice3", "remote", "start-tunnel"]
    if udid:
        cmd += ["--udid", udid]
    log.debug(f"start_tunnel_daemon: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    # Attendre 3s et vérifier que le process est vivant
    time.sleep(3)
    if proc.poll() is not None:
        stderr = proc.stderr.read() if proc.stderr else ""
        raise RuntimeError(f"Tunnel mort au démarrage: {stderr[:200]}")
    log.info(f"Tunnel RemoteXPC démarré (pid={proc.pid})")
    return proc


@dataclass
class DeviceContext:
    """Résolution unique du device : pairing record (.enc) ou device connecté trusted."""
    udid: Optional[str] = None
    record_path: Optional[Path] = None
    password: Optional[str] = None
    _lockdown: Optional[object] = field(default=None, repr=False)

    def resolve(self) -> object:
        """
        Retourne un LockdownClient.
        Ordre de priorité : record_path > device connecté trusted > erreur.
        Cache le résultat dans _lockdown (idempotent).
        """
        if self._lockdown is not None:
            return self._lockdown
        if self.record_path:
            try:
                self._lockdown = load_pairing_record(self.record_path, password=self.password)
            except ValueError as e:
                raise RuntimeError(f"Impossible de déchiffrer {self.record_path}: {e}") from e
            if self._lockdown is None:
                raise RuntimeError(f"Pairing record invalide : {self.record_path}")
        else:
            devs = get_connected_devices()
            trusted = [d for d in devs if d["trusted"]]
            if not trusted:
                raise RuntimeError("Aucun device trusted. Lance: python iphone_afu.py pair")
            if self.udid:
                match = [d for d in trusted if d["udid"] == self.udid]
                if not match:
                    raise RuntimeError(f"UDID {self.udid} non trouvé ou non trusted")
                self._lockdown = match[0]["lockdown"]
            else:
                self._lockdown = trusted[0]["lockdown"]
        _warn_if_tunnel_missing()
        return self._lockdown


# ═══════════════════════════════════════════════════════════════════════════════
# EXTRACTION — DCIM / Backup / Keychain
# ═══════════════════════════════════════════════════════════════════════════════

def _afc_retry(fn, *args, retries: int = 3, delay: float = 1.5, on_retry=None, **kwargs):
    """Retente fn jusqu'à retries fois avec backoff linéaire."""
    last_err = None
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            last_err = e
            log.warning(f"AFC retry {attempt+1}/{retries} — {e}")
            if on_retry is not None and attempt + 1 < retries:
                on_retry()
            time.sleep(delay * (attempt + 1))
    raise last_err


def extract_dcim(lockdown: object, output_dir: Path, progress_cb=None) -> dict:
    """
    Extrait DCIM complet via AFC.
    Retourne stats: {files, bytes, errors, retries}
    """
    stats = {"files": 0, "bytes": 0, "errors": [], "retries": 0}
    output_dir.mkdir(parents=True, exist_ok=True)
    log.debug(f"extract_dcim: début → {output_dir}")

    def count_retry():
        stats["retries"] += 1

    try:
        afc = AfcService(lockdown)

        def walk_afc(remote_path: str, local_path: Path):
            try:
                entries = _afc_retry(afc.listdir, remote_path, on_retry=count_retry)
            except Exception as e:
                stats["errors"].append(f"listdir {remote_path}: {e}")
                log.warning(f"extract_dcim: listdir {remote_path} échoué — {e}")
                return

            for entry in entries:
                if entry in (".", ".."):
                    continue
                remote_full = f"{remote_path}/{entry}"
                local_full = local_path / entry
                try:
                    info = _afc_retry(afc.stat, remote_full, on_retry=count_retry)
                    if info.get("st_ifmt") == "S_IFDIR":
                        local_full.mkdir(parents=True, exist_ok=True)
                        walk_afc(remote_full, local_full)
                    else:
                        data = _afc_retry(afc.get_file_contents, remote_full, on_retry=count_retry)
                        local_full.write_bytes(data)
                        stats["files"] += 1
                        stats["bytes"] += len(data)
                        if progress_cb:
                            progress_cb(entry, stats["files"], stats["bytes"])
                except Exception as e:
                    stats["errors"].append(f"{remote_full}: {e}")
                    log.warning(f"extract_dcim: fichier échoué {remote_full} — {e}")

        walk_afc("/DCIM", output_dir)

    except Exception as e:
        stats["errors"].append(f"AFC init: {e}")
        log.error(f"extract_dcim: init AFC — {e}")

    log.debug(
        f"extract_dcim: fin — {stats['files']} fichiers, {stats['bytes']} bytes, "
        f"{len(stats['errors'])} erreurs, {stats['retries']} retries"
    )
    return stats


def extract_backup(lockdown: object, output_dir: Path, encrypted: bool = False) -> dict:
    """
    Lance un backup complet via Mobilebackup2.
    encrypted=False = backup non chiffré (photos accessibles directement).
    """
    stats = {"status": "pending", "path": str(output_dir), "error": None}
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        mb2 = Mobilebackup2Service(lockdown)
        if not encrypted:
            # Désactiver le chiffrement si actif
            try:
                mb2.change_backup_password(old="", new="", enable_encryption=False)
            except Exception as e:
                log.debug(f"extract_backup: change_backup_password — {e} (déjà désactivé ?)")

        mb2.backup(full=True, backup_directory=output_dir)
        stats["status"] = "success"
        log.info(f"extract_backup: terminé → {output_dir}")

    except Exception as e:
        stats["status"] = "error"
        stats["error"] = str(e)
        log.error(f"extract_backup: {e}")

    return stats


def extract_installed_apps(lockdown: object) -> list[dict]:
    """Liste toutes les apps installées avec bundle ID et version."""
    apps = []
    try:
        svc = InstallationProxyService(lockdown)
        raw = svc.get_apps(app_types=["User", "System"])
        for bundle_id, info in raw.items():
            apps.append({
                "bundle_id": bundle_id,
                "name":      info.get("CFBundleDisplayName", info.get("CFBundleName", "?")),
                "version":   info.get("CFBundleShortVersionString", "?"),
                "type":      info.get("ApplicationType", "?"),
            })
        log.debug(f"extract_installed_apps: {len(apps)} apps")
    except Exception as e:
        log.error(f"extract_installed_apps: {e}")
    return apps


def dump_keychain_frida(udid: str, bundle_id: str, output_path: Path) -> dict:
    """
    Keychain dump via Frida + script inline.
    Nécessite frida-server sur le device OU app re-signée avec gadget.
    """
    log.debug(f"dump_keychain_frida: udid={udid} bundle={bundle_id} → {output_path}")
    frida_script = """
'use strict';

var results = [];

function dumpKeychain() {
    var SecItemCopyMatching = new NativeFunction(
        Module.findExportByName('Security', 'SecItemCopyMatching'),
        'int', ['pointer', 'pointer']
    );

    var classes = [
        'kSecClassGenericPassword',
        'kSecClassInternetPassword',
        'kSecClassCertificate',
        'kSecClassKey',
        'kSecClassIdentity'
    ];

    classes.forEach(function(cls) {
        var query = ObjC.classes.NSMutableDictionary.dictionary();
        var Security = Process.findModuleByName('Security');

        try {
            var classRef = Memory.readPointer(
                Module.findExportByName('Security', cls)
            );
            query.setObject_forKey_(classRef,
                Memory.readPointer(Module.findExportByName('Security', 'kSecClass')));
            query.setObject_forKey_(
                Memory.readPointer(Module.findExportByName('Security', 'kSecMatchLimitAll')),
                Memory.readPointer(Module.findExportByName('Security', 'kSecMatchLimit')));
            query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true),
                Memory.readPointer(Module.findExportByName('Security', 'kSecReturnAttributes')));
            query.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(true),
                Memory.readPointer(Module.findExportByName('Security', 'kSecReturnData')));

            var resultPtr = Memory.alloc(Process.pointerSize);
            Memory.writePointer(resultPtr, NULL);

            var status = SecItemCopyMatching(query, resultPtr);
            if (status === 0) {
                var items = new ObjC.Object(Memory.readPointer(resultPtr));
                for (var i = 0; i < items.count(); i++) {
                    var item = items.objectAtIndex_(i);
                    results.push({
                        class: cls,
                        data: item.toString()
                    });
                }
            }
        } catch(e) {}
    });

    send({type: 'keychain', data: results});
}

dumpKeychain();
"""

    result = {"status": "pending", "items": [], "error": None, "by_class": {}}

    try:
        script_path = Path("/tmp/_frida_kc_dump.js")
        script_path.write_text(frida_script)

        proc = subprocess.run(
            ["frida", "-U", "--no-pause", "-f", bundle_id, "-l", str(script_path), "--json"],
            capture_output=True, text=True, timeout=30
        )

        if proc.returncode == 0:
            lines = [l for l in proc.stdout.splitlines() if l.strip().startswith("{")]
            for line in lines:
                try:
                    parsed = json.loads(line)
                    if parsed.get("type") == "keychain":
                        result["items"] = parsed.get("data", [])
                except Exception as e:
                    log.debug(f"dump_keychain_frida: parse ligne — {e}")
            result["status"] = "success"
            result["by_class"] = summarize_keychain_items(result["items"])
            output_path.write_text(json.dumps(result["items"], indent=2))
        else:
            result["status"] = "error"
            result["error"] = proc.stderr[:500]
            log.error(f"dump_keychain_frida: frida rc={proc.returncode} — {result['error']}")

    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["error"] = "frida timeout 30s"
        log.error("dump_keychain_frida: timeout 30s")
    except FileNotFoundError:
        result["status"] = "error"
        result["error"] = "frida non installé — pip install frida-tools"
        log.error("dump_keychain_frida: frida introuvable")
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        log.error(f"dump_keychain_frida: {e}")

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# MANIFEST — index JSON/CSV de l'extraction DCIM
# ═══════════════════════════════════════════════════════════════════════════════

def build_dcim_manifest(output_dir: Path) -> list[dict]:
    """
    Parcourt output_dir récursivement.
    Pour chaque fichier : path relatif, taille bytes, mtime, extension.
    Pour les JPEG/HEIC : tente d'extraire date EXIF (silencieux si Pillow absent).
    Retourne une liste de dicts triée par mtime desc.
    """
    if not output_dir.exists():
        return []
    manifest = []
    for p in output_dir.rglob("*"):
        if not p.is_file():
            continue
        st = p.stat()
        exif_date = None
        if PILLOW and p.suffix.lower() in (".jpg", ".jpeg", ".heic", ".heif"):
            exif_date = _read_exif_date(p)
        manifest.append({
            "path":       str(p.relative_to(output_dir)),
            "size_bytes": st.st_size,
            "mtime":      datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            "ext":        p.suffix.lower(),
            "exif_date":  exif_date,
        })
    return sorted(manifest, key=lambda e: e["mtime"], reverse=True)


def _read_exif_date(path: Path) -> Optional[str]:
    """Date EXIF (tag 306 DateTime) ou None — ne lève jamais."""
    try:
        with Image.open(path) as img:
            raw = img.getexif().get(306)
            return str(raw) if raw else None
    except Exception as e:
        log.debug(f"_read_exif_date {path}: {e}")
        return None


def export_manifest(manifest: list[dict], output_dir: Path) -> tuple[Path, Path]:
    """Écrit manifest.json + manifest.csv dans output_dir."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "manifest.json"
    csv_path = output_dir / "manifest.csv"
    json_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["path", "size_bytes", "mtime", "ext", "exif_date"])
        writer.writeheader()
        writer.writerows(manifest)
    log.debug(f"export_manifest: {len(manifest)} entrées → {json_path}, {csv_path}")
    return json_path, csv_path


def _print_manifest_summary(manifest: list[dict], output_dir: Path):
    """Affiche le résumé du manifest DCIM (Rich ou fallback)."""
    total = len(manifest)
    total_mb = sum(e["size_bytes"] for e in manifest) / (1024 * 1024)
    dates = sorted(e["exif_date"] for e in manifest if e.get("exif_date"))
    if RICH:
        lines = [
            f"Fichiers  : {total}",
            f"Taille    : {total_mb:.1f} MB",
        ]
        if dates:
            lines.append(f"Dates EXIF: {dates[0]} → {dates[-1]}")
        lines.append(f"Manifest  : {output_dir / 'manifest.json'}")
        lines.append(f"            {output_dir / 'manifest.csv'}")
        console.print(Panel("\n".join(lines), title="Manifest DCIM", border_style="cyan"))
    else:
        print(f"[+] manifest: {total} fichiers, {total_mb:.1f} MB")
        if dates:
            print(f"[+] EXIF {dates[0]} → {dates[-1]}")


# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY AUDIT — IPA statique (Mach-O/Info.plist), AASA, scan, bypass Frida
# Playbooks: ios-pentesting-tricks §3/§4/§6/§7/§8, mobile-ssl-pinning-bypass §3.1
# ═══════════════════════════════════════════════════════════════════════════════

MH_MAGIC_64 = 0xFEEDFACF
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_CIGAM_64 = 0xCFFAEDFE
MH_PIE = 0x200000
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_CODE_SIGNATURE = 0x1D
FAT_MAGICS_BE = (0xCAFEBABE, 0xCAFEBABF)
FAT_MAGICS_LE = (0xBEBAFECA, 0xBFBAFECA)
CPU_NAMES = {12: "armv7", 0x01000007: "x86_64", 0x0100000C: "arm64"}
ANY_TEAM_ID = ".*"

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
SEVERITY_STYLE = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "dim", "INFO": "cyan"}


def _macho_slices(data: bytes) -> list[bytes]:
    """Retourne les tranches Mach-O d'un binaire (fat → chaque arch, thin → le binaire)."""
    if len(data) < 8:
        return []
    magic_be = int.from_bytes(data[:4], "big")
    if magic_be in FAT_MAGICS_BE:
        endian = "big"
    elif magic_be in FAT_MAGICS_LE:
        endian = "little"
    else:
        return [data]
    is64 = magic_be in (0xCAFEBABF, 0xBFBAFECA)
    nfat = int.from_bytes(data[4:8], endian)
    entry = 32 if is64 else 20
    out = []
    for i in range(min(max(nfat, 0), 8)):
        base = 8 + i * entry
        if base + entry > len(data):
            break
        if is64:
            off = int.from_bytes(data[base + 8:base + 16], endian)
            size = int.from_bytes(data[base + 16:base + 24], endian)
        else:
            off = int.from_bytes(data[base + 8:base + 12], endian)
            size = int.from_bytes(data[base + 12:base + 16], endian)
        if off < len(data):
            out.append(data[off:off + size])
    return out


def _parse_macho_header(data: bytes) -> Optional[dict]:
    """Parse une tranche Mach-O : cputype/flags, cryptid (LC_ENCRYPTION_INFO), blob signature."""
    if len(data) < 28:
        return None
    magic = int.from_bytes(data[:4], "little")
    if magic in (MH_MAGIC_64, MH_MAGIC):
        endian = "little"
    elif magic in (MH_CIGAM, MH_CIGAM_64):
        endian = "big"
    else:
        return None
    is64 = magic in (MH_MAGIC_64, MH_CIGAM_64)

    def u32(off):
        return int.from_bytes(data[off:off + 4], endian)

    ncmds = u32(16)
    flags = u32(24)
    cryptid = None
    code_signature = None
    off = 32 if is64 else 28
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd = u32(off)
        cmdsize = u32(off + 4)
        if cmdsize < 8:
            break
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64) and cmdsize >= 20:
            cryptid = u32(off + 16)
        elif cmd == LC_CODE_SIGNATURE and cmdsize >= 16:
            dataoff = u32(off + 8)
            datasize = u32(off + 12)
            if 0 < dataoff < len(data):
                code_signature = data[dataoff:dataoff + datasize]
        off += cmdsize
    return {
        "cputype": u32(4),
        "cpusubtype": u32(8),
        "flags": flags,
        "cryptid": cryptid,
        "code_signature": code_signature,
    }


def _cpu_name(cputype: int, cpusubtype: int) -> str:
    name = CPU_NAMES.get(cputype, hex(cputype))
    if name == "arm64" and cpusubtype & 0x80000000:   # PTRAUTH → arm64e
        name = "arm64e"
    return name


def extract_entitlements(cs_data: Optional[bytes]) -> Optional[dict]:
    """Extrait les entitlements XML depuis le blob LC_CODE_SIGNATURE (SuperBlob type 5)."""
    if not cs_data or len(cs_data) < 20:
        return None
    if int.from_bytes(cs_data[:4], "big") != 0xFADE0CC0:   # SuperBlob
        return None
    count = int.from_bytes(cs_data[8:12], "big")
    for i in range(min(count, 32)):
        base = 12 + i * 8
        if base + 8 > len(cs_data):
            break
        btype = int.from_bytes(cs_data[base:base + 4], "big")
        boff = int.from_bytes(cs_data[base + 4:base + 8], "big")
        if btype == 5 and 0 < boff and boff + 8 <= len(cs_data):    # CSSLOT_ENTITLEMENTS
            blen = int.from_bytes(cs_data[boff + 4:boff + 8], "big")
            if blen > 8 and boff + blen <= len(cs_data):
                try:
                    return plistlib.loads(cs_data[boff + 8:boff + blen])
                except Exception as e:
                    log.debug(f"extract_entitlements: plist — {e}")
                    return None
    return None


def analyze_binary_data(data: bytes) -> dict:
    """Analyse un binaire Mach-O (thin/fat) : archs, PIE/canary/ARC/cryptid, entitlements."""
    out = {
        "archs": [], "raw_ok": False, "pie": None, "canary": False,
        "arc": False, "cryptid": None, "entitlements": None,
    }
    for chunk in _macho_slices(data):
        hdr = _parse_macho_header(chunk)
        if not hdr:
            continue
        out["raw_ok"] = True
        out["archs"].append(_cpu_name(hdr["cputype"], hdr["cpusubtype"]))
        pie = bool(hdr["flags"] & MH_PIE)
        out["pie"] = pie if out["pie"] is None else (out["pie"] and pie)
        if hdr["cryptid"] is not None:
            out["cryptid"] = hdr["cryptid"] if out["cryptid"] is None else max(out["cryptid"], hdr["cryptid"])
        if b"__stack_chk_guard" in chunk:
            out["canary"] = True
        if b"objc_release" in chunk:
            out["arc"] = True
        if out["entitlements"] is None and hdr["code_signature"]:
            out["entitlements"] = extract_entitlements(hdr["code_signature"])
    return out


def load_app_bundle(path: Path) -> tuple[dict, bytes, str]:
    """Charge Info.plist + binaire principal depuis un .ipa (zip) ou un dossier .app."""
    if path.is_file() and path.suffix.lower() == ".ipa":
        with zipfile.ZipFile(path) as zf:
            plists = [n for n in zf.namelist()
                      if n.startswith("Payload/") and n.endswith("/Info.plist") and n.count("/") == 2]
            if not plists:
                raise RuntimeError(f"Payload/*.app introuvable dans {path.name}")
            app_dir = plists[0][:-len("Info.plist")]        # "Payload/Test.app/"
            info = plistlib.loads(zf.read(plists[0]))
            exe_name = info.get("CFBundleExecutable") or app_dir.rstrip("/").split("/")[-1][:-4]
            return info, zf.read(app_dir + exe_name), exe_name
    if path.is_dir():
        info = plistlib.loads((path / "Info.plist").read_bytes())
        exe_name = info.get("CFBundleExecutable") or path.stem
        return info, (path / exe_name).read_bytes(), exe_name
    raise RuntimeError(f"Chemin invalide (attendu .ipa ou .app) : {path}")


def _url_schemes(info: dict) -> list[str]:
    """Schémas URL déclarés dans CFBundleURLTypes."""
    return [s for t in info.get("CFBundleURLTypes", []) for s in t.get("CFBundleURLSchemes", [])]


def analyze_app_findings(info: dict, binary: dict) -> list[dict]:
    """Findings de risque depuis Info.plist + analyse binaire (ios-pentesting-tricks §6/§8)."""
    f = []

    def add(sev, fid, title, detail):
        f.append({"severity": sev, "id": fid, "title": title, "detail": detail})

    ats = info.get("NSAppTransportSecurity") or {}
    if ats.get("NSAllowsArbitraryLoads"):
        add("HIGH", "ats-arbitrary", "ATS désactivé globalement",
            "NSAllowsArbitraryLoads=true → HTTP en clair autorisé partout")
    if ats.get("NSAllowsArbitraryLoadsInWebContent"):
        add("MEDIUM", "ats-webcontent", "ATS désactivé pour WebView",
            "NSAllowsArbitraryLoadsInWebContent=true → contenu web en HTTP")
    domains = list((ats.get("NSExceptionDomains") or {}).keys())
    if domains:
        add("MEDIUM", "ats-exception", "Exceptions ATS par domaine",
            f"{len(domains)} domaine(s) : {', '.join(domains[:5])}")

    schemes = _url_schemes(info)
    if schemes:
        add("LOW", "schemes-custom", "Schémas URL custom (hijackables par nature)",
            f"{len(schemes)} : {', '.join(schemes[:8])} — OAuth/callback via scheme = interception possible (§3)")
    if any("oauth" in s.lower() or "callback" in s.lower() or "auth" in s.lower() for s in schemes):
        add("MEDIUM", "oauth-scheme", "Schéma lié à l'auth/OAuth",
            "Un schéma contenant oauth/callback/auth : risque de vol de code d'autorisation (§3.2)")

    if binary.get("cryptid") == 1:
        add("HIGH", "encrypted", "Binaire chiffré (FairPlay)",
            "cryptid=1 → déchiffrer l'IPA avant analyse statique (§6.2)")
    if binary.get("raw_ok"):
        if binary.get("pie") is False:
            add("HIGH", "no-pie", "PIE absent",
                "ASLR désactivé → adresses prévisibles (§6.1)")
        if not binary.get("canary"):
            add("MEDIUM", "no-canary", "Stack canaries absents",
                "__stack_chk_guard introuvable → overflow plus exploitable (§6.1)")
        if not binary.get("arc"):
            add("LOW", "no-arc", "ARC non détecté (heuristique)",
                "objc_release absent → gestion mémoire manuelle, UAF plus probable (§6.1)")

    ents = binary.get("entitlements") or {}
    if ents.get("get-task-allow") is True:
        add("HIGH", "debuggable", "App debuggable (get-task-allow)",
            "entitlement get-task-allow=true → attachement debugger/Frida facilité")
    priv = [k for k in ents if k.startswith("com.apple.private.")]
    if priv:
        add("INFO", "private-entitlements", "Entitlements privés Apple",
            f"{len(priv)} : {', '.join(priv[:5])}")
    groups = ents.get("keychain-access-groups")
    if groups:
        add("INFO", "keychain-groups", "keychain-access-groups", ", ".join(map(str, groups[:5])))
    return sorted(f, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))


def audit_app(path: Path) -> dict:
    """Audit statique complet d'un IPA/.app : bundle, binaire, findings."""
    log.debug(f"audit_app: {path}")
    info, bin_data, exe_name = load_app_bundle(path)
    binary = analyze_binary_data(bin_data)
    findings = analyze_app_findings(info, binary)
    return {
        "path": str(path),
        "executable": exe_name,
        "bundle": {
            "id": info.get("CFBundleIdentifier"),
            "name": info.get("CFBundleDisplayName") or info.get("CFBundleName"),
            "version": info.get("CFBundleShortVersionString"),
            "min_os": info.get("MinimumOSVersion"),
            "schemes": _url_schemes(info),
            "ats": info.get("NSAppTransportSecurity") or {},
        },
        "binary": {
            "archs": binary["archs"],
            "pie": binary["pie"],
            "canary": binary["canary"],
            "arc": binary["arc"],
            "cryptid": binary["cryptid"],
            "entitlements": binary["entitlements"],
        },
        "findings": findings,
    }


def analyze_aasa(data: Optional[dict], content_type: str = "", status: int = 200) -> list[dict]:
    """Findings Universal Links depuis l'AASA (ios-pentesting-tricks §4.1)."""
    f = []
    if status != 200 or data is None:
        f.append({
            "severity": "MEDIUM", "id": "aasa-missing",
            "title": "AASA absent ou inaccessible",
            "detail": f"HTTP {status} — pas d'association Universal Links → fallback vers schéma custom (hijackable, §4.1)",
        })
        return f
    applinks = data.get("applinks") or data
    details = applinks.get("details") or []
    if not details:
        f.append({
            "severity": "MEDIUM", "id": "aasa-no-details",
            "title": "AASA sans 'details'",
            "detail": "Structure applinks.details manquante — Universal Links non associés",
        })
        return f
    wildcard = []
    app_ids = []
    for d in details:
        for p in d.get("paths") or []:
            if "*" in str(p):
                wildcard.append(str(p))
        for c in d.get("components") or []:
            for k, v in c.items():
                if "*" in str(v):
                    wildcard.append(f"{k}={v}")
        app_ids += d.get("appIDs") or ([d["appID"]] if d.get("appID") else [])
    if wildcard:
        f.append({
            "severity": "HIGH", "id": "aasa-wildcard",
            "title": "AASA avec wildcard de chemins",
            "detail": f"Patterns larges: {', '.join(wildcard[:5])} — l'app revendique des URL trop larges (§4.1)",
        })
    ct = (content_type or "").lower()
    if ct and "json" not in ct:
        f.append({
            "severity": "MEDIUM", "id": "aasa-content-type",
            "title": "Content-Type non JSON",
            "detail": f"'{content_type}' — certains parseurs stricts rejettent l'AASA (§4.1)",
        })
    if app_ids:
        f.append({"severity": "INFO", "id": "aasa-appids", "title": "App IDs associés",
                  "detail": ", ".join(app_ids[:8])})
    return sorted(f, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))


def fetch_aasa(domain: str) -> tuple[int, str, Optional[dict]]:
    """Récupère l'AASA (/.well-known puis racine). Retourne (status, content_type, json|None)."""
    base = domain.strip().rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base
    last = (0, "", None)
    for path in ("/.well-known/apple-app-site-association", "/apple-app-site-association"):
        req = urllib.request.Request(base + path, headers={"User-Agent": "iphone-afu/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read()
                try:
                    data = json.loads(body)
                except Exception:
                    data = None
                return resp.status, resp.headers.get("Content-Type", ""), data
        except urllib.error.HTTPError as e:
            last = (e.code, "", None)
        except Exception as e:
            last = (0, str(e), None)
    return last


# ─── scan de données sensibles (§7.1) ────────────────────────────────────────

SCAN_SKIP_EXT = {".jpg", ".jpeg", ".png", ".heic", ".heif", ".gif", ".mov", ".mp4", ".m4a", ".aae"}
SCAN_MAX_BYTES = 10 * 1024 * 1024

STORAGE_NAME_PATTERNS = [
    (re.compile(r"(?i)Snapshots[/\\]"), "screenshot", "LOW", "snapshot d'état d'app (§7.1)"),
    (re.compile(r"(?i)Cookies\.binarycookies$"), "cookies", "MEDIUM", "cookies de session (§7.1)"),
    (re.compile(r"(?i)keychain"), "keychain", "MEDIUM", "artefact keychain (§2/§7.1)"),
    (re.compile(r"(?i)\.(sqlite3?|db|realm)$"), "sqlite", "LOW", "base locale — caches/API responses (§7.1)"),
    (re.compile(r"(?i)Preferences[/\\].+\.plist$"), "nsuserdefaults", "LOW", "NSUserDefaults — tokens en clair possibles (§7.1)"),
    (re.compile(r"(?i)Keyboard[/\\]"), "keyboard-cache", "LOW", "cache clavier (§7.1)"),
]

STORAGE_TITLES = {
    "screenshot": "Snapshots d'app",
    "cookies": "Cookies de session",
    "keychain": "Artefact keychain",
    "sqlite": "Base SQLite locale",
    "nsuserdefaults": "NSUserDefaults (prefs)",
    "keyboard-cache": "Cache clavier",
}

SECRET_PATTERNS = [
    ("private-key", "HIGH", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github-token", "HIGH", re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("jwt", "HIGH", re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")),
    ("aws-key", "MEDIUM", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("bearer-token", "MEDIUM", re.compile(rb"(?i)bearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("password", "MEDIUM", re.compile(rb"(?i)(?:password|passwd|pwd)\"?\s*[:=]\s*\"?[^\s\"<,;]{4,}")),
    ("api-key", "MEDIUM", re.compile(rb"(?i)(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret)\"?\s*[:=]\s*\"?[A-Za-z0-9_\-]{8,}")),
]


def scan_directory(root: Path) -> dict:
    """Scanne un répertoire (backup/container/export) : fichiers sensibles + secrets en clair."""
    result = {"root": str(root), "scanned_files": 0, "scanned_bytes": 0, "findings": []}
    if not root.is_dir():
        raise RuntimeError(f"Répertoire introuvable : {root}")
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(root))
        try:
            size = p.stat().st_size
        except OSError:
            continue
        result["scanned_files"] += 1
        result["scanned_bytes"] += size
        for rx, fid, sev, detail in STORAGE_NAME_PATTERNS:
            if rx.search(rel):
                result["findings"].append({
                    "path": rel, "id": fid, "severity": sev, "kind": "storage",
                    "title": STORAGE_TITLES.get(fid, fid), "detail": detail, "sample": "",
                })
        if size > SCAN_MAX_BYTES or p.suffix.lower() in SCAN_SKIP_EXT:
            continue
        try:
            blob = p.read_bytes()
        except OSError:
            continue
        for fid, sev, rx in SECRET_PATTERNS:
            m = rx.search(blob)
            if m:
                sample = m.group(0)[:80].decode("utf-8", errors="replace")
                result["findings"].append({
                    "path": rel, "id": fid, "severity": sev, "kind": "secret",
                    "title": f"Secret en clair: {fid}",
                    "detail": f"motif '{fid}' trouvé", "sample": sample,
                })
    result["findings"].sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))
    log.debug(f"scan_directory: {result['scanned_files']} fichiers, {len(result['findings'])} findings")
    return result


# ─── bypass runtime Frida (mobile-ssl-pinning-bypass §3.1, IOS_RUNTIME_TRICKS §1.3) ──

BYPASS_SSL_JS = r"""'use strict';
// SSL pinning bypass — hooks SecTrust/SSLHandshake (non-jailbreak: gadget requis)
function _hookExport(mod, name, retval) {
    var addr = Module.findExportByName(mod, name);
    if (!addr) { console.log('[bypass] ' + name + ' absent'); return; }
    Interceptor.attach(addr, {
        onLeave: function (rv) { rv.replace(ptr(retval)); console.log('[bypass] ' + name + ' -> ' + retval); }
    });
    console.log('[bypass] hook: ' + mod + '!' + name);
}
_hookExport('Security', 'SecTrustEvaluateWithError', 1);
_hookExport('Security', 'SecTrustEvaluate', 0);
var _hs = Module.findExportByName('Security', 'SSLHandshake');
if (_hs) {
    Interceptor.attach(_hs, {
        onLeave: function (rv) {
            if (rv.toInt32() === -9807) { rv.replace(ptr(0)); console.log('[bypass] SSLHandshake errSSLXCertChainInvalid -> 0'); }
        }
    });
}
var _th = Module.findExportByName('Security', 'tls_helper_create_peer_trust');
if (_th) { Interceptor.attach(_th, { onLeave: function (rv) { rv.replace(ptr(1)); } }); }
console.log('[+] SSL pinning bypass installé');
"""

BYPASS_JB_JS = r"""'use strict';
// Jailbreak detection bypass (IOS_RUNTIME_TRICKS §1.3)
var JB_PATHS = ['/Applications/Cydia.app','/usr/sbin/sshd','/bin/bash','/usr/bin/ssh','/etc/apt',
    '/private/var/lib/apt/','/usr/local/bin/cycript','/var/lib/cydia','/var/jb',
    '/Applications/Sileo.app','/Library/MobileSubstrate/MobileSubstrate.dylib'];
try {
    var _fm = ObjC.classes.NSFileManager;
    Interceptor.attach(_fm['- fileExistsAtPath:'].implementation, {
        onEnter: function (args) { this.path = ObjC.Object(args[2]).toString(); },
        onLeave: function (rv) {
            if (JB_PATHS.indexOf(this.path) !== -1) { rv.replace(ptr(0)); console.log('[jb] fileExistsAtPath bloqué: ' + this.path); }
        }
    });
} catch (e) { console.log('[jb] NSFileManager hook échoué: ' + e); }
try {
    var _app = ObjC.classes.UIApplication;
    Interceptor.attach(_app['- canOpenURL:'].implementation, {
        onEnter: function (args) { this.url = ObjC.Object(args[2]).toString(); },
        onLeave: function (rv) {
            if (this.url.indexOf('cydia://') !== -1 || this.url.indexOf('sileo://') !== -1) { rv.replace(ptr(0)); }
        }
    });
} catch (e) { console.log('[jb] canOpenURL hook échoué: ' + e); }
var _fopen = Module.findExportByName(null, 'fopen');
if (_fopen) {
    Interceptor.attach(_fopen, {
        onEnter: function (args) { this.path = args[0].readUtf8String(); },
        onLeave: function (rv) {
            if (this.path === '/bin/sh' || this.path === '/etc/fstab' || this.path === '/bin/bash') { rv.replace(ptr(0)); }
        }
    });
}
var _fork = Module.findExportByName(null, 'fork');
if (_fork) { Interceptor.attach(_fork, { onLeave: function (rv) { rv.replace(ptr(-1)); } }); }
console.log('[+] Jailbreak bypass installé');
"""


def build_bypass_script(ssl: bool = True, jailbreak: bool = False) -> str:
    """Compose le script Frida de bypass (SSL par défaut, + jailbreak optionnel)."""
    parts = []
    if ssl:
        parts.append(BYPASS_SSL_JS)
    if jailbreak:
        parts.append(BYPASS_JB_JS)
    return "\n".join(parts)


def _run_frida_script(bundle_id: str, script_text: str, timeout: int = 30) -> dict:
    """Injecte un script Frida inline via le CLI (même approche que dump_keychain_frida)."""
    result = {"status": "pending", "error": None, "stdout": ""}
    script_path = Path(tempfile.gettempdir()) / "_frida_bypass.js"
    try:
        script_path.write_text(script_text)
        proc = subprocess.run(
            ["frida", "-U", "--no-pause", "-f", bundle_id, "-l", str(script_path)],
            capture_output=True, text=True, timeout=timeout,
        )
        result["stdout"] = proc.stdout[-2000:]
        if proc.returncode == 0:
            result["status"] = "success"
        else:
            result["status"] = "error"
            result["error"] = (proc.stderr or proc.stdout)[:500]
    except subprocess.TimeoutExpired:
        result["status"] = "injected"
        result["error"] = "frida toujours actif après %ss (hooks en place — Ctrl+C)" % timeout
    except FileNotFoundError:
        result["status"] = "error"
        result["error"] = "frida non installé — pip install frida-tools"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result


def summarize_keychain_items(items: list[dict]) -> dict:
    """Compte les items keychain par classe (genp/inet/cert/keys/idnt)."""
    return dict(sorted(Counter(str(it.get("class", "?")) for it in items).items()))


# ═══════════════════════════════════════════════════════════════════════════════
# CLI — commandes argparse
# ═══════════════════════════════════════════════════════════════════════════════

def cli_check(args):
    """Vérifie les dépendances et les devices connectés."""
    deps = check_deps()

    if RICH:
        t = Table(title="Dépendances", show_header=True)
        t.add_column("Outil", style="cyan")
        t.add_column("Status", style="bold")
        for k, v in deps.items():
            t.add_row(k, "[green]✓ OK[/green]" if v else "[red]✗ Manquant[/red]")
        console.print(t)

        devs = get_connected_devices()
        if devs:
            t2 = Table(title="Devices connectés")
            t2.add_column("UDID", style="dim")
            t2.add_column("Nom")
            t2.add_column("iOS")
            t2.add_column("Modèle")
            t2.add_column("Trust")
            for d in devs:
                trust_str = "[green]✓[/green]" if d["trusted"] else "[red]✗ Taper 'Faire confiance'[/red]"
                t2.add_row(d["udid"][:20]+"…", d["name"], d["ios"], d["model"], trust_str)
            console.print(t2)
        else:
            console.print("[yellow]Aucun device détecté[/yellow]")
        console.print(f"[dim]Log → {LOG_PATH}[/dim]")
    else:
        for k, v in deps.items():
            print(f"{'OK' if v else 'MISSING'} {k}")
        print(f"[log] {LOG_PATH}")


def cli_pair(args):
    """Attend le trust et sauvegarde le pairing record."""
    if RICH:
        console.print("[cyan]Branche le téléphone et tape 'Faire confiance' sur l'écran...[/cyan]")
    else:
        print("Branche le téléphone et tape 'Faire confiance'...")

    ld = wait_for_trust(udid=args.udid, timeout=args.timeout)
    if ld is None:
        msg = f"Timeout {args.timeout}s — trust non établi"
        if RICH:
            console.print(f"[red]{msg}[/red]")
        else:
            print(f"[!] {msg}")
        sys.exit(1)

    if RICH:
        console.print("[green]Trust établi ![/green]")

    password = getattr(args, "password", None)
    out = Path(args.output)
    if password and CRYPTO:
        out = _encrypted_record_path(out)
    if save_pairing_record(ld, out, password=password):
        if RICH:
            console.print(f"[green]Pairing record sauvegardé → {out}[/green]")
        else:
            print(f"[+] Sauvegardé → {out}")
    else:
        if RICH:
            console.print("[yellow]Trust établi mais impossible de sauvegarder le record[/yellow]")
        else:
            print("[!] Trust établi mais échec de sauvegarde du record")


def cli_dcim(args):
    """Extrait le DCIM via AFC + écrit le manifest (JSON/CSV)."""
    ctx = DeviceContext(
        udid=getattr(args, "udid", None),
        record_path=Path(args.record) if getattr(args, "record", None) else None,
        password=getattr(args, "password", None),
    )
    try:
        ld = ctx.resolve()
    except RuntimeError as e:
        if RICH:
            console.print(f"[red]{e}[/red]")
        else:
            print(f"[!] {e}")
        return

    out = Path(args.output)
    if RICH:
        console.print(f"[cyan]Extraction DCIM → {out}[/cyan]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
        ) as progress:
            task = progress.add_task("Extraction...", total=None)
            def cb(name, count, total_bytes):
                progress.update(task, description=f"{name} ({count} fichiers, {total_bytes//1024}KB)")
            stats = extract_dcim(ld, out, progress_cb=cb)

        if stats["errors"]:
            console.print(f"[yellow]{len(stats['errors'])} erreurs[/yellow]")
        if stats["retries"]:
            console.print(f"[yellow]⚠ {stats['retries']} retries AFC[/yellow]")
        console.print(f"[green]{stats['files']} fichiers, {stats['bytes']//1024//1024}MB extraits[/green]")
    else:
        stats = extract_dcim(ld, out)
        print(f"[+] {stats['files']} fichiers, {stats['bytes']//1024//1024}MB")
        if stats["errors"]:
            print(f"[!] {len(stats['errors'])} erreurs")
        if stats["retries"]:
            print(f"[!] {stats['retries']} AFC retries")

    manifest = build_dcim_manifest(out)
    export_manifest(manifest, out)
    _print_manifest_summary(manifest, out)


def cli_backup(args):
    """Lance un backup complet."""
    ctx = DeviceContext(
        udid=getattr(args, "udid", None),
        record_path=Path(args.record) if getattr(args, "record", None) else None,
        password=getattr(args, "password", None),
    )
    try:
        ld = ctx.resolve()
    except RuntimeError as e:
        if RICH:
            console.print(f"[red]{e}[/red]")
        else:
            print(f"[!] {e}")
        return

    out = Path(args.output)
    if RICH:
        console.print(f"[cyan]Backup complet → {out}[/cyan]")
        with console.status("Backup en cours..."):
            stats = extract_backup(ld, out, encrypted=args.encrypted)
    else:
        stats = extract_backup(ld, out, encrypted=args.encrypted)

    if stats["status"] == "success":
        msg = f"Backup terminé → {stats['path']}"
        if RICH:
            console.print(f"[green]{msg}[/green]")
        else:
            print(f"[+] {msg}")
    else:
        msg = f"Erreur backup: {stats['error']}"
        if RICH:
            console.print(f"[red]{msg}[/red]")
        else:
            print(f"[!] {msg}")


def cli_apps(args):
    """Liste les apps installées."""
    ctx = DeviceContext(
        udid=getattr(args, "udid", None),
        record_path=Path(args.record) if getattr(args, "record", None) else None,
        password=getattr(args, "password", None),
    )
    try:
        ld = ctx.resolve()
    except RuntimeError as e:
        if RICH:
            console.print(f"[red]{e}[/red]")
        else:
            print(f"[!] {e}")
        return

    apps = extract_installed_apps(ld)
    if RICH:
        t = Table(title=f"Apps ({len(apps)})")
        t.add_column("Bundle ID", style="dim cyan")
        t.add_column("Nom")
        t.add_column("Version")
        t.add_column("Type")
        for a in sorted(apps, key=lambda x: x["name"]):
            t.add_row(a["bundle_id"], a["name"], a["version"], a["type"])
        console.print(t)
    else:
        for a in apps:
            print(f"{a['bundle_id']}\t{a['name']}\t{a['version']}")


def cli_keychain(args):
    """Dump keychain via Frida."""
    devs = get_connected_devices()
    trusted = [d for d in devs if d["trusted"]]
    if not trusted:
        msg = "Aucun device trusted connecté"
        if RICH:
            console.print(f"[red]{msg}[/red]")
        else:
            print(f"[!] {msg}")
        return

    udid = args.udid or trusted[0]["udid"]
    out = Path(args.output)

    if RICH:
        console.print(f"[cyan]Keychain dump via Frida — bundle: {args.bundle_id}[/cyan]")
        with console.status("Injection Frida..."):
            result = dump_keychain_frida(udid, args.bundle_id, out)
    else:
        result = dump_keychain_frida(udid, args.bundle_id, out)

    if result["status"] == "success":
        msg = f"{len(result['items'])} items → {out}"
        if RICH:
            console.print(f"[green]{msg}[/green]")
            for cls, n in (result.get("by_class") or {}).items():
                console.print(f"  [dim]{cls}: {n}[/dim]")
        else:
            print(f"[+] {msg}")
            for cls, n in (result.get("by_class") or {}).items():
                print(f"    {cls}: {n}")
    else:
        msg = f"Erreur: {result['error']}"
        if RICH:
            console.print(f"[red]{msg}[/red]")
        else:
            print(f"[!] {msg}")


def cli_tunnel(args):
    """Démarre le tunnel RemoteXPC (iOS 17/18, nécessite sudo)."""
    try:
        proc = start_tunnel_daemon(getattr(args, "udid", None))
    except (PermissionError, RuntimeError) as e:
        if RICH:
            console.print(f"[red]{e}[/red]")
        else:
            print(f"[!] {e}")
        sys.exit(1)

    keep_alive = getattr(args, "keep_alive", False)
    state = {"proc": proc}

    def _shutdown(signum, frame):
        if RICH:
            console.print("[yellow]Arrêt du tunnel...[/yellow]")
        else:
            print("[!] Arrêt du tunnel...")
        try:
            state["proc"].terminate()
        except Exception as e:
            log.debug(f"cli_tunnel: terminate — {e}")
        sys.exit(0)

    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            try:
                signal.signal(sig, _shutdown)
            except (ValueError, OSError) as e:
                log.debug(f"cli_tunnel: signal {sig_name} — {e}")

    mode = "keep-alive" if keep_alive else "foreground"
    msg = f"Tunnel RemoteXPC actif (pid={state['proc'].pid}, mode={mode})"
    if RICH:
        console.print(f"[green]{msg}[/green]")
        console.print("[dim]Ctrl+C pour arrêter[/dim]")
    else:
        print(f"[+] {msg}")

    if not keep_alive:
        state["proc"].wait()
        return

    while True:
        time.sleep(2)
        if state["proc"].poll() is not None:
            log.warning("cli_tunnel: tunnel mort — relance (--keep-alive)")
            if RICH:
                console.print("[yellow]⚠ Tunnel mort — relance...[/yellow]")
            else:
                print("[!] Tunnel mort — relance...")
            try:
                state["proc"] = start_tunnel_daemon(getattr(args, "udid", None))
            except (PermissionError, RuntimeError) as e:
                if RICH:
                    console.print(f"[red]{e}[/red]")
                else:
                    print(f"[!] {e}")
                sys.exit(1)


def _print_findings(findings: list[dict], title: str):
    """Affiche une liste de findings security (Rich ou fallback)."""
    has_path = any(fd.get("path") for fd in findings)
    if RICH:
        t = Table(title=f"{title} ({len(findings)})")
        t.add_column("Sev", style="bold")
        t.add_column("ID", style="dim")
        if has_path:
            t.add_column("Chemin", style="dim")
        t.add_column("Titre")
        t.add_column("Détail", style="dim")
        for fd in findings:
            style = SEVERITY_STYLE.get(fd["severity"], "white")
            row = [f"[{style}]{fd['severity']}[/{style}]", fd.get("id", "?")]
            if has_path:
                row.append(fd.get("path", ""))
            row += [fd.get("title", "—"), fd.get("detail", "")[:90]]
            t.add_row(*row)
        console.print(t)
    else:
        for fd in findings:
            loc = f"{fd['path']} — " if fd.get("path") else ""
            print(f"[{fd['severity']}] {loc}{fd.get('title', fd.get('id', '?'))} — {fd.get('detail', '')}")


def cli_audit(args):
    """Audit statique d'un IPA/.app (hors device)."""
    path = Path(args.path)
    try:
        report = audit_app(path)
    except Exception as e:
        log.error(f"cli_audit: {e}")
        msg = f"Audit impossible: {e}"
        if RICH:
            console.print(f"[red]{msg}[/red]")
        else:
            print(f"[!] {msg}")
        return

    if RICH:
        b = report["bundle"]
        binr = report["binary"]
        console.print(Panel(
            f"Bundle    : {b['id']} ({b['name']}) v{b['version']} — min OS {b['min_os']}\n"
            f"Binaire   : {report['executable']} [{', '.join(binr['archs']) or '?'}]\n"
            f"PIE={binr['pie']}  canary={binr['canary']}  ARC={binr['arc']}  cryptid={binr['cryptid']}\n"
            f"Schemes   : {', '.join(b['schemes']) or '—'}\n"
            f"Entitlements: {len(binr['entitlements'] or {})} clés",
            title="Audit IPA", border_style="cyan",
        ))
        _print_findings(report["findings"], "Findings")
    else:
        for fd in report["findings"]:
            print(f"[{fd['severity']}] {fd['id']}: {fd['detail']}")

    if getattr(args, "json_out", None):
        out = Path(args.json_out)
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        msg = f"Rapport JSON → {out}"
        if RICH:
            console.print(f"[green]{msg}[/green]")
        else:
            print(f"[+] {msg}")


def cli_aasa(args):
    """Analyse l'Apple-App-Site-Association d'un domaine."""
    status, ctype, data = fetch_aasa(args.domain)
    findings = analyze_aasa(data, ctype, status)
    if RICH:
        console.print(f"[cyan]AASA {args.domain} — HTTP {status} ({ctype or 'sans content-type'})[/cyan]")
        _print_findings(findings, "Universal Links")
    else:
        print(f"[*] AASA {args.domain} — HTTP {status}")
        for fd in findings:
            print(f"[{fd['severity']}] {fd['id']}: {fd['detail']}")


def cli_scan(args):
    """Scanne un répertoire pour données sensibles."""
    root = Path(args.path)
    try:
        result = scan_directory(root)
    except RuntimeError as e:
        if RICH:
            console.print(f"[red]{e}[/red]")
        else:
            print(f"[!] {e}")
        return
    mb = result["scanned_bytes"] / (1024 * 1024)
    if RICH:
        console.print(f"[cyan]Scan {result['scanned_files']} fichiers ({mb:.1f} MB)[/cyan]")
        _print_findings(result["findings"], "Données sensibles")
    else:
        print(f"[*] {result['scanned_files']} fichiers ({mb:.1f} MB)")
        for fd in result["findings"]:
            print(f"[{fd['severity']}] {fd['path']} — {fd['detail']} {fd['sample']}")
    if getattr(args, "json_out", None):
        Path(args.json_out).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        if RICH:
            console.print(f"[green]Findings JSON → {args.json_out}[/green]")
        else:
            print(f"[+] {args.json_out}")


def cli_bypass(args):
    """Génère/injecte un script Frida SSL pinning + jailbreak bypass."""
    script = build_bypass_script(ssl=True, jailbreak=args.jailbreak)
    if args.write:
        out = Path(args.write)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(script)
        msg = f"Script Frida → {out} (frida -U -f <bundle> -l {out})"
        if RICH:
            console.print(f"[green]{msg}[/green]")
        else:
            print(f"[+] {msg}")
        return

    if not args.bundle_id:
        msg = "Bundle ID requis pour l'injection (ou utilise --write <fichier.js>)"
        if RICH:
            console.print(f"[red]{msg}[/red]")
        else:
            print(f"[!] {msg}")
        return

    if RICH:
        console.print(f"[cyan]Injection Frida — {args.bundle_id}[/cyan]")
        with console.status("Injection..."):
            result = _run_frida_script(args.bundle_id, script)
    else:
        result = _run_frida_script(args.bundle_id, script)

    if result["status"] in ("success", "injected"):
        msg = f"Bypass actif sur {args.bundle_id}"
        if RICH:
            console.print(f"[green]{msg}[/green]")
        else:
            print(f"[+] {msg}")
        if result.get("stdout"):
            print(result["stdout"])
    else:
        msg = f"Erreur: {result['error']}"
        if RICH:
            console.print(f"[red]{msg}[/red]")
        else:
            print(f"[!] {msg}")


INFO_KEYS = [
    "DeviceName", "ProductType", "ProductVersion", "BuildVersion", "HardwareModel",
    "BoardId", "UniqueDeviceID", "SerialNumber", "RegionInfo", "TimeZone",
    "ActivationState", "IsPaired", "PasswordProtected", "CPUArchitecture",
]


def collect_device_info(ld: object) -> dict:
    """Infos device via lockdown (clés manquantes → '—')."""
    vals = {}
    allv = getattr(ld, "all_values", None)
    if isinstance(allv, dict):
        vals.update(allv)
    for k in INFO_KEYS:
        if k not in vals:
            try:
                vals[k] = ld.get_value(key=k)
            except Exception:
                vals[k] = "—"
    return {k: vals.get(k, "—") for k in INFO_KEYS}


def cli_info(args):
    """Infos détaillées du device via lockdown."""
    ctx = DeviceContext(
        udid=getattr(args, "udid", None),
        record_path=Path(args.record) if getattr(args, "record", None) else None,
        password=getattr(args, "password", None),
    )
    try:
        ld = ctx.resolve()
    except RuntimeError as e:
        if RICH:
            console.print(f"[red]{e}[/red]")
        else:
            print(f"[!] {e}")
        return

    vals = collect_device_info(ld)

    if RICH:
        t = Table(title="Device")
        t.add_column("Clé", style="cyan")
        t.add_column("Valeur")
        for k in INFO_KEYS:
            t.add_row(k, str(vals.get(k, "—")))
        console.print(t)
    else:
        for k in INFO_KEYS:
            print(f"{k}\t{vals.get(k, '—')}")


def cli_syslog(args):
    """Collecte le syslog du device (pymobiledevice3 syslog collect)."""
    ctx = DeviceContext(
        udid=getattr(args, "udid", None),
        record_path=Path(args.record) if getattr(args, "record", None) else None,
        password=getattr(args, "password", None),
    )
    try:
        ctx.resolve()
    except RuntimeError as e:
        if RICH:
            console.print(f"[red]{e}[/red]")
        else:
            print(f"[!] {e}")
        return

    out = Path(args.output)
    cmd = ["pymobiledevice3", "syslog", "collect", "--output", str(out)]
    if getattr(args, "udid", None):
        cmd += ["--udid", args.udid]
    if args.timeout:
        cmd += ["--timeout", str(args.timeout)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout + 60)
    except FileNotFoundError:
        msg = "pymobiledevice3 introuvable — active le venv (source .venv/bin/activate)"
        if RICH:
            console.print(f"[red]{msg}[/red]")
        else:
            print(f"[!] {msg}")
        return
    except subprocess.TimeoutExpired:
        msg = f"Timeout syslog — fichier partiel: {out}"
        if RICH:
            console.print(f"[yellow]{msg}[/yellow]")
        else:
            print(f"[!] {msg}")
        return

    if proc.returncode == 0 and out.exists():
        size_kb = out.stat().st_size // 1024
        msg = f"Syslog ({args.timeout}s) → {out} ({size_kb}KB)"
        if RICH:
            console.print(f"[green]{msg}[/green]")
        else:
            print(f"[+] {msg}")
    else:
        msg = f"Syslog échoué: {(proc.stderr or proc.stdout or '')[:300]}"
        log.error(f"cli_syslog: {msg}")
        if RICH:
            console.print(f"[red]{msg}[/red]")
        else:
            print(f"[!] {msg}")


# ═══════════════════════════════════════════════════════════════════════════════
# AUTO — pipeline plug & play (device → extraction → analyse → rapport)
# ═══════════════════════════════════════════════════════════════════════════════

AUTO_STAGES = ("info", "apps", "dcim", "backup", "syslog", "scan")


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _dir_stats(path: Path) -> tuple[int, int]:
    """(nombre de fichiers, taille totale) d'un répertoire."""
    files = 0
    total = 0
    if path.is_dir():
        for p in path.rglob("*"):
            if p.is_file():
                files += 1
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
    return files, total


def default_record_path() -> Path:
    """Record AFU persistant par défaut (réutilisé d'un run à l'autre)."""
    return Path.home() / ".iphone_afu" / "afu_record.json"


def _wait_for_device(udid: Optional[str], timeout: int, emit) -> list[dict]:
    """Attend qu'au moins un device apparaisse (trusted ou non)."""
    deadline = time.time() + max(timeout, 0)
    first = True
    while True:
        devs = get_connected_devices()
        if devs:
            return devs
        if time.time() >= deadline:
            return []
        if first:
            emit("    Branche l'iPhone (déverrouillé la 1re fois pour le trust)…")
            first = False
        time.sleep(2)


def _auto_acquire_lockdown(record_path: Optional[Path], password: Optional[str],
                           udid: Optional[str], wait: int, emit) -> tuple[object, str]:
    """Obtient un LockdownClient : record existant (AFU) sinon device live + trust + record."""
    ld = None
    source = ""
    if record_path and record_path.exists():
        try:
            ld = load_pairing_record(record_path, password=password)
        except ValueError as e:
            emit(f"    [!] {e}")
            ld = None
        if ld is not None:
            source = f"record {record_path.name}"
    if ld is None:
        devs = _wait_for_device(udid, wait, emit)
        if not devs:
            raise RuntimeError(
                "aucun device détecté — câble data ? USB passthrough activé ? (WSL2: usbipd attach --wsl)"
            )
        trusted = [d for d in devs if d["trusted"] and (not udid or d["udid"] == udid)]
        if trusted:
            ld = trusted[0]["lockdown"]
            source = f"device live ({trusted[0]['name']})"
        else:
            emit("    Sur l'écran : accepte « Faire confiance » (device déverrouillé)")
            ld = wait_for_trust(udid, timeout=wait)
            if ld is None:
                raise RuntimeError(f"timeout {wait}s — trust non établi")
            source = "trust live (nouveau pairing)"
        if record_path:
            ok = save_pairing_record(ld, record_path, password=password)
            if ok:
                target = _encrypted_record_path(record_path) if (password and CRYPTO) else record_path
                emit(f"    Record sauvegardé → {target}")
            else:
                emit("    [!] Impossible de sauvegarder le record")
    if not tunnel_is_active():
        emit("    [!] Tunnel RemoteXPC non détecté — lance dans un autre terminal :")
        emit("        sudo python iphone_afu.py tunnel")
    return ld, source


def run_auto(out_dir: Path, *, udid: Optional[str] = None, record_path: Optional[Path] = None,
             password: Optional[str] = None, wait: int = 120, skip: tuple = (),
             backup_encrypted: bool = False, syslog_seconds: int = 10, emit=print) -> dict:
    """
    Pipeline plug & play : connexion (record/live), info, apps, dcim, backup, syslog, scan.
    Écrit out_dir/auto_report.json + fichiers de sortie. Retourne le rapport.
    """
    started = time.time()
    skip = {s.lower() for s in skip}
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "started": datetime.now().isoformat(timespec="seconds"),
        "output_dir": str(out_dir),
        "device": {"source": None, "udid": udid},
        "stages": [],
        "outputs": {},
        "ok": False,
    }
    log.debug(f"run_auto: start → {out_dir} (skip={sorted(skip)})")

    emit(f"[*] Sortie : {out_dir.resolve()}")

    # ── connexion device ──
    emit("[*] Connexion device…")
    try:
        ld, source = _auto_acquire_lockdown(record_path, password, udid, wait, emit)
        report["device"]["source"] = source
        emit(f"    ✓ {source}")
    except Exception as e:
        log.error(f"run_auto: connexion — {e}")
        report["stages"].append({"name": "connexion device", "status": "error",
                                 "detail": str(e), "seconds": 0.0})
        emit(f"    ✗ {e}")
        (out_dir / "auto_report.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        return report

    def stage(name: str, fn):
        t0 = time.time()
        emit(f"[*] {name}…")
        try:
            detail = fn()
            report["stages"].append({"name": name, "status": "ok", "detail": detail,
                                     "seconds": round(time.time() - t0, 1)})
            emit(f"    ✓ {detail}")
        except Exception as e:
            log.error(f"run_auto[{name}]: {e}")
            report["stages"].append({"name": name, "status": "error", "detail": str(e),
                                     "seconds": round(time.time() - t0, 1)})
            emit(f"    ✗ {e}")

    # ── info ──
    if "info" not in skip:
        def _info():
            vals = collect_device_info(ld)
            (out_dir / "device.json").write_text(
                json.dumps(vals, indent=2, ensure_ascii=False), encoding="utf-8")
            report["outputs"]["device.json"] = str(out_dir / "device.json")
            return f"{vals.get('DeviceName')} — {vals.get('ProductType')} iOS {vals.get('ProductVersion')}"
        stage("info device", _info)

    # ── apps ──
    if "apps" not in skip:
        def _apps():
            apps = extract_installed_apps(ld)
            (out_dir / "apps.json").write_text(
                json.dumps(apps, indent=2, ensure_ascii=False), encoding="utf-8")
            report["outputs"]["apps.json"] = str(out_dir / "apps.json")
            return f"{len(apps)} apps installées"
        stage("apps", _apps)

    # ── dcim ──
    if "dcim" not in skip:
        def _dcim():
            target = out_dir / "dcim"
            stats = extract_dcim(ld, target)
            manifest = build_dcim_manifest(target)
            export_manifest(manifest, target)
            report["outputs"]["dcim"] = str(target)
            extra = ""
            if stats["retries"]:
                extra += f", {stats['retries']} retries"
            if stats["errors"]:
                extra += f", {len(stats['errors'])} erreurs"
            return f"{stats['files']} fichiers, {_fmt_bytes(stats['bytes'])}{extra}"
        stage("dcim", _dcim)

    # ── backup ──
    if "backup" not in skip:
        def _backup():
            target = out_dir / "backup"
            stats = extract_backup(ld, target, encrypted=backup_encrypted)
            if stats["status"] != "success":
                raise RuntimeError(stats.get("error") or "backup échoué")
            files, total = _dir_stats(target)
            report["outputs"]["backup"] = str(target)
            return f"{files} fichiers, {_fmt_bytes(total)}"
        stage("backup", _backup)

    # ── syslog ──
    if "syslog" not in skip:
        def _syslog():
            target = out_dir / "syslog.txt"
            cmd = ["pymobiledevice3", "syslog", "collect", "--output", str(target)]
            if udid:
                cmd += ["--udid", udid]
            if syslog_seconds:
                cmd += ["--timeout", str(syslog_seconds)]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=syslog_seconds + 60)
            if proc.returncode != 0 or not target.exists():
                raise RuntimeError((proc.stderr or proc.stdout or "échec")[:200])
            report["outputs"]["syslog.txt"] = str(target)
            return f"{target.stat().st_size // 1024}KB ({syslog_seconds}s)"
        stage("syslog", _syslog)

    # ── scan (analyse du backup) ──
    if "scan" not in skip:
        def _scan():
            target = out_dir / "backup" if (out_dir / "backup").is_dir() else out_dir
            result = scan_directory(target)
            (out_dir / "findings.json").write_text(
                json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
            report["outputs"]["findings.json"] = str(out_dir / "findings.json")
            highs = len([f for f in result["findings"] if f["severity"] == "HIGH"])
            return (f"{len(result['findings'])} findings ({highs} HIGH) sur "
                    f"{result['scanned_files']} fichiers")
        stage("scan données", _scan)

    report["finished"] = datetime.now().isoformat(timespec="seconds")
    report["duration_s"] = round(time.time() - started, 1)
    report["ok"] = all(s["status"] == "ok" for s in report["stages"])
    (out_dir / "auto_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info(f"run_auto: terminé ok={report['ok']} en {report['duration_s']}s")
    return report


def cli_auto(args):
    """Plug & Play : détecte, (re)pair si besoin, extrait tout, analyse et rapporte."""
    if RICH:
        emit = lambda m: console.print(m, highlight=False)
    else:
        emit = print

    out = Path(args.output)
    skip = tuple(s.strip() for s in (getattr(args, "skip", "") or "").split(",") if s.strip())
    record_path = Path(args.record) if getattr(args, "record", None) else default_record_path()

    emit("[*] Pipeline AFU automatique — Ctrl+C pour interrompre")
    report = run_auto(
        out,
        udid=getattr(args, "udid", None),
        record_path=record_path,
        password=getattr(args, "password", None),
        wait=args.timeout,
        skip=skip,
        backup_encrypted=args.encrypted,
        syslog_seconds=args.syslog_timeout,
        emit=emit,
    )

    if RICH:
        t = Table(title="Résumé")
        t.add_column("Étape", style="cyan")
        t.add_column("Statut", style="bold")
        t.add_column("Détail")
        for s in report["stages"]:
            stat = "[green]✓ OK[/green]" if s["status"] == "ok" else "[red]✗ ÉCHEC[/red]"
            t.add_row(s["name"], stat, s["detail"][:80])
        console.print(t)
        console.print(Panel(
            "\n".join(f"{k}: {v}" for k, v in report["outputs"].items()) or "—",
            title=f"Sorties → {out.resolve()}", border_style="green" if report["ok"] else "red",
        ))
    else:
        for s in report["stages"]:
            print(f"[{'OK' if s['status'] == 'ok' else 'FAIL'}] {s['name']}: {s['detail']}")
        for k, v in report["outputs"].items():
            print(f"  {k}: {v}")

    if report["ok"]:
        emit(f"[+] Terminé en {report.get('duration_s', '?')}s — rapport: {out / 'auto_report.json'}")
    else:
        emit(f"[!] Terminé avec erreurs — voir {out / 'auto_report.json'}")
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# TUI — Textual app
# ═══════════════════════════════════════════════════════════════════════════════

if TEXTUAL:
    class TextInputModal(ModalScreen):
        """Dialog modal générique pour saisir un chemin / identifiant."""

        DEFAULT_CSS = """
        TextInputModal {
            align: center middle;
        }
        #modal-box {
            width: 60;
            height: 12;
            border: thick $primary;
            background: $surface;
            padding: 1 2;
        }
        """

        def __init__(self, prompt: str, placeholder: str = ""):
            super().__init__()
            self._prompt = prompt
            self._placeholder = placeholder

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-box"):
                yield Label(self._prompt)
                yield Input(placeholder=self._placeholder, id="text-input")
                with Horizontal():
                    yield Button("OK",     id="modal-ok",     variant="primary")
                    yield Button("Annuler",id="modal-cancel", variant="default")

        def on_button_pressed(self, event: Button.Pressed):
            if event.button.id == "modal-ok":
                val = self.query_one("#text-input", Input).value.strip()
                self.dismiss(val or None)
            else:
                self.dismiss(None)

        def on_input_submitted(self, event: Input.Submitted):
            self.dismiss(event.value.strip() or None)


    class DevicePanel(Static):
        devices: reactive = reactive([])

        def compose(self) -> ComposeResult:
            yield Label("Devices", id="dev-title")
            yield Log(id="dev-log", max_lines=20)

        def refresh_devices(self):
            log = self.query_one("#dev-log", Log)
            log.clear()
            devs = get_connected_devices()
            if not devs:
                log.write_line("[red]Aucun device détecté[/red]")
            for d in devs:
                status = "✓ TRUSTED" if d["trusted"] else "✗ Faire confiance requis"
                log.write_line(f"{d['name']} | {d['ios']} | {d['model']} | {status}")
                log.write_line(f"  UDID: {d['udid']}")


    class ActionPanel(Static):
        def compose(self) -> ComposeResult:
            yield Label("Actions", id="action-title")
            with Vertical():
                yield Button("🔍 Check deps",     id="btn-check",   variant="default")
                yield Button("🔐 Pair device",    id="btn-pair",    variant="primary")
                yield Button("📸 Extract DCIM",   id="btn-dcim",    variant="success")
                yield Button("💾 Full backup",    id="btn-backup",  variant="success")
                yield Button("📱 List apps",      id="btn-apps",    variant="default")
                yield Button("🔑 Keychain dump",  id="btn-keychain",variant="warning")
                yield Button("🔎 Audit IPA",      id="btn-audit",   variant="default")
                yield Button("🧪 Scan données",   id="btn-scan",    variant="default")


    class OutputPanel(Static):
        def compose(self) -> ComposeResult:
            yield Label("Output", id="out-title")
            yield Log(id="out-log", max_lines=200)

        def log(self, msg: str):
            self.query_one("#out-log", Log).write_line(msg)


    class IphoneAFUApp(App):
        CSS = """
        Screen {
            layout: grid;
            grid-size: 3 2;
            grid-rows: 1fr 1fr;
            grid-columns: 1fr 1fr 2fr;
        }
        DevicePanel {
            row-span: 1;
            column-span: 2;
            border: solid $primary;
            padding: 1;
        }
        ActionPanel {
            row-span: 2;
            border: solid $accent;
            padding: 1;
        }
        OutputPanel {
            row-span: 2;
            column-span: 2;
            border: solid $success;
            padding: 1;
        }
        Button { margin: 1 0; width: 100%; }
        #dev-title, #action-title, #out-title {
            text-style: bold;
            color: $text-muted;
        }
        """

        BINDINGS = [
            ("q", "quit", "Quitter"),
            ("r", "refresh", "Refresh devices"),
        ]

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            yield DevicePanel(id="device-panel")
            yield ActionPanel(id="action-panel")
            yield OutputPanel(id="output-panel")
            yield Footer()

        def on_mount(self):
            self.title = "iPhone AFU Tool"
            self.action_refresh()

        def action_refresh(self):
            self.query_one(DevicePanel).refresh_devices()

        def _out(self, msg: str):
            self.query_one(OutputPanel).log(msg)

        def on_button_pressed(self, event: Button.Pressed):
            bid = event.button.id

            if bid == "btn-check":
                deps = check_deps()
                for k, v in deps.items():
                    self._out(f"{'✓' if v else '✗'} {k}")

            elif bid == "btn-pair":
                self._out("Attente trust (60s)... Branche + 'Faire confiance'")
                self.run_worker(self._worker_pair())

            elif bid == "btn-dcim":
                out = Path.home() / "iphone_dcim_out"
                self._out(f"Extraction DCIM → {out}")
                self.run_worker(self._worker_dcim(out))

            elif bid == "btn-backup":
                out = Path.home() / "iphone_backup_out"
                self._out(f"Backup → {out}")
                self.run_worker(self._worker_backup(out))

            elif bid == "btn-apps":
                self.run_worker(self._worker_apps())

            elif bid == "btn-keychain":
                self.push_screen(
                    TextInputModal("Bundle ID de l'app cible :", "com.apple.mobilesafari"),
                    callback=self._on_bundle_id,
                )

            elif bid == "btn-audit":
                self.push_screen(
                    TextInputModal("Chemin de l'IPA ou du .app :", "C:/chemin/app.ipa"),
                    callback=self._on_audit_path,
                )

            elif bid == "btn-scan":
                self.push_screen(
                    TextInputModal("Répertoire à scanner :", str(Path.home())),
                    callback=self._on_scan_path,
                )

        async def _worker_pair(self):
            ld = await asyncio.get_event_loop().run_in_executor(
                None, lambda: wait_for_trust(timeout=60)
            )
            if ld:
                out = Path.home() / "iphone_pair.json"
                ok = save_pairing_record(ld, out)
                self._out(f"✓ Trust établi — record → {out}" if ok else "✓ Trust établi")
                self.action_refresh()
            else:
                self._out("✗ Timeout — trust non établi")

        async def _worker_dcim(self, out: Path):
            devs = get_connected_devices()
            trusted = [d for d in devs if d["trusted"]]
            if not trusted:
                self._out("✗ Aucun device trusted")
                return
            ld = trusted[0]["lockdown"]
            stats = await asyncio.get_event_loop().run_in_executor(
                None, lambda: extract_dcim(ld, out)
            )
            self._out(f"✓ {stats['files']} fichiers, {stats['bytes']//1024//1024}MB")
            if stats["errors"]:
                self._out(f"⚠ {len(stats['errors'])} erreurs")

        async def _worker_backup(self, out: Path):
            devs = get_connected_devices()
            trusted = [d for d in devs if d["trusted"]]
            if not trusted:
                self._out("✗ Aucun device trusted")
                return
            ld = trusted[0]["lockdown"]
            stats = await asyncio.get_event_loop().run_in_executor(
                None, lambda: extract_backup(ld, out)
            )
            self._out(f"{'✓' if stats['status'] == 'success' else '✗'} {stats['status']}")
            if stats.get("error"):
                self._out(f"  {stats['error']}")

        async def _worker_apps(self):
            devs = get_connected_devices()
            trusted = [d for d in devs if d["trusted"]]
            if not trusted:
                self._out("✗ Aucun device trusted")
                return
            ld = trusted[0]["lockdown"]
            apps = await asyncio.get_event_loop().run_in_executor(
                None, lambda: extract_installed_apps(ld)
            )
            self._out(f"{len(apps)} apps installées:")
            for a in sorted(apps, key=lambda x: x["name"])[:50]:
                self._out(f"  {a['name']} ({a['bundle_id']}) v{a['version']}")

        def _on_bundle_id(self, bundle_id: Optional[str]):
            if bundle_id:
                self.run_worker(self._worker_keychain(bundle_id))
            else:
                self._out("Keychain dump annulé")

        async def _worker_keychain(self, bundle_id: str):
            devs = get_connected_devices()
            trusted = [d for d in devs if d["trusted"]]
            if not trusted:
                self._out("✗ Aucun device trusted")
                return
            udid = trusted[0]["udid"]
            out = Path.home() / "keychain_dump.json"
            self._out(f"Keychain dump → {out} (bundle {bundle_id})")
            result = await asyncio.get_event_loop().run_in_executor(
                None, lambda: dump_keychain_frida(udid, bundle_id, out)
            )
            if result["status"] == "success":
                self._out(f"✓ {len(result['items'])} items → {out}")
                for cls, n in (result.get("by_class") or {}).items():
                    self._out(f"    {cls}: {n}")
            else:
                self._out(f"✗ {result['error']}")

        def _on_audit_path(self, path: Optional[str]):
            if path:
                self.run_worker(self._worker_audit(Path(path)))
            else:
                self._out("Audit annulé")

        async def _worker_audit(self, path: Path):
            self._out(f"Audit statique → {path}")
            try:
                report = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: audit_app(path)
                )
            except Exception as e:
                self._out(f"✗ {e}")
                return
            for fd in report["findings"]:
                self._out(f"  [{fd['severity']}] {fd['title']}")
            self._out(f"✓ {len(report['findings'])} findings — {report['bundle']['id']}")

        def _on_scan_path(self, path: Optional[str]):
            if path:
                self.run_worker(self._worker_scan(Path(path)))
            else:
                self._out("Scan annulé")

        async def _worker_scan(self, path: Path):
            self._out(f"Scan données sensibles → {path}")
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: scan_directory(path)
                )
            except RuntimeError as e:
                self._out(f"✗ {e}")
                return
            for fd in result["findings"][:50]:
                self._out(f"  [{fd['severity']}] {fd['path']} — {fd['detail']}")
            self._out(f"✓ {result['scanned_files']} fichiers scannés, {len(result['findings'])} findings")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="iphone_afu",
        description="iPhone AFU Extraction Tool — iOS 17/18, A18 Pro"
    )
    parser.add_argument("--udid",   help="UDID du device (optionnel si un seul device)")
    parser.add_argument("--record", help="Chemin vers un pairing record JSON existant")

    sub = parser.add_subparsers(dest="cmd")

    # check
    sub.add_parser("check", help="Vérifie deps + devices connectés")

    # pair
    p_pair = sub.add_parser("pair", help="Attend le trust + sauvegarde le pairing record")
    p_pair.add_argument("-o", "--output",  default="iphone_pair.json", help="Fichier de sortie")
    p_pair.add_argument("-t", "--timeout", type=int, default=60, help="Timeout en secondes")
    p_pair.add_argument("--password", help="Mot de passe pour chiffrer le pairing record (.enc)")

    # dcim
    p_dcim = sub.add_parser("dcim", help="Extrait DCIM via AFC")
    p_dcim.add_argument("-o", "--output", default="./iphone_dcim", help="Répertoire de sortie")
    p_dcim.add_argument("--password", help="Mot de passe si --record est un .enc")

    # backup
    p_backup = sub.add_parser("backup", help="Backup complet")
    p_backup.add_argument("-o", "--output",    default="./iphone_backup", help="Répertoire de sortie")
    p_backup.add_argument("--encrypted",       action="store_true", help="Garder le chiffrement")
    p_backup.add_argument("--password",        help="Mot de passe si --record est un .enc")

    # apps
    p_apps = sub.add_parser("apps", help="Liste les apps installées")
    p_apps.add_argument("--password", help="Mot de passe si --record est un .enc")

    # keychain
    p_kc = sub.add_parser("keychain", help="Dump keychain via Frida (nécessite frida)")
    p_kc.add_argument("-b", "--bundle-id", required=True, dest="bundle_id", help="Bundle ID de l'app cible")
    p_kc.add_argument("-o", "--output",    default="keychain_dump.json", help="Fichier de sortie JSON")

    # tui
    sub.add_parser("tui", help="Lance l'interface TUI")

    # tunnel
    p_tunnel = sub.add_parser("tunnel", help="Démarre le tunnel RemoteXPC (iOS 17/18, nécessite sudo)")
    p_tunnel.add_argument("--keep-alive", action="store_true", help="Relancer si le tunnel meurt")

    # audit (offline)
    p_audit = sub.add_parser("audit", help="Audit statique d'un IPA/.app (protections, ATS, schemes, entitlements)")
    p_audit.add_argument("path", help="Chemin vers app.ipa ou Target.app")
    p_audit.add_argument("--json", dest="json_out", help="Écrit le rapport complet en JSON")

    # aasa (réseau)
    p_aasa = sub.add_parser("aasa", help="Analyse l'Apple-App-Site-Association (Universal Links)")
    p_aasa.add_argument("domain", help="Domaine cible (ex: target.com)")

    # scan (offline)
    p_scan = sub.add_parser("scan", help="Scanne un backup/container pour données sensibles")
    p_scan.add_argument("path", help="Répertoire à scanner")
    p_scan.add_argument("--json", dest="json_out", help="Écrit les findings en JSON")

    # bypass (Frida)
    p_bypass = sub.add_parser("bypass", help="Frida SSL pinning bypass (+ jailbreak bypass optionnel)")
    p_bypass.add_argument("-b", "--bundle-id", dest="bundle_id", help="Bundle ID cible")
    p_bypass.add_argument("--jailbreak", action="store_true", help="Ajoute le bypass de détection de jailbreak")
    p_bypass.add_argument("--write", help="Écrit le script JS au lieu d'injecter")

    # info (device)
    sub.add_parser("info", help="Infos détaillées du device (lockdown)")

    # syslog (device)
    p_syslog = sub.add_parser("syslog", help="Collecte le syslog du device")
    p_syslog.add_argument("-o", "--output", default="iphone_syslog.txt", help="Fichier de sortie")
    p_syslog.add_argument("-t", "--timeout", type=int, default=10, help="Durée de collecte (secondes)")

    # auto / plug (pipeline complet)
    p_auto = sub.add_parser(
        "auto", aliases=["plug"],
        help="Plug & Play : détecte, (re)pair, extrait tout (info+apps+dcim+backup+syslog) et analyse",
    )
    p_auto.add_argument("-o", "--output", default="./afu_out", help="Répertoire de sortie (défaut ./afu_out)")
    p_auto.add_argument("-t", "--timeout", type=int, default=120, help="Attente device/trust (secondes)")
    p_auto.add_argument("--password", help="Mot de passe du record chiffré (.enc)")
    p_auto.add_argument("--encrypted", action="store_true", help="Garder le backup chiffré")
    p_auto.add_argument("--skip", help="Étapes à ignorer : info,apps,dcim,backup,syslog,scan")
    p_auto.add_argument("--syslog-timeout", type=int, default=10, dest="syslog_timeout",
                        help="Durée de collecte syslog (secondes)")

    args = parser.parse_args()

    if args.cmd == "check":
        cli_check(args)
    elif args.cmd == "pair":
        cli_pair(args)
    elif args.cmd == "dcim":
        cli_dcim(args)
    elif args.cmd == "backup":
        cli_backup(args)
    elif args.cmd == "apps":
        cli_apps(args)
    elif args.cmd == "keychain":
        cli_keychain(args)
    elif args.cmd == "tunnel":
        cli_tunnel(args)
    elif args.cmd == "audit":
        cli_audit(args)
    elif args.cmd == "aasa":
        cli_aasa(args)
    elif args.cmd == "scan":
        cli_scan(args)
    elif args.cmd == "bypass":
        cli_bypass(args)
    elif args.cmd == "info":
        cli_info(args)
    elif args.cmd == "syslog":
        cli_syslog(args)
    elif args.cmd in ("auto", "plug"):
        cli_auto(args)
    elif args.cmd == "tui":
        if not TEXTUAL:
            print("[!] textual manquant — pip install textual")
            sys.exit(1)
        IphoneAFUApp().run()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
