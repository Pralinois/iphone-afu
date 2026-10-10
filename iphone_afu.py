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
import secrets
import shutil
import signal
import subprocess
import sys
import time
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

    result = {"status": "pending", "items": [], "error": None}

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
    json_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
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
        else:
            print(f"[+] {msg}")
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


# ═══════════════════════════════════════════════════════════════════════════════
# TUI — Textual app
# ═══════════════════════════════════════════════════════════════════════════════

if TEXTUAL:
    class BundleInputModal(ModalScreen):
        """Dialog modal pour saisir un bundle ID."""

        DEFAULT_CSS = """
        BundleInputModal {
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

        def compose(self) -> ComposeResult:
            with Vertical(id="modal-box"):
                yield Label("Bundle ID de l'app cible :")
                yield Input(placeholder="com.apple.mobilesafari", id="bundle-input")
                with Horizontal():
                    yield Button("OK",     id="modal-ok",     variant="primary")
                    yield Button("Annuler",id="modal-cancel", variant="default")

        def on_button_pressed(self, event: Button.Pressed):
            if event.button.id == "modal-ok":
                val = self.query_one("#bundle-input", Input).value.strip()
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
                self.push_screen(BundleInputModal(), callback=self._on_bundle_id)

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
            else:
                self._out(f"✗ {result['error']}")


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
    elif args.cmd == "tui":
        if not TEXTUAL:
            print("[!] textual manquant — pip install textual")
            sys.exit(1)
        IphoneAFUApp().run()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
