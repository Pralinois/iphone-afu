# iPhone AFU Tool — Copilot Improvement Brief

> Ce document est un brief opérationnel pour GitHub Copilot (ou tout autre agent de code).
> Chaque section = une tâche autonome. Prends-les dans l'ordre ou en parallèle — les dépendances sont signalées.
> Ne modifie rien hors du périmètre de chaque tâche. Ship du code runnable, pas des stubs.

---

## Contexte du projet

**Fichiers existants :**
```
iphone_afu_tool/
├── iphone_afu.py      — outil principal (CLI argparse + TUI Textual)
├── requirements.txt   — dépendances Python
├── setup.sh           — install Debian/Ubuntu
└── README.md          — documentation utilisateur
```

**Stack :**
- Python 3.10+
- `pymobiledevice3` ≥ 4.0 — protocole iOS (AFC, backup, lockdown)
- `rich` — rendu CLI
- `textual` — TUI
- `frida-tools` — injection runtime
- Target : Linux natif + VM Linux sur Windows, iPhone 16 Pro A18 Pro iOS 18.4+

**Architecture actuelle :**
```
iphone_afu.py
├── check_deps()           — vérifie binaires + imports
├── get_connected_devices() — liste devices via pymobiledevice3
├── wait_for_trust()       — boucle polling jusqu'au trust dialog
├── save/load_pairing_record() — persist le cert de pairing
├── extract_dcim()         — walk AFC /DCIM → disque
├── extract_backup()       — Mobilebackup2Service full backup
├── extract_installed_apps() — InstallationProxyService
├── dump_keychain_frida()  — script Frida inline via subprocess
├── cli_*()                — handlers argparse
├── _get_lockdown()        — helper device resolution
└── IphoneAFUApp           — Textual TUI (DevicePanel / ActionPanel / OutputPanel)
```

---

## TÂCHE 1 — Logging structuré

**Fichier cible :** `iphone_afu.py`

**Problème :** les erreurs partent en `stats["errors"].append(str(e))` sans contexte ni niveau. Impossible de débugger sur VM sans voir ce qui se passe côté usbmuxd.

**Ce que Copilot doit faire :**

1. Ajouter en tête de fichier, après les imports existants :

```python
import logging
from logging.handlers import RotatingFileHandler

LOG_PATH = Path.home() / ".iphone_afu" / "debug.log"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

_fmt = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(funcName)s — %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("iphone_afu")
log.setLevel(logging.DEBUG)

_fh = RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=3)
_fh.setFormatter(_fmt)
_fh.setLevel(logging.DEBUG)
log.addHandler(_fh)

_ch = logging.StreamHandler()
_ch.setFormatter(_fmt)
_ch.setLevel(logging.WARNING)   # console : WARNING+ seulement
log.addHandler(_ch)
```

2. Remplacer **tous** les `except Exception as e: pass` et `stats["errors"].append(...)` par `log.warning(...)` / `log.error(...)` avec contexte : nom de la fonction, paramètres utiles.

3. Ajouter `log.debug(...)` aux points clés :
   - entrée dans `get_connected_devices()`
   - chaque device trouvé + trusted/not-trusted
   - entrée/sortie de `extract_dcim()` avec nombre de fichiers
   - chaque fichier AFC échoué

4. Exposer le path du log dans `cli_check()` :
   - Rich : `console.print(f"[dim]Log → {LOG_PATH}[/dim]")`
   - Fallback : `print(f"[log] {LOG_PATH}")`

**Ne pas modifier** le comportement des fonctions — juste instrumenter.

---

## TÂCHE 2 — Retry + robustesse AFC

**Fichier cible :** `iphone_afu.py`, fonction `extract_dcim()`

**Problème :** sur VM Linux, la connexion AFC peut dropper en cours d'extraction (USB passthrough instable). Actuellement, une erreur = fichier skipé silencieusement.

**Ce que Copilot doit faire :**

1. Créer un helper de retry au-dessus de `extract_dcim` :

```python
def _afc_retry(fn, *args, retries: int = 3, delay: float = 1.5, **kwargs):
    """Retente fn jusqu'à retries fois avec backoff linéaire."""
    last_err = None
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            last_err = e
            log.warning(f"AFC retry {attempt+1}/{retries} — {e}")
            time.sleep(delay * (attempt + 1))
    raise last_err
```

2. Wrapper les appels critiques dans `walk_afc` :
   - `afc.listdir(remote_path)` → `_afc_retry(afc.listdir, remote_path)`
   - `afc.get_file_contents(remote_full)` → `_afc_retry(afc.get_file_contents, remote_full)`

3. Ajouter `stats["retries"]` dans le dict retourné par `extract_dcim()`.

4. Afficher le compteur de retries dans `cli_dcim()` si `stats["retries"] > 0` :
   - Rich : `[yellow]⚠ {stats['retries']} retries AFC[/yellow]`
   - Fallback : `print(f"[!] {stats['retries']} AFC retries")`

---

## TÂCHE 3 — Pairing record chiffré (AES-GCM)

**Fichier cible :** `iphone_afu.py`
**Dépendance nouvelle :** `cryptography` — ajouter à `requirements.txt`

**Problème :** `iphone_pair.json` contient le certificat de pairing en clair. Sur disque Windows partagé avec la VM (dossier monté), c'est un risque.

**Ce que Copilot doit faire :**

1. Ajouter l'import :
```python
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    import base64, secrets
    CRYPTO = True
except ImportError:
    CRYPTO = False
```

2. Créer deux fonctions standalone :

```python
def encrypt_pairing_record(data: dict, password: str) -> bytes:
    """
    Chiffre un pairing record en AES-256-GCM avec clé dérivée par scrypt.
    Format : salt(32) || nonce(12) || ciphertext
    """
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
    salt, nonce, ct = blob[:32], blob[32:44], blob[44:]
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    key = kdf.derive(password.encode())
    plaintext = AESGCM(key).decrypt(nonce, ct, None)
    return json.loads(plaintext)
```

3. Modifier `save_pairing_record(lockdown, output_path, password=None)` :
   - Si `password` et `CRYPTO` : écrire le blob chiffré en binaire (`.enc`)
   - Sinon : comportement actuel (JSON)

4. Modifier `load_pairing_record(record_path, password=None)` :
   - Si `record_path.suffix == ".enc"` : déchiffrer avec `password`, lever `ValueError` propre si raté
   - Sinon : comportement actuel

5. Ajouter `--password` optionnel aux commandes `pair`, `dcim`, `backup`, `apps` dans argparse :
```python
parser.add_argument("--password", help="Mot de passe pour pairing record chiffré (.enc)")
```

6. Passer `args.password` à `_get_lockdown()` et `cli_pair()`.

**Contrainte :** si `CRYPTO = False`, ignorer silencieusement le chiffrement et logger un `log.warning`.

---

## TÂCHE 4 — Export metadata JSON + CSV

**Fichier cible :** `iphone_afu.py`
**Dépendance nouvelle :** aucune (csv stdlib)

**Problème :** après extraction DCIM, l'utilisateur n'a aucune vue sur ce qui a été extrait — noms, tailles, dates EXIF.

**Ce que Copilot doit faire :**

1. Créer une fonction `build_dcim_manifest(output_dir: Path) -> list[dict]` :

```python
def build_dcim_manifest(output_dir: Path) -> list[dict]:
    """
    Parcourt output_dir récursivement.
    Pour chaque fichier : path relatif, taille bytes, mtime, extension.
    Pour les JPEG/HEIC : tente d'extraire date EXIF (Exif.Image.DateTime).
    Retourne une liste de dicts triée par mtime desc.
    """
```

   - Tenter `from PIL import Image, ExifTags` — si absent, ignorer EXIF silencieusement
   - Champs par entrée : `{"path": str, "size_bytes": int, "mtime": str, "ext": str, "exif_date": str|None}`

2. Créer `export_manifest(manifest: list[dict], output_dir: Path)` :
   - Écrire `manifest.json` dans `output_dir`
   - Écrire `manifest.csv` dans `output_dir` avec `csv.DictWriter`
   - Colonnes CSV : `path,size_bytes,mtime,ext,exif_date`

3. Appeler `build_dcim_manifest` + `export_manifest` à la fin de `cli_dcim()`, après l'extraction.

4. Afficher le résumé dans `cli_dcim()` :
   - Total fichiers, taille totale MB, range de dates EXIF si disponible
   - Rich : `Panel` avec ces stats
   - Fallback : `print`

5. Ajouter `Pillow>=10.0.0` à `requirements.txt` (optionnel — le code doit fonctionner sans).

---

## TÂCHE 5 — Commande `tunnel` et RemoteXPC wrapper

**Fichier cible :** `iphone_afu.py`

**Problème :** iOS 17/18 exige le tunnel RemoteXPC (`sudo pymobiledevice3 remote start-tunnel`) en permanence dans un terminal séparé. Actuellement le tool ne le gère pas — l'utilisateur doit le lancer manuellement.

**Ce que Copilot doit faire :**

1. Créer une fonction `start_tunnel_daemon(udid: Optional[str] = None) -> subprocess.Popen` :

```python
def start_tunnel_daemon(udid: Optional[str] = None) -> subprocess.Popen:
    """
    Lance pymobiledevice3 remote start-tunnel en arrière-plan.
    Retourne le Popen pour kill propre à la sortie.
    Nécessite sudo — lève PermissionError si non-root.
    """
    if os.geteuid() != 0:
        raise PermissionError("start-tunnel nécessite sudo")
    cmd = ["pymobiledevice3", "remote", "start-tunnel"]
    if udid:
        cmd += ["--udid", udid]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    # Attendre 3s et vérifier que le process est vivant
    time.sleep(3)
    if proc.poll() is not None:
        stderr = proc.stderr.read()
        raise RuntimeError(f"Tunnel mort au démarrage: {stderr[:200]}")
    log.info(f"Tunnel RemoteXPC démarré (pid={proc.pid})")
    return proc
```

2. Ajouter la sous-commande `tunnel` à argparse :
```python
p_tunnel = sub.add_parser("tunnel", help="Démarre le tunnel RemoteXPC (iOS 17/18, nécessite sudo)")
p_tunnel.add_argument("--keep-alive", action="store_true", help="Relancer si le tunnel meurt")
```

3. Créer `cli_tunnel(args)` :
   - Lance `start_tunnel_daemon()`
   - Si `--keep-alive` : boucle `while True` qui relance si `proc.poll() is not None`
   - Signal handler `SIGINT` / `SIGTERM` pour `proc.terminate()` propre
   - Affiche pid + statut via Rich / fallback

4. Dans `_get_lockdown()`, si le tunnel n'est pas actif (tester avec une connexion pymobiledevice3 rapide), afficher un warning :
   - Rich : `[yellow]⚠ Tunnel RemoteXPC non détecté — lance: sudo python iphone_afu.py tunnel[/yellow]`

---

## TÂCHE 6 — TUI : input dialog + keychain interactif

**Fichier cible :** `iphone_afu.py`
**Dépendance :** `textual` déjà présent

**Problème :** dans la TUI, le keychain dump demande un bundle ID mais redirige vers le CLI. C'est une sortie de l'interface qui casse l'expérience.

**Ce que Copilot doit faire :**

1. Importer depuis textual :
```python
from textual.widgets import Input
from textual.screen import ModalScreen
```

2. Créer un `ModalScreen` minimal :

```python
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
```

3. Dans `IphoneAFUApp.on_button_pressed`, pour `btn-keychain` :
   - Pousser `BundleInputModal` via `self.push_screen(BundleInputModal(), callback=self._on_bundle_id)`
   - Créer `_on_bundle_id(self, bundle_id: Optional[str])` qui lance `_worker_keychain(bundle_id)` si bundle_id non-None

4. Créer `_worker_keychain(self, bundle_id: str)` dans `IphoneAFUApp` :
   - Récupère le premier device trusted
   - Appelle `dump_keychain_frida()` via `run_in_executor`
   - Log résultat dans OutputPanel

---

## TÂCHE 7 — Tests unitaires

**Nouveau fichier :** `tests/test_iphone_afu.py`
**Dépendance nouvelle :** `pytest`, `pytest-asyncio` — ajouter à `requirements.txt`

**Ce que Copilot doit faire :**

Créer `tests/test_iphone_afu.py` avec les cas suivants. Tous les tests doivent passer sans device connecté (mock complet de pymobiledevice3).

```python
# Structure attendue — Copilot implémente les corps

import pytest
from unittest.mock import MagicMock, patch, mock_open
from pathlib import Path
import json, tempfile

# 1. check_deps retourne un dict avec les bonnes clés
def test_check_deps_keys():
    ...

# 2. get_connected_devices retourne [] si pymobiledevice3 lève une exception
def test_get_connected_devices_empty_on_error():
    ...

# 3. save_pairing_record écrit un JSON valide
def test_save_pairing_record_writes_json():
    ...

# 4. load_pairing_record retourne None si fichier absent
def test_load_pairing_record_missing_file():
    ...

# 5. extract_dcim stats["files"] == 0 si AFC liste vide
def test_extract_dcim_empty_afc():
    ...

# 6. extract_dcim stats["errors"] contient l'erreur si AFC plante
def test_extract_dcim_afc_error():
    ...

# 7. build_dcim_manifest retourne [] sur répertoire vide
def test_build_dcim_manifest_empty_dir():
    ...

# 8. encrypt/decrypt round-trip (si CRYPTO disponible)
def test_encrypt_decrypt_roundtrip():
    ...

# 9. decrypt lève ValueError avec mauvais password
def test_decrypt_wrong_password():
    ...

# 10. _afc_retry retente 3 fois puis lève
def test_afc_retry_exhausted():
    ...
```

Ajouter `conftest.py` dans `tests/` avec les fixtures partagées (mock lockdown, mock AfcService).

Ajouter à `setup.sh` :
```bash
echo "[*] pytest..."
pip install pytest pytest-asyncio
```

---

## TÂCHE 8 — Frida gadget sideload helper

**Nouveau fichier :** `frida_sideload.sh`

**Problème :** pour le keychain dump sans jailbreak (A18 Pro), il faut re-signer l'IPA avec le gadget Frida. C'est une séquence manuelle de 8 étapes. L'automatiser.

**Ce que Copilot doit faire :**

Créer `frida_sideload.sh` — script bash autonome :

```bash
#!/bin/bash
# frida_sideload.sh — Re-signe un IPA avec FridaGadget pour runtime hooking sans jailbreak
# Usage: bash frida_sideload.sh <app.ipa> <bundle_id> [signing_identity]
# Dépendances : ios-deploy, ldid OU codesign (macOS), curl, unzip
```

Séquence à implémenter :

1. Valider les args ($1=IPA path, $2=bundle_id, $3=signing identity optionnel)
2. Détecter OS host (Linux / macOS) pour choisir `ldid` vs `codesign`
3. Vérifier que `ios-deploy` est installé
4. Télécharger `FridaGadget.dylib` depuis GitHub releases (dernière version) si absent dans `/tmp/`
5. Unzip l'IPA dans un répertoire temp
6. Copier `FridaGadget.dylib` dans `Payload/*.app/Frameworks/`
7. Patcher le binaire principal pour charger le gadget (via `insert_dylib` ou `ldid`)
8. Re-signer : si macOS + signing identity → `codesign`; si Linux → `ldid -S`
9. Rezipper en IPA
10. Installer via `ios-deploy --bundle <path> --no-wifi`
11. Afficher le port Frida à utiliser : `frida -U -f <bundle_id>`

Ajouter les guards :
- Sortir avec message clair si dépendance manquante
- Nettoyer le répertoire temp dans un `trap EXIT`
- Afficher chaque étape avec `echo "[N/10] ..."`

---

## TÂCHE 9 — VM USB passthrough checker

**Nouveau fichier :** `check_vm_usb.py`

**Problème :** la cause la plus fréquente d'échec sur VM Linux est le USB passthrough mal configuré ou le device non reconnu par usbmuxd.

**Ce que Copilot doit faire :**

Créer `check_vm_usb.py` — script standalone, aucune dépendance hors stdlib + `rich` optionnel :

```python
#!/usr/bin/env python3
"""
Diagnostic USB + usbmuxd pour VM Linux.
Détecte : VMware / VirtualBox / natif, état usbmuxd, device Apple visible, trust.
"""
```

Checks à implémenter dans l'ordre :

1. **Détection VM** : lire `/proc/cpuinfo`, `/sys/class/dmi/id/product_name`, `dmidecode` — détecter VMware / VirtualBox / KVM / bare-metal
2. **usbmuxd actif** : `systemctl is-active usbmuxd` + socket `/var/run/usbmuxd`
3. **Device Apple visible USB** : parser `lsusb` — VendorID `05ac` (Apple)
4. **Device reconnu par usbmuxd** : tenter `idevice_id -l` via subprocess
5. **Trust établi** : si device reconnu, tenter `ideviceinfo` — succès = trusted
6. **USB passthrough VMware** : si VMware détecté, vérifier `vmware-toolsd` actif + lire `/proc/bus/usb/devices` si dispo
7. **Groupes utilisateur** : `groups $USER` → vérifier `plugdev` et `dialout`

Sortie :
- Rich table si disponible : colonne Check / Status / Fix
- Fallback : lignes `[OK]` / `[FAIL] → fix`
- Exit code 0 si tout OK, 1 si au moins un check échoue

Ajouter dans `setup.sh` :
```bash
echo "[*] Diagnostic VM USB..."
python check_vm_usb.py
```

---

## TÂCHE 10 — `iphone_afu.py` : refactor `_get_lockdown` → classe `DeviceContext`

**Fichier cible :** `iphone_afu.py`

**Problème :** `_get_lockdown()` est un helper global qui fait trop de choses — résoudre le device, charger le record, gérer le fallback. Difficile à tester et à étendre.

**Ce que Copilot doit faire :**

1. Créer une dataclass `DeviceContext` :

```python
from dataclasses import dataclass, field

@dataclass
class DeviceContext:
    udid: Optional[str] = None
    record_path: Optional[Path] = None
    password: Optional[str] = None
    _lockdown: Optional[object] = field(default=None, repr=False)

    def resolve(self) -> object:
        """
        Retourne un LockdownClient.
        Ordre de priorité : record_path > device connecté trusted > erreur.
        Thread-safe : cache dans _lockdown.
        """
        if self._lockdown is not None:
            return self._lockdown
        if self.record_path:
            self._lockdown = load_pairing_record(self.record_path, self.password)
            if self._lockdown is None:
                raise RuntimeError(f"Pairing record invalide : {self.record_path}")
            return self._lockdown
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
        return self._lockdown
```

2. Remplacer tous les appels à `_get_lockdown(args)` dans les `cli_*` par :
```python
ctx = DeviceContext(
    udid=getattr(args, "udid", None),
    record_path=Path(args.record) if getattr(args, "record", None) else None,
    password=getattr(args, "password", None),
)
try:
    ld = ctx.resolve()
except RuntimeError as e:
    # afficher l'erreur avec Rich ou print, puis return
```

3. Passer `ctx.resolve()` directement aux fonctions d'extraction au lieu de `ld` brut.

4. Supprimer `_get_lockdown()` une fois tous les appels migrés.

---

## Ordre de priorité suggéré

| Priorité | Tâche | Impact |
|---|---|---|
| 1 | TÂCHE 1 — Logging | Debug VM impossible sans ça |
| 2 | TÂCHE 2 — Retry AFC | Stabilité sur USB passthrough instable |
| 3 | TÂCHE 5 — Tunnel wrapper | Friction d'usage iOS 17/18 |
| 4 | TÂCHE 9 — VM USB checker | Onboarding + diagnostic |
| 5 | TÂCHE 10 — DeviceContext | Qualité code, prerequis pour les tests |
| 6 | TÂCHE 7 — Tests | Prerequis TÂCHE 10 fait avant |
| 7 | TÂCHE 4 — Manifest export | Feature utile post-extraction |
| 8 | TÂCHE 3 — Chiffrement | Sécurité pairing record |
| 9 | TÂCHE 6 — TUI modal | UX TUI |
| 10 | TÂCHE 8 — Sideload helper | Feature avancée, dépend de l'env |

---

## Contraintes globales pour Copilot

- **Aucun stub.** Chaque fonction livrée est runnable et testable sans device.
- **Backward compat.** Les commandes CLI existantes (`check`, `pair`, `dcim`, `backup`, `apps`, `keychain`, `tui`) gardent leur signature exacte.
- **Pas de breaking change** sur `requirements.txt` — ajouter seulement, ne pas downgrader.
- **Commentaires inline** : une ligne par bloc logique non-évident. Pas de commentaires de type "cette fonction fait X" sur des fonctions dont le nom dit déjà X.
- **Convention de nommage existante** : fonctions `snake_case`, classes `PascalCase`, constantes `UPPER_CASE`.
- **Gestion d'erreur** : retourner des valeurs d'erreur plutôt que lever des exceptions dans les fonctions d'extraction (`extract_*`). Lever des exceptions dans `DeviceContext.resolve()` et les `cli_*`.
- **Rich conditionnel** : chaque chemin d'affichage a son fallback `else: print(...)`.
- **iOS 18.4+ / A18 Pro** : aucune technique nécessitant checkm8 ou jailbreak dans les paths principaux. Le keychain via Frida reste dans une branche optionnelle explicitement documentée.
