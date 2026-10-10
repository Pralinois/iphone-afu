# iPhone AFU Tool

iOS 17/18 — A18 Pro — Linux natif / VM Linux / WSL2 sur Windows

---

## Setup

```bash
bash setup.sh
source .venv/bin/activate
```

Guide complet de lancement (WSL2 pas-à-pas / VM / natif) : [docs/GUIDE_LANCEMENT.md](docs/GUIDE_LANCEMENT.md)

---

## Commandes CLI

### Vérifier l'environnement
```bash
python iphone_afu.py check
```

### Établir le trust + sauvegarder le pairing record
```bash
# Branche le téléphone déverrouillé, tape "Faire confiance" sur l'écran
python iphone_afu.py pair -o mon_iphone.json

# Timeout custom (120s)
python iphone_afu.py pair -t 120 -o mon_iphone.json

# Record chiffré AES-256-GCM (scrypt) → mon_iphone.json.enc
python iphone_afu.py pair -o mon_iphone.json --password "mon secret"
```

### Extraire DCIM (photos + vidéos)
```bash
# Device branché (trust établi en live)
python iphone_afu.py dcim -o ./photos_out

# Avec pairing record sauvegardé (AFU, sans déverrouiller)
python iphone_afu.py --record mon_iphone.json dcim -o ./photos_out

# Avec record chiffré
python iphone_afu.py --record mon_iphone.json.enc dcim -o ./photos_out --password "mon secret"
```

Après extraction, un manifeste est écrit dans le répertoire de sortie :
`manifest.json` + `manifest.csv` (path, size_bytes, mtime, ext, exif_date).
La date EXIF est extraite si Pillow est installé.

### Backup complet
```bash
python iphone_afu.py backup -o ./backup_out

# Avec record
python iphone_afu.py --record mon_iphone.json backup -o ./backup_out

# Avec record chiffré
python iphone_afu.py --record mon_iphone.json.enc backup -o ./backup_out --password "mon secret"

# Garder le chiffrement (backup chiffré)
python iphone_afu.py backup --encrypted -o ./backup_out
```

### Lister les apps installées
```bash
python iphone_afu.py apps
python iphone_afu.py --record mon_iphone.json apps
python iphone_afu.py --record mon_iphone.json.enc apps --password "mon secret"
```

### Tunnel RemoteXPC (iOS 17/18 — requis par la plupart des services)
```bash
# Terminal dédié, sudo requis
sudo python iphone_afu.py tunnel

# Relance automatique si le tunnel meurt
sudo python iphone_afu.py tunnel --keep-alive
```

### Infos device + syslog
```bash
python iphone_afu.py info                       # infos détaillées (lockdown)
python iphone_afu.py syslog -t 15 -o log.txt    # collecte le syslog
```

### Audit de sécurité (offline — aucun device requis)
```bash
# Audit statique d'un IPA/.app : protections Mach-O (PIE/canary/ARC/chiffrement),
# entitlements, schémas URL, ATS. Rapport JSON optionnel.
python iphone_afu.py audit app.ipa
python iphone_afu.py audit Payload/Target.app --json rapport.json

# Universal Links : analyse l'AASA du domaine (wildcards, content-type)
python iphone_afu.py aasa target.com

# Scan de données sensibles (backup/container) : cookies, prefs, sqlite,
# secrets en clair (JWT, tokens, clés privées, mots de passe…)
python iphone_afu.py scan ./backup_out --json findings.json
```

### Bypass runtime Frida (SSL pinning / jailbreak)
```bash
# Génère le script (à charger avec frida -U -f <bundle> -l script.js)
python iphone_afu.py bypass --write bypass.js

# Injecte directement sur le device (frida-server ou gadget sideload requis)
python iphone_afu.py bypass -b com.target.app
python iphone_afu.py bypass -b com.target.app --jailbreak
```

### Keychain dump via Frida
```bash
# Nécessite frida-server sur le device OU app re-signée avec gadget
python iphone_afu.py keychain -b com.apple.mobilesafari -o keychain.json

# Device spécifique
python iphone_afu.py --udid <UDID> keychain -b com.target.app -o kc.json
```

### Interface TUI
```bash
python iphone_afu.py tui
```

Le bouton "Keychain dump" ouvre un dialog pour saisir le bundle ID directement
dans la TUI (plus besoin de repasser par le CLI).

---

## Diagnostic VM USB

```bash
python check_vm_usb.py
```

Vérifie dans l'ordre : hyperviseur (VMware / VirtualBox / KVM / bare-metal),
usbmuxd actif, device Apple visible sur le bus USB (05ac), device reconnu par
usbmuxd, trust établi, passthrough VMware, groupes utilisateur (plugdev/dialout).
Exit code 0 si tout OK, 1 sinon. (Linux uniquement)

---

## Frida gadget — sideload sans jailbreak

```bash
# Linux (ldid)
bash frida_sideload.sh mon_app.ipa com.example.app

# macOS avec identité de signature
bash frida_sideload.sh mon_app.ipa com.example.app "Apple Development: moi@example.com"
```

Télécharge FridaGadget.dylib, l'insère dans l'IPA, re-signe (ldid ou codesign),
rezippe et installe via `ios-deploy`. Lancement ensuite : `frida -U -f <bundle_id>`.

---

## Tests

```bash
python -m pytest tests/
```

Les tests ne nécessitent aucun device (pymobiledevice3 entièrement mocké).

---

## Problèmes courants

| Symptôme | Fix |
|---|---|
| `idevice_id` retourne rien | `sudo systemctl start usbmuxd` |
| Trust non proposé à l'écran | Déverrouille avant de brancher |
| Tunnel RemoteXPC échoue | `sudo` requis sur pymobiledevice3 |
| AFC vide | Trust expiré → re-pair |
| Permission USB denied | `sudo usermod -aG plugdev $USER` + reconnect session |
| `Tunnel RemoteXPC non détecté` | `sudo python iphone_afu.py tunnel` (terminal dédié) |
| Record `.enc` refusé | `--password` manquant/incorrect — vérifie le mot de passe |
| VM ne voit pas le device | Activer USB passthrough VMware/VirtualBox (ou `usbipd attach` en WSL2) — puis `python check_vm_usb.py` |

---

## AFU — ce que ça permet sans jailbreak (A18 Pro)

| Capacité | Status |
|---|---|
| DCIM photos/vidéos | ✅ |
| Métadonnées EXIF | ✅ |
| Liste des apps | ✅ |
| Backup complet | ✅ |
| Keychain (tokens background) | ⚠️ Frida gadget requis |
| Filesystem complet | ❌ pas de jailbreak A18 public |
| Mémoire live | ❌ |

## Audit de sécurité (hors device)

| Capacité | Commande |
|---|---|
| Protections binaire (PIE/canary/ARC/chiffrement) | `audit` |
| Entitlements (get-task-allow, keychain groups, privés Apple) | `audit` |
| Schémas URL + ATS (HTTP en clair, exceptions) | `audit` |
| Universal Links / AASA (wildcards, content-type) | `aasa` |
| Secrets en clair dans backup/container (JWT, tokens, clés) | `scan` |
| Bypass SSL pinning (SecTrust/SSLHandshake) + détection JB | `bypass` |

---

## VM Linux sur Windows

1. VMware Workstation Player (gratuit) ou VirtualBox
2. **USB passthrough** : Settings → USB → Add device → Apple iPhone
3. VMware garde la connexion USB plus stable que VirtualBox sur reconnect
4. Lancer le setup depuis la VM — les drivers USB sont gérés par usbmuxd Linux

### Alternative : WSL2 + usbipd-win

Fonctionne (usbmuxd tourne dans WSL), avec un passthrough USB explicite :

```powershell
# Windows (admin) — installer puis attacher l'iPhone
winget install usbipd
usbipd list                  # repère le BUSID de l'iPhone
usbipd bind --force --busid <X>
usbipd attach --wsl --busid <X>
```

```bash
# Dans WSL (Ubuntu)
sudo apt install usbip usbutils   # si indisponible : linux-tools-generic + update-alternatives
bash setup.sh
source .venv/bin/activate
sudo systemctl restart usbmuxd    # ou: sudo usbmuxd -f -v (WSL sans systemd)
python iphone_afu.py check
```

Caveats WSL2 :
- Pas d'udev → relancer usbmuxd après chaque `usbipd attach`
- Reconnexions USB capricieuses → relancer `usbipd attach --wsl --busid <X>`
- WSL1 ne supporte pas l'USB du tout (`wsl --set-version <distro> 2`)
