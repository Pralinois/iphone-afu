# Guide de lancement — iPhone AFU Tool

> **But :** rendre ce projet opérationnel sur une nouvelle machine (WSL2, VM Linux ou Linux natif), puis lancer une première extraction iPhone.
> Ce document est un **runbook** : chaque bloc se copie-colle tel quel. Copilot peut l'exécuter étape par étape.
> Repo privé : `https://github.com/Pralinois/iphone-afu`

---

## 0. Ce que fait l'outil (30 s)

- **DCIM** : extraction photos/vidéos + manifest `manifest.json` / `manifest.csv` (dates EXIF si Pillow installé)
- **Backup** : backup complet Mobilebackup2 (option non chiffrée)
- **Apps** : liste des apps installées
- **Info/Syslog** : infos détaillées du device + collecte du syslog
- **Tunnel** : wrapper RemoteXPC (iOS 17/18, sudo, `--keep-alive`)
- **Keychain** : dump via Frida (comptage par classe) — branche optionnelle (frida-server ou gadget sideload)
- **Audit (offline)** : IPA statique — protections Mach-O (PIE/canary/ARC/chiffrement), entitlements, schémas URL, ATS ; analyse AASA (Universal Links) ; scan de secrets (JWT/tokens/clés) dans backups
- **Bypass** : scripts Frida SSL pinning (SecTrust/SSLHandshake) + détection jailbreak
- **v2 — RE statique** : `macho` (protections + bypass vectors + anti-debug), `class-dump` (classes ObjC / Swift), `strings-hunt` (secrets + entropie + score d'obfuscation)
- **v2 — données** : `plist-dump` (9 locations de storage iOS), `network-recon` (surface réseau depuis syslog + DNS + GeoIP), `report` (HTML standalone)
- **v2 — runtime** : `proxy` (MITM mitmproxy + CA + bypass pinning), `objection` (10 presets recon)
- **TUI** : interface Textual (check / pair / dcim / backup / apps / keychain / audit / scan)
- **Auto** : pipeline plug & play en une commande (`auto`/`plug` ou `auto.sh`)
- **Tests** : 74 tests unitaires sans device (`pytest`)

---

## 1. Prérequis

| Élément | Détail |
|---|---|
| iPhone | iOS 17/18 (validé pour iPhone 16 Pro / A18 Pro) — déverrouillé la première fois |
| Machine | Windows → **WSL2** (recommandé) • ou VM Linux (VMware/VirtualBox) • ou Linux natif |
| Python | 3.10+ dans l'environnement Linux |
| Câble | USB data (pas charge-seule), éviter les hubs |

---

## 2. Récupérer le projet (repo privé)

```bash
# Option GitHub CLI (recommandée)
gh auth login                  # HTTPS → login navigateur
git clone https://github.com/Pralinois/iphone-afu.git
cd iphone-afu
```

Autres options : `git clone` avec un PAT, ou télécharger l'archive ZIP depuis l'UI GitHub (bouton Code → Download ZIP).

---

## 3. Option A — WSL2 (Windows) ⭐

### 3.1 Windows (une seule fois)
```powershell
wsl --install -d Ubuntu       # redémarrer si demandé
winget install usbipd         # (ou choco install usbipd -y, ou MSI usbipd-win)
```
Vérifier dans WSL : `uname -r` doit contenir `microsoft-standard-WSL2`.
Si erreur `0x80370102` au boot : virtualisation désactivée dans le BIOS (ou nested virt si PC déjà virtualisé).

### 3.2 Activer systemd dans WSL (une fois)
```bash
sudo tee /etc/wsl.conf > /dev/null <<'EOF'
[boot]
systemd=true
EOF
```
Puis côté Windows : `wsl --shutdown`, et relancer le terminal WSL.

### 3.3 Dépendances + projet
```bash
sudo apt update
sudo apt install -y usbip usbutils python3-pip python3-venv
cd iphone-afu
bash setup.sh
source .venv/bin/activate
```

### 3.4 Brancher l'iPhone et l'attacher à WSL
iPhone **déverrouillé** branché. Côté Windows (admin) :
```powershell
usbipd list                            # repérer la ligne Apple → BUSID (ex: 2-4)
usbipd bind --force --busid 2-4        # une seule fois (persiste au reboot)
usbipd attach --wsl --busid 2-4        # À REFAIRE à chaque rebranchement
```

> ⚠️ WSL n'a pas d'udev : après **chaque** `usbipd attach`, relancer usbmuxd :
```bash
sudo systemctl restart usbmuxd || sudo usbmuxd -f -v &
```

### 3.5 Vérifier la chaîne
```bash
python check_vm_usb.py            # doit détecter "WSL2" + device Apple (05ac)
python iphone_afu.py check        # deps OK + device visible, trust ✓
```

---

## 4. Option B — VM Linux (VMware / VirtualBox)

1. VM Debian/Ubuntu + `bash setup.sh` à l'intérieur
2. **USB passthrough** : VM Settings → USB → Add device → Apple iPhone (brancher APRÈS le boot de la VM)
3. VMware garde mieux la connexion USB que VirtualBox sur reconnexion
4. `python iphone_afu.py check` dans la VM

---

## 5. Option C — Linux natif

```bash
bash setup.sh
source .venv/bin/activate
python iphone_afu.py check
```

---

## 6. Première session complète (toutes options)

### 🚀 Le plus simple : tout en une commande

```bash
python iphone_afu.py auto        # alias: plug — ou: bash auto.sh
```
Détecte le device, gère le trust + record persistant, puis enchaîne :
`info` → `apps` → `dcim` (+manifest) → `backup` → `syslog` → `scan` → rapport
`auto_report.json`. En AFU (runs suivants), il réutilise automatiquement le record
`~/.iphone_afu/afu_record.json` — écran verrouillé, rien à faire.

Options utiles : `-o <dir>` (sortie), `--skip syslog,backup` (run rapide),
`--encrypted` (backup chiffré), `--password` (record chiffré).

### Version manuelle (étape par étape)

```bash
# 1) Trust + pairing record (iPhone déverrouillé, accepter "Faire confiance" à l'écran)
python iphone_afu.py pair -o mon_iphone.json

# variante chiffrée (recommandée si disque partagé) → mon_iphone.json.enc
python iphone_afu.py pair -o mon_iphone.json --password "mon secret"

# 2) Extraction DCIM + manifest (json/csv + résumé)
python iphone_afu.py dcim -o ./photos_out
python iphone_afu.py --record mon_iphone.json dcim -o ./photos_out

# 3) Backup complet (non chiffré)
python iphone_afu.py backup -o ./backup_out

# 4) Liste des apps + infos device + syslog
python iphone_afu.py apps
python iphone_afu.py info
python iphone_afu.py syslog -t 15 -o log.txt

# 5) Tunnel RemoteXPC — iOS 17/18, terminal dédié
sudo python iphone_afu.py tunnel --keep-alive

# 6) TUI
python iphone_afu.py tui

# 7) Tests (sans device) — attendu : 74 passed
python -m pytest tests/

# 8) Hors device — audit de sécurité
python iphone_afu.py audit app.ipa --json rapport.json   # IPA statique
python iphone_afu.py macho app.ipa --json macho.json     # protections + bypass vectors
python iphone_afu.py class-dump app.ipa --swift          # classes ObjC / Swift
python iphone_afu.py aasa target.com                     # Universal Links
python iphone_afu.py scan ./backup_out                   # secrets en clair
python iphone_afu.py strings-hunt ./backup_out --obfuscation
python iphone_afu.py plist-dump --backup ./backup_out -o ./plist_out
python iphone_afu.py network-recon --syslog-parse log.txt --resolve
python iphone_afu.py report ./afu_out -o report.html     # rapport HTML consolidé

# 9) Bypass + runtime (frida-server/gadget requis)
python iphone_afu.py bypass --write bypass.js            # script seul
python iphone_afu.py bypass -b com.target.app            # injection directe
python iphone_afu.py proxy --port 8080 --frida-bypass -b com.target.app
python iphone_afu.py objection -b com.target.app --batch -o ./obj_out
```

---

## 7. Dépannage

| Symptôme | Fix |
|---|---|
| `idevice_id` vide | `sudo systemctl start usbmuxd` — et relancer usbmuxd après chaque `usbipd attach` |
| Device disparaît après attach (WSL) | re-`usbipd attach --wsl --busid <X>` ; vérifier le câble |
| Trust non proposé à l'écran | déverrouiller AVANT de brancher ; re-pair |
| `AFC vide` | trust expiré → re-pair |
| Tunnel échoue | `sudo` requis ; terminal dédié |
| `Permission USB denied` | `sudo usermod -aG plugdev $USER` + reconnexion session |
| VM ne voit pas le device | activer USB passthrough, puis `python check_vm_usb.py` |
| WSL : pas de device après attach | pas d'udev → `sudo systemctl restart usbmuxd` (ou `sudo usbmuxd -f -v`) |
| Erreur `0x80370102` (WSL) | virtualisation désactivée (BIOS) ou nested virt absent |
| Record `.enc` refusé | `--password` manquant/incorrect |

---

## 8. Checklist Copilot (à exécuter sur la nouvelle machine)

1. `uname -r` → contient `microsoft-standard-WSL2` (ou Linux natif/VM)
2. `python3 --version` ≥ 3.10
3. `bash setup.sh` → pas d'erreur bloquante. Les lignes `[!] systemd indisponible` / `[!] Groupe plugdev indisponible` sont **normales** sous WSL sans systemd (presque inoffensives)
4. `python -m pytest tests/` → **74 passed** (aucun device requis — c'est le premier feu vert)
5. `python iphone_afu.py auto` → pipeline complet une fois le trust accepté (⚠ premier run : accepte « Faire confiance » sur l'écran)
6. `usbmuxd` actif + `python iphone_afu.py check` → device visible avec trust ✓
7. `python check_vm_usb.py` → exit code 0
8. Runs suivants en AFU : `python iphone_afu.py auto` réutilise `~/.iphone_afu/afu_record.json` — écran verrouillé OK ; vérifie `auto_report.json` (stages `ok`) et `dcim/manifest.json`

Erreurs connues par étape : voir §7. Logs détaillés : `~/.iphone_afu/debug.log` (fichier rotatif, console = WARNING+).
Diagnostic sans device : `python -m pytest tests/` couvre retry AFC, chiffrement, manifest, détection deps.

---

## 9. Sécurité

- Le pairing record contient les clés du device → **jamais commité** (déjà couvert par `.gitignore` : `*.enc`, `iphone_pair.json`)
- Préférer `--password` (AES-256-GCM + scrypt) si le disque est partagé/dossier monté
- Le keychain via Frida reste une branche optionnelle explicite (frida-server ou sideload gadget — voir `frida_sideload.sh`)

---

## 10. Où continuer

- README utilisateur : `README.md`
- Améliorations planifiées : `docs/COPILOT_BRIEF.md`
- Diagnostic VM/WSL : `check_vm_usb.py`
