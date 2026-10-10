# Récupération du pairing record depuis une machine déjà trustée

> Objectif : réutiliser un pairing record existant (créé sur une autre machine)
> pour accéder à un iPhone en mode **AFU** (After First Unlock) — sans retaper
> « Faire confiance » — puis extraire photos/vidéos, backup, etc.

---

## Pourquoi ça marche

Le trust dialog iOS génère un pairing record stocké **côté host ET côté phone** :

| Côté | Emplacement |
|---|---|
| Phone | `/var/db/lockdown/<UDID>.plist` |
| Host | Chemins par OS — voir §« Récupérer le record » |

Le record contient les certificats croisés (RootCertificate, HostCertificate,
DeviceCertificate) et la clé privée de l'host. Il permet à n'importe quelle
machine de s'authentifier auprès du device sans re-trust, **tant que** :

- Le device est en **AFU** (déverrouillé au moins une fois depuis le dernier reboot)
- L'utilisateur n'a pas fait **Reset Location & Privacy** côté phone
  (ce reset efface les records côté phone → re-pair obligatoire)

Fonctionne sur toutes versions iOS jusqu'à **iOS 26.x** actuel.

---

## Récupérer le record (machine source = celle qui a déjà trusté)

### Depuis Linux
```bash
ls /var/lib/lockdown/          # lister les UDIDs
sudo cp /var/lib/lockdown/<UDID>.plist ./mon_record.plist
# fallback sans sudo : ~/.config/lockdown/ ou ~/.local/share/lockdown/
```

### Depuis macOS
```bash
ls /var/db/lockdown/
sudo cp /var/db/lockdown/<UDID>.plist ./mon_record.plist
```

### Depuis Windows (iTunes)
```
C:\ProgramData\Apple\Lockdown\<UDID>.plist
# ou si iTunes Microsoft Store :
%LOCALAPPDATA%\Apple\MobileSync\Lockdown\<UDID>.plist
```
Copier via explorateur ou :
```powershell
Copy-Item "$env:ALLUSERSPROFILE\Apple\Lockdown\*.plist" .\
```

### Depuis Windows (3uTools / iMazing)
Ces outils stockent le record dans leurs propres répertoires :
- iMazing : `%APPDATA%\DigiDNA\iMazing\Lockdown\`
- 3uTools : `%APPDATA%\3uTools\Lockdown\`

`record-find` scanne automatiquement tous ces chemins (+ `~/.iphone_afu/` et
`%APPDATA%\Apple Computer\Lockdown\`).

### Automatiquement avec le tool
```bash
python iphone_afu.py record-find                    # liste (UDID, validité, chemin, WiFi MAC)
python iphone_afu.py record-find --udid <UDID>      # filtre
python iphone_afu.py record-find --export ./records_out/   # copie les records valides
```

---

## Utiliser le record sur la nouvelle machine

```bash
# 1. Vérifier que le record est complet et fonctionnel (5 étapes)
python iphone_afu.py record-test ./mon_record.plist
#   ✓ Parse plist → ✓ Load LockdownClient → ✓ AFU confirmé → ✓ AFC accessible

# 2. Si AFC accessible → extraire directement
python iphone_afu.py --record ./mon_record.plist dcim   -o ./photos_out
python iphone_afu.py --record ./mon_record.plist backup -o ./backup_out
python iphone_afu.py --record ./mon_record.plist auto   -o ./afu_out

# 3. (optionnel) Installer pour usage automatique sans --record
python iphone_afu.py record-import ./mon_record.plist --install --test
```

L'installation copie le record aux emplacements standards pour que
pymobiledevice3 / libimobiledevice le trouvent tout seuls :

| OS | Chemin d'installation |
|---|---|
| Linux | `/var/lib/lockdown/<UDID>.plist` (sudo) + `~/.config/lockdown/<UDID>.plist` (fallback) |
| macOS | `/var/db/lockdown/<UDID>.plist` (sudo) |
| Windows | `%ALLUSERSPROFILE%\Apple\Lockdown\<UDID>.plist` |

---

## Cas d'échec et solutions

| Symptôme (`record-test`) | Cause | Solution |
|---|---|---|
| Étape 1 ✗ — record incomplet | plist tronqué, champs manquants | Re-copier le record source ; vérifier `HostPrivateKey` présent |
| Étape 2 ✗ — lockdown error | pymobiledevice3 absent ou record illisible | `pip install pymobiledevice3` ; vérifier le fichier |
| Étape 3 ✗ — device injoignable | **BFU** (pas déverrouillé depuis le reboot) | Déverrouiller le phone **une fois** — le record reste valide |
| Étape 4 ✗ — AFC bloqué | **Reset Location & Privacy** (record effacé côté phone) ou mauvais record | Impossible à récupérer : `python iphone_afu.py pair -o nouveau_record.plist` |
| Device non détecté | câble/passthrough | `check` / `check_vm_usb.py` / `usbipd attach` (WSL2) |

---

## Dans le pipeline `auto`

Quand un record est utilisé (`--record` ou le record persistant
`~/.iphone_afu/afu_record.json`) **et** qu'un device est branché, `auto` exécute
automatiquement un **record-test** avant d'extraire :

- AFC OK → pipeline normal
- AFU mais AFC bloqué → erreur claire « Reset Location & Privacy probable »
- BFU → erreur claire « déverrouille le phone une fois puis relance »

Étape skippable : `python iphone_afu.py auto --skip record-test`.

---

## Sécurité

- Le record contient la **clé privée de l'host** → traitez-le comme un secret
  (jamais commité — déjà dans `.gitignore` : `*.plist`, `*.enc`, `iphone_pair.json`)
- Le transport (clé USB, scp) doit être de confiance
- Un record volé permet l'accès AFU au device : en cas de doute → Reset Location & Privacy côté phone
