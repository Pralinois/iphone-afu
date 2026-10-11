# Extraction PTP — Zéro trust, zéro pairing record

> Le seul canal d'extraction photos/vidéos qui ne crée ni n'exige de pairing
> record. Condition unique : iPhone **déverrouillé** au branchement + tap
> **« Allow »** une fois sur l'écran.

---

## Ce que c'est

PTP (Picture Transfer Protocol) = interface caméra générique d'iOS.
Complètement distinct du protocole Apple (lockdownd/AFC/trust).

- Aucun pairing record créé ou requis
- Aucun dialogue « Trust This Computer »
- Reconnu nativement par Windows (WPD/Explorateur), macOS (Image Capture),
  Linux (libgphoto2 / gphoto2)
- Après le tap « Allow », la session survit au reverrouillage (doc Apple 111806)

Accès : `/DCIM/` complet — JPG, HEIC, MOV, MP4, RAW, Live Photos, ProRes.

---

## Windows (recommandé — le plus simple, zéro install)

```powershell
# Brancher l'iPhone, le déverrouiller, taper « Allow » sur l'écran
.\wpd_media_export.ps1

# variantes
.\wpd_media_export.ps1 -OutputDir .\mes_photos          # dossier de sortie
.\wpd_media_export.ps1 -Resume                          # reprendre une extraction
.\wpd_media_export.ps1 -MaxFiles 50                     # tester avec 50 fichiers
.\wpd_media_export.ps1 -Extensions "heic,mov"           # filtrer
.\wpd_media_export.ps1 -Yes                             # sans confirmation
```

Le script utilise WPD natif (aucun driver, aucun iTunes). Il gère :
État 1 (aucun device) → État 2/3 (verrouillé / Allow pas tapé) → État 4 (accès
confirmé + comptage taille) → État 5 (reverrouillage/stall pendant la copie).

---

## Linux / VM Linux

```bash
sudo apt install libgphoto2-dev gphoto2
pip install gphoto2

# Vérifier d'abord (4 étapes)
python iphone_afu.py ptp-check

# Extraire
python iphone_afu.py ptp -o ./mes_photos --wait

# reprendre après interruption
python iphone_afu.py ptp -o ./mes_photos --resume
```

Structure préservée : `mes_photos/DCIM/APPLE100/IMG_xxxx.HEIC` + `manifest.json`/`manifest.csv`.

---

## Les 5 états (mêmes messages des deux côtés)

| État | Situation | Message / action |
|---|---|---|
| 1 | Aucun device | « Branchez l'iPhone via USB » — retry 5s |
| 2 | Device détecté, storage vide (verrouillé) | « Déverrouillez-le maintenant » |
| 3 | Déverrouillé, « Allow » pas tapé | « Tapez Allow sur l'écran » — retry 3s |
| 4 | Storage accessible | « Accès DCIM confirmé — [N fichiers, X GB] » |
| 5 | Reverrouillage en cours de copie | « La copie peut continuer si session active » ; stall 30s → retry |

---

## Que faire si ça stalle en cours de copie

iOS peut interrompre la session PTP sur certaines versions.

1. Déverrouiller à nouveau → la session reprend
2. Relancer avec `--resume` (Python) / `-Resume` (PowerShell) → reprend où ça s'est arrêté
3. Sur Linux : `sudo gphoto2 --auto-detect` pour vérifier l'état du device
4. PowerShell : les échecs sont loggés dans `errors.txt` (dossier de sortie)

---

## Limitations connues

- HEIC avec gain-map HDR (iOS 18+) : copiés **tels quels**, pas convertis
- Live Photos : les deux fichiers (.HEIC + .MOV) sont copiés, lien par nom identique
- Vidéos ProRes 4K : longues à copier (USB 2.0 ≈ 40 MB/s)
- Grosses volumétries : possible erreur ParentObject → relancer avec `--resume`
  (la structure par dossiers DCIM/APPLE100 est déjà préservée)
- Python : une copie bloquée ne peut pas être préemptée finement (pas de callback
  de progression dans python-gphoto2) → `Ctrl+C` puis `--resume`

---

## Différence avec trust / pairing record (AFC)

| | PTP | Pairing record (AFC) |
|---|---|---|
| Trust requis | ❌ Non | ✅ Oui |
| Pairing record | ❌ Non | ✅ Oui |
| Accès DCIM | ✅ | ✅ |
| Accès autres dossiers | ❌ | ✅ |
| Backup complet | ❌ | ✅ |
| Keychain | ❌ | ⚠️ (Frida) |
| Phone verrouillé | ❌ (déverr. requis 1×) | ✅ (AFU) |
| Windows natif | ✅ (WPD) | ❌ (usbmuxd) |

Les deux pipelines partagent le même format de manifest — `report` et `scan`
fonctionnent indifféremment sur une extraction PTP ou AFC.
