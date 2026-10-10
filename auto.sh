#!/bin/bash
# auto.sh — Plug & Play : branche l'iPhone puis lance ce script.
# Usage: bash auto.sh [options de "iphone_afu.py auto"]
# Exemples:
#   bash auto.sh                          # pipeline complet → ./afu_out
#   bash auto.sh -o /data/iphone1         # sortie custom
#   bash auto.sh --skip syslog,backup     # run rapide (dcim + apps + scan)

set -e
cd "$(dirname "$0")"

if [ -f .venv/bin/activate ]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
fi

echo "[*] Diagnostic USB / usbmuxd..."
python check_vm_usb.py || true

echo "[*] Lancement du pipeline AFU automatique..."
exec python iphone_afu.py auto "$@"
