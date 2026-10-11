#!/bin/bash
# setup.sh — installe tout ce qu'il faut sur Debian/Ubuntu
# Usage: bash setup.sh

set -e

echo "[*] Dépendances système..."
sudo apt update -qq
sudo apt install -y \
  usbmuxd \
  libimobiledevice-utils \
  libimobiledevice-dev \
  ifuse \
  python3-pip \
  python3-venv \
  libssl-dev \
  libffi-dev \
  build-essential \
  usbutils

echo "[*] usbmuxd service..."
if sudo systemctl enable usbmuxd && sudo systemctl start usbmuxd; then
  echo "    usbmuxd activé via systemd"
else
  echo "[!] systemd indisponible (WSL sans systemd ?) — lance usbmuxd manuellement: sudo usbmuxd -f -v"
fi

echo "[*] Groupe plugdev pour accès USB sans sudo..."
sudo usermod -aG plugdev "$USER" 2>/dev/null || echo "[!] Groupe plugdev indisponible (normal en WSL — sans effet)"

echo "[*] Venv Python..."
python3 -m venv .venv
source .venv/bin/activate

echo "[*] Dépendances Python..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] libgphoto2 pour extraction PTP..."
sudo apt install -y libgphoto2-dev gphoto2 || echo "[!] libgphoto2 indisponible (PTP désactivé)"
pip install gphoto2 || echo "[!] python-gphoto2 indisponible (PTP désactivé)"

echo "[*] pytest..."
pip install pytest pytest-asyncio

echo "[*] Diagnostic VM USB..."
python check_vm_usb.py || true

echo ""
echo "[+] Setup terminé."
echo ""
echo "    Active le venv : source .venv/bin/activate"
echo "    Check          : python iphone_afu.py check"
echo "    Pair           : python iphone_afu.py pair"
echo "    TUI            : python iphone_afu.py tui"
echo "    Tests          : python -m pytest tests/"
echo "    Tunnel         : sudo python iphone_afu.py tunnel"
echo ""
echo "[!] Si VM : active le USB passthrough dans VMware/VirtualBox avant de brancher le téléphone."
echo "[!] Si WSL2 : attache l'iPhone via usbipd-win (usbipd list → bind --force → attach --wsl) puis relance usbmuxd."
echo "[!] Reconnecte ta session (ou source /etc/profile) pour que le groupe plugdev soit pris en compte."
