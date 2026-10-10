#!/bin/bash
# frida_sideload.sh — Re-signe un IPA avec FridaGadget pour runtime hooking sans jailbreak
# Usage: bash frida_sideload.sh <app.ipa> <bundle_id> [signing_identity]
# Dépendances : ios-deploy, ldid OU codesign (macOS), curl, unzip, insert_dylib

set -euo pipefail

IPA_PATH="${1:-}"
BUNDLE_ID="${2:-}"
SIGN_ID="${3:-}"

usage() {
    echo "Usage: bash frida_sideload.sh <app.ipa> <bundle_id> [signing_identity]"
    echo "  app.ipa          IPA non chiffré à re-signer"
    echo "  bundle_id        Bundle ID de l'app (ex: com.apple.mobilesafari)"
    echo "  signing_identity Identité codesign macOS (optionnel, ex: 'Apple Development: ...')"
}

# ── 1/10 Validation des arguments ────────────────────────────────────────────
echo "[1/10] Validation des arguments..."
if [[ -z "$IPA_PATH" || -z "$BUNDLE_ID" ]]; then
    usage
    exit 1
fi
if [[ ! -f "$IPA_PATH" ]]; then
    echo "[!] IPA introuvable: $IPA_PATH"
    exit 1
fi
IPA_ABS="$(cd "$(dirname "$IPA_PATH")" && pwd)/$(basename "$IPA_PATH")"

# ── 2/10 Détection OS host ───────────────────────────────────────────────────
echo "[2/10] Détection OS host..."
OS_HOST="$(uname -s)"
SIGN_TOOL=""
case "$OS_HOST" in
    Darwin)
        if [[ -n "$SIGN_ID" ]]; then
            SIGN_TOOL="codesign"
        elif command -v ldid >/dev/null 2>&1; then
            SIGN_TOOL="ldid"
        else
            echo "[!] macOS: installe ldid (brew install ldid) ou passe une signing_identity codesign"
            exit 1
        fi
        ;;
    Linux)
        if command -v ldid >/dev/null 2>&1; then
            SIGN_TOOL="ldid"
        else
            echo "[!] ldid requis sur Linux — sudo apt install ldid (ou build: https://github.com/ProcursusTeam/ldid)"
            exit 1
        fi
        ;;
    *)
        echo "[!] OS non supporté: $OS_HOST"
        exit 1
        ;;
esac
echo "      OS=$OS_HOST, signature via $SIGN_TOOL"

# ── 3/10 Vérifie les outils ──────────────────────────────────────────────────
echo "[3/10] Vérifie ios-deploy + outils (curl, unzip)..."
if ! command -v ios-deploy >/dev/null 2>&1; then
    echo "[!] ios-deploy manquant — brew install ios-deploy (macOS)"
    echo "    ou build depuis https://github.com/ios-control/ios-deploy"
    exit 1
fi
for dep in curl unzip; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        echo "[!] $dep manquant — installe-le puis relance"
        exit 1
    fi
done

# ── répertoire temp + nettoyage garanti ──────────────────────────────────────
WORKDIR="$(mktemp -d /tmp/frida_sideload.XXXXXX)"
cleanup() {
    rm -rf "$WORKDIR"
    echo "[*] Nettoyage $WORKDIR"
}
trap cleanup EXIT

GADGET="/tmp/FridaGadget.dylib"

# ── 4/10 Télécharge FridaGadget.dylib ────────────────────────────────────────
echo "[4/10] FridaGadget.dylib..."
if [[ -f "$GADGET" ]]; then
    echo "      déjà présent: $GADGET"
else
    URL="https://github.com/frida/frida/releases/latest/download/FridaGadget.dylib"
    if curl -fL --retry 3 -o "$GADGET" "$URL"; then
        echo "      téléchargé → $GADGET"
    else
        echo "      fallback: recherche de l'asset ios-arm64 via l'API GitHub..."
        API="https://api.github.com/repos/frida/frida/releases/latest"
        RELEASE_JSON="$(curl -fsSL "$API")"
        ASSET_URL="$(echo "$RELEASE_JSON" | grep -o 'https://[^"]*ios-arm64e[^"]*\.dylib\.gz' | head -n1 || true)"
        if [[ -z "$ASSET_URL" ]]; then
            ASSET_URL="$(echo "$RELEASE_JSON" | grep -o 'https://[^"]*ios-arm64[^"]*\.dylib\.gz' | head -n1 || true)"
        fi
        if [[ -z "$ASSET_URL" ]]; then
            echo "[!] Impossible de trouver FridaGadget.dylib — télécharge-le manuellement dans /tmp/"
            exit 1
        fi
        curl -fL --retry 3 -o "$GADGET.gz" "$ASSET_URL"
        gunzip -f "$GADGET.gz"
        echo "      téléchargé (gz) → $GADGET"
    fi
fi

# ── 5/10 Extraction de l'IPA ─────────────────────────────────────────────────
echo "[5/10] Extraction de l'IPA..."
unzip -q "$IPA_ABS" -d "$WORKDIR"
APP_DIR="$(find "$WORKDIR/Payload" -maxdepth 1 -name '*.app' -type d | head -n1)"
if [[ -z "$APP_DIR" ]]; then
    echo "[!] Payload/*.app introuvable dans $IPA_ABS"
    exit 1
fi
echo "      app: $(basename "$APP_DIR")"

# ── 6/10 Copie du gadget ─────────────────────────────────────────────────────
echo "[6/10] Copie FridaGadget.dylib → Frameworks/"
mkdir -p "$APP_DIR/Frameworks"
cp "$GADGET" "$APP_DIR/Frameworks/FridaGadget.dylib"

# ── 7/10 Patch du binaire principal ──────────────────────────────────────────
echo "[7/10] Patch du binaire principal (insert_dylib)..."
BINARY="$APP_DIR/$(basename "$APP_DIR" .app)"
if [[ ! -f "$BINARY" ]]; then
    echo "[!] Binaire principal introuvable: $BINARY"
    exit 1
fi
if ! command -v insert_dylib >/dev/null 2>&1; then
    echo "[!] insert_dylib manquant — brew install insert_dylib (macOS)"
    echo "    ou build depuis https://github.com/Tyilo/insert_dylib"
    exit 1
fi
insert_dylib --strip-codesig --all-yes --inplace "@executable_path/Frameworks/FridaGadget.dylib" "$BINARY" >/dev/null

# ── 8/10 Re-signature ────────────────────────────────────────────────────────
echo "[8/10] Re-signature ($SIGN_TOOL)..."
if [[ "$SIGN_TOOL" == "codesign" ]]; then
    codesign --force --sign "$SIGN_ID" --deep "$APP_DIR"
else
    # ldid signe des Mach-O, pas des répertoires : gadget + binaire patché
    ldid -S "$APP_DIR/Frameworks/FridaGadget.dylib"
    ldid -S "$BINARY"
fi

# ── 9/10 Rezip IPA ───────────────────────────────────────────────────────────
echo "[9/10] Rezip IPA..."
OUT_IPA="${IPA_ABS%.ipa}_frida.ipa"
( cd "$WORKDIR" && zip -qr "$OUT_IPA" Payload )
echo "      IPA patché → $OUT_IPA"

# ── 10/10 Installation + lancement Frida ─────────────────────────────────────
echo "[10/10] Installation via ios-deploy..."
ios-deploy --bundle "$APP_DIR" --no-wifi

echo ""
echo "[+] Terminé. Lance ensuite :"
echo "    frida -U -f $BUNDLE_ID"
echo ""
echo "[!] Rappel: profil de dev valide requis; accepte le certificat sur le device"
echo "    (Réglages > Général > VPN & Gestion de l'appareil) avant de lancer l'app."
