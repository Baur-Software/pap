#!/usr/bin/env bash
# Install the Papillon native messaging host manifest.
#
# This script is run during Papillon desktop installation to register
# the native messaging host with Chrome/Chromium and Firefox.
#
# Usage: ./install.sh <papillon-binary-path> <chrome-extension-id>

set -euo pipefail

PAPILLON_PATH="${1:?Usage: install.sh <papillon-binary-path> <chrome-extension-id>}"
EXTENSION_ID="${2:?Usage: install.sh <papillon-binary-path> <chrome-extension-id>}"
HOST_NAME="com.baur_software.papillon"

# Generate manifest
MANIFEST=$(cat <<EOF
{
  "name": "${HOST_NAME}",
  "description": "Papillon PAP desktop application — native messaging bridge",
  "path": "${PAPILLON_PATH}",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://${EXTENSION_ID}/"
  ]
}
EOF
)

# Detect OS and install
case "$(uname -s)" in
  Darwin)
    # macOS — Chrome
    CHROME_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    mkdir -p "$CHROME_DIR"
    echo "$MANIFEST" > "$CHROME_DIR/${HOST_NAME}.json"
    echo "Installed Chrome native messaging host: $CHROME_DIR/${HOST_NAME}.json"

    # macOS — Firefox
    FIREFOX_MANIFEST=$(echo "$MANIFEST" | sed 's/"allowed_origins"/"allowed_extensions"/' | sed "s|chrome-extension://${EXTENSION_ID}/|papillon@baur-software.com|")
    FIREFOX_DIR="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
    mkdir -p "$FIREFOX_DIR"
    echo "$FIREFOX_MANIFEST" > "$FIREFOX_DIR/${HOST_NAME}.json"
    echo "Installed Firefox native messaging host: $FIREFOX_DIR/${HOST_NAME}.json"
    ;;

  Linux)
    # Linux — Chrome
    CHROME_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
    mkdir -p "$CHROME_DIR"
    echo "$MANIFEST" > "$CHROME_DIR/${HOST_NAME}.json"
    echo "Installed Chrome native messaging host: $CHROME_DIR/${HOST_NAME}.json"

    # Linux — Chromium
    CHROMIUM_DIR="$HOME/.config/chromium/NativeMessagingHosts"
    mkdir -p "$CHROMIUM_DIR"
    echo "$MANIFEST" > "$CHROMIUM_DIR/${HOST_NAME}.json"
    echo "Installed Chromium native messaging host: $CHROMIUM_DIR/${HOST_NAME}.json"

    # Linux — Firefox
    FIREFOX_MANIFEST=$(echo "$MANIFEST" | sed 's/"allowed_origins"/"allowed_extensions"/' | sed "s|chrome-extension://${EXTENSION_ID}/|papillon@baur-software.com|")
    FIREFOX_DIR="$HOME/.mozilla/native-messaging-hosts"
    mkdir -p "$FIREFOX_DIR"
    echo "$FIREFOX_MANIFEST" > "$FIREFOX_DIR/${HOST_NAME}.json"
    echo "Installed Firefox native messaging host: $FIREFOX_DIR/${HOST_NAME}.json"
    ;;

  MINGW*|MSYS*|CYGWIN*)
    # Windows — uses registry
    echo "Windows: Register via registry instead:"
    echo "  HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${HOST_NAME}"
    echo "  Value: path to ${HOST_NAME}.json"
    echo ""
    echo "Writing manifest to: %LOCALAPPDATA%\\Papillon\\${HOST_NAME}.json"
    ;;

  *)
    echo "Unsupported OS: $(uname -s)"
    exit 1
    ;;
esac
