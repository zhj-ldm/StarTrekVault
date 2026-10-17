#!/usr/bin/env bash
# Star Trek Vault - development launch (Electron + Rust backend).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -x "$ROOT/resources/bin/stvault-backend" ]]; then
  echo "==> backend missing, building"
  bash "$ROOT/tools/build.sh"
fi

if [[ ! -f "$ROOT/resources/assets/drag-icon.png" ]]; then
  node "$ROOT/tools/mkicon.js"
fi

echo "==> electron $ROOT"
ELECTRON_BIN="$ROOT/node_modules/electron/dist/Electron.app/Contents/MacOS/Electron"
if [[ -x "$ELECTRON_BIN" ]]; then
  exec "$ELECTRON_BIN" "$ROOT"
fi
exec npx electron "$ROOT"
