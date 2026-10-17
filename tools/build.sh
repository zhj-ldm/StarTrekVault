#!/usr/bin/env bash
# Star Trek Vault - build the Rust backend and stage it for the Electron app.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/backend/target/release/stvault-backend"

echo "==> cargo build --release"
(cd "$ROOT/backend" && cargo build --release)

mkdir -p "$ROOT/resources/bin"
cp -f "$BIN" "$ROOT/resources/bin/stvault-backend"
chmod +x "$ROOT/resources/bin/stvault-backend"

# Re-sign ad-hoc after every copy: macOS kills a replaced binary whose cached
# signature no longer matches (SIGKILL "Code Signature Invalid").
codesign --remove-signature "$ROOT/resources/bin/stvault-backend" 2>/dev/null || true
codesign -s - --force "$ROOT/resources/bin/stvault-backend"

echo "==> staged $ROOT/resources/bin/stvault-backend"
