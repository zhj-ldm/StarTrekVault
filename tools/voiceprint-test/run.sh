#!/usr/bin/env bash
# Standalone voiceprint matching test - TEST ONLY, does not touch main code.
#
# Generates two clearly different EDGE-TTS timbres (each with 2 utterances),
# converts them to 16 kHz / mono / f32 PCM, then runs backend/examples/spk_probe.rs,
# which uses the SAME model (resources/models/spk/sv.onnx) and the SAME cosine
# similarity as the app.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/audio"
EDGE="${EDGE_TTS:-/tmp/edgev/bin/edge-tts}"
MODEL="$ROOT/resources/models/spk/sv.onnx"

if [ ! -x "$EDGE" ]; then
  echo "edge-tts not found at $EDGE"
  echo "install: python3 -m venv /tmp/edgev && /tmp/edgev/bin/pip install edge-tts"
  exit 1
fi

mkdir -p "$OUT"

# Two different timbres.
VA="en-US-AriaNeural"   # female
VB="en-US-GuyNeural"    # male

say () { # $1 voice  $2 out-stem  $3 text
  local mp3="$OUT/$2.mp3" f32="$OUT/$2.f32"
  "$EDGE" --voice "$1" --text "$3" --write-media "$mp3" >/dev/null 2>&1
  ffmpeg -y -loglevel error -i "$mp3" -ar 16000 -ac 1 -f f32le "$f32"
  echo "  $2.f32  ($(stat -f%z "$f32") bytes)  [$1]"
}

echo "[1] generate EDGE TTS audio -> 16k mono f32"
say "$VA" "A1" "The stars are bright tonight, and the galaxy is calm. This is a voice matching test for the encrypted vault."
say "$VA" "A2" "Please authorize access to my personal log before anyone arrives on the bridge this evening."
say "$VB" "B1" "The stars are bright tonight, and the galaxy is calm. This is a voice matching test for the encrypted vault."
say "$VB" "B2" "Please authorize access to my personal log before anyone arrives on the bridge this evening."

echo
echo "[2] voiceprint probe (same model + same cosine as the app)"
cd "$ROOT/backend"
cargo run --release --quiet --example spk_probe -- \
  "$MODEL" "$OUT/A1.f32" "$OUT/A2.f32" "$OUT/B1.f32" "$OUT/B2.f32"
