#!/usr/bin/env bash
#
# Take a screenshot on the HarmonyOS tablet and pull it into tmp/ on this Mac.
#
#   ./scripts/shot.sh              # tmp/shot-20261018-145612.jpeg
#   ./scripts/shot.sh diag         # tmp/diag-20261018-145612.jpeg
#
# Override the device with HDC_TARGET=<serial>.
set -euo pipefail

DEVICE="${HDC_TARGET:-$("${HDC}" list targets | head -1)}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/../tmp"
NAME="${1:-shot}"
STAMP="$(date +%Y%m%d-%H%M%S)"
LOCAL="${OUT_DIR}/${NAME}-${STAMP}.jpeg"
REMOTE="/data/local/tmp/muharmony-shot.jpeg"

HDC="${HDC:-/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/toolchains/hdc}"
if [ ! -x "${HDC}" ]; then
  HDC="$(command -v hdc || true)"
fi
if [ -z "${HDC}" ] || [ ! -x "${HDC}" ]; then
  echo "hdc not found. Set HDC=/path/to/hdc" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

"${HDC}" -t "${DEVICE}" shell "snapshot_display -f ${REMOTE}" >/dev/null
"${HDC}" -t "${DEVICE}" file recv "${REMOTE}" "${LOCAL}" >/dev/null
"${HDC}" -t "${DEVICE}" shell "rm -f ${REMOTE}" >/dev/null 2>&1 || true

echo "${LOCAL}"
