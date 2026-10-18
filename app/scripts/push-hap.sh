#!/usr/bin/env bash
#
# Copy the signed HAP to the tablet's user-visible storage so it can be installed from
# the Files app (no hdc needed on the device side).
#
#   ./scripts/push-hap.sh
#
set -euo pipefail

DEVICE="${HDC_TARGET:-$("${HDC}" list targets | head -1)}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HAP="${ROOT}/entry/build/default/outputs/default/entry-default-signed.hap"

HDC="${HDC:-/Applications/DevEco-Studio.app/Contents/sdk/default/openharmony/toolchains/hdc}"
if [ ! -x "${HDC}" ]; then
  HDC="$(command -v hdc || true)"
fi
if [ -z "${HDC}" ] || [ ! -x "${HDC}" ]; then
  echo "hdc not found. Set HDC=/path/to/hdc" >&2
  exit 1
fi
if [ ! -f "${HAP}" ]; then
  echo "missing ${HAP} — run hvigorw assembleHap first" >&2
  exit 1
fi

BASE=/storage/media/100/local/files/Docs
for dir in "${BASE}/Download" "${BASE}/Documents" "${BASE}"; do
  "${HDC}" -t "${DEVICE}" file send "${HAP}" "${dir}/MuHarmony-signed.hap" >/dev/null
  echo "${dir}/MuHarmony-signed.hap"
done
