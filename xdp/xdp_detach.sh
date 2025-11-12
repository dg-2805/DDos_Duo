#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <iface>"
  exit 1
fi

IFACE="$1"
echo "Detaching XDP from ${IFACE} (if any)..."
sudo ip link set dev "$IFACE" xdp off || true
echo "Done."


