#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <iface> [vip (A.B.C.D)]"
  exit 1
fi

IFACE="$1"
VIP="${2:-}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"

cd "$DIR"
make
CMD=(sudo "$DIR/dns_lb_user" --iface "$IFACE" --config "$ROOT/config.txt")
if [[ -n "$VIP" ]]; then
  CMD+=("--vip" "$VIP")
fi
echo "Running: ${CMD[*]}"
"${CMD[@]}"


