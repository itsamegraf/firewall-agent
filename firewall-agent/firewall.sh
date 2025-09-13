#!/usr/bin/env bash
set -euo pipefail

# firewall.sh - Utility to manually apply/reset rules for debugging.
#
# This script thinly wraps the Python iptables manager so you can quickly
# test the firewall behavior on a node.
#
# Usage:
#   ./firewall.sh enable
#   ./firewall.sh disable
#   ./firewall.sh status
#   ./firewall.sh allow-ip 10.0.0.12
#   ./firewall.sh allow-service gluetun

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IPT_PY="$SCRIPT_DIR/iptables.py"

if [[ ! -f "$IPT_PY" ]]; then
  echo "iptables.py not found at $IPT_PY" >&2
  exit 1
fi

cmd=${1:-}
case "$cmd" in
  enable)
    python3 "$IPT_PY" reset ;;
  disable)
    python3 "$IPT_PY" disable ;;
  status)
    python3 "$IPT_PY" status ;;
  allow-ip)
    shift
    ip=${1:-}
    if [[ -z "$ip" ]]; then
      echo "Usage: $0 allow-ip <ip>" >&2
      exit 2
    fi
    python3 "$IPT_PY" allow-ip "$ip" ;;
  allow-service)
    shift
    svc=${1:-}
    if [[ -z "$svc" ]]; then
      echo "Usage: $0 allow-service <service_name>" >&2
      exit 2
    fi
    python3 "$IPT_PY" allow-service "$svc" ;;
  *)
    cat >&2 <<USAGE
Usage: $0 <command>
  enable            Apply baseline firewall with default DROP
  disable           Flush chain (failsafe)
  status            Show chain status
  allow-ip <ip>     Allow egress for a container IP
  allow-service <name>  Allow egress for all tasks of service
USAGE
    exit 2
    ;;
esac

