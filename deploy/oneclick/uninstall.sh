#!/usr/bin/env bash
# PhishTide one-click uninstaller.
#
#   sudo ./uninstall.sh          # stop/remove service, keep data
#   sudo ./uninstall.sh --purge  # also delete /opt/phishsim (database, keys, certs)
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "please run as root: sudo ./uninstall.sh" >&2
    exit 1
fi

PURGE=0
if [ "${1:-}" = "--purge" ]; then
    PURGE=1
fi

systemctl disable --now phishsim 2>/dev/null || true
rm -f /etc/systemd/system/phishsim.service /etc/phishsim.env
systemctl daemon-reload
userdel phishsim 2>/dev/null || true

if [ "$PURGE" -eq 1 ]; then
    rm -rf /opt/phishsim
    echo "removed /opt/phishsim (database, keys and certificates deleted)"
else
    echo "service removed; data kept at /opt/phishsim/data"
    echo "run with --purge to delete data as well"
fi
