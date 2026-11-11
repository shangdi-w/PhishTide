#!/usr/bin/env bash
# PhishTide one-click installer for Ubuntu/Debian.
#
#   sudo ./install.sh
#   sudo ./install.sh --public-url https://phish.example.com --port 8443
#   sudo ./install.sh --mysql-dsn 'phish:pass@tcp(127.0.0.1:3306)/phishsim?...'
#
# The phishsim binary must sit next to this script (the release bundle includes it).
set -euo pipefail

PORT=8443
ADMIN_USER=admin
ADMIN_PASS=""
PUBLIC_URL=""
MYSQL_DSN=""
NO_START=0
INSTALL_DIR=/opt/phishsim
DATA_DIR=/opt/phishsim/data

usage() {
    cat <<'EOF'
Usage: sudo ./install.sh [options]

  --port N            HTTPS port (default 8443)
  --public-url URL    external base URL used in email links
                      (default https://<detected-public-ip>:<port>)
  --admin-user NAME   console username (default admin)
  --admin-pass PASS   console password (default: generated)
  --mysql-dsn DSN     use MySQL instead of SQLite
  --no-start          install but do not start the service
  -h, --help          show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT="${2:?}"; shift 2 ;;
        --public-url) PUBLIC_URL="${2:?}"; shift 2 ;;
        --admin-user) ADMIN_USER="${2:?}"; shift 2 ;;
        --admin-pass) ADMIN_PASS="${2:?}"; shift 2 ;;
        --mysql-dsn) MYSQL_DSN="${2:?}"; shift 2 ;;
        --no-start) NO_START=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "please run as root: sudo ./install.sh" >&2
    exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemd is required (Ubuntu/Debian)" >&2
    exit 1
fi
if [ ! -f ./phishsim ]; then
    echo "phishsim binary not found next to install.sh" >&2
    echo "download the one-click bundle from the GitHub Releases page" >&2
    exit 1
fi
case "$(uname -m)" in
    x86_64|aarch64|arm64) ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "invalid port: $PORT" >&2
    exit 1
fi

# Detect a public address when the operator did not supply one.
if [ -z "$PUBLIC_URL" ]; then
    IP=""
    if command -v curl >/dev/null 2>&1; then
        IP=$(curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)
    fi
    if [ -z "$IP" ]; then
        IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    fi
    if [ -z "$IP" ]; then
        IP=127.0.0.1
    fi
    PUBLIC_URL="https://${IP}:${PORT}"
fi

# Generate a console password if the operator did not supply one.
if [ -z "$ADMIN_PASS" ]; then
    if command -v openssl >/dev/null 2>&1; then
        ADMIN_PASS=$(openssl rand -hex 12)
    else
        ADMIN_PASS=$(date +%s%N | sha256sum | cut -c1-24)
    fi
fi
if ! [[ "$ADMIN_PASS" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "admin password may only contain letters, digits, dot, underscore and dash" >&2
    exit 1
fi

echo "==> installing to ${INSTALL_DIR}"
id phishsim >/dev/null 2>&1 || useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin phishsim
install -d -m 750 "$INSTALL_DIR" "$DATA_DIR"
chown -R phishsim:phishsim "$INSTALL_DIR"
install -m 755 -o root -g root ./phishsim "$INSTALL_DIR/phishsim"

echo "==> writing /etc/phishsim.env"
{
    echo "PHISH_LISTEN=0.0.0.0:${PORT}"
    echo "PHISH_PUBLIC_URL=${PUBLIC_URL}"
    echo "PHISH_DATA_DIR=${DATA_DIR}"
    echo "PHISH_ADMIN_USER=${ADMIN_USER}"
    echo "PHISH_ADMIN_PASS=${ADMIN_PASS}"
    echo "PHISH_CLONE_DENY_PRIVATE=true"
    echo "PHISH_RETENTION_DAYS=30"
    echo "PHISH_MAX_SEND_TARGETS=500"
    if [ -n "$MYSQL_DSN" ]; then
        echo "PHISH_DB_DRIVER=mysql"
        echo "PHISH_DB_DSN=${MYSQL_DSN}"
    fi
} > /etc/phishsim.env
chmod 600 /etc/phishsim.env

echo "==> writing systemd unit"
cat > /etc/systemd/system/phishsim.service <<'EOF'
[Unit]
Description=PhishTide phishing simulation platform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=phishsim
Group=phishsim
WorkingDirectory=/opt/phishsim
EnvironmentFile=/etc/phishsim.env
ExecStart=/opt/phishsim/phishsim
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/phishsim/data
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SyslogIdentifier=phishsim

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable phishsim >/dev/null
if [ "$NO_START" -eq 0 ]; then
    systemctl restart phishsim
fi

# Open the port if a local firewall is active.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${PORT}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
fi

# Health check.
CODE=""
if command -v curl >/dev/null 2>&1 && [ "$NO_START" -eq 0 ]; then
    for _ in $(seq 1 20); do
        CODE=$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 2 "https://127.0.0.1:${PORT}/__admin/login" 2>/dev/null || true)
        [ "$CODE" = "200" ] && break
        sleep 1
    done
fi

cat <<EOF

============================================================
 PhishTide installed / 安装完成
------------------------------------------------------------
 Admin URL : ${PUBLIC_URL}/__admin
 Username  : ${ADMIN_USER}
 Password  : ${ADMIN_PASS}
 Data dir  : ${DATA_DIR}
 Service   : systemctl status phishsim
 Logs      : journalctl -u phishsim -f
 Health    : ${CODE:-not checked}
------------------------------------------------------------
 Browser will warn about the self-signed certificate:
 choose "Advanced" -> "Proceed". / 浏览器提示自签名证书时选择继续。
 For a domain + real certificate, see docs/DEPLOYMENT.md.
 To remove: sudo ./uninstall.sh   (add --purge to delete data)
============================================================

EOF
