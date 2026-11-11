#!/usr/bin/env bash
# One-command start for PhishTide in Docker.
#
#   ./deploy/docker/quickstart.sh
#   ./deploy/docker/quickstart.sh --binary ./phishsim-linux-amd64
#
# Source mode builds the binary inside Docker (needs network for Go modules).
# Binary mode uses a prebuilt linux/amd64 binary and only installs the runtime
# packages, which is faster and works on hosts that cannot reach the Go proxy.
set -euo pipefail
cd "$(dirname "$0")/../.."

MODE=source
BIN=""
if [ "${1:-}" = "--binary" ]; then
  MODE=binary
  BIN="${2:-}"
  [ -n "$BIN" ] || { echo "usage: $0 --binary <phishsim-linux-amd64>" >&2; exit 1; }
  [ -f "$BIN" ] || { echo "binary not found: $BIN" >&2; exit 1; }
fi

command -v docker >/dev/null 2>&1 || { echo "Docker is required: https://docs.docker.com/engine/install/" >&2; exit 1; }

PORT="${PHISH_PORT:-8443}"

if [ ! -f .env ]; then
  PASS="$(openssl rand -hex 12 2>/dev/null || date +%s%N | sha256sum | cut -c1-24)"
  IP="$(curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null || true)"
  [ -n "$IP" ] || IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ -n "$IP" ] || IP=127.0.0.1
  cat > .env <<EOF
PHISH_ADMIN_USER=admin
PHISH_ADMIN_PASS=$PASS
PHISH_PUBLIC_URL=https://$IP:$PORT
PHISH_PORT=$PORT
EOF
  chmod 600 .env
  echo "generated .env"
  echo "admin user: admin"
  echo "admin pass: $PASS"
fi

if [ "$MODE" = source ]; then
  if docker compose version >/dev/null 2>&1; then
    docker compose up -d --build
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose up -d --build
  else
    echo "docker compose is not installed; install docker-compose-plugin or the docker-compose package" >&2
    exit 1
  fi
else
  cp "$BIN" ./phishsim
  docker build -f deploy/docker/Dockerfile.binary -t "phishtide:${PHISH_VERSION:-0.1.0}" .
  rm -f ./phishsim
  set -a; . ./.env; set +a
  docker rm -f phishtide >/dev/null 2>&1 || true
  docker run -d --name phishtide --restart unless-stopped \
    -p "${PHISH_PORT:-8443}:8443" \
    -v phishtide-data:/data \
    -e PHISH_ADMIN_USER="${PHISH_ADMIN_USER:-admin}" \
    -e PHISH_ADMIN_PASS="$PHISH_ADMIN_PASS" \
    -e PHISH_PUBLIC_URL="${PHISH_PUBLIC_URL:-}" \
    -e TZ="${TZ:-Asia/Shanghai}" \
    "phishtide:${PHISH_VERSION:-0.1.0}"
fi

echo "admin URL: $(grep -h '^PHISH_PUBLIC_URL=' .env | cut -d= -f2-)/__admin"
echo "health:    docker inspect --format '{{.State.Health.Status}}' phishtide"
