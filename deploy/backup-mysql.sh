#!/usr/bin/env bash
# PhishTide MySQL 备份（Linux）
# 用法：
#   DB_PASS='密码' ./backup-mysql.sh
#   DB_USER=phishsim DB_PASS='...' KEEP=30 ./backup-mysql.sh
# 建议加进 crontab：
#   15 3 * * * DB_PASS='...' /opt/phishsim/deploy/backup-mysql.sh >> /var/log/phishsim-backup.log 2>&1

set -euo pipefail

DB="${DB:-phishsim}"
DB_USER="${DB_USER:-phishsim}"
DB_PASS="${DB_PASS:-}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-3306}"
KEEP="${KEEP:-14}"
OUT_DIR="${OUT_DIR:-$(cd "$(dirname "$0")/.." && pwd)/backups}"

mkdir -p "$OUT_DIR"
stamp="$(date +%Y%m%d-%H%M%S)"
file="$OUT_DIR/$DB-$stamp.sql"

if [ -n "$DB_PASS" ]; then
    export MYSQL_PWD="$DB_PASS"
fi
trap 'unset MYSQL_PWD || true' EXIT

mysqldump --single-transaction --quick --routines --triggers \
    --default-character-set=utf8mb4 \
    -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" \
    --databases "$DB" > "$file"

gzip -f "$file"

# 只保留最近 KEEP 份
ls -1t "$OUT_DIR"/"$DB"-*.sql.gz 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f

echo "backup ok: $file.gz"
