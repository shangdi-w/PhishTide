# Deployment

PhishTide is a static Go binary. You can run it on the same host as the database or behind a reverse proxy.

## Deployment models

### A. Single host + SQLite (simplest)

```bash
go build -o phishsim ./cmd/phishsim
./phishsim -listen 127.0.0.1:8443 -data /opt/phishsim/data \
  -admin-user admin -admin-pass 'long-random-password' \
  -public-url https://phish.example.com
```

SQLite lives in `/opt/phishsim/data/phishsim.db`. No external dependencies.

### B. Single host + MySQL

Create a least-privilege database and user:

```sql
CREATE DATABASE phishsim CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'phish'@'127.0.0.1' IDENTIFIED BY 'change-me';
GRANT ALL PRIVILEGES ON phishsim.* TO 'phish'@'127.0.0.1';
```

Run:

```bash
PHISH_DB_DRIVER=mysql \
PHISH_DB_DSN='phish:change-me@tcp(127.0.0.1:3306)/phishsim?charset=utf8mb4&parseTime=true&loc=Local' \
./phishsim -listen 127.0.0.1:8443 -data /opt/phishsim/data \
  -admin-user admin -admin-pass 'long-random-password' \
  -public-url https://phish.example.com
```

The schema is created automatically; additive migrations tolerate duplicate columns.

### C. Reverse proxy on the same host

Run PhishTide on loopback and let nginx/Caddy terminate TLS:

```bash
./phishsim -listen 127.0.0.1:8443 -data /opt/phishsim/data \
  -admin-user admin -admin-pass-hash "$(./phishsim -hash-pass 'long-random-password')" \
  -public-url https://phish.example.com -clone-deny-private
```

nginx:

```nginx
server {
    listen 443 ssl;
    server_name phish.example.com;
    ssl_certificate     /etc/letsencrypt/live/phish.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/phish.example.com/privkey.pem;

    # Keep the console off the public internet.
    location /__admin {
        allow 203.0.113.10;   # your admin IP / VPN
        deny all;
        proxy_pass https://127.0.0.1:8443;
        proxy_ssl_verify off;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass https://127.0.0.1:8443;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
```

Caddy:

```caddy
phish.example.com {
    reverse_proxy 127.0.0.1:8443 {
        transport http { tls_insecure_skip_verify }
    }
    @admin path /__admin*
    handle @admin {
        @notme not remote_ip 203.0.113.10
        respond @notme 404
        reverse_proxy 127.0.0.1:8443 { transport http { tls_insecure_skip_verify } }
    }
}
```

Set `-trusted-proxies` so the real client IP is recorded:

```bash
-trusted-proxies 127.0.0.1/32
```

### D. Reverse tunnel (data stays elsewhere)

`deploy/frpc.toml` and `deploy/frps.toml` are generic frp templates (`VPS_IP` / `CHANGE_ME_TOKEN`). Alternatively use SSH:

```bash
ssh -N -R 127.0.0.1:18081:127.0.0.1:8443 -p 22 root@your-vps
```

Point the VPS nginx/Caddy at `127.0.0.1:18081`. Keep `/__admin` denied there.

## TLS

- By default PhishTide generates a self-signed certificate covering the public URL host/IP plus loopback. Browsers warn; strict clients may reject it.
- For realistic drills, use a real certificate on the reverse proxy (Let's Encrypt DNS-01 if 80/443 are unavailable).
- If PhishTide terminates TLS itself, replace `<data>/tls/cert.pem` and `key.pem`, or restart with a new `-public-url` to regenerate the self-signed SANs.

## systemd

```ini
[Unit]
Description=PhishTide phishing simulation platform
After=network.target

[Service]
WorkingDirectory=/opt/phishsim
EnvironmentFile=/etc/phishsim.env
ExecStart=/opt/phishsim/phishsim
Restart=always
RestartSec=3
User=phishsim
Group=phishsim

[Install]
WantedBy=multi-user.target
```

`/etc/phishsim.env` (root-only, `chmod 600`) can be based on `deploy/phishsim.env.example`.

## Permissions

- Data directory: owned by the service user, `0750`.
- `secret.key`: `0600`.
- TLS keys: `0600`.
- MySQL: least-privilege user, bound to loopback.
- The admin panel should never be exposed directly to the public internet.

## Backups

- MySQL: `deploy/backup-mysql.sh` or `deploy/backup-mysql.ps1` (mysqldump, utf8mb4, retains N copies).
- SQLite: `deploy/backup-sqlite.ps1`.
- Always restore with `--default-character-set=utf8mb4` to avoid mojibake.
- Back up `data/secret.key` separately: without it, encrypted credentials/submissions cannot be decrypted.

## Metrics

`GET /metrics` exposes Prometheus text. Set `PHISH_METRICS_TOKEN` to require `Authorization: Bearer <token>` or `?token=`; otherwise only loopback scrapes are allowed.

## Upgrades

1. Back up the database and `secret.key`.
2. Replace the binary.
3. Restart the service.
4. Migrations run at startup; additive changes are idempotent.

## First-run checklist

- [ ] Strong `-admin-pass` / bcrypt hash; console not publicly reachable.
- [ ] `-public-url` (or Settings → Public URL) matches the external address.
- [ ] Real TLS certificate on the proxy; `-trusted-proxies` set.
- [ ] `-clone-deny-private` enabled unless internal cloning is required.
- [ ] Database uses a least-privilege account and is not exposed.
- [ ] Backups + off-host copy configured.
- [ ] `PHISH_MASK_PASSWORDS=true` if exports may leave the operator host.
