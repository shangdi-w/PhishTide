# Docker quick start

Run PhishTide with one command. The image ships SQLite, a generated admin
password and Chromium for cloning, screenshots and end-to-end checks.

> For authorized phishing simulations and internal training only.

## Requirements

- Docker Engine 20.10+ on Linux or macOS (Docker Desktop on Windows)
- `docker compose` (bundled plugin) or `docker-compose`
- 2 GB RAM and about 1.5 GB disk (the image includes Chromium and CJK fonts)
- Network access to `debian:bookworm-slim`; source builds also need the Go proxy

## Option A: build from source

```bash
git clone https://github.com/shangdi-w/PhishTide.git
cd PhishTide
chmod +x deploy/docker/quickstart.sh
./deploy/docker/quickstart.sh
```

The script writes `.env` with a random password, builds `phishtide:0.1.0`,
starts container `phishtide` on port 8443 and keeps data in the
`phishtide-data` volume.

Behind slow mirrors:

```bash
APT_MIRROR=https://mirrors.aliyun.com GOPROXY=https://goproxy.cn,direct \
  ./deploy/docker/quickstart.sh
```

## Option B: prebuilt binary (no Go build)

```bash
./deploy/docker/quickstart.sh --binary ./phishsim-linux-amd64
```

Only the base image and runtime packages are pulled.

## Manual compose

```bash
printf 'PHISH_ADMIN_PASS=%s\n' "$(openssl rand -hex 12)" > .env
docker compose up -d --build
docker compose logs -f
```

## Access

```
https://<public-ip>:8443/__admin
```

User `admin`, password from `.env`. The certificate is self-signed; accept the
browser warning. Open TCP 8443 in the cloud security group.

## Variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `PHISH_ADMIN_USER` | `admin` | Console user |
| `PHISH_ADMIN_PASS` | required | Console password (generated) |
| `PHISH_PUBLIC_URL` | detected | External base URL used in email links |
| `PHISH_PORT` | `8443` | Host port |
| `PHISH_RETENTION_DAYS` | `30` | Submission/event retention (`0` off) |
| `TZ` | `Asia/Shanghai` | Time zone |

All other `PHISH_*` settings from [CONFIGURATION.md](CONFIGURATION.md) can be
added under `environment` in `docker-compose.yml`.

## Data and backup

Everything lives in the `phishtide-data` volume (`/data`): SQLite, `secret.key`,
TLS certificate, background image. Back up `secret.key`; without it encrypted
credentials cannot be decrypted.

```bash
docker run --rm -v phishtide-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/phishtide-data-$(date +%F).tar.gz -C /data .
```

## Update

```bash
git pull
docker compose up -d --build
```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Image pull times out | configure `registry-mirrors` and restart Docker |
| `apt-get` is slow during build | pass `APT_MIRROR=https://mirrors.aliyun.com` |
| Go module download fails | pass `GOPROXY=https://goproxy.cn,direct` |
| `docker compose` not found | install `docker-compose-plugin` or use `docker-compose` |
| Port 8443 taken | change `PHISH_PORT` in `.env` |
| Chrome not found | use this image; do not swap in a slim base without Chromium |
