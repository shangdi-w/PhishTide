# Building and prebuilt binaries

## Requirements

- Go **1.27+**
- No CGO, no external SQLite library (the build uses `modernc.org/sqlite`)
- Chrome/Chromium only for clone, screenshots and end-to-end checks (not needed to build or run the core platform)

## Version

`-version` prints the build version. Set it at build time:

```bash
go build -ldflags "-s -w -X main.version=0.1.0" -o phishsim ./cmd/phishsim
./phishsim -version
```

## Reproducible release build

```bash
./scripts/build-release.sh 0.1.0
```

This produces:

| File | Platform | Notes |
| --- | --- | --- |
| `dist/phishsim-linux-amd64` | Ubuntu 20.04+/Debian 11+ **x86_64** | static, CGO disabled, no glibc dependency |
| `dist/phishsim-linux-arm64` | Ubuntu 22.04+ **ARM64** (AWS Graviton, Ampere) | static, CGO disabled |
| `dist/phishsim-windows-amd64.exe` | Windows 10/11 **x64** | console binary |
| `dist/SHA256SUMS` | all files | verify with `sha256sum -c SHA256SUMS` |

Prebuilt binaries are attached to **GitHub Releases**, not committed to git history. Download them from the repository's Releases page.

## Manual cross-compilation

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w -X main.version=0.1.0" \
  -o phishsim-linux-amd64 ./cmd/phishsim

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w -X main.version=0.1.0" \
  -o phishsim-linux-arm64 ./cmd/phishsim
```

## One-click Ubuntu installer

The release also ships a bundle containing the binary and installer:

```bash
tar xzf phishsim-oneclick-linux-amd64.tar.gz
cd phishsim-oneclick-linux-amd64
sudo ./install.sh
```

`install.sh` creates the `phishsim` user, `/opt/phishsim`, a systemd unit, a
root-only `/etc/phishsim.env` with a generated password, enables the service,
opens the port if `ufw`/`firewalld` is active, and prints the admin URL.
Options: `--port`, `--public-url`, `--admin-user`, `--admin-pass`, `--mysql-dsn`,
`--no-start`. Uninstall with `sudo ./uninstall.sh` (`--purge` deletes data).

See [deploy/oneclick/README.md](../../deploy/oneclick/README.md).

## Ubuntu single-server deployment

Everything can run on one Ubuntu host: the binary, SQLite or MySQL, and nginx/Caddy.

```bash
# 1. Binary
sudo useradd --system --home /opt/phishsim --shell /usr/sbin/nologin phishsim
sudo mkdir -p /opt/phishsim/data
sudo cp phishsim-linux-amd64 /opt/phishsim/phishsim
sudo chmod 755 /opt/phishsim/phishsim

# 2. Quick test
/opt/phishsim/phishsim -version
sudo -u phishsim /opt/phishsim/phishsim \
  -listen 127.0.0.1:8443 -data /opt/phishsim/data \
  -admin-user admin -admin-pass 'long-random-password' \
  -public-url https://phish.example.com -clone-deny-private

# 3. systemd (see docs/en/DEPLOYMENT.md for the unit and reverse proxy)
```

- SQLite is the default and needs no separate service.
- For MySQL, create a least-privilege user and set `PHISH_DB_DRIVER=mysql` + `PHISH_DB_DSN`.
- Install Chrome/Chromium only if you use clone/screenshot/e2e checks:
  `sudo apt install chromium-browser` (or Google Chrome).
- The binary listens TLS-only; put nginx/Caddy in front for a real certificate.
- Keep `/__admin` off the public internet.

Full deployment reference: [DEPLOYMENT.md](DEPLOYMENT.md).

## Verify a download

```bash
sha256sum -c SHA256SUMS
```
