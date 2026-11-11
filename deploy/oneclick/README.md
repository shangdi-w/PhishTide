<p align="center">
  <img src="../../docs/images/wechat-contact.jpg" width="200" alt="微信二维码"><br>
  <strong>遇到问题？扫码联系作者</strong>
</p>

# PhishTide one-click install (Ubuntu/Debian) / 一键部署

This bundle installs PhishTide as a systemd service with SQLite, generates a
random console password, opens the firewall port if `ufw`/`firewalld` is active,
and prints the admin URL. No Go toolchain, database server or reverse proxy is
required for the default setup.

这个包会把 PhishTide 装成 systemd 服务，默认使用 SQLite，自动生成后台密码，
如果本机启用了 `ufw`/`firewalld` 会自动放行端口，最后打印后台地址。
默认不需要安装 Go、MySQL 或 nginx。

## Requirements / 环境

- Ubuntu 20.04+ / Debian 11+ (x86_64 or ARM64)
- root (`sudo`)
- an open port (default **8443**) in the cloud security group / firewall

## Install / 安装

1. Download `phishsim-oneclick-linux-amd64.tar.gz` (or the arm64 bundle) from the
   repository's **Releases** page (public, no sign-in required), or directly on
   the server:

```bash
cd /root
curl -L -o phishsim-oneclick-linux-amd64.tar.gz \
  https://github.com/shangdi-w/PhishTide/releases/download/v0.1.0/phishsim-oneclick-linux-amd64.tar.gz
```

2. Extract and run:

```bash
tar xzf phishsim-oneclick-linux-amd64.tar.gz
cd phishsim-oneclick-linux-amd64
sudo ./install.sh
```

Optional:

```bash
# known public address (recommended when behind NAT / a domain)
sudo ./install.sh --public-url https://phish.example.com

# different port
sudo ./install.sh --port 9443

# fixed admin password (otherwise a random one is generated)
sudo ./install.sh --admin-pass 'long-random-password'

# MySQL instead of SQLite
sudo ./install.sh --mysql-dsn 'phish:change-me@tcp(127.0.0.1:3306)/phishsim?charset=utf8mb4&parseTime=true&loc=Local'

# install but do not start
sudo ./install.sh --no-start
```

3. Open the printed URL:

```
https://<server-ip>:8443/__admin
```

The certificate is self-signed: choose **Advanced → Proceed** in the browser.
Log in with the username and password printed by the installer.

## What it creates / 安装内容

| Path | Purpose |
| --- | --- |
| `/opt/phishsim/phishsim` | binary (root-owned, 0755) |
| `/opt/phishsim/data/` | SQLite database, `secret.key`, TLS certs, background image |
| `/etc/phishsim.env` | runtime env (root-only, 0600), includes the admin password |
| `/etc/systemd/system/phishsim.service` | systemd unit |
| user `phishsim` | unprivileged service account |

## Manage / 管理

```bash
systemctl status phishsim
systemctl restart phishsim
journalctl -u phishsim -f
```

Change the admin password in the console: **Settings → Change password**. That
stores a bcrypt hash in the database and invalidates old sessions.

## Uninstall / 卸载

```bash
sudo ./uninstall.sh          # keep /opt/phishsim/data
sudo ./uninstall.sh --purge  # delete database, keys and certificates too
```

## Security / 安全

- The default setup exposes `/__admin` on the same port as landing pages. Use a
  strong password (the installer generates one), and ideally restrict the port
  to your own IP or put the console behind a VPN.
- For production, use a domain + real certificate and deny `/__admin` at
  nginx/Caddy. See `docs/en/DEPLOYMENT.md` / `docs/zh-CN/DEPLOYMENT.md`.
- `PHISH_CLONE_DENY_PRIVATE=true` is set by the installer, so clone/proxy URLs
  resolving to private addresses are refused.
- The dataset contains captured credentials. Set a retention window, protect
  backups, and delete data after the exercise.

## Manual build / 手动构建

If you prefer to build from source:

```bash
go build -o phishsim ./cmd/phishsim
sudo ./install.sh
```

The bundle's `phishsim` binary was built with `CGO_ENABLED=0` (static, no glibc
dependency) and reports its version with `./phishsim -version`.
