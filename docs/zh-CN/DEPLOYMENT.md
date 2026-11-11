# 部署

PhishTide 是单个静态 Go 二进制，可以和数据库同机运行，也可以放在反向代理后面。

## 部署形态

### A. 单机 + SQLite（最简单）

```bash
go build -o phishsim ./cmd/phishsim
./phishsim -listen 127.0.0.1:8443 -data /opt/phishsim/data \
  -admin-user admin -admin-pass '长随机密码' \
  -public-url https://phish.example.com
```

SQLite 在 `/opt/phishsim/data/phishsim.db`，无外部依赖。

### B. 单机 + MySQL

创建最小权限库和账号：

```sql
CREATE DATABASE phishsim CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'phish'@'127.0.0.1' IDENTIFIED BY 'change-me';
GRANT ALL PRIVILEGES ON phishsim.* TO 'phish'@'127.0.0.1';
```

启动：

```bash
PHISH_DB_DRIVER=mysql \
PHISH_DB_DSN='phish:change-me@tcp(127.0.0.1:3306)/phishsim?charset=utf8mb4&parseTime=true&loc=Local' \
./phishsim -listen 127.0.0.1:8443 -data /opt/phishsim/data \
  -admin-user admin -admin-pass '长随机密码' \
  -public-url https://phish.example.com
```

建表自动完成；增量迁移容忍重复列。

### C. 同机反向代理

PhishTide 绑回环，nginx/Caddy 终止 TLS：

```bash
./phishsim -listen 127.0.0.1:8443 -data /opt/phishsim/data \
  -admin-user admin -admin-pass-hash "$(./phishsim -hash-pass '长随机密码')" \
  -public-url https://phish.example.com -clone-deny-private
```

nginx：

```nginx
server {
    listen 443 ssl;
    server_name phish.example.com;
    ssl_certificate     /etc/letsencrypt/live/phish.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/phish.example.com/privkey.pem;

    # 后台不要对公网开放
    location /__admin {
        allow 203.0.113.10;   # 你的管理 IP / VPN
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

Caddy：

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

反代后面加 `-trusted-proxies` 才能记录真实客户端 IP：

```bash
-trusted-proxies 127.0.0.1/32
```

### D. 反向隧道（数据留在本机）

`deploy/frpc.toml` / `frps.toml` 是通用 frp 模板（`VPS_IP` / `CHANGE_ME_TOKEN`）。也可以用 SSH：

```bash
ssh -N -R 127.0.0.1:18081:127.0.0.1:8443 -p 22 root@your-vps
```

VPS 的 nginx/Caddy 指向 `127.0.0.1:18081`，并在入口继续拒绝 `/__admin`。

## TLS

- 默认自签证书覆盖对外地址的主机/IP 与回环；浏览器会警告，严格客户端可能拒绝。
- 真实演练建议在反代上用真证书（80/443 不可用时用 Let's Encrypt DNS-01）。
- 如果由 PhishTide 自己终止 TLS，替换 `<data>/tls/cert.pem` / `key.pem`，或用新的 `-public-url` 重启重新生成自签 SAN。

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

`/etc/phishsim.env`（仅 root 可读，`chmod 600`）可参考 `deploy/phishsim.env.example`。

## 权限

- 数据目录：服务用户所有，`0750`。
- `secret.key`：`0600`。
- TLS 私钥：`0600`。
- MySQL：最小权限账号，只绑回环。
- 后台面板不要直接暴露公网。

## 备份

- MySQL：`deploy/backup-mysql.sh` 或 `deploy/backup-mysql.ps1`（mysqldump、utf8mb4、保留 N 份）。
- SQLite：`deploy/backup-sqlite.ps1`。
- 恢复时务必带 `--default-character-set=utf8mb4`，否则中文会错位。
- `data/secret.key` 要单独备份：丢了就无法解密已加密的凭据/提交。

## 指标

`GET /metrics` 输出 Prometheus 文本。设置 `PHISH_METRICS_TOKEN` 后需要 `Authorization: Bearer <token>` 或 `?token=`；未设置时仅回环可抓取。

## 升级

1. 备份数据库与 `secret.key`；
2. 替换二进制；
3. 重启服务；
4. 启动时自动迁移，增量变更幂等。

## 首次上线检查

- [ ] 强 `-admin-pass` / bcrypt；后台不对公网开放
- [ ] `-public-url`（或后台「对外地址」）与外部地址一致
- [ ] 反代真证书；`-trusted-proxies` 已配
- [ ] 除非需要内网克隆，开启 `-clone-deny-private`
- [ ] 数据库最小权限、不对公网暴露
- [ ] 备份 + 异机副本已配置
- [ ] 导出文件可能离开本机时设置 `PHISH_MASK_PASSWORDS=true`
