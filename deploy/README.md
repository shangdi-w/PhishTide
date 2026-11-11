# 方案 C 部署手册：VPS 只做入口，程序与数据留在本机

> 通用的 frp + Caddy 方案；请把域名、VPS IP、端口换成你自己的。若 80/443 不可用，可改用 Caddy 之外的 nginx 或 SSH 反向隧道。

链路：

```
收件人浏览器
  │ https://phish.你的域名   (443, 合法证书)
  ▼
VPS: Caddy ──► 127.0.0.1:8443 (frps)
                    │ frp 隧道 (7000)
                    ▼
本机: frpc ──► phishsim:8443 ──► 本机 MySQL
```

数据落点：表单提交经隧道直接写进**本机** `phishsim` 库，VPS 不存业务数据。

## 0. 开工前确认

- 域名 A 记录指向 VPS 公网 IP，**代理状态必须是「DNS only / 灰云」**，否则 Caddy 签不到 Let's Encrypt 证书。
- VPS 安全组/防火墙放行：80/tcp、443/tcp、7000/tcp（7000 建议只放行你本机公网 IP）。
- VPS 在**中国大陆**：域名需 ICP 备案才能用 80/443；没备案就选香港/海外 VPS。
- 邮件发送走 SMTP 中继（465/587），不依赖 VPS 的 25 端口，所以 VPS 封 25 不影响。

## 1. VPS 端

```bash
# 1.1 装 frp（版本号以 releases 最新为准）
cd /opt
curl -LO https://github.com/fatedier/frp/releases/download/v0.61.1/frp_0.61.1_linux_amd64.tar.gz
tar xzf frp_0.61.1_linux_amd64.tar.gz
mv frp_0.61.1_linux_amd64 frp

# 1.2 放入配置
cp /path/to/frps.toml /opt/frp/frps.toml

# 1.3 systemd
cat >/etc/systemd/system/frps.service <<'EOF'
[Unit]
Description=frps
After=network.target

[Service]
Type=simple
ExecStart=/opt/frp/frps -c /opt/frp/frps.toml
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now frps
systemctl status frps --no-pager

# 1.4 装 Caddy 并放配置
apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  > /etc/apt/sources.list.d/caddy-stable.list
apt update && apt install -y caddy

cp /path/to/Caddyfile /etc/caddy/Caddyfile   # 改好域名
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy

# 1.5 防火墙
ufw allow 80,443/tcp
ufw allow from 你的本机公网IP to any port 7000 proto tcp
ufw enable
```

## 2. 本机端（Windows）

```powershell
# 2.1 下载 frp windows 包并解压，例如 D:\tools\frp
# https://github.com/fatedier/frp/releases  -> frp_0.61.1_windows_amd64.zip

# 2.2 改 deploy\frpc.toml 里的 serverAddr 为 VPS 公网 IP，然后启动
cd D:\tools\frp
.\frpc.exe -c C:\path\to\phishsim\deploy\frpc.toml
```

看到 `start proxy success` 即隧道通。想开机自启可用 NSSM 把 `frpc.exe -c ...` 注册为服务。

## 3. 用域名重启平台

先停掉当前进程，再执行：

```bash
cd /path/to/phishsim
PHISH_DB_DRIVER=mysql \
PHISH_DB_DSN='phish:change-me@tcp(127.0.0.1:3306)/phishsim?charset=utf8mb4&parseTime=true&loc=Local' \
./phishsim.exe -listen :8443 -data ./data-mysql \
  -admin-key '换一个足够长的密钥' \
  -public-url https://phish.你的域名
```

**`-public-url` 必须在发信前改好**，邮件里的跟踪像素、落地页链接都按它生成；已经发出去的邮件改不回来。

## 4. 验证

```bash
# 外网访问落地页（应返回 200/HTML）
curl -I https://phish.你的域名/l/test/

# 后台
# 后台建议仅本机或通过 SSH 隧道访问：https://127.0.0.1:8443/__admin
```

然后按之前的流程建单人群组 → 活动 → 发送，确认：
- 邮件里的链接是 `https://phish.你的域名/l/...`
- 打开邮件后台「打开」+1
- 点链接「点击」+1
- 落地页提交后「📥 提交记录」立即出现，且数据在本机 MySQL：

```bash
mysql -u phishsim -p phishsim \
  -e "select id,email,username,password,ip,ts from submissions order by id desc limit 5;"
```

## 4.1 数据治理与发送护栏

启动参数：

```bash
-retention-days 30      # 自动清理 30 天前的提交与事件；0 关闭
-max-send-targets 500   # 单次发送待发人数上限；0 关闭
```

- 自动清理在启动时跑一次，之后每 24 小时一次；后台「数据分析 → 数据维护」可手动清理。
- 捕获的密码与全部表单字段都以 AES-256-GCM 加密落库（`enc:v1:` 前缀），后台读取时自动解密。历史明文行仍可读，但不会被自动重写。
- 发送前会二次确认；活动详情里有「仅预览」，只渲染不发送。待发人数超过上限时服务端直接拒绝。

备份脚本：

```powershell
# Windows + MySQL（当前环境）
.\deploy\backup-mysql.ps1
# 指定密码、保留 30 份
.\deploy\backup-mysql.ps1 -Password '你的密码' -Keep 30
# SQLite 模式
.\deploy\backup-sqlite.ps1
```

```bash
# Linux + MySQL（VPS 方案）
DB_PASS='你的密码' ./deploy/backup-mysql.sh
```

备份默认写到项目下 `backups/`，只保留最近 N 份。生产建议用任务计划程序/cron 每天跑一次，并把 `backups/` 同步到另一块盘或对象存储。

## 5. 常见故障

| 现象 | 原因 |
|---|---|
| Caddy 502 | frpc 没连上，或 frps 没起；`systemctl status frps`、看 frpc 日志 |
| 证书签不下来 | 域名还是橙云代理；或 80 端口没放行 |
| 隧道通但页面 404 | `-listen` 绑到了非 8443，或本机防火墙拦了 127.0.0.1:8443 |
| 邮件链接打不开 | 发信时 `-public-url` 还是旧的；或域名解析没生效 |
| 邮件进垃圾箱 | SPF/DKIM/DMARC 没配；用平台「发件配置 → DNS 检查」逐条补 |

## 6. 安全

- 后台密钥至少 32 位随机串，别用示例值。
- Caddyfile 里取消注释 `@admin` 段，把 `/__admin` 限制到你的固定 IP。
- 演练结束 `systemctl stop frps caddy` 或关隧道，避免长期暴露。
