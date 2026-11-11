# Docker 一键启动

一条命令把 PhishTide 跑起来：内置 SQLite、自动生成后台密码、自带 Chromium（克隆/截图/端到端自检可直接用）。

> 仅用于已授权的钓鱼演练与内部培训。

## 环境要求

- Linux / macOS 上的 Docker Engine 20.10+（Windows 用 Docker Desktop）
- `docker compose`（Docker 自带插件）或 `docker-compose`
- 2 GB 内存、约 1.5 GB 磁盘（镜像含 Chromium 和中文字体）
- 网络：能拉取 `debian:bookworm-slim`；源码构建还需要 Go 模块代理

## 方式 A：源码构建（推荐）

```bash
git clone https://github.com/shangdi-w/PhishTide.git
cd PhishTide
chmod +x deploy/docker/quickstart.sh
./deploy/docker/quickstart.sh
```

脚本会：

1. 生成 `.env`（随机后台密码、按公网 IP 推断对外地址）；
2. 构建镜像 `phishtide:0.1.0`；
3. 启动容器 `phishtide`，端口 `8443`，数据卷 `phishtide-data`。

中国网络拉不到 Docker Hub / Go 代理时：

```bash
# 先给 Docker 配镜像源（/etc/docker/daemon.json 的 registry-mirrors），然后
APT_MIRROR=https://mirrors.aliyun.com GOPROXY=https://goproxy.cn,direct \
  ./deploy/docker/quickstart.sh
```

## 方式 B：预编译二进制（最快，不需要 Go）

```bash
# 从 Release 下载 phishsim-linux-amd64 后
./deploy/docker/quickstart.sh --binary ./phishsim-linux-amd64
```

这种方式只拉基础镜像和安装 Chromium，不编译 Go，适合服务器网络受限的场景。

## 手动 docker compose

```bash
cp .env.example .env   # 或自己写：PHISH_ADMIN_PASS=强密码
docker compose up -d --build
docker compose logs -f
```

## 访问

安装完成会打印：

```
admin URL: https://<公网IP>:8443/__admin
```

- 用户名默认 `admin`，密码在 `.env` 的 `PHISH_ADMIN_PASS`。
- 自签证书，浏览器点「高级 → 继续前往」。
- 安全组/防火墙放行 `8443`。

## 环境变量

`docker-compose.yml` 读取同目录 `.env`：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PHISH_ADMIN_USER` | `admin` | 后台用户名 |
| `PHISH_ADMIN_PASS` | 必填 | 后台密码（脚本自动生成） |
| `PHISH_PUBLIC_URL` | 安装脚本推断 | 邮件链接用的对外地址，例如 `https://phish.example.com` |
| `PHISH_PORT` | `8443` | 宿主机端口 |
| `PHISH_RETENTION_DAYS` | `30` | 提交/事件清理天数，`0` 关闭 |
| `TZ` | `Asia/Shanghai` | 时区 |

更多参数（LLM、SMTP、退信、SSRF 收紧）见 [CONFIGURATION.md](CONFIGURATION.md)，在 `docker-compose.yml` 的 `environment` 里追加即可。

## 数据与备份

- 数据都在命名卷 `phishtide-data`（容器内 `/data`）：SQLite、`secret.key`、TLS 证书、背景图。
- **必须备份 `secret.key`**，丢了无法解密已加密的凭证/提交。

```bash
docker run --rm -v phishtide-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/phishtide-data-$(date +%F).tar.gz -C /data .
```

## 更新

```bash
git pull
docker compose up -d --build
```

数据库在启动时自动迁移；数据卷不受影响。

## 常用命令

```bash
docker compose ps
docker compose logs -f
docker compose restart
docker compose down            # 停止，保留数据卷
docker compose down -v         # 连数据一起删（不可恢复）
```

## 常见问题

| 现象 | 处理 |
| --- | --- |
| `docker pull` 超时 | 配 `registry-mirrors`（阿里云/腾讯云/DaoCloud 等）后重启 Docker |
| 构建时 `apt-get` 很慢 | 加 `APT_MIRROR=https://mirrors.aliyun.com` |
| 构建时 Go 模块下载失败 | 加 `GOPROXY=https://goproxy.cn,direct` |
| 提示 `docker compose` 不存在 | 安装 `docker-compose-plugin`，或改用 `docker-compose` |
| 8443 被占用 | `.env` 里改 `PHISH_PORT` |
| 克隆/截图报找不到 Chrome | 确认用的是本仓库镜像（已内置 Chromium），不要自己换精简镜像 |
| 浏览器证书警告 | 自签证书，点「高级 → 继续」 |

## 安全注意

- 后台默认直接暴露在 `https://IP:8443/__admin`，**务必用强密码**（脚本已随机生成）。
- 生产建议把 `/__admin` 限制为固定 IP/VPN，或只走 SSH 隧道。
- 演练结束停容器（`docker compose down`）或关端口。
