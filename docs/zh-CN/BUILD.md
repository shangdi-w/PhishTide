# 编译与预编译二进制

## 环境要求

- Go **1.27+**
- 不需要 CGO，不依赖外部 SQLite 库（使用 `modernc.org/sqlite`）
- Chrome/Chromium 仅用于克隆、截图和端到端自检，编译和核心运行不需要

## 版本号

`-version` 打印构建版本，编译时写入：

```bash
go build -ldflags "-s -w -X main.version=0.1.0" -o phishsim ./cmd/phishsim
./phishsim -version
```

## 可复现的发布构建

```bash
./scripts/build-release.sh 0.1.0
```

产物：

| 文件 | 平台 | 说明 |
| --- | --- | --- |
| `dist/phishsim-linux-amd64` | Ubuntu 20.04+/Debian 11+ **x86_64** | 静态、CGO 关闭、不依赖 glibc |
| `dist/phishsim-linux-arm64` | Ubuntu 22.04+ **ARM64**（AWS Graviton、Ampere） | 静态、CGO 关闭 |
| `dist/phishsim-windows-amd64.exe` | Windows 10/11 **x64** | 控制台程序 |
| `dist/SHA256SUMS` | 全部文件 | `sha256sum -c SHA256SUMS` 校验 |

预编译二进制放在 **GitHub Releases**，不提交进 git 历史。到仓库 Releases 页面下载。

## 手动交叉编译

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "-s -w -X main.version=0.1.0" \
  -o phishsim-linux-amd64 ./cmd/phishsim

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w -X main.version=0.1.0" \
  -o phishsim-linux-arm64 ./cmd/phishsim
```

## Ubuntu 一键安装

Release 还提供包含二进制和安装脚本的压缩包：

```bash
tar xzf phishsim-oneclick-linux-amd64.tar.gz
cd phishsim-oneclick-linux-amd64
sudo ./install.sh
```

`install.sh` 会创建 `phishsim` 用户、`/opt/phishsim`、systemd 服务、仅 root 可读的
`/etc/phishsim.env`（自动生成密码），启用服务，检测到 `ufw`/`firewalld` 时放行端口，
最后打印后台地址。支持 `--port`、`--public-url`、`--admin-user`、`--admin-pass`、
`--mysql-dsn`、`--no-start`。卸载：`sudo ./uninstall.sh`（`--purge` 连数据一起删）。

详见 [deploy/oneclick/README.md](../../deploy/oneclick/README.md)。

## Ubuntu 单机部署

程序、SQLite/MySQL、nginx/Caddy 都可以在同一台 Ubuntu 上：

```bash
# 1. 二进制
sudo useradd --system --home /opt/phishsim --shell /usr/sbin/nologin phishsim
sudo mkdir -p /opt/phishsim/data
sudo cp phishsim-linux-amd64 /opt/phishsim/phishsim
sudo chmod 755 /opt/phishsim/phishsim

# 2. 试跑
/opt/phishsim/phishsim -version
sudo -u phishsim /opt/phishsim/phishsim \
  -listen 127.0.0.1:8443 -data /opt/phishsim/data \
  -admin-user admin -admin-pass '长随机密码' \
  -public-url https://phish.example.com -clone-deny-private

# 3. systemd 与反向代理见 docs/zh-CN/DEPLOYMENT.md
```

- 默认 SQLite，不需要额外数据库服务。
- 用 MySQL 时创建最小权限账号，并设置 `PHISH_DB_DRIVER=mysql` + `PHISH_DB_DSN`。
- 只有用克隆/截图/端到端自检时才需要 Chrome/Chromium：
  `sudo apt install chromium-browser`（或 Google Chrome）。
- 二进制只监听 TLS；真实证书交给 nginx/Caddy。
- 后台 `/__admin` 不要暴露公网。

完整部署参考：[DEPLOYMENT.md](DEPLOYMENT.md)。

## 校验下载

```bash
sha256sum -c SHA256SUMS
```
