# syntax=docker/dockerfile:1

# ---- build stage -----------------------------------------------------------
# Builds the static Go binary. No CGO, no external SQLite library.
ARG GO_VERSION=1.27
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src

# Optional module proxy for networks that cannot reach proxy.golang.org,
# e.g. --build-arg GOPROXY=https://goproxy.cn,direct
ARG GOPROXY=
ENV CGO_ENABLED=0
ENV GOPROXY=${GOPROXY}

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=0.1.0
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/phishsim ./cmd/phishsim

# ---- runtime stage ---------------------------------------------------------
FROM debian:bookworm-slim

# China networks can pass --build-arg APT_MIRROR=https://mirrors.aliyun.com.
# ca-certificates is installed from the default mirror first so that an https
# mirror can be verified afterwards.
ARG APT_MIRROR=
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && if [ -n "$APT_MIRROR" ]; then \
      sed -i "s|http://deb.debian.org|$APT_MIRROR|g" /etc/apt/sources.list.d/debian.sources; \
    fi \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      curl tzdata dumb-init \
      chromium fonts-noto-cjk fonts-liberation fonts-noto-color-emoji \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/phishsim /usr/local/bin/phishsim

ENV PHISH_LISTEN=:8443 \
    PHISH_DATA_DIR=/data \
    TZ=Asia/Shanghai

RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8443

# The console login page answers 200 over the self-signed certificate.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -ksf https://127.0.0.1:8443/__admin/login -o /dev/null || exit 1

# The process runs as root so headless Chromium gets --no-sandbox
# automatically (chromedp adds it when uid is 0 inside a container).
ENTRYPOINT ["dumb-init", "/usr/local/bin/phishsim"]
