#!/usr/bin/env bash
# Build label-ready release binaries. Binaries are uploaded as GitHub Release
# assets, not committed to git history.
#
#   ./scripts/build-release.sh 0.1.0
#
set -euo pipefail

VERSION="${1:-0.1.0}"
OUT="${OUT:-dist}"
mkdir -p "$OUT"

LDFLAGS="-s -w -X main.version=${VERSION}"

build() {
    local goos="$1" goarch="$2" name="$3"
    echo "building ${name} (${goos}/${goarch})"
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
        go build -trimpath -ldflags "$LDFLAGS" -o "${OUT}/${name}" ./cmd/phishsim
}

# Ubuntu/Debian x86_64 (static, no CGO, no glibc dependency)
build linux amd64 phishsim-linux-amd64
# Ubuntu 22.04+/AWS Graviton ARM64
build linux arm64 phishsim-linux-arm64
# Windows 10/11 x64
build windows amd64 phishsim-windows-amd64.exe

(
    cd "$OUT"
    sha256sum phishsim-* > SHA256SUMS
)

echo
echo "version: ${VERSION}"
ls -lh "$OUT"
echo
echo "checksums: ${OUT}/SHA256SUMS"
