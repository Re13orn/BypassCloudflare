#!/usr/bin/env bash
#
# Build cfproxy for every supported platform and package the Burp extension
# into a single self-contained jar (the proxy binaries are embedded as
# resources and auto-started by the extension at load time).
#
# Requirements: Maven, a JDK 17+, and Go. The Go toolchain version is set by
# cfproxy/go.mod (currently 1.27, required by tls-client); a stock Go with the
# default GOTOOLCHAIN=auto will fetch it automatically if your local Go is older.
# No cgo / cross toolchains needed (pure Go, so GOOS/GOARCH just works).
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFPROXY_DIR="$ROOT/cfproxy"
BIN_DIR="$ROOT/extension/src/main/resources/bin"

command -v go  >/dev/null || { echo "error: go not found";  exit 1; }
command -v mvn >/dev/null || { echo "error: mvn not found"; exit 1; }

# Keep in sync with ProxyManager.resourceForPlatform().
PLATFORMS=(
  "darwin arm64"
  "darwin amd64"
  "linux amd64"
  "linux arm64"
  "windows amd64"
  "windows arm64"
)

echo "==> building cfproxy (${#PLATFORMS[@]} platforms)"
mkdir -p "$BIN_DIR"
for p in "${PLATFORMS[@]}"; do
  os="${p%% *}"
  arch="${p##* }"
  ext=""
  [ "$os" = "windows" ] && ext=".exe"
  out="$BIN_DIR/cfproxy-$os-$arch$ext"
  printf '    %-16s -> %s\n' "$os/$arch" "${out#$ROOT/}"
  ( cd "$CFPROXY_DIR" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
      go build -trimpath -ldflags="-s -w" -o "$out" . )
done

echo "==> packaging extension"
( cd "$ROOT/extension" && mvn -q package )

echo
echo "==> done: ${ROOT}/extension/target/cf-bypass-extension.jar"
