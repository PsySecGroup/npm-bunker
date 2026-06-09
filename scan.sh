#!/usr/bin/env bash
# npm-bunker/scan.sh
#
# Usage:
#   ./scan.sh <package[@version]>        # fetch from registry + scan
#   ./scan.sh <package[@version]> --net  # allow outbound connections
#   ./scan.sh /path/to/local.tgz         # scan pre-downloaded tarball
#
# Docker setup:
#   Default install (docker group):  ./scan.sh lodash
#   Docker not in group (more secure): sudo -E ./scan.sh lodash
#   Explicit override:               DOCKER="sudo docker" ./scan.sh lodash

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED=$(printf '\033[0;31m'); YLW=$(printf '\033[0;33m')
GRN=$(printf '\033[0;32m'); CYN=$(printf '\033[0;36m'); RST=$(printf '\033[0m')
log()  { echo "${CYN}[*]${RST} $1"; }
ok()   { echo "${GRN}[+]${RST} $1"; }
warn() { echo "${YLW}[!]${RST} $1"; }
err()  { echo "${RED}[!!]${RST} $1" >&2; }

# ── Usage ─────────────────────────────────────────────────────────────────────
PACKAGE="${1:-}"
NET_MODE="${2:-}"

if [ -z "$PACKAGE" ]; then
  echo ""
  echo "  npm-bunker — npm package security sandbox"
  echo ""
  echo "  Usage:"
  echo "    ./scan.sh <package>              scan latest version"
  echo "    ./scan.sh <package@version>      scan specific version"
  echo "    ./scan.sh /path/to/pkg.tgz       scan local tarball"
  echo "    ./scan.sh <package> --net        allow outbound connections"
  echo ""
  echo "  Examples:"
  echo "    ./scan.sh lodash"
  echo "    ./scan.sh colors@1.4.0"
  echo "    ./scan.sh some-sketchy-pkg@2.1.0 --net"
  echo ""
  echo "  Results land in ./results/<package>-<timestamp>/"
  echo ""
  exit 1
fi

# ── Detect docker invocation method ──────────────────────────────────────────
# Three cases:
#   1. User is in docker group (default Ubuntu install) — plain 'docker' works
#   2. Docker not in group (security-conscious) — need 'sudo docker'
#   3. Explicit override via DOCKER env var
#
if [ -n "${DOCKER:-}" ]; then
  # Explicit override — use exactly what they gave us
  DOCKER_CMD="$DOCKER"
elif docker info >/dev/null 2>&1; then
  # Docker accessible without sudo
  DOCKER_CMD="docker"
elif sudo -n docker info >/dev/null 2>&1; then
  # Docker accessible with passwordless sudo
  DOCKER_CMD="sudo docker"
else
  # Need sudo with password — check if we're already root
  if [ "$(id -u)" = "0" ]; then
    DOCKER_CMD="docker"
  else
    echo ""
    err "Cannot reach Docker daemon. Try one of:"
    echo ""
    echo "    sudo -E ./scan.sh $PACKAGE        # preserves your PATH (recommended)"
    echo "    DOCKER='sudo docker' ./scan.sh $PACKAGE"
    echo ""
    echo "  Or add yourself to the docker group (less secure):"
    echo "    sudo usermod -aG docker \$USER && newgrp docker"
    echo ""
    exit 1
  fi
fi

# ── Locate npm ────────────────────────────────────────────────────────────────
# sudo strips PATH so nvm/nodenv installs disappear. Resolution order:
#   1. NPM_BIN env var override
#   2. PATH (works for non-sudo or sudo -E)
#   3. Common fixed locations
#   4. nvm shim under original user's HOME
#
if [ -z "${NPM_BIN:-}" ]; then
  NPM_BIN=$(which npm 2>/dev/null || \
    ls /usr/local/bin/npm \
       /usr/bin/npm \
       /opt/homebrew/bin/npm \
       "${HOME}/.nvm/versions/node/"*/bin/npm \
       "${SUDO_HOME:-/nonexistent}/.nvm/versions/node/"*/bin/npm \
       2>/dev/null | head -1 || true)
fi

if [ -z "$NPM_BIN" ]; then
  echo ""
  err "npm not found. Try:"
  echo ""
  echo "    sudo -E ./scan.sh $PACKAGE          # -E preserves your PATH"
  echo "    NPM_BIN=/path/to/npm ./scan.sh $PACKAGE"
  echo ""
  exit 1
fi

# Prepend npm's bin dir so 'node' is found too (nvm keeps them together)
NPM_DIR=$(dirname "$NPM_BIN")
export PATH="$NPM_DIR:$PATH"

# ── Folder name ───────────────────────────────────────────────────────────────
if [ -f "$PACKAGE" ]; then
  SAFE_NAME=$(basename "$PACKAGE" .tgz | tr -dc 'a-zA-Z0-9-' | sed 's/^-*//;s/-*$//')
else
  SAFE_NAME=$(echo "$PACKAGE" | tr '@/.' '-' | tr -dc 'a-zA-Z0-9-' | sed 's/^-*//;s/-*$//')
fi
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUT_DIR="./results/${SAFE_NAME}-${TIMESTAMP}"
IMAGE="npm-sandbox"

mkdir -p "$OUT_DIR"

echo ""
log "npm-bunker"
log "target:  $PACKAGE"
log "docker:  $DOCKER_CMD"
log "npm:     $NPM_BIN"
log "output:  $OUT_DIR"
echo ""

# ── Build image ───────────────────────────────────────────────────────────────
log "Building sandbox image..."
$DOCKER_CMD build -t "$IMAGE" . -q

# ── Phase A: get the tarball ──────────────────────────────────────────────────
if [ -f "$PACKAGE" ]; then
  log "Local tarball — skipping registry fetch"
  cp "$PACKAGE" "$OUT_DIR/"
else
  log "Fetching $PACKAGE from registry (no scripts)..."
  "$NPM_BIN" pack "$PACKAGE" \
    --pack-destination "$OUT_DIR" \
    --ignore-scripts \
    2>&1 | grep -v '^npm notice' || {
      echo ""
      err "npm pack failed. If running under sudo, try:"
      echo "    sudo -E ./scan.sh $PACKAGE"
      exit 1
    }
fi

TARBALL_PATH=$(ls "$OUT_DIR"/*.tgz 2>/dev/null | head -1 || true)
if [ -z "$TARBALL_PATH" ]; then
  err "No .tgz found in $OUT_DIR"
  exit 1
fi
TARBALL_FILE=$(basename "$TARBALL_PATH")
ok "Tarball: $TARBALL_FILE"

# ── Phase A.2: pre-warm dep cache ─────────────────────────────────────────────
log "Pre-warming dependency cache (no scripts)..."
CACHE_DIR="$(realpath "$OUT_DIR")/npm-cache"
mkdir -p "$CACHE_DIR"

"$NPM_BIN" install "$TARBALL_PATH" \
  --prefix "$OUT_DIR/prefetch" \
  --ignore-scripts \
  --no-save \
  --no-fund \
  --cache "$CACHE_DIR" \
  2>&1 | grep -v '^npm notice' || true

CACHE_SIZE=$(du -sh "$CACHE_DIR" 2>/dev/null | cut -f1)
ok "Cache: $CACHE_SIZE"
if [ "$CACHE_SIZE" = "0" ] || [ "$CACHE_SIZE" = "4.0K" ]; then
  warn "Cache looks empty — container install may need network"
fi

# ── Phase B: detonate ─────────────────────────────────────────────────────────
if [ "$NET_MODE" = "--net" ]; then
  NET_NAME="sandbox-net-${SAFE_NAME}-${TIMESTAMP}"
  $DOCKER_CMD network create \
    --driver bridge \
    --opt com.docker.network.bridge.enable_icc=false \
    "$NET_NAME" 2>/dev/null || true
  NETWORK_FLAG="--network $NET_NAME"
  warn "Network ENABLED — outbound connections allowed"
else
  NETWORK_FLAG="--network none"
  log "Network disabled (offline detonation)"
fi

echo ""
log "Detonating..."
echo ""

$DOCKER_CMD run --rm \
  $NETWORK_FLAG \
  --cap-drop ALL \
  --cap-add  SYS_PTRACE \
  --cap-add  NET_RAW \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /sandbox:rw,exec,nosuid,size=256m \
  --tmpfs /tmp:rw,nosuid,size=128m \
  --tmpfs /root:rw,noexec,nosuid,size=64m \
  --memory      512m \
  --memory-swap 512m \
  --cpus        1 \
  --pids-limit  200 \
  --ulimit      nofile=1024:1024 \
  --ipc         none \
  -v "$(realpath "$OUT_DIR"):/results:rw" \
  -v "$(realpath "$CACHE_DIR"):/tmp/npm-cache:rw" \
  -e TARGET_PACKAGE="/results/$TARBALL_FILE" \
  --name "sandbox-${SAFE_NAME}-${TIMESTAMP}" \
  "$IMAGE" 2>&1 | tee "$OUT_DIR/run.log"

EXIT_CODE=${PIPESTATUS[0]}

if [ "$NET_MODE" = "--net" ]; then
  $DOCKER_CMD network rm "$NET_NAME" >/dev/null 2>&1 || true
fi

echo ""
ok "Results: $OUT_DIR"
echo ""
ls -lh "$OUT_DIR/" | grep -v '^total'
echo ""
exit $EXIT_CODE