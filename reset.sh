#!/usr/bin/env bash
# reset.sh — nuclear reset of npm-sandbox environment
# Usage: ./reset.sh [--results]   # --results also wipes ./results/ directory

set -euo pipefail

RED=$(printf '\033[0;31m'); GRN=$(printf '\033[0;32m')
CYN=$(printf '\033[0;36m'); DIM=$(printf '\033[2m'); RST=$(printf '\033[0m')

WIPE_RESULTS="${1:-}"
IMAGE="npm-sandbox"
SANDBOX_NET_PREFIX="sandbox-net-"

log()  { echo "${CYN}[*]${RST} $1"; }
ok()   { echo "${GRN}[+]${RST} $1"; }
warn() { echo "${RED}[!]${RST} $1"; }
dim()  { echo "${DIM}    $1${RST}"; }

# Auto-detect docker invocation (same logic as scan.sh)
if [ -n "${DOCKER:-}" ]; then
  DOCKER_CMD="$DOCKER"
elif docker info >/dev/null 2>&1; then
  DOCKER_CMD="docker"
elif sudo -n docker info >/dev/null 2>&1; then
  DOCKER_CMD="sudo docker"
elif [ "$(id -u)" = "0" ]; then
  DOCKER_CMD="docker"
else
  echo "${RED}[!!]${RST} Cannot reach Docker. Try: sudo -E ./reset.sh" >&2
  exit 1
fi

echo ""
echo "${RED}============================================${RST}"
echo "${RED}     npm-sandbox nuclear reset${RST}"
echo "${RED}============================================${RST}"
echo ""

# ── 1. Kill + remove all sandbox containers (running or stopped) ──────────────
log "Containers..."

CONTAINERS=$($DOCKER_CMD ps -a --filter "name=sandbox-" --format "{{.ID}} {{.Names}}" 2>/dev/null || true)

if [ -n "$CONTAINERS" ]; then
  while IFS= read -r line; do
    CID=$(echo "$line" | awk '{print $1}')
    CNAME=$(echo "$line" | awk '{print $2}')
    STATUS=$($DOCKER_CMD inspect --format '{{.State.Status}}' "$CID" 2>/dev/null || echo "unknown")

    case "$STATUS" in
      running|paused)
        $DOCKER_CMD kill "$CID" >/dev/null 2>&1 && dim "killed:   $CNAME ($CID)"
        ;;
    esac

    $DOCKER_CMD rm -f "$CID" >/dev/null 2>&1 && dim "removed:  $CNAME ($CID)"
  done <<< "$CONTAINERS"
  ok "Containers cleared"
else
  ok "No sandbox containers found"
fi

# ── 2. Remove the image ───────────────────────────────────────────────────────
log "Image..."

if $DOCKER_CMD image inspect "$IMAGE" >/dev/null 2>&1; then
  $DOCKER_CMD rmi -f "$IMAGE" >/dev/null 2>&1
  ok "Image '$IMAGE' removed"
else
  ok "Image '$IMAGE' not present"
fi

# ── 3. Remove dangling images from iterative builds ──────────────────────────
log "Dangling images..."

DANGLING=$($DOCKER_CMD images -f "dangling=true" -q 2>/dev/null || true)
if [ -n "$DANGLING" ]; then
  echo "$DANGLING" | xargs $DOCKER_CMD rmi -f >/dev/null 2>&1 || true
  ok "Dangling images pruned"
else
  ok "No dangling images"
fi

# ── 4. Remove sandbox bridge networks ────────────────────────────────────────
log "Networks..."

NETS=$($DOCKER_CMD network ls --format "{{.Name}}" 2>/dev/null \
  | grep "^${SANDBOX_NET_PREFIX}" || true)

if [ -n "$NETS" ]; then
  while IFS= read -r net; do
    $DOCKER_CMD network rm "$net" >/dev/null 2>&1 && dim "removed:  $net"
  done <<< "$NETS"
  ok "Sandbox networks removed"
else
  ok "No sandbox networks found"
fi

# ── 5. Remove any anonymous volumes left behind ───────────────────────────────
log "Volumes..."

VOLS=$($DOCKER_CMD volume ls -f "dangling=true" -q 2>/dev/null || true)
if [ -n "$VOLS" ]; then
  echo "$VOLS" | xargs $DOCKER_CMD volume rm >/dev/null 2>&1 || true
  ok "Dangling volumes removed"
else
  ok "No dangling volumes"
fi

# ── 6. Kill any strace/tcpdump processes that escaped ────────────────────────
log "Leaked host processes..."

for proc in strace tcpdump; do
  PIDS=$(pgrep -f "$proc" 2>/dev/null || true)
  if [ -n "$PIDS" ]; then
    echo "$PIDS" | xargs kill -9 2>/dev/null || true
    warn "Killed escaped $proc pids: $PIDS"
  fi
done
ok "Host process check done"

# ── 7. Optionally wipe results directory ─────────────────────────────────────
if [ "$WIPE_RESULTS" = "--results" ]; then
  log "Results directory..."
  if [ -d "./results" ]; then
    rm -rf ./results
    ok "./results wiped"
  else
    ok "./results not present"
  fi
else
  dim "Skipping ./results (pass --results to wipe)"
fi

# ── 8. Docker system df — confirm state ──────────────────────────────────────
echo ""
log "Current $DOCKER_CMD state:"
docker system df 2>/dev/null || true

echo ""
ok "Reset complete — clean slate"
echo ""