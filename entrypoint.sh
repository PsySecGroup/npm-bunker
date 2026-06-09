#!/bin/sh
# entrypoint.sh — npm package sandbox analysis entrypoint
set -u

RED=$(printf '\033[0;31m')
YLW=$(printf '\033[0;33m')
GRN=$(printf '\033[0;32m')
CYN=$(printf '\033[0;36m')
MAG=$(printf '\033[0;35m')
RST=$(printf '\033[0m')

RESULTS="/results"
REPORT="$RESULTS/report.txt"
PCAP="$RESULTS/capture.pcap"
STRACE_LOG="$RESULTS/strace.log"
NPM_LOG="$RESULTS/npm-install.log"
RUNTIME_STRACE="$RESULTS/strace-runtime.log"
RUNTIME_OUT="$RESULTS/runtime-output.txt"
OBFUSC_REPORT="$RESULTS/obfuscation.txt"
PCAP_PAYLOAD="$RESULTS/pcap-payload.txt"
ENV_REPORT="$RESULTS/env-exfil.txt"

log()  { echo "${CYN}[*]${RST} $1" | tee -a "$REPORT"; }
warn() { echo "${YLW}[!]${RST} $1" | tee -a "$REPORT"; }
hit()  { echo "${RED}[!!]${RST} $1" | tee -a "$REPORT"; }
ok()   { echo "${GRN}[+]${RST} $1" | tee -a "$REPORT"; }
sec()  { echo "${MAG}[S]${RST} $1" | tee -a "$REPORT"; }

mkdir -p "$RESULTS" 2>/dev/null || true

echo "============================================================" | tee "$REPORT"
echo " npm sandbox report"                                          | tee -a "$REPORT"
echo " target: ${TARGET_PACKAGE:-<none>}"                          | tee -a "$REPORT"
echo " date:   $(date -u)"                                         | tee -a "$REPORT"
echo "============================================================" | tee -a "$REPORT"

if [ -z "$TARGET_PACKAGE" ]; then
  echo "ERROR: TARGET_PACKAGE not set" | tee -a "$REPORT"
  exit 1
fi

if [ ! -f "$TARGET_PACKAGE" ]; then
  echo "ERROR: tarball not found at $TARGET_PACKAGE" | tee -a "$REPORT"
  ls /results/ | tee -a "$REPORT"
  exit 1
fi

# ── 1. Static analysis from tarball ──────────────────────────────────────────
log "Phase 1: static analysis (from tarball)"

PKG_JSON=$(tar -xOf "$TARGET_PACKAGE" "package/package.json" 2>/dev/null || true)

if [ -z "$PKG_JSON" ]; then
  warn "Could not extract package.json from tarball"
else
  SCRIPTS=$(echo "$PKG_JSON" | jq -r \
    '.scripts // {} | to_entries[]
     | select(.key | test("install|postinstall|preinstall|prepare"))
     | "\(.key): \(.value)"' 2>/dev/null || true)
  if [ -n "$SCRIPTS" ]; then
    hit "Install lifecycle scripts declared:"
    echo "$SCRIPTS" | tee -a "$REPORT"
  else
    ok "No install lifecycle scripts"
  fi

  PKG_NAME=$(echo "$PKG_JSON"  | jq -r '.name    // "unknown"' 2>/dev/null || echo "unknown")
  PKG_VER=$(echo "$PKG_JSON"   | jq -r '.version // "unknown"' 2>/dev/null || echo "unknown")
  DEP_COUNT=$(echo "$PKG_JSON" | jq -r '[.dependencies // {}, .optionalDependencies // {}] | add // {} | length' 2>/dev/null || echo "?")
  GYP_SCRIPTS=$(echo "$PKG_JSON" | jq -r '(.scripts.install // "") + " " + (.scripts.postinstall // "")' 2>/dev/null || echo "")
  case "$GYP_SCRIPTS" in
    *node-gyp*) warn "Uses node-gyp — native compilation" ;;
  esac

  log "Package: $PKG_NAME@$PKG_VER"
  log "Direct dependencies: $DEP_COUNT"
fi

# ── 2. Static obfuscation scan (pre-install, from tarball) ───────────────────
log "Phase 2: static obfuscation scan"

> "$OBFUSC_REPORT"

# Extract all JS files from tarball and scan each
tar -tf "$TARGET_PACKAGE" 2>/dev/null | grep '\.js$' | while read -r jsfile; do
  content=$(tar -xOf "$TARGET_PACKAGE" "$jsfile" 2>/dev/null || true)
  [ -z "$content" ] && continue

  filepath=$(echo "$jsfile" | sed 's|^package/||')

  # --- eval() with dynamic content
  if echo "$content" | grep -qE 'eval\s*\('; then
    echo "[!!] eval() — $filepath" | tee -a "$OBFUSC_REPORT"
    echo "$content" | grep -nE 'eval\s*\(' | head -3 >> "$OBFUSC_REPORT"
  fi

  # --- Function constructor (new Function(...))
  if echo "$content" | grep -qE 'new\s+Function\s*\('; then
    echo "[!!] Function constructor — $filepath" | tee -a "$OBFUSC_REPORT"
    echo "$content" | grep -nE 'new\s+Function\s*\(' | head -3 >> "$OBFUSC_REPORT"
  fi

  # --- Base64 decode + eval pattern
  if echo "$content" | grep -qE "Buffer\.from\s*\([^)]+['\"]base64['\"]" && \
     echo "$content" | grep -qE 'eval|exec|spawn|Function'; then
    echo "[!!] Buffer.from(base64) + execution — $filepath" | tee -a "$OBFUSC_REPORT"
    echo "$content" | grep -nE "Buffer\.from|eval|exec\b|spawn\b" | head -5 >> "$OBFUSC_REPORT"
  fi

  # --- atob/btoa decode chains
  if echo "$content" | grep -qE 'atob\s*\(' && echo "$content" | grep -qE 'eval|Function'; then
    echo "[!!] atob() + execution — $filepath" | tee -a "$OBFUSC_REPORT"
  fi

  # --- Hex string reassembly (\x41\x42 style long chains)
  if echo "$content" | grep -qE '(\\x[0-9a-fA-F]{2}){8,}'; then
    echo "[!] Long hex escape sequence — $filepath" | tee -a "$OBFUSC_REPORT"
    echo "$content" | grep -nE '(\\x[0-9a-fA-F]{2}){8,}' | head -2 >> "$OBFUSC_REPORT"
  fi

  # --- Unicode escape reassembly (\u0041 chains)
  if echo "$content" | grep -qE '(\\u[0-9a-fA-F]{4}){6,}'; then
    echo "[!] Long unicode escape sequence — $filepath" | tee -a "$OBFUSC_REPORT"
  fi

  # --- process.env reads (collected for correlation with network later)
  if echo "$content" | grep -qE 'process\.env\.[A-Z_]{3,}'; then
    echo "[env] process.env access — $filepath" >> "$OBFUSC_REPORT"
    echo "$content" | grep -nE 'process\.env\.[A-Z_]{3,}' | head -5 >> "$OBFUSC_REPORT"
  fi

  # --- Hardcoded external URLs (not localhost/loopback)
  # Use grep -P for word boundary so [object Array] style strings don't match
  URLS=$(echo "$content" | grep -oE 'https?://[a-zA-Z0-9._/-]{6,}' \
    | grep -v 'localhost\|127\.0\.0\.1\|0\.0\.0\.0\|example\.com\|schema\.org\|w3\.org\|mozilla\.org' \
    | head -5 || true)
  if [ -n "$URLS" ]; then
    echo "[!] Hardcoded URL — $filepath" | tee -a "$OBFUSC_REPORT"
    echo "$URLS" | head -3 >> "$OBFUSC_REPORT"
  fi

  # --- Hardcoded routable IPs (not RFC1918/loopback/multicast)
  # Require word boundary: not preceded by digit/dot, not followed by digit/dot
  HARDIPS=$(echo "$content" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | grep -vE '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.|255\.|224\.)' \
    | grep -vE '^(0\.0\.|1\.0\.|0\.)' \
    | head -5 || true)
  if [ -n "$HARDIPS" ]; then
    echo "[!] Hardcoded routable IP — $filepath" | tee -a "$OBFUSC_REPORT"
    echo "$HARDIPS" | head -3 >> "$OBFUSC_REPORT"
  fi

done

# Report obfuscation findings
if [ -s "$OBFUSC_REPORT" ]; then
  EVAL_HITS=$(grep -c '^\[!!' "$OBFUSC_REPORT" 2>/dev/null); EVAL_HITS=${EVAL_HITS:-0}
  WARN_HITS=$(grep -c '^\[!'  "$OBFUSC_REPORT" 2>/dev/null); WARN_HITS=${WARN_HITS:-0}
  ENV_HITS=$(grep -c '^\[env\]' "$OBFUSC_REPORT" 2>/dev/null); ENV_HITS=${ENV_HITS:-0}
  # [! matches [!! too so subtract to get pure warn-only count
  WARN_ONLY=$((WARN_HITS - EVAL_HITS)); [ "$WARN_ONLY" -lt 0 ] && WARN_ONLY=0
  [ "$EVAL_HITS" -gt 0 ] && hit "Obfuscation/execution patterns: $EVAL_HITS critical hits — see obfuscation.txt"
  [ "$WARN_ONLY" -gt 0 ] && warn "Suspicious patterns: $WARN_ONLY warnings — see obfuscation.txt"
  [ "$ENV_HITS"  -gt 0 ] && sec "process.env access in $ENV_HITS location(s) — correlate with network"
else
  ok "No obfuscation patterns detected"
fi

# ── 3. Network capture ────────────────────────────────────────────────────────
log "Phase 3: network capture"

TCPDUMP_PID=""
if command -v tcpdump >/dev/null 2>&1; then
  tcpdump -i any -w "$PCAP" -q 2>/dev/null &
  TCPDUMP_PID=$!
  log "tcpdump pid $TCPDUMP_PID"
else
  warn "tcpdump unavailable"
fi

# ── 4. Pre-install snapshot ───────────────────────────────────────────────────
log "Phase 4: filesystem baseline"
find /sandbox /tmp -not -path '/proc/*' 2>/dev/null | sort > /tmp/pre-install.txt

# ── 5. Instrumented install ───────────────────────────────────────────────────
log "Phase 5: detonation (scripts ENABLED)"

strace -f \
  -e trace=network,file,process \
  -o "$STRACE_LOG" \
  npm install "$TARGET_PACKAGE" \
    --prefix /sandbox \
    --no-save \
    --no-fund \
    --no-audit \
    --prefer-offline \
    --offline \
    --cache /tmp/npm-cache \
    2>&1 | tee "$NPM_LOG"

INSTALL_EXIT=$?
[ $INSTALL_EXIT -ne 0 ] && warn "npm exited $INSTALL_EXIT" || ok "npm install completed"

# ── 6. Stop capture ───────────────────────────────────────────────────────────
if [ -n "$TCPDUMP_PID" ]; then
  kill "$TCPDUMP_PID" 2>/dev/null || true
  wait "$TCPDUMP_PID" 2>/dev/null || true
fi

# ── 7. Filesystem diff ────────────────────────────────────────────────────────
log "Phase 6: filesystem diff"
find /sandbox /tmp -not -path '/proc/*' 2>/dev/null | sort > /tmp/post-install.txt

NEW_FILES=$(comm -13 /tmp/pre-install.txt /tmp/post-install.txt \
  | grep -v 'node-compile-cache' \
  | grep -v 'pre-install.txt\|post-install.txt' \
  || true)

if [ -n "$NEW_FILES" ]; then
  log "New files:"
  echo "$NEW_FILES" | tee -a "$REPORT"
  SUSPICIOUS=$(echo "$NEW_FILES" \
    | grep -v 'node_modules\|\.npm\|/tmp\|/results' \
    || true)
  [ -n "$SUSPICIOUS" ] && hit "Files OUTSIDE node_modules:" && echo "$SUSPICIOUS" | tee -a "$REPORT"
else
  ok "No unexpected filesystem changes"
fi

# ── 8. Network analysis + payload inspection ──────────────────────────────────
log "Phase 7: network analysis"

> "$PCAP_PAYLOAD"

if [ -f "$PCAP" ] && [ -s "$PCAP" ]; then
  CONNECTIONS=$(tcpdump -r "$PCAP" -nn -q 2>/dev/null \
    | grep -E '^[0-9]' \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
    | sed 's/\.[0-9]*$//' \
    | sort -u || true)

  if [ -n "$CONNECTIONS" ]; then
    log "IPs contacted:"
    echo "$CONNECTIONS" | tee -a "$REPORT"

    NON_INFRA=$(echo "$CONNECTIONS" \
      | grep -v '^127\.' \
      | grep -v '^10\.' \
      | grep -v '^172\.1[6-9]\.' \
      | grep -v '^172\.2[0-9]\.' \
      | grep -v '^172\.3[0-1]\.' \
      | grep -v '^224\.' \
      | grep -v '^104\.16\.' \
      || true)

    [ -n "$NON_INFRA" ] && hit "Non-infrastructure IPs:" && echo "$NON_INFRA" | tee -a "$REPORT" \
      || ok "All connections to local/infra IPs only"
  else
    ok "No network connections"
  fi

  # pcap payload inspection — extract ASCII strings from packet data
  # Shows what was actually transmitted (URLs, tokens, env vars, etc.)
  log "Phase 7b: pcap payload inspection"
  # Extract only TCP payload — filter out mDNS(5353), multicast, ARP
  tcpdump -r "$PCAP" -nn -A     'tcp and not port 5353 and not dst net 224.0.0.0/4'     2>/dev/null     | grep -E '^[[:print:]]{4,}'     | grep -v '^[0-9][0-9]:[0-9][0-9]'     | grep -v '^\.'     | grep -v '^--'     > "$PCAP_PAYLOAD" 2>/dev/null || true

  if [ -s "$PCAP_PAYLOAD" ]; then
    # Look for high-value strings in payload
    PAYLOAD_HITS=""

    # env var values (HOME, PATH, user tokens, API keys)
    # Match sensitive strings only in HTTP context (headers/query strings)
    # Avoids mDNS/Bonjour noise which contains _ftp, _sftp, _smb etc.
    ENV_IN_PAYLOAD=$(grep -iE '^(Authorization|X-Api-Key|X-Token|X-Secret): |[?&](token|secret|password|api_key|auth|aws_|npm_token)=' \
      "$PCAP_PAYLOAD" 2>/dev/null | head -5 || true)
    [ -n "$ENV_IN_PAYLOAD" ] && PAYLOAD_HITS="yes" \
      && hit "Sensitive strings in network payload:" \
      && echo "$ENV_IN_PAYLOAD" | tee -a "$REPORT"

    # HTTP requests
    HTTP_REQS=$(grep -E '^(GET|POST|PUT|DELETE|HEAD|OPTIONS) ' \
      "$PCAP_PAYLOAD" 2>/dev/null | head -10 || true)
    [ -n "$HTTP_REQS" ] && sec "HTTP requests observed:" \
      && echo "$HTTP_REQS" | tee -a "$REPORT"

    # Host headers
    HOSTS=$(grep -iE '^Host: ' "$PCAP_PAYLOAD" 2>/dev/null | sort -u | head -10 || true)
    [ -n "$HOSTS" ] && sec "Destination hosts:" \
      && echo "$HOSTS" | tee -a "$REPORT"

    [ -z "$PAYLOAD_HITS" ] && ok "No sensitive strings in pcap payload — see pcap-payload.txt for full content"
  else
    ok "No printable payload content captured"
  fi
else
  ok "No pcap (expected with --network none)"
fi

# ── 9. strace highlights ──────────────────────────────────────────────────────
log "Phase 8: strace highlights"

if [ -f "$STRACE_LOG" ]; then
  EXECS=$(grep 'execve' "$STRACE_LOG" \
    | grep -v '"node"\|"npm"\|"/bin/sh"\|"env"\|"strace"' \
    | head -20 || true)
  [ -n "$EXECS" ] && hit "Unexpected execve:" && echo "$EXECS" | tee -a "$REPORT" || ok "No unexpected execve"

  WRITES=$(grep -E 'open(at)?\(.*O_WRONLY|open(at)?\(.*O_RDWR' "$STRACE_LOG" \
    | grep -v 'node_modules\|\.npm\|/tmp\|/proc\|/results' \
    | head -20 || true)
  [ -n "$WRITES" ] && warn "Writes outside expected paths:" && echo "$WRITES" | tee -a "$REPORT" \
    || ok "No unexpected writes"
else
  warn "No strace log — SYS_PTRACE may be blocked"
fi

# ── 10. Postinstall script dump ───────────────────────────────────────────────
log "Phase 9: postinstall script inventory"

find /sandbox/node_modules -name "package.json" 2>/dev/null \
  | while read -r pkg; do
      scripts=$(jq -r \
        '.scripts // {} | to_entries[]
         | select(.key | test("install|postinstall|preinstall"))
         | "\(.key): \(.value)"' \
        "$pkg" 2>/dev/null || true)
      [ -n "$scripts" ] && echo "--- $pkg ---" && echo "$scripts"
    done \
  | tee -a "$REPORT"

# ── 11. Post-install obfuscation scan (installed files) ──────────────────────
log "Phase 10: post-install obfuscation scan (installed tree)"

INSTALL_OBFUSC=0
find /sandbox/node_modules -name "*.js" 2>/dev/null | while read -r jsfile; do
  # Skip minified files (single line > 500 chars — noise)
  lines=$(wc -l < "$jsfile" 2>/dev/null || echo 1)
  chars=$(wc -c < "$jsfile" 2>/dev/null || echo 0)
  [ "$lines" -lt 3 ] && [ "$chars" -gt 500 ] && continue

  pkg=$(echo "$jsfile" | grep -oE 'node_modules/[^/]+' | head -1)

  for pattern in \
    'eval[[:space:]]*(' \
    'new[[:space:]]+Function[[:space:]]*(' \
    'require[[:space:]]*([[:space:]]*Buffer' \
    ; do
    if grep -qE "$pattern" "$jsfile" 2>/dev/null; then
      echo "[!!] $pattern — $jsfile" | tee -a "$OBFUSC_REPORT"
      grep -nE "$pattern" "$jsfile" | head -2 >> "$OBFUSC_REPORT"
    fi
  done
done

if grep -q '^\[!!' "$OBFUSC_REPORT" 2>/dev/null; then
  hit "Obfuscation patterns in installed tree — see obfuscation.txt"
else
  ok "No obfuscation in installed tree"
fi

# ── 12. Runtime detonation ────────────────────────────────────────────────────
log "Phase 11: runtime detonation (require with 10s timeout)"

PKG_MAIN=$(tar -xOf "$TARGET_PACKAGE" "package/package.json" 2>/dev/null \
  | jq -r '.main // "index.js"' 2>/dev/null || echo "index.js")
PKG_MAIN=$(echo "$PKG_MAIN" | sed 's|^\./||')
PKG_NAME=$(tar -xOf "$TARGET_PACKAGE" "package/package.json" 2>/dev/null \
  | jq -r '.name' 2>/dev/null || echo "unknown")

ENTRY="/sandbox/node_modules/$PKG_NAME/$PKG_MAIN"

if [ ! -f "$ENTRY" ]; then
  warn "Entry point not found: $ENTRY — skipping runtime detonation"
else
  log "Requiring: $ENTRY"

  # Intercept proxy — catches ALL outbound HTTP/HTTPS regardless of destination
  # Strategy 1: Node preload patches http.request + https.request before require()
  # Strategy 2: HTTP_PROXY env var for packages that check it
  # Strategy 3: loopback server on 9876 logs everything routed to it
  CAPTURE_LOG="$RESULTS/http-capture.txt"

  # Proxy is baked into the image at /sandbox-proxy.js
  CAPTURE_SERVER_PID=""
  CAPTURE_SERVER_PID=""
  sleep 0.1

  # Start a second tcpdump for runtime-only traffic
  RUNTIME_PCAP="$RESULTS/capture-runtime.pcap"
  tcpdump -i any -w "$RUNTIME_PCAP" -q 2>/dev/null &
  RT_TCPDUMP_PID=$!

  # Wrap require() in a Node-level timeout so strace doesn't swallow SIGTERM.
  # The outer shell timeout is a backstop only; Node kills itself first.
  NODE_WRAPPER="
    const t = setTimeout(() => {
      process.stderr.write('[sandbox] 30s timeout — killing process\\n');
      process.exit(124);
    }, 30000);
    t.unref();
    try { require('$ENTRY'); } catch(e) { process.stderr.write(e.message+'\\n'); process.exit(1); }
  "
  set +e
  timeout 45s strace -f \
    -e trace=network,file,process \
    -o "$RUNTIME_STRACE" \
    env CAPTURE_LOG="$CAPTURE_LOG" node --require /sandbox-proxy.js -e "$NODE_WRAPPER" \
    > "$RUNTIME_OUT" 2>&1
  RUNTIME_EXIT=$?
  set -e
  # Normalise: node exits 124 on our timeout, shell timeout gives 124 too
  [ $RUNTIME_EXIT -eq 143 ] && RUNTIME_EXIT=124  # SIGTERM -> 128+15

  kill "$RT_TCPDUMP_PID" 2>/dev/null || true
  wait "$RT_TCPDUMP_PID" 2>/dev/null || true
  kill "$CAPTURE_SERVER_PID" 2>/dev/null || true

  head -200 "$RUNTIME_OUT" | tee -a "$REPORT" || true

  if [ $RUNTIME_EXIT -eq 124 ]; then
    OUTPUT_LINES=$(wc -l < "$RUNTIME_OUT" 2>/dev/null || echo 0)
    if [ "${OUTPUT_LINES:-0}" -le 1 ]; then
      hit "Runtime TIMED OUT — no output produced — likely infinite loop"
    else
      warn "Runtime TIMED OUT — produced $OUTPUT_LINES lines before timeout — possible slow load under strace"
    fi
    tail -20 "$RUNTIME_OUT" | tee -a "$REPORT"
  elif [ $RUNTIME_EXIT -eq 0 ]; then
    ok "Runtime completed cleanly (exit 0)"
  else
    warn "Runtime exited $RUNTIME_EXIT"
    tail -10 "$RUNTIME_OUT" | tee -a "$REPORT"
  fi

  # Runtime strace analysis
  # HTTP capture server results
  if [ -f "$CAPTURE_LOG" ] && [ -s "$CAPTURE_LOG" ]; then
    hit "HTTP requests captured by loopback server:"
    cat "$CAPTURE_LOG" | tee -a "$REPORT"
    # Check for env var content in captured requests
    ENV_IN_HTTP=$(grep -iE '[?&](HOME|USER|PATH|TOKEN|SECRET|KEY|AWS|GITHUB|NPM)='       "$CAPTURE_LOG" 2>/dev/null || true)
    [ -n "$ENV_IN_HTTP" ] && hit "ENVIRONMENT DATA IN CAPTURED REQUEST:"       && echo "$ENV_IN_HTTP" | tee -a "$RESULTS/env-exfil.txt" | tee -a "$REPORT"
  fi

  if [ -f "$RUNTIME_STRACE" ]; then
    RT_CONNECTS=$(grep -E 'connect\(' "$RUNTIME_STRACE" \
      | grep -v '127\.' | grep -v 'AF_UNIX' | grep -v 'AF_NETLINK' \
      | head -20 || true)
    [ -n "$RT_CONNECTS" ] && hit "Network connections during runtime:" \
      && echo "$RT_CONNECTS" | tee -a "$REPORT" || ok "No runtime network connections"

    RT_WRITES=$(grep -E 'open(at)?\(.*O_WRONLY|open(at)?\(.*O_RDWR' "$RUNTIME_STRACE" \
      | grep -v 'node_modules\|\.npm\|/proc\|/results\|/dev' \
      | grep -v '/tmp/npm-cache\|/tmp/node-compile-cache\|/tmp/npm-logs' \
      | head -20 || true)
    [ -n "$RT_WRITES" ] && hit "Runtime file writes outside expected paths:" \
      && echo "$RT_WRITES" | tee -a "$REPORT" || ok "No unexpected runtime writes"

    RT_EXECS=$(grep 'execve' "$RUNTIME_STRACE" \
      | grep -v '"node"\|"npm"\|"/bin/sh"\|"env"\|"strace"' \
      | head -20 || true)
    [ -n "$RT_EXECS" ] && hit "Unexpected runtime execve:" \
      && echo "$RT_EXECS" | tee -a "$REPORT" || ok "No unexpected runtime execve"
  fi

  # Runtime pcap payload inspection
  if [ -f "$RUNTIME_PCAP" ] && [ -s "$RUNTIME_PCAP" ]; then
    log "Phase 11b: runtime pcap payload inspection"
    RUNTIME_PAYLOAD="$RESULTS/pcap-payload-runtime.txt"

    # Extract only TCP payload — filter mDNS/multicast noise
    tcpdump -r "$RUNTIME_PCAP" -nn -A       'tcp and not port 5353 and not dst net 224.0.0.0/4'       2>/dev/null       | grep -E '^[[:print:]]{4,}'       | grep -v '^[0-9][0-9]:[0-9][0-9]'       | grep -v '^\.'       | grep -v '^--'       > "$RUNTIME_PAYLOAD" 2>/dev/null || true

    if [ -s "$RUNTIME_PAYLOAD" ]; then
      log "Runtime payload size: $(wc -c < "$RUNTIME_PAYLOAD") bytes"
      # HTTP requests show what was actually being sent
      HTTP_REQS=$(grep -E '^(GET|POST|PUT|DELETE) ' "$RUNTIME_PAYLOAD" | head -10 || true)
      [ -n "$HTTP_REQS" ] && hit "Runtime HTTP requests:" \
        && echo "$HTTP_REQS" | tee -a "$REPORT"

      HOSTS=$(grep -iE '^Host: ' "$RUNTIME_PAYLOAD" | sort -u | head -10 || true)
      [ -n "$HOSTS" ] && sec "Runtime destination hosts:" \
        && echo "$HOSTS" | tee -a "$REPORT"

      # Check for env var content in payload — the smoking gun for exfil
      # Cross-reference: did we see process.env reads AND outbound data?
      if grep -q '^\[env\]' "$OBFUSC_REPORT" 2>/dev/null; then
        sec "process.env reads were detected in source — checking payload for env content..."
        # Look for common env var patterns in payload content
        # Look for env var names appearing as HTTP query params or header values
        ENV_EXFIL=$(grep -iE '[?&](HOME|USER|TOKEN|SECRET|KEY|AWS_|GITHUB_|NPM_TOKEN|PATH)=|^(Authorization|X-Token): ' \
          "$RUNTIME_PAYLOAD" 2>/dev/null | head -10 || true)
        if [ -n "$ENV_EXFIL" ]; then
          hit "ENVIRONMENT DATA IN NETWORK PAYLOAD — likely exfil:" \
            | tee -a "$ENV_REPORT"
          echo "$ENV_EXFIL" | tee -a "$ENV_REPORT" | tee -a "$REPORT"
        else
          # Softer check — any payload at all when env was read
          PAYLOAD_SIZE=$(wc -c < "$RUNTIME_PAYLOAD" 2>/dev/null || echo 0)
          [ "$PAYLOAD_SIZE" -gt 50 ] \
            && warn "process.env reads + outbound data ($PAYLOAD_SIZE bytes) — manual review recommended" \
            && sec "See pcap-payload-runtime.txt for full payload"
        fi
      fi

      ok "Runtime payload captured — see pcap-payload-runtime.txt"
    else
      ok "No printable runtime payload"
    fi
  fi
fi

echo ""                                                               | tee -a "$REPORT"
echo "============================================================"  | tee -a "$REPORT"
echo " Artifacts:"                                                    | tee -a "$REPORT"
echo "  report.txt             — full findings"                       | tee -a "$REPORT"
echo "  obfuscation.txt        — static code scan hits"               | tee -a "$REPORT"
echo "  strace.log             — install syscall trace"               | tee -a "$REPORT"
echo "  strace-runtime.log     — runtime syscall trace"               | tee -a "$REPORT"
echo "  npm-install.log        — npm output"                          | tee -a "$REPORT"
echo "  capture.pcap           — install network (if --net)"          | tee -a "$REPORT"
echo "  capture-runtime.pcap   — runtime network (if --net)"          | tee -a "$REPORT"
echo "  pcap-payload.txt       — install payload strings"             | tee -a "$REPORT"
echo "  pcap-payload-runtime.txt — runtime payload strings"           | tee -a "$REPORT"
echo "  env-exfil.txt          — env var exfil hits"                  | tee -a "$REPORT"
echo "  *.tgz                  — original tarball"                    | tee -a "$REPORT"
echo "============================================================"  | tee -a "$REPORT"

sync