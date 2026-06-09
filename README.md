# npm-bunker

Sacrificial sandbox for analyzing `npm` packages for malicious behavior.
Pass a package name and version — it fetches the tarball safely on the host,
detonates it inside a hardened isolated container, and produces a structured
report covering static analysis, network activity, filesystem changes, syscall
traces, and HTTP payload inspection including `env` var exfil detection.

---

## Requirements

### Docker

Docker Engine must be installed and the daemon must be running.

```bash
# Verify
docker info
```

Install: https://docs.docker.com/engine/install/

### Node.js + npm

`npm` is used on the host to fetch tarballs and pre-warm the dependency cache.
Any recent version (16+) works. `nvm` installs are supported.

```bash
# Verify
npm --version
node --version
```

Install via nvm (recommended): https://github.com/nvm-sh/nvm
Or directly: https://nodejs.org

---

## Setup

```bash
git clone https://github.com/PsySecGroup/npm-bunker
cd npm-bunker
chmod +x scan.sh reset.sh

# Build the sandbox image (once, or after editing source files)
docker build -t npm-sandbox .
# — or if docker requires sudo on your system —
sudo docker build -t npm-sandbox .
```

---

## Docker invocation — which command to use

`npm-bunker` auto-detects how to invoke Docker. Depending on your setup,
use one of the following approaches:

### Option A — Docker group (default Ubuntu/Mac install)

If your user is in the `docker` group, plain `docker` works without sudo:

```bash
./scan.sh lodash
./scan.sh colors@1.4.0 --net
./reset.sh
```

Verify this is your setup:
```bash
groups | grep docker   # should print 'docker'
docker info            # should succeed without sudo
```

### Option B — Docker not in group (more secure)

If you've intentionally removed Docker from your user groups, prefix with
`sudo -E`. The `-E` flag preserves your environment including `$PATH`,
which is required so `npm` can be found (nvm installs live in `$HOME`):

```bash
sudo -E ./scan.sh lodash
sudo -E ./scan.sh colors@1.4.0 --net
sudo -E ./reset.sh --results
```

Why `-E` and not just `sudo`? Plain `sudo` resets `$PATH` to a minimal
system path. `npm` installed via nvm lives in `/home/you/.nvm/...` which
disappears under a bare sudo. `-E` passes your full environment through.

### Option C — Explicit override

Override the docker command entirely via the `DOCKER` env var:

```bash
DOCKER="sudo docker" ./scan.sh lodash
DOCKER="sudo -E docker" ./scan.sh lodash
```

This is useful in CI or when you need a specific docker binary path.

### Option D — Running as root

If you're already root (e.g. in a VM or container), plain invocation works:

```bash
sudo su -
cd /path/to/npm-bunker
./scan.sh lodash
```

---

## Usage

### Scan a package from the registry

```bash
# Latest version
./scan.sh lodash

# Specific version
./scan.sh colors@1.4.0

# With outbound network allowed (observe exfil attempts)
./scan.sh colors@1.4.0 --net
```

No `npm pack` step needed — scan.sh handles the fetch automatically.

### Scan a local tarball

If you already have a `.tgz` (e.g. from a previous `npm pack`, a private
registry download, or a threat intel source):

```bash
./scan.sh ./some-package-1.2.3.tgz
./scan.sh /path/to/suspicious.tgz --net
```

### Network modes

```
(default)  --network none    Package cannot reach the internet.
                             DNS and TCP connections fail immediately.
                             Use for: clean baseline, install-time analysis.

--net      isolated bridge   Package can make outbound connections.
                             Traffic is captured in capture-runtime.pcap.
                             Use for: observing exfil, DNS lookups, C2 callbacks.
```

The HTTP intercept proxy runs in both modes — it catches `http`/`https` module
calls at the Node level regardless of network mode.

### Reset between runs

```bash
./reset.sh            # removes containers, image, networks, volumes
                      # preserves ./results/ so you keep your scan artifacts

./reset.sh --results  # also wipes ./results/ — full clean slate
```

### Rebuild the image

Only needed when you edit `Dockerfile`, `entrypoint.sh`, or `sandbox-proxy.js`:

```bash
docker build --no-cache -t npm-sandbox .
# or
sudo docker build --no-cache -t npm-sandbox .
```

Normal `reset` + `scan` cycles reuse the cached image automatically.

---

## Files

```
Dockerfile            hardened Alpine+Node22 image (strace, tcpdump, jq)
entrypoint.sh         11-phase analysis pipeline (runs inside container)
sandbox-proxy.js      HTTP/HTTPS intercept proxy (baked into image)
scan.sh               host orchestration: fetch → cache → detonate → report
reset.sh              cleanup: containers, image, networks, volumes, results
```

---

## What it does

### Host side (`scan.sh`)

1. Locates `npm` (handles `nvm`, sudo PATH stripping, explicit override)
2. `npm pack` — downloads tarball from registry, no script execution
3. `npm install --ignore-scripts` — pre-warms full dep cache on host
4. Runs the hardened container with tarball + cache bind-mounted in

### Inside the container (`entrypoint.sh`)

| Phase | Description |
|-------|-------------|
| 1 | **Static analysis** from tarball — lifecycle scripts, node-gyp, dependency count |
| 2 | **Static obfuscation scan** — `eval()`, `Function()` constructor, `Buffer.from(base64)` + exec, long hex/unicode chains, `process.env` reads, hardcoded URLs and routable IPs |
| 3 | tcpdump starts (install-phase capture) |
| 4 | Filesystem baseline snapshot |
| 5 | **Install detonation** — `npm install` wrapped in strace, scripts intentionally enabled |
| 6 | **Filesystem diff** — every new file, flags anything outside `node_modules` |
| 7 | **Network analysis** — IP categorization, Docker infra ranges filtered out |
| 7b | **pcap payload inspection** — TCP streams only, mDNS/multicast stripped |
| 8 | **strace highlights** — unexpected `execve`, writes outside expected paths |
| 9 | Postinstall script inventory across all installed packages |
| 10 | **Post-install obfuscation scan** — repeats Phase 2 on the fully installed tree |
| 11 | **Runtime detonation** — `node --require sandbox-proxy.js -e "require(entry)"` with 30s Node-level timeout; distinguishes infinite loop (no output) from slow load (output before timeout) |
| 11b | **Runtime pcap + HTTP capture** — env var exfil correlation, payload content inspection |

### HTTP intercept proxy (`sandbox-proxy.js`)

Loaded via `--require` before the target package executes. Monkey-patches
`http.request`, `http.get`, `https.request`, `https.get` at the Node module
level so all outbound HTTP and HTTPS is redirected to a loopback server on
port 9876 regardless of the destination hostname or IP.

The proxy logs the full request including headers and query string.
`X-Original-Host` and `X-Original-Port` headers preserve the real destination.
HTTPS is downgraded to plain HTTP at the proxy so request content is readable.

Raw `net.Socket` connections bypass the proxy but are caught by strace's
`connect()` tracing.

---

## Artifacts

Each scan produces a timestamped directory under `./results/`:

```
results/<package>-<timestamp>/
  report.txt               full findings — all phase output, all hits
  obfuscation.txt          static code scan hits (pre- and post-install)
  strace.log               install-phase syscall trace
  strace-runtime.log       runtime-phase syscall trace
  npm-install.log          npm stdout/stderr during install
  capture.pcap             install-phase network capture (tcpdump)
  capture-runtime.pcap     runtime-phase network capture
  pcap-payload.txt         printable strings from install TCP streams
  pcap-payload-runtime.txt printable strings from runtime TCP streams
  http-capture.txt         full HTTP requests intercepted by proxy
  env-exfil.txt            env var exfil hits (process.env + network correlation)
  *.tgz                    original tarball (preserved for re-analysis)
  npm-cache/               pre-warmed dep cache (host-side, not executed)
  prefetch/                host-side dep install tree (not executed)
```

---

## Detection coverage

| Threat | Phase | Method |
|--------|-------|--------|
| Install lifecycle scripts declared | 1 | package.json parse |
| Native build (node-gyp) | 1 | scripts.install/postinstall parse |
| `eval()` / `Function()` constructor | 2, 10 | source grep |
| `Buffer.from(base64)` + exec | 2, 10 | source grep |
| Long hex / unicode escape chains | 2 | source grep |
| Hardcoded external URLs | 2, 10 | source grep |
| Hardcoded routable IPs | 2, 10 | source grep |
| `process.env` reads | 2 | source grep (flagged, correlated) |
| Network connections at install | 7 pcap, 8 strace | `connect()` syscalls |
| File writes outside node_modules | 8 strace | `open()` / `openat()` syscalls |
| Unexpected process spawns at install | 8 strace | `execve()` syscalls |
| Network connections at runtime | 11 strace | `connect()` syscalls |
| HTTP/HTTPS payload content | 11 proxy | full request logging |
| HTTPS payload (decrypted) | 11 proxy | downgrade to HTTP |
| Env var exfil via HTTP | 11 proxy + correlation | query string analysis |
| File writes outside expected paths | 11 strace | `open()` / `openat()` |
| Unexpected process spawns at runtime | 11 strace | `execve()` |
| Infinite loop | 11 timeout | no output within 30s |
| Hang / slow load | 11 timeout | output present, timeout fires |

---

## Container security

The container is hardened to limit blast radius if a package attempts escape:

```
--cap-drop ALL                drop all Linux capabilities
--cap-add SYS_PTRACE          required for strace
--cap-add NET_RAW             required for tcpdump
--security-opt no-new-privileges   blocks setuid escalation
--read-only                   root filesystem read-only
--tmpfs /sandbox:exec         work dir (exec allowed for npm)
--tmpfs /tmp:nosuid           temp files (exec allowed for Node cache)
--tmpfs /root:noexec,nosuid   npm config/logs (no exec)
--memory 512m                 OOM kills runaway processes
--pids-limit 200              fork bomb containment
--network none                default; --net creates isolated bridge
--ipc none                    no shared memory with host
```

Note: the custom seccomp profile (`seccomp-sandbox.json`) is included but
not applied by default due to kernel compatibility issues observed on some
systems. Docker's built-in default seccomp profile is used instead, which
already blocks ~40 dangerous syscalls including `kexec`, `mount`, and
`init_module`.

---

## Known limitations

- **Raw TCP sockets** bypass the HTTP proxy. Caught by strace `connect()`.
- **`child_process.exec('curl ...')`** bypasses the proxy. Caught by strace `execve()`.
- **Native addons** (`.node` files) making direct syscalls bypass JS-layer hooks entirely. strace catches the syscalls but payload content is opaque.
- **Steganographic delays** — malware that counts invocations and only activates after N runs. Not detectable in a single-run sandbox.
- **Kernel exploits** — a package exploiting a kernel CVE can escape the container. Mitigate by running the Docker host inside a VM with a throwaway snapshot (Proxmox, QEMU, etc).
- **Supply chain at install time** — the dep cache is pre-warmed with `--ignore-scripts` on the host, but a package with a postinstall that fetches and executes a second-stage payload will only be caught if the network call is visible in strace (it will be).