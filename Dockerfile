# =============================================================================
# npm package security sandbox — SACRIFICIAL / DISPOSABLE
# =============================================================================

FROM node:22-alpine

RUN apk add --no-cache \
      strace        \
      iproute2      \
      tcpdump       \
      lsof          \
      procps        \
      jq            \
      file          \
      findutils

# Remove apk so malware can't install tools
RUN rm -f /sbin/apk /usr/bin/apk /etc/apk/repositories 2>/dev/null || true

# Strip setuid/setgid bits
RUN find / -perm /6000 -not -path '/proc/*' -exec chmod a-s {} \; 2>/dev/null || true

# /sandbox = work dir (tmpfs at runtime, noexec)
# /results = volume mount for artifact extraction (rw)
RUN mkdir -p /sandbox /results

WORKDIR /sandbox

COPY entrypoint.sh /entrypoint.sh
COPY sandbox-proxy.js /sandbox-proxy.js
RUN chmod +x /entrypoint.sh

# NOTE: run as root inside container so strace + tcpdump work without capability dance
# Container is isolated by seccomp + cap-drop in scan.sh — root here != root on host

ENV TARGET_PACKAGE=""

VOLUME ["/results"]

ENTRYPOINT ["/entrypoint.sh"]