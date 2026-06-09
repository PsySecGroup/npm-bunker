'use strict';
// sandbox-proxy.js — loaded via node --require before the target package
// Intercepts ALL http/https requests regardless of destination,
// redirects to loopback proxy server, logs full request content.

const net   = require('net');
const fs    = require('fs');
const http  = require('http');
const https = require('https');

const LOG = process.env.CAPTURE_LOG || '/results/http-capture.txt';

function log(s) {
  try { fs.appendFileSync(LOG, s); } catch(_) {}
}

// ── Proxy server ──────────────────────────────────────────────────────────────
const proxy = net.createServer(conn => {
  const chunks = [];
  let responded = false;

  function respond() {
    if (responded) return;
    responded = true;
    const raw = Buffer.concat(chunks).toString('utf8', 0, 4096);
    log('--- connection from ' + (conn.remoteAddress || '?') + ' ---\n');
    log(raw);
    log('\n--- end ---\n');
    try {
      conn.write('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK');
      conn.end();
    } catch(_) {}
  }

  conn.on('data', d => {
    chunks.push(d);
    const so_far = Buffer.concat(chunks).toString('utf8', 0, 4096);
    // Respond once we have the full request headers
    if (so_far.includes('\r\n\r\n') || so_far.includes('\n\n')) {
      respond();
    }
  });
  conn.on('end', respond);
  conn.on('error', () => {});
  // Safety timeout — respond after 500ms regardless
  setTimeout(respond, 500);
});

proxy.on('error', e => log('[proxy error] ' + e.message + '\n'));
proxy.listen(9876, '127.0.0.1', () => {
  log('[proxy] listening on 127.0.0.1:9876\n');
});

// ── Intercept helpers ─────────────────────────────────────────────────────────
function redirectOpts(opts) {
  let url;
  try {
    url = typeof opts === 'string' ? new URL(opts) : null;
  } catch(_) {}

  const origHost = url ? url.hostname
    : (opts && (opts.hostname || opts.host || '?'));
  const origPort = url ? (url.port || 80)
    : (opts && opts.port || 80);
  const origPath = url ? (url.pathname + url.search)
    : (opts && opts.path || '/');

  log('[intercept] ' + origHost + ':' + origPort + origPath + '\n');

  const base = url ? {
    method:  opts.method  || 'GET',
    headers: opts.headers || {},
    path:    origPath,
  } : Object.assign({}, opts);

  return Object.assign(base, {
    hostname: '127.0.0.1',
    host:     '127.0.0.1',
    port:     9876,
    path:     origPath,
    headers:  Object.assign({}, base.headers, {
      'Host':            origHost + ':' + origPort,
      'X-Original-Host': String(origHost),
      'X-Original-Port': String(origPort),
    }),
  });
}

// ── Patch http ────────────────────────────────────────────────────────────────
const _httpReq = http.request.bind(http);
http.request = function(opts, cb) { return _httpReq(redirectOpts(opts), cb); };
http.get = function(opts, cb) {
  const req = http.request(opts, cb);
  req.end();
  return req;
};

// ── Patch https ───────────────────────────────────────────────────────────────
const _httpsReq = https.request.bind(https);
https.request = function(opts, cb) {
  // Downgrade to plain HTTP so the proxy can read it
  return _httpReq(redirectOpts(opts), cb);
};
https.get = function(opts, cb) {
  const req = https.request(opts, cb);
  req.end();
  return req;
};