'use strict';

const { URL } = require('url');

/**
 * Normalise arbitrary user input (a full URL, a host, or host:port) into a
 * structured target descriptor. Mirrors the Go tool's NormalizeUrl but does
 * no network I/O — liveness is checked separately by the scanner.
 *
 * Returns `{ ok, target?, error? }`.
 */
function normalizeTarget(input) {
  if (!input || typeof input !== 'string') {
    return { ok: false, error: 'empty target' };
  }
  let raw = input.trim().replace(/\/+$/, '');
  if (!raw) return { ok: false, error: 'empty target' };

  const hasScheme = /^https?:\/\//i.test(raw);
  const candidates = hasScheme ? [raw] : [`http://${raw}`, `https://${raw}`];

  for (const candidate of candidates) {
    try {
      const u = new URL(candidate);
      const protocol = u.protocol.replace(':', '');
      const port = u.port || (protocol === 'https' ? '443' : '80');
      const host = u.hostname;
      const hostPort = u.port ? `${host}:${u.port}` : host;
      // Rebuild a clean base url without trailing path/query.
      const url = `${protocol}://${hostPort}`;
      return {
        ok: true,
        target: {
          host,
          hostPort,
          ip: host,
          port,
          protocol,
          url,
          input: raw,
        },
      };
    } catch (_e) {
      // try next candidate
    }
  }
  return { ok: false, error: `could not parse target: ${input}` };
}

/** Stable identifier used to key a target in the store (host:port). */
function targetKey(target) {
  return `${target.protocol}://${target.hostPort}`;
}

module.exports = { normalizeTarget, targetKey };
