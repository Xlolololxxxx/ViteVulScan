'use strict';

const USER_AGENT =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 ViteVulScan/1.0';

const DEFAULT_TIMEOUT_MS = 10000;

/**
 * Perform a GET request and return `{ ok, status, body }`.
 *
 * Uses the global `fetch` (Node >= 18). TLS verification is left to Node; the
 * dashboard is meant for local/authorized targets so we do not disable it.
 * Never throws — network errors are returned as `{ ok: false, error }`.
 */
async function get(url, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      headers: { 'User-Agent': USER_AGENT },
      signal: controller.signal,
    });
    const body = await res.text();
    return { ok: true, status: res.status, body };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      body: '',
      error: err && err.name === 'AbortError' ? 'timeout' : String(err && err.message ? err.message : err),
    };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { get, USER_AGENT, DEFAULT_TIMEOUT_MS };
