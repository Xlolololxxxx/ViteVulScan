'use strict';

const express = require('express');
const { normalizeTarget } = require('../scanner/targets');
const { scanTarget, readSinglePath, listCves } = require('../scanService');
const { RULES } = require('../scanner/secretScanner');
const { pathsFor } = require('../dict');

/**
 * Build the API router. Takes the shared store so routes are stateless.
 * @param {import('../store').Store} store
 */
module.exports = function apiRouter(store) {
  const router = express.Router();

  // --- metadata ---
  router.get('/cves', (_req, res) => res.json({ cves: listCves() }));

  router.get('/secret-rules', (_req, res) =>
    res.json({
      rules: RULES.map((r) => ({ id: r.id, name: r.name, severity: r.severity })),
    })
  );

  router.get('/paths', (req, res) => {
    const mode = String(req.query.mode || 'default');
    const platform = String(req.query.platform || 'linux');
    res.json({ mode, paths: pathsFor(mode, platform) });
  });

  // --- targets ---
  router.get('/targets', (_req, res) => res.json({ targets: store.list() }));

  router.post('/targets', (req, res) => {
    const input = req.body && req.body.target;
    const inputs = Array.isArray(input) ? input : [input];
    const added = [];
    const errors = [];
    for (const raw of inputs) {
      const norm = normalizeTarget(raw);
      if (!norm.ok) {
        errors.push({ input: raw, error: norm.error });
        continue;
      }
      added.push(store.summary(store.addTarget(norm.target)));
    }
    res.status(errors.length && !added.length ? 400 : 201).json({ added, errors });
  });

  router.get('/targets/:id', (req, res) => {
    const detail = store.detail(req.params.id);
    if (!detail) return res.status(404).json({ error: 'target not found' });
    res.json(detail);
  });

  router.delete('/targets/:id', (req, res) => {
    const ok = store.removeById(req.params.id);
    if (!ok) return res.status(404).json({ error: 'target not found' });
    res.json({ removed: true });
  });

  // --- scanning ---
  router.post('/targets/:id/scan', async (req, res) => {
    const body = req.body || {};
    try {
      const detail = await scanTarget(store, req.params.id, {
        cve: body.cve,
        pathMode: body.pathMode,
        concurrency: body.concurrency,
        timeoutMs: body.timeoutMs,
      });
      res.json(detail);
    } catch (err) {
      res.status(err.message === 'target not found' ? 404 : 500).json({
        error: String(err.message || err),
      });
    }
  });

  // Read a single ad-hoc path from a target.
  router.post('/targets/:id/read', async (req, res) => {
    const body = req.body || {};
    if (!body.path) return res.status(400).json({ error: 'path is required' });
    try {
      const file = await readSinglePath(store, req.params.id, body.path, {
        cve: body.cve,
        timeoutMs: body.timeoutMs,
      });
      res.json(file);
    } catch (err) {
      res.status(err.message === 'target not found' ? 404 : 500).json({
        error: String(err.message || err),
      });
    }
  });

  // --- retrieved file content & secrets ---
  router.get('/targets/:id/file', (req, res) => {
    const filePath = req.query.path;
    if (!filePath) return res.status(400).json({ error: 'path query is required' });
    const file = store.fileContent(req.params.id, String(filePath));
    if (!file) return res.status(404).json({ error: 'file not retrieved' });
    res.json(file);
  });

  router.get('/targets/:id/secrets', (req, res) => {
    const detail = store.detail(req.params.id);
    if (!detail) return res.status(404).json({ error: 'target not found' });
    res.json({ secrets: detail.secrets });
  });

  // Aggregated secrets across all targets, grouped by host.
  router.get('/secrets', (_req, res) => {
    const groups = store.list().map((t) => {
      const detail = store.detail(t.id);
      return {
        targetId: t.id,
        host: t.hostPort,
        url: t.url,
        secrets: detail ? detail.secrets : [],
      };
    });
    res.json({ groups: groups.filter((g) => g.secrets.length > 0) });
  });

  return router;
};
