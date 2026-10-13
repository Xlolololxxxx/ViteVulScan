'use strict';

const path = require('path');
const express = require('express');
const { Store } = require('./src/store');
const apiRouter = require('./src/routes/api');

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';

function createApp() {
  const app = express();
  const store = new Store();

  app.use(express.json({ limit: '1mb' }));
  app.use('/api', apiRouter(store));
  app.use(express.static(path.join(__dirname, 'public')));

  app.get('/healthz', (_req, res) => res.json({ ok: true }));

  // JSON 404 for unknown API routes.
  app.use('/api', (_req, res) => res.status(404).json({ error: 'not found' }));

  return { app, store };
}

if (require.main === module) {
  const { app } = createApp();
  app.listen(PORT, HOST, () => {
    // eslint-disable-next-line no-console
    console.log(`ViteVulScan dashboard listening on http://${HOST}:${PORT}`);
    // eslint-disable-next-line no-console
    console.log('Reminder: only scan Vite servers you own or are authorized to test.');
  });
}

module.exports = { createApp };
