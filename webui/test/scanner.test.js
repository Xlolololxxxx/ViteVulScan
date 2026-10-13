'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { scanContent } = require('../src/scanner/secretScanner');
const { normalizeTarget } = require('../src/scanner/targets');
const { resolveCve, listCves } = require('../src/scanner/payloads');
const { buildTree } = require('../src/store');
const viteScanner = require('../src/scanner/viteScanner');
const { createMockViteServer } = require('./mockViteServer');

test('secretScanner flags common secret shapes', () => {
  const content = [
    'AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE',
    'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    'GITHUB=ghp_1234567890abcdefghijklmnopqrstuvwx',
    'db=postgres://user:secret@localhost:5432/app',
    '-----BEGIN RSA PRIVATE KEY-----',
    'password: "hunter2secret"',
  ].join('\n');
  const findings = scanContent(content);
  const ids = findings.map((f) => f.ruleId);
  assert.ok(ids.includes('aws-access-key-id'));
  assert.ok(ids.includes('github-token'));
  assert.ok(ids.includes('db-connection-string'));
  assert.ok(ids.includes('private-key'));
  for (const f of findings) {
    assert.ok(!f.redacted.includes('AKIAIOSFODNN7EXAMPLE'));
  }
});

test('normalizeTarget handles host, host:port and full url', () => {
  assert.strictEqual(normalizeTarget('localhost:5173').target.port, '5173');
  assert.strictEqual(normalizeTarget('http://127.0.0.1').target.protocol, 'http');
  assert.strictEqual(normalizeTarget('https://example.com').target.port, '443');
  assert.strictEqual(normalizeTarget('').ok, false);
});

test('resolveCve accepts aliases', () => {
  assert.strictEqual(resolveCve('cve-2023-30208').id, 'cve-2025-30208');
  assert.strictEqual(resolveCve('cve-2024-23331').id, 'cve-2025-31486');
  assert.strictEqual(resolveCve('31125').id, 'cve-2025-31125');
  assert.strictEqual(resolveCve('nope'), null);
  assert.ok(listCves().length >= 3);
});

test('buildTree nests absolute and relative paths', () => {
  const tree = buildTree([
    { path: '/etc/passwd', size: 10, secretCount: 0 },
    { path: '.env', size: 20, secretCount: 2 },
    { path: 'src/main.js', size: 5, secretCount: 0 },
  ]);
  const names = tree.children.map((c) => c.name);
  assert.ok(names.includes('etc'));
  assert.ok(names.includes('.env'));
  assert.ok(names.includes('src'));
});

test('viteScanner verifies and reads from a mock vulnerable server', async () => {
  const server = createMockViteServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  const descriptor = {
    host: '127.0.0.1',
    hostPort: `127.0.0.1:${port}`,
    port: String(port),
    protocol: 'http',
    url: `http://127.0.0.1:${port}`,
  };
  try {
    const result = await viteScanner.verify(descriptor, 'cve-2025-30208');
    assert.strictEqual(result.vulnerable, true);
    assert.strictEqual(result.platform, 'linux');

    const file = await viteScanner.readFile(descriptor, 'cve-2025-30208', '.env', result);
    assert.strictEqual(file.ok, true);
    assert.match(file.content, /API_KEY/);
    assert.ok(file.secrets.length > 0);
  } finally {
    server.close();
  }
});
