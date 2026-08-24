'use strict';

const http = require('http');

/**
 * A minimal mock that mimics a Vite dev server vulnerable to CVE-2025-30208
 * (`?import&raw??`). Serves a fake file system so the scanner can be tested
 * end-to-end without a real vulnerable target.
 */
function createMockViteServer(files = {}) {
  const defaults = {
    '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\n',
    '.env': 'API_KEY="AKIAIOSFODNN7EXAMPLE"\nDB=postgres://user:pass@localhost:5432/app\n',
    'package.json': '{\n  "name": "demo",\n  "version": "1.0.0"\n}\n',
  };
  const fsFiles = { ...defaults, ...files };

  const server = http.createServer((req, res) => {
    const url = req.url;

    // Index page with the Vite client marker.
    if (url === '/' || url === '') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html><body><script type="module" src="/@vite/client"></script></body></html>');
      return;
    }

    // Only honour the raw-bypass shape.
    if (url.includes('?import&raw??')) {
      const clean = decodeURIComponent(url.split('?')[0]).replace(/^\/@fs/, '');
      const key = clean.replace(/^\/+/, '');
      const content =
        fsFiles[clean] !== undefined
          ? fsFiles[clean]
          : fsFiles[key] !== undefined
          ? fsFiles[key]
          : fsFiles['/' + key];
      if (content !== undefined) {
        const escaped = content
          .replace(/\\/g, '\\\\')
          .replace(/"/g, '\\"')
          .replace(/\r/g, '\\r')
          .replace(/\n/g, '\\n')
          .replace(/\t/g, '\\t');
        res.writeHead(200, { 'content-type': 'application/javascript' });
        res.end(`export default "${escaped}"\n//# sourceMappingURL=x`);
        return;
      }
    }

    res.writeHead(404);
    res.end('not found');
  });

  return server;
}

module.exports = { createMockViteServer };
