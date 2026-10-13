# ViteVulScan Dashboard (`webui/`)

A web-based security auditing dashboard for evaluating **Vite dev-server
arbitrary file-read vulnerabilities**. It is a Node.js/Express reimplementation
of the CVE verification & exploitation logic in the root Go tool, wrapped in a
mobile-first dashboard so you can manage targets, trigger scans, browse the
retrieved file tree per host, and review flagged secrets.

> ⚠️ **Authorized testing only.** Use this against Vite servers you own or are
> explicitly permitted to audit. Unauthorized scanning may be illegal.

## Vulnerabilities covered

| CVE | Bypass shape | Reference concept |
| --- | --- | --- |
| CVE-2025-30208 | `?import&raw??` | CVE-2023-30208 (`?raw` bypass) |
| CVE-2025-31125 | `?import&?inline=1.wasm?init` (base64) | inline data-URI bypass |
| CVE-2025-31486 | `.../?/../../` traversal segment | CVE-2024-23331 (`/@fs` traversal) |

Each definition (payload builder + response detector + content decoder) lives in
[`src/scanner/payloads.js`](src/scanner/payloads.js). Both the empty separator
and the `/@fs` prefix are attempted, on Linux (`/etc/passwd`) and Windows
(`C://windows/win.ini`) probes.

## Features

- **Verification module** — fingerprints the Vite client, extracts the app
  base/root path, and confirms exploitability per CVE/platform.
- **Target & host management** — targets keyed by `protocol://host:port`; each
  keeps its own retrieved-file tree and secret list.
- **File trees** — retrieved files (relative and absolute) organised into a
  nested tree per host.
- **Inline secret scanning** — retrieved content is scanned in real time for
  API keys, tokens, credentials, private keys and connection strings; findings
  are redacted and grouped by host + file path
  ([`src/scanner/secretScanner.js`](src/scanner/secretScanner.js)).
- **Dashboard** — Express backend + dependency-free, mobile-first frontend
  (`public/`).

## Project structure

```
webui/
├── server.js                 # Express entrypoint (createApp + listen)
├── src/
│   ├── routes/api.js         # REST API (targets, scan, files, secrets)
│   ├── store.js              # in-memory target store + file-tree builder
│   ├── scanService.js        # orchestrates verify + bounded-concurrency reads
│   ├── dict.js               # sensitive-path list loader
│   └── scanner/
│       ├── payloads.js       # CVE payloads + detectors + decoders
│       ├── viteScanner.js    # fingerprint / verify / readFile
│       ├── httpClient.js     # fetch wrapper (timeout, UA)
│       ├── targets.js        # target normalisation
│       └── secretScanner.js  # secret regex rules + redaction
├── dict/                     # sensitive path lists + curated default targets
├── public/                   # index.html, styles.css, app.js (frontend)
└── test/                     # node:test unit + mock-server integration tests
```

## Getting started

```bash
cd webui
npm install
npm start            # http://127.0.0.1:3000  (override with PORT / HOST)
```

Then open the dashboard, add a target (e.g. `http://localhost:5173`), pick a CVE
and a path list, and click **Scan**.

```bash
npm test             # unit + integration tests (uses a mock vulnerable server)
npm run lint         # eslint
```

## REST API

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/cves` | supported CVEs |
| GET | `/api/secret-rules` | secret rule metadata |
| GET | `/api/paths?mode=&platform=` | resolve a probe path list |
| GET/POST | `/api/targets` | list / add targets |
| GET/DELETE | `/api/targets/:id` | target detail / remove |
| POST | `/api/targets/:id/scan` | verify + read the selected path list |
| POST | `/api/targets/:id/read` | read a single ad-hoc path |
| GET | `/api/targets/:id/file?path=` | retrieved file content |
| GET | `/api/targets/:id/secrets` | secrets for a target |
| GET | `/api/secrets` | secrets across all targets, grouped by host |

State is in-memory and lives for the process lifetime.
