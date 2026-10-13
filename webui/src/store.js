'use strict';

const crypto = require('crypto');
const { targetKey } = require('./scanner/targets');

/**
 * In-memory store of scan targets and their results. Not persistent — data
 * lives for the lifetime of the process. Each target holds:
 *   - descriptor    : host/ip/port/protocol/url
 *   - status        : idle | scanning | vulnerable | not_vulnerable | error
 *   - vuln          : { cve, platform, separator, rootPath, evidenceUrl }
 *   - files         : map of path -> { path, url, size, secretCount, content }
 *   - secrets       : flat list of findings (with file path attached)
 *   - tree          : nested directory tree derived from `files`
 */
class Store {
  constructor() {
    /** @type {Map<string, any>} */
    this.targets = new Map();
  }

  list() {
    return Array.from(this.targets.values()).map((t) => this.summary(t));
  }

  summary(t) {
    return {
      id: t.id,
      host: t.descriptor.host,
      hostPort: t.descriptor.hostPort,
      ip: t.descriptor.ip,
      port: t.descriptor.port,
      protocol: t.descriptor.protocol,
      url: t.descriptor.url,
      status: t.status,
      vuln: t.vuln || null,
      fileCount: Object.keys(t.files).length,
      secretCount: t.secrets.length,
      lastScannedAt: t.lastScannedAt,
      error: t.error || null,
    };
  }

  addTarget(descriptor) {
    const key = targetKey(descriptor);
    if (this.targets.has(key)) return this.targets.get(key);
    const target = {
      id: crypto.createHash('sha1').update(key).digest('hex').slice(0, 12),
      key,
      descriptor,
      status: 'idle',
      vuln: null,
      files: {},
      secrets: [],
      tree: emptyTree(),
      lastScannedAt: null,
      error: null,
    };
    this.targets.set(key, target);
    return target;
  }

  getById(id) {
    for (const t of this.targets.values()) {
      if (t.id === id) return t;
    }
    return null;
  }

  removeById(id) {
    for (const [key, t] of this.targets.entries()) {
      if (t.id === id) {
        this.targets.delete(key);
        return true;
      }
    }
    return false;
  }

  setStatus(target, status, error) {
    target.status = status;
    if (error !== undefined) target.error = error;
  }

  setVuln(target, vuln) {
    target.vuln = vuln;
  }

  /** Record a successfully read file and its secret findings. */
  addFile(target, file) {
    target.files[file.path] = {
      path: file.path,
      url: file.url,
      size: file.size,
      secretCount: (file.secrets || []).length,
      content: file.content,
    };
    for (const s of file.secrets || []) {
      target.secrets.push({ ...s, path: file.path });
    }
    target.tree = buildTree(Object.values(target.files));
  }

  detail(id) {
    const t = this.getById(id);
    if (!t) return null;
    return {
      ...this.summary(t),
      tree: t.tree,
      files: Object.values(t.files).map((f) => ({
        path: f.path,
        url: f.url,
        size: f.size,
        secretCount: f.secretCount,
      })),
      secrets: t.secrets,
    };
  }

  fileContent(id, filePath) {
    const t = this.getById(id);
    if (!t) return null;
    return t.files[filePath] || null;
  }
}

function emptyTree() {
  return { name: '/', type: 'dir', children: [] };
}

/**
 * Build a nested directory tree from a flat list of files. Handles both
 * project-relative (`.env`, `src/main.js`) and absolute (`/etc/passwd`) paths.
 */
function buildTree(files) {
  const root = emptyTree();
  const sorted = [...files].sort((a, b) => a.path.localeCompare(b.path));
  for (const file of sorted) {
    const parts = file.path.split('/').filter(Boolean);
    let node = root;
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      const isLeaf = i === parts.length - 1;
      if (isLeaf) {
        node.children.push({
          name: part,
          type: 'file',
          path: file.path,
          size: file.size,
          secretCount: file.secretCount,
        });
      } else {
        let dir = node.children.find(
          (c) => c.type === 'dir' && c.name === part
        );
        if (!dir) {
          dir = { name: part, type: 'dir', children: [] };
          node.children.push(dir);
        }
        node = dir;
      }
    }
  }
  return root;
}

module.exports = { Store, buildTree };
