'use strict';

const api = {
  async get(url) {
    const r = await fetch(url);
    return r.json();
  },
  async send(method, url, body) {
    const r = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    return r.json();
  },
};

const state = { selectedId: null, targets: [], detail: null };

const $ = (sel) => document.querySelector(sel);

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.add('hidden'), 3000);
}

/* ---------------- init ---------------- */
async function init() {
  const { cves } = await api.get('/api/cves');
  const sel = $('#cveSelect');
  sel.innerHTML = cves
    .map((c) => `<option value="${c.id}">${c.label}</option>`)
    .join('');

  $('#addForm').addEventListener('submit', onAddTargets);
  $('#adhocRead').addEventListener('click', onAdhocRead);
  $('#menuToggle').addEventListener('click', togglePanel);

  document.querySelectorAll('.tab').forEach((tab) =>
    tab.addEventListener('click', () => switchTab(tab.dataset.tab))
  );

  await refreshTargets();
}

function togglePanel() {
  const panel = $('#panel');
  const open = panel.classList.toggle('open');
  $('#menuToggle').setAttribute('aria-expanded', String(open));
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t) =>
    t.classList.toggle('active', t.dataset.tab === name)
  );
  document.querySelectorAll('.tabpane').forEach((p) =>
    p.classList.toggle('active', p.id === `tab-${name}`)
  );
}

/* ---------------- targets ---------------- */
async function onAddTargets(e) {
  e.preventDefault();
  const raw = $('#targetInput').value.trim();
  if (!raw) return;
  const targets = raw.split(/\n+/).map((s) => s.trim()).filter(Boolean);
  const res = await api.send('POST', '/api/targets', { target: targets });
  $('#targetInput').value = '';
  if (res.errors && res.errors.length) {
    toast(`${res.added.length} added, ${res.errors.length} invalid`);
  } else {
    toast(`${res.added.length} target(s) added`);
  }
  await refreshTargets();
}

async function refreshTargets() {
  const { targets } = await api.get('/api/targets');
  state.targets = targets;
  $('#targetCount').textContent = targets.length;
  renderTargetList();
}

function renderTargetList() {
  const ul = $('#targetList');
  if (!state.targets.length) {
    ul.innerHTML = '<li class="empty-state">No targets yet.</li>';
    return;
  }
  ul.innerHTML = state.targets
    .map((t) => {
      const selected = t.id === state.selectedId ? ' selected' : '';
      return `
      <li class="target-item${selected}" data-id="${t.id}">
        <div class="target-row">
          <span class="host">${escapeHtml(t.hostPort)}</span>
          <span class="status ${t.status}">${statusLabel(t.status)}</span>
        </div>
        <div class="target-meta">
          <span>${t.protocol}</span>
          <span>files: ${t.fileCount}</span>
          <span>secrets: ${t.secretCount}</span>
        </div>
        <div class="target-actions">
          <button class="btn small" data-action="scan" data-id="${t.id}">Scan</button>
          <button class="btn small danger" data-action="remove" data-id="${t.id}">Remove</button>
        </div>
      </li>`;
    })
    .join('');

  ul.querySelectorAll('.target-item').forEach((el) => {
    el.addEventListener('click', (ev) => {
      if (ev.target.dataset.action) return;
      selectTarget(el.dataset.id);
    });
  });
  ul.querySelectorAll('[data-action="scan"]').forEach((b) =>
    b.addEventListener('click', () => scanTarget(b.dataset.id))
  );
  ul.querySelectorAll('[data-action="remove"]').forEach((b) =>
    b.addEventListener('click', () => removeTarget(b.dataset.id))
  );
}

function statusLabel(s) {
  return {
    idle: 'idle',
    scanning: 'scanning…',
    vulnerable: 'VULNERABLE',
    not_vulnerable: 'safe',
    error: 'error',
  }[s] || s;
}

async function removeTarget(id) {
  await api.send('DELETE', `/api/targets/${id}`);
  if (state.selectedId === id) {
    state.selectedId = null;
    state.detail = null;
    renderDetail();
  }
  await refreshTargets();
}

async function scanTarget(id) {
  const opts = {
    cve: $('#cveSelect').value,
    pathMode: $('#pathMode').value,
    concurrency: Number($('#concurrency').value) || 8,
  };
  // optimistic status
  const t = state.targets.find((x) => x.id === id);
  if (t) t.status = 'scanning';
  renderTargetList();
  toast('Scanning… this may take a moment');
  const detail = await api.send('POST', `/api/targets/${id}/scan`, opts);
  state.selectedId = id;
  state.detail = detail;
  await refreshTargets();
  renderDetail();
  if (detail.vuln) {
    switchTab('tree');
    toast(`Vulnerable — ${detail.fileCount} file(s), ${detail.secretCount} secret(s)`);
  } else {
    toast(detail.error ? `Error: ${detail.error}` : 'Not vulnerable');
  }
}

async function selectTarget(id) {
  state.selectedId = id;
  state.detail = await api.get(`/api/targets/${id}`);
  renderTargetList();
  renderDetail();
  if (window.matchMedia('(max-width: 820px)').matches) {
    $('#panel').classList.remove('open');
    $('#menuToggle').setAttribute('aria-expanded', 'false');
  }
}

/* ---------------- detail ---------------- */
function renderDetail() {
  const header = $('#detailHeader');
  const d = state.detail;
  if (!d) {
    header.className = 'detail-header empty';
    header.innerHTML = '<p>Select a target and run a scan.</p>';
    renderTree(null);
    renderSecrets([]);
    return;
  }
  header.className = 'detail-header';
  const vulnLine = d.vuln
    ? `<div class="vuln-line">
        <span class="status vulnerable">VULNERABLE</span>
        <span class="tag">${d.vuln.cve}</span>
        <span class="tag">platform: ${d.vuln.platform}</span>
        <span class="tag">sep: ${d.vuln.separator || '(none)'}</span>
        ${d.vuln.rootPath ? `<span class="tag">root: ${escapeHtml(d.vuln.rootPath)}</span>` : ''}
      </div>`
    : `<div class="vuln-line"><span class="status ${d.status}">${statusLabel(d.status)}</span>${d.error ? `<span class="tag">${escapeHtml(d.error)}</span>` : ''}</div>`;
  header.innerHTML = `
    <strong>${escapeHtml(d.url)}</strong>
    ${vulnLine}
    <div class="target-meta">
      <span>files: ${d.fileCount}</span>
      <span>secrets: ${d.secretCount}</span>
      ${d.lastScannedAt ? `<span>scanned: ${new Date(d.lastScannedAt).toLocaleTimeString()}</span>` : ''}
    </div>`;

  const badge = $('#secretBadge');
  badge.textContent = d.secretCount;
  badge.classList.toggle('hidden', !d.secretCount);

  renderTree(d.tree);
  renderSecrets(d.secrets || []);
}

function renderTree(tree) {
  const el = $('#tree');
  if (!tree || !tree.children.length) {
    el.innerHTML = '<div class="empty-state">No files retrieved yet.</div>';
    return;
  }
  el.innerHTML = `<ul>${tree.children.map(renderNode).join('')}</ul>`;
  el.querySelectorAll('.node.file').forEach((n) =>
    n.addEventListener('click', () => openFile(n.dataset.path))
  );
}

function renderNode(node) {
  if (node.type === 'dir') {
    return `<li>
      <div class="node dir"><span class="icon">▸</span><span class="fname">${escapeHtml(node.name)}/</span></div>
      <ul>${node.children.map(renderNode).join('')}</ul>
    </li>`;
  }
  const badge = node.secretCount
    ? `<span class="pill danger badge">${node.secretCount}🔑</span>`
    : `<span class="pill badge">${node.size}b</span>`;
  return `<li>
    <div class="node file" data-path="${escapeAttr(node.path)}">
      <span class="icon">📄</span><span class="fname">${escapeHtml(node.name)}</span>${badge}
    </div>
  </li>`;
}

async function openFile(path) {
  const d = state.detail;
  const res = await api.get(
    `/api/targets/${d.id}/file?path=${encodeURIComponent(path)}`
  );
  $('#viewerPath').textContent = path;
  $('#viewer').innerHTML = `<code>${escapeHtml(res.content || '(empty)')}</code>`;
  switchTab('viewer');
}

function renderSecrets(secrets) {
  const el = $('#secrets');
  if (!secrets.length) {
    el.innerHTML = '<div class="empty-state">No secrets flagged.</div>';
    return;
  }
  const byFile = {};
  for (const s of secrets) {
    (byFile[s.path] = byFile[s.path] || []).push(s);
  }
  el.innerHTML = Object.entries(byFile)
    .map(
      ([path, items]) => `
      <div class="secret-group">
        <h3>📄 ${escapeHtml(path)}</h3>
        ${items
          .map(
            (s) => `<div class="secret">
              <span class="sev ${s.severity}">${s.severity}</span>
              <span>${escapeHtml(s.name)}</span>
              <span class="mono">${escapeHtml(s.redacted)}</span>
              <span class="path">line ${s.line}</span>
            </div>`
          )
          .join('')}
      </div>`
    )
    .join('');
}

async function onAdhocRead() {
  if (!state.selectedId) return toast('Select a target first');
  const path = $('#adhocPath').value.trim();
  if (!path) return;
  const res = await api.send('POST', `/api/targets/${state.selectedId}/read`, {
    path,
    cve: $('#cveSelect').value,
  });
  if (!res.ok) return toast(`Failed: ${res.error}`);
  $('#adhocPath').value = '';
  state.detail = await api.get(`/api/targets/${state.selectedId}`);
  await refreshTargets();
  renderDetail();
  openFile(res.path);
}

/* ---------------- utils ---------------- */
function escapeHtml(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
function escapeAttr(str) {
  return escapeHtml(str).replace(/"/g, '&quot;');
}

init();
