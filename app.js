import { CHECKS, GROUPS } from './registry.js';
import { makeCtx, startRedirectRecorder } from './core.js';
import { buildPdf } from './report.js';

startRedirectRecorder();
const $ = (s) => document.querySelector(s);
const state = { ctx: null, active: CHECKS[0].id, status: {}, results: {}, progress: {}, runAllRunning: false };

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) el.append(k.nodeType ? k : document.createTextNode(String(k)));
  return el;
}
const safeHref = (u) => { try { const x = new URL(u); return /^https?:$/.test(x.protocol) ? x.href : null; } catch { return null; } };

// ---------- rendering of structured results ----------
function cell(v) {
  if (v == null || v === '') return h('span', { class: 'dim' }, '–');
  if (typeof v !== 'object') return document.createTextNode(String(v));
  const cls = ['cell', v.tone && 't-' + v.tone, v.mono && 'mono'].filter(Boolean).join(' ');
  const href = v.href && safeHref(v.href);
  return href ? h('a', { href, target: '_blank', rel: 'noopener noreferrer', class: cls }, v.t) : h('span', { class: cls }, v.t);
}
const plain = (v) => (v && typeof v === 'object' ? v.t : v == null ? '' : String(v)).toLowerCase();
function withFilter(box, rowsSelector) {
  const input = h('input', { class: 'mini', type: 'search', placeholder: 'Filter this list', 'aria-label': 'Filter this list' });
  input.addEventListener('input', () => { const q = input.value.toLowerCase(); box.querySelectorAll(rowsSelector).forEach((r) => { r.hidden = q && !r.textContent.toLowerCase().includes(q); }); });
  return input;
}
function section(s) {
  const wrap = h('div', { class: 'sec' });
  if (s.title) wrap.append(h('h3', null, s.title));
  if (s.kv) {
    const g = h('div', { class: 'kv' });
    s.kv.forEach(([k, v]) => g.append(h('div', { class: 'k' }, k), h('div', null, cell(v))));
    wrap.append(g);
  }
  if (s.table) {
    const t = h('table', null, h('thead', null, h('tr', null, s.table.head.map((x) => h('th', null, x)))),
      h('tbody', null, s.table.rows.map((r) => h('tr', null, r.map((c) => h('td', null, cell(c)))))));
    const box = h('div', { class: 'scroll' }, t);
    if (s.filter && s.table.rows.length > 8) wrap.append(withFilter(box, 'tbody tr'));
    wrap.append(box);
  }
  if (s.list) {
    const ul = h('ul', { class: 'list' }, s.list.map((x) => h('li', null, cell(x))));
    if (s.filter && s.list.length > 8) wrap.append(withFilter(ul, 'li'));
    if (s.list.length) wrap.append(ul);
  }
  if (s.text) wrap.append(h('p', null, s.text));
  if (s.pre) wrap.append(h('pre', null, s.pre));
  if (s.img) {
    const img = h('img', { class: 'shot', alt: 'Screenshot of the site', referrerpolicy: 'no-referrer' });
    let i = 0; img.addEventListener('error', () => { if (++i < s.img.length) img.src = s.img[i]; else img.alt = 'The screenshot service did not return an image.'; });
    img.src = s.img[0]; wrap.append(img);
  }
  if (s.note) wrap.append(h('p', { class: 'note' }, s.note));
  return wrap;
}

// ---------- panel ----------
const meta = (id) => CHECKS.find((c) => c.id === id);
function renderPanel() {
  const c = meta(state.active), st = state.status[c.id], panel = $('#panel');
  const head = [h('p', { class: 'crumb' }, c.group), h('h1', null, c.title), h('p', { class: 'lead' }, c.desc), h('p', { class: 'src' }, `Data source: ${c.src}`)];
  panel.replaceChildren(...head);
  if (!state.ctx) { panel.append(h('p', { class: 'empty' }, 'Open a website in a tab and click the extension icon, or type a URL above and press Load.')); return; }
  if (st === 'running') { panel.append(h('div', { class: 'spin' }, h('i'), h('span', null, state.progress[c.id] || 'Running…'))); return; }
  const r = state.results[c.id];
  if (!r) { panel.append(h('div', { class: 'actions' }, h('button', { class: 'btn', onclick: () => runCheck(c) }, 'Run check')), h('p', { class: 'empty' }, `This will check ${state.ctx.host}.`)); return; }
  panel.append(h('div', { class: 'actions' }, h('button', { class: 'btn', onclick: () => runCheck(c) }, 'Run again'), h('button', { class: 'btn ghost', onclick: (e) => copyJson(c, e.target) }, 'Copy result as JSON')));
  panel.append(h('div', { class: `banner ${r.tone}` }, r.summary));
  (r.sections || []).forEach((s) => s && panel.append(section(s)));
}
function select(id) { state.active = id; renderNav(); renderPanel(); $('#panel').scrollTop = 0; }
function renderNav() {
  const q = $('#filter').value.trim().toLowerCase();
  const ul = $('#navList'), keep = ul.scrollTop, out = [];
  for (const [name, ids] of GROUPS) {
    const items = ids.map(meta).filter((c) => !q || `${c.title} ${c.desc} ${name}`.toLowerCase().includes(q));
    if (!items.length) continue;
    const done = items.filter((c) => state.status[c.id] && state.status[c.id] !== 'running').length;
    out.push(h('li', { class: 'grp', role: 'presentation' }, h('span', null, name), h('small', null, done ? `${done}/${items.length}` : `${items.length}`)));
    items.forEach((c) => out.push(h('li', null, h('button', { class: 'item', 'data-id': c.id, 'aria-current': c.id === state.active ? 'true' : 'false', onclick: () => select(c.id) },
      h('span', { class: `dot ${state.status[c.id] || ''}` }), h('span', null, h('span', { class: 'nm' }, c.title), h('span', { class: 'ds' }, c.desc))))));
  }
  if (!out.length) out.push(h('li', { class: 'empty-nav' }, 'No check matches that search.'));
  ul.replaceChildren(...out); ul.scrollTop = keep;
}
$('#navList').addEventListener('keydown', (e) => {
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
  const items = [...document.querySelectorAll('.item')], i = items.indexOf(document.activeElement);
  if (i < 0) return;
  e.preventDefault();
  const next = items[Math.max(0, Math.min(items.length - 1, i + (e.key === 'ArrowDown' ? 1 : -1)))];
  select(next.dataset.id);
  document.querySelector(`.item[data-id="${next.dataset.id}"]`).focus();
});
function updateProgress() {
  const done = CHECKS.filter((c) => state.status[c.id] && state.status[c.id] !== 'running').length;
  $('#progress').textContent = done ? `${done} of ${CHECKS.length} checks done` : '';
}
async function copyJson(c, btn) {
  await navigator.clipboard.writeText(JSON.stringify({ check: c.title, target: state.ctx.url, result: state.results[c.id] }, null, 2));
  const t = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => (btn.textContent = t), 1200);
}

// ---------- running ----------
async function runCheck(c) {
  const ctx = state.ctx;
  if (!ctx || state.status[c.id] === 'running') return;
  state.status[c.id] = 'running'; delete state.results[c.id]; state.progress[c.id] = '';
  renderNav(); if (state.active === c.id) renderPanel();
  const say = (m) => { if (state.ctx !== ctx) return; state.progress[c.id] = m; if (state.active === c.id && state.status[c.id] === 'running') renderPanel(); };
  let out;
  try { out = await c.run(ctx, say); }
  catch (e) { out = { tone: 'error', summary: e?.message || String(e), sections: [{ note: 'This check could not complete. You can run it again.' }] }; }
  if (state.ctx !== ctx) return; // target changed while running
  state.results[c.id] = out; state.status[c.id] = out.tone;
  renderNav(); updateProgress(); if (state.active === c.id) renderPanel();
}
async function runQueue(list) {
  const queue = [...list];
  const worker = async () => { while (queue.length) await runCheck(queue.shift()); };
  await Promise.all([worker(), worker(), worker(), worker()]);
}
async function runAll() {
  if (!state.ctx || state.runAllRunning) return;
  state.runAllRunning = true; $('#runAll').disabled = true;
  await runQueue(CHECKS.filter((c) => state.status[c.id] !== 'running'));
  state.runAllRunning = false; $('#runAll').disabled = false;
}
async function downloadReport() {
  const ctx = state.ctx, btn = $('#download');
  if (!ctx || btn.disabled) return;
  btn.disabled = true; $('#runAll').disabled = true;
  const label = btn.textContent;
  try {
    btn.textContent = 'Preparing report…';
    await runQueue(CHECKS.filter((c) => !state.results[c.id] && state.status[c.id] !== 'running'));
    while (CHECKS.some((c) => state.status[c.id] === 'running')) await new Promise((r) => setTimeout(r, 200)); // wait for checks started elsewhere
    if (state.ctx !== ctx) return;
    const items = CHECKS.map((c) => ({ id: c.id, title: c.title, group: c.group, desc: c.desc, result: state.results[c.id] }));
    const doc = buildPdf({ jspdf: window.jspdf, target: ctx.url, when: new Date().toLocaleString(), items });
    doc.save(`site-check-${ctx.host}-${new Date().toISOString().slice(0, 10)}.pdf`);
  } catch (e) {
    alert(`Could not create the PDF: ${e.message || e}`);
  } finally {
    btn.textContent = label; btn.disabled = false; $('#runAll').disabled = state.runAllRunning;
  }
}

// ---------- target ----------
function setTarget(raw, tabId) {
  let u = raw.trim();
  if (!u) return;
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  try { state.ctx = makeCtx(u, tabId); } catch { $('#panel').replaceChildren(h('p', { class: 'empty' }, 'That does not look like a valid URL.')); return; }
  state.status = {}; state.results = {}; state.progress = {};
  $('#download').disabled = false;
  $('#url').value = state.ctx.url; document.title = `Site Checker: ${state.ctx.host}`;
  renderNav(); renderPanel(); updateProgress();
}
$('#target').addEventListener('submit', (e) => { e.preventDefault(); setTarget($('#url').value, null); });
$('#runAll').addEventListener('click', runAll);
$('#download').addEventListener('click', downloadReport);
$('#filter').addEventListener('input', renderNav);

const qp = new URLSearchParams(location.search);
if (qp.get('embed')) {
  const closeBtn = $('#close'); closeBtn.hidden = false;
  const close = () => parent.postMessage({ type: 'sitecheck-close' }, '*');
  closeBtn.addEventListener('click', close);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
}
renderNav(); renderPanel();
if (qp.get('url')) setTarget(qp.get('url'), qp.get('tab') ? Number(qp.get('tab')) : null);
