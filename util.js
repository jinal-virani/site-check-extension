// Pure helpers (no browser APIs) so they can be unit-tested in Node.
const SLD = new Set(['co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','co.in','net.in','org.in','gov.in','ac.in','nic.in','res.in','co.jp','co.nz','co.za','com.br','com.cn','com.mx','com.tr','com.sg','com.hk','com.tw','com.ar','co.kr','co.id','com.my','com.pk','com.ng','com.eg','com.sa','com.ua','com.vn','com.ph']);

export function registrable(host) {
  host = String(host).toLowerCase().replace(/\.$/, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':')) return host;
  const p = host.split('.');
  if (p.length <= 2) return host;
  return SLD.has(p.slice(-2).join('.')) ? p.slice(-3).join('.') : p.slice(-2).join('.');
}
export const isIPv4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const fmtDate = (v) => { const d = new Date(v); return isNaN(d) ? String(v ?? '') : d.toISOString().slice(0, 10); };
export const daysUntil = (v) => { const d = new Date(v); return isNaN(d) ? null : Math.floor((d - Date.now()) / 864e5); };
export function fmtBytes(n) {
  if (n == null || isNaN(n)) return '–';
  const u = ['B', 'KB', 'MB', 'GB']; let i = 0;
  while (n >= 1024 && i < 3) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}
export const looksLikeHtml = (t) => /^\s*<(!doctype|html|head|body|script|meta)/i.test(t || '');

export function parseRobots(text) {
  const groups = [], sitemaps = [];
  let cur = null, lastAgent = false;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    const i = line.indexOf(':');
    if (i < 0) continue;
    const k = line.slice(0, i).trim().toLowerCase(), v = line.slice(i + 1).trim();
    if (k === 'user-agent') {
      if (!cur || !lastAgent) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(v); lastAgent = true; continue;
    }
    lastAgent = false;
    if (k === 'sitemap') sitemaps.push(v);
    else if (cur && ['disallow', 'allow', 'crawl-delay'].includes(k)) cur.rules.push({ type: k, path: v });
  }
  return { groups, sitemaps };
}
export function agentAccess(parsed, agent) {
  const a = agent.toLowerCase();
  let g = parsed.groups.find((x) => x.agents.some((n) => n.toLowerCase() === a)), named = true;
  if (!g) { g = parsed.groups.find((x) => x.agents.includes('*')); named = false; }
  if (!g) return { state: 'allowed', named: false };
  const blockAll = g.rules.some((r) => r.type === 'disallow' && r.path === '/');
  const allowAll = g.rules.some((r) => r.type === 'allow' && r.path === '/');
  const some = g.rules.some((r) => r.type === 'disallow' && r.path);
  if (blockAll && !allowAll) return { state: 'blocked', named };
  return { state: some ? 'partial' : 'allowed', named };
}

export const unquoteTxt = (d) => {
  const m = String(d).match(/"((?:[^"\\]|\\.)*)"/g);
  return m ? m.map((s) => s.slice(1, -1)).join('') : String(d);
};
export function decodeCaa(data) {
  let m = /^\\#\s+\d+\s+([0-9a-fA-F\s]+)$/.exec(data);
  if (m) {
    const b = m[1].trim().split(/\s+/).map((x) => parseInt(x, 16)), tl = b[1];
    const s = (a) => String.fromCharCode(...a);
    return { flags: b[0], tag: s(b.slice(2, 2 + tl)), value: s(b.slice(2 + tl)) };
  }
  m = /^(\d+)\s+(\w+)\s+"?(.*?)"?$/.exec(data);
  return m ? { flags: +m[1], tag: m[2], value: m[3] } : { flags: 0, tag: '?', value: String(data) };
}
export function analyzeSpf(rec) {
  const t = rec.trim().split(/\s+/).slice(1);
  const all = t.find((x) => /^[+\-~?]?all$/.test(x));
  const lookups = t.filter((x) => /^[+\-~?]?(include:|a(:|\/|$)|mx(:|\/|$)|ptr|exists:)|^redirect=/.test(x)).length;
  return { all, lookups };
}
export function parseHsts(v) {
  if (!v) return null;
  const age = /max-age=(\d+)/i.exec(v);
  return { maxAge: age ? +age[1] : 0, sub: /includeSubDomains/i.test(v), preload: /preload/i.test(v) };
}
export function parseKV(text) {
  const out = [];
  for (const l of String(text).split(/\r?\n/)) {
    if (!l.trim() || l.trim().startsWith('#')) continue;
    const i = l.indexOf(':');
    if (i > 0) out.push([l.slice(0, i).trim(), l.slice(i + 1).trim()]);
  }
  return out;
}
export const reverseV4 = (ip) => ip.split('.').reverse().join('.') + '.in-addr.arpa';
export const vcardGet = (ent, key) => {
  const arr = ent?.vcardArray?.[1] || [];
  const f = arr.find((x) => x[0] === key);
  const v = f?.[3];
  return Array.isArray(v) ? v.filter(Boolean).join(', ') : v || '';
};

// Remote pages are full of inline handlers (onclick="…"). They are inert inside DOMParser, but Chrome still
// checks them against the extension's CSP and logs "Executing inline event handler violates…". Remove them first.
const TAG = /<[a-zA-Z][^\s>/]*(?:"[^"]*"|'[^']*'|[^'">])*>/g;
const HANDLER = /[\s/]on[a-z]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi;
export const stripInlineHandlers = (html) => String(html).replace(TAG, (tag) => tag.replace(HANDLER, ' '));
