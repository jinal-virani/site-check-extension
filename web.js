import { fetchT, fetchText, fetchJSON } from './core.js';
import { T, M, L, res } from './res.js';
import { registrable, parseRobots, agentAccess, looksLikeHtml, parseKV, parseHsts, fmtDate, daysUntil } from './util.js';
import { detectTech, lookupThird, TRACKING_CATS } from './tech.js';

const textFile = async (ctx, path) => {
  const { r, text } = await fetchText(new URL(path, ctx.origin).href, {}, 15000).catch(() => ({ r: null, text: '' }));
  const ok = r && r.ok && !looksLikeHtml(text) && text.trim().length > 0;
  return { ok, text, url: new URL(path, ctx.origin).href, status: r?.status };
};
const abs = (href, base) => { try { return new URL(href, base); } catch { return null; } };

export const cookies = async (ctx) => {
  const list = await chrome.cookies.getAll({ domain: ctx.domain });
  if (!list.length) return res('info', 'Your browser holds no cookies for this site', [{ note: 'This reads your browser\'s cookie jar. Open the dashboard from a tab that already loaded the site to see its cookies.' }]);
  const weak = list.filter((c) => (ctx.https && !c.secure) || c.sameSite === 'unspecified' || c.sameSite === 'no_restriction' && !c.secure);
  const rows = list.map((c) => [M(c.name), M(c.domain), c.path, c.secure ? T('Yes', 'good') : T('No', ctx.https ? 'warn' : 'info'), c.httpOnly ? T('Yes', 'good') : T('No', 'info'), c.sameSite === 'unspecified' ? T('Not set', 'warn') : c.sameSite, c.session ? 'Session' : fmtDate(c.expirationDate * 1000)]);
  return res(weak.length ? 'warn' : 'good', `${list.length} cookie${list.length > 1 ? 's' : ''}${weak.length ? `, ${weak.length} with weak flags` : ', all well scoped'}`, [{ table: { head: ['Name', 'Domain', 'Path', 'Secure', 'HttpOnly', 'SameSite', 'Expires'], rows } }, { note: 'Cookie values are never shown.' }]);
};

const AI_BOTS = ['GPTBot', 'ChatGPT-User', 'ClaudeBot', 'anthropic-ai', 'Google-Extended', 'CCBot', 'PerplexityBot', 'Bytespider', 'Applebot-Extended', 'Amazonbot', 'FacebookBot'];
export const robots = async (ctx) => {
  const f = await textFile(ctx, '/robots.txt');
  if (!f.ok) return res('warn', 'No robots.txt found, so all crawlers are allowed by default', [{ note: `Checked ${f.url} (HTTP ${f.status ?? 'no response'}).` }]);
  const p = parseRobots(f.text);
  const aiRows = AI_BOTS.map((b) => { const a = agentAccess(p, b); return [M(b), a.state === 'blocked' ? T('Blocked', 'bad') : a.state === 'partial' ? T('Partly restricted', 'warn') : T('Allowed', 'good'), a.named ? 'Named in file' : 'Follows * rules']; });
  const star = agentAccess(p, '*');
  return res(star.state === 'blocked' ? 'warn' : 'info', `${p.groups.length} rule group${p.groups.length === 1 ? '' : 's'}, ${p.sitemaps.length} sitemap${p.sitemaps.length === 1 ? '' : 's'} declared`, [
    { title: 'Search and AI crawlers', table: { head: ['Crawler', 'Access', 'Basis'], rows: aiRows } },
    p.sitemaps.length && { title: 'Sitemaps declared', list: p.sitemaps.map((s) => M(s)) },
    { title: 'robots.txt', pre: f.text.slice(0, 4000) }].filter(Boolean));
};

export const headers = async (ctx) => {
  const p = await ctx.page();
  const rows = Object.entries(p.headers).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [M(k), M(v)]);
  return res('info', `${rows.length} response headers (HTTP ${p.status})`, [{ table: { head: ['Header', 'Value'], rows }, filter: true }]);
};

export const sitemap = async (ctx) => {
  const rb = await textFile(ctx, '/robots.txt');
  const up = (u) => (ctx.https && u.startsWith(`http://${ctx.host}`) ? 'https://' + u.slice(7) : u);
  const cands = [...new Set([...(rb.ok ? parseRobots(rb.text).sitemaps : []), new URL('/sitemap.xml', ctx.origin).href, new URL('/sitemap_index.xml', ctx.origin).href].map(up))];
  for (const u of cands) {
    const f = await textFile(ctx, u).catch(() => ({ ok: false }));
    if (f.ok && /<(urlset|sitemapindex)/i.test(f.text)) {
      const locs = [...f.text.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1]);
      const index = /<sitemapindex/i.test(f.text);
      return res('good', `${locs.length} ${index ? 'child sitemaps' : 'URLs'} listed`, [{ kv: [['Location', M(u)], ['Type', index ? 'Sitemap index' : 'URL set'], ['Entries', locs.length]] }, { title: index ? 'Child sitemaps' : 'URLs (first 200)', list: locs.slice(0, 200).map((l) => M(l)), filter: true }]);
    }
  }
  return res('warn', 'No sitemap found', [{ note: `Looked at: ${cands.join(', ')}` }]);
};

export const securityTxt = async (ctx) => {
  let f = await textFile(ctx, '/.well-known/security.txt');
  if (!f.ok || !/contact\s*:/i.test(f.text)) f = await textFile(ctx, '/security.txt');
  if (!f.ok || !/contact\s*:/i.test(f.text)) return res('warn', 'No security.txt published', [{ note: 'RFC 9116 asks sites to publish /.well-known/security.txt so researchers know whom to contact.' }]);
  const kv = parseKV(f.text), exp = kv.find(([k]) => /^expires$/i.test(k))?.[1], left = exp ? daysUntil(exp) : null;
  const tone = left != null && left < 0 ? 'warn' : 'good';
  return res(tone, left != null && left < 0 ? 'security.txt is present but expired' : 'security.txt is published', [{ kv: kv.map(([k, v]) => [k, /^https?:/.test(v) ? L(v, v) : M(v)]) }, exp && { note: `Expires ${fmtDate(exp)}${left != null ? ` (${left < 0 ? 'expired' : left + ' days left'})` : ''}.` }, { note: `Source: ${f.url}` }].filter(Boolean));
};

export const linked = async (ctx) => {
  const [doc, snap] = [await ctx.doc(), await ctx.snapshot()];
  const internal = new Map(), external = new Map(); let other = 0;
  doc.querySelectorAll('a[href]').forEach((a) => {
    const u = abs(a.getAttribute('href'), snap.url);
    if (!u || !/^https?:$/.test(u.protocol)) { other++; return; }
    u.hash = '';
    const m = registrable(u.hostname) === ctx.domain ? internal : external;
    if (!m.has(u.href)) m.set(u.href, (a.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 60));
  });
  const tbl = (m) => ({ head: ['Link text', 'URL'], rows: [...m].slice(0, 300).map(([u, t]) => [t || '–', L(u, u)]) });
  return res('info', `${internal.size} internal and ${external.size} external links`, [{ kv: [['Internal', internal.size], ['External', external.size], ['mailto / tel / script', other], ['Read from', snap.live ? 'the live page in your tab' : 'the HTML the server sent']] }, { title: 'Internal links', table: tbl(internal), filter: true }, { title: 'External links', table: tbl(external), filter: true }]);
};

export const socialTags = async (ctx) => {
  const doc = await ctx.doc();
  const metas = [...doc.querySelectorAll('meta')].map((m) => [m.getAttribute('property') || m.getAttribute('name'), m.getAttribute('content')]).filter(([k, v]) => k && v && /^(og:|twitter:|description$|theme-color$|robots$)/i.test(k));
  const title = doc.querySelector('title')?.textContent?.trim();
  const canon = doc.querySelector('link[rel="canonical"]')?.getAttribute('href');
  const og = metas.filter(([k]) => /^og:/i.test(k)), tw = metas.filter(([k]) => /^twitter:/i.test(k));
  const has = (k) => metas.some(([n]) => n.toLowerCase() === k);
  const missing = ['og:title', 'og:description', 'og:image', 'twitter:card'].filter((k) => !has(k));
  const img = metas.find(([k]) => k.toLowerCase() === 'og:image')?.[1];
  const imgUrl = img && abs(img, (await ctx.snapshot()).url)?.href;
  return res(missing.length ? 'warn' : 'good', missing.length ? `Missing: ${missing.join(', ')}` : 'Open Graph and Twitter tags are complete', [
    { kv: [['Title', title], ['Canonical', canon ? M(canon) : null]] },
    { title: `Open Graph (${og.length})`, table: { head: ['Tag', 'Value'], rows: og.map(([k, v]) => [M(k), v]) } },
    { title: `Twitter (${tw.length})`, table: { head: ['Tag', 'Value'], rows: tw.map(([k, v]) => [M(k), v]) } },
    imgUrl && { title: 'Share image preview', img: [imgUrl] }].filter(Boolean));
};

const SOCIAL = { 'facebook.com': 'Facebook', 'fb.com': 'Facebook', 'twitter.com': 'X / Twitter', 'x.com': 'X / Twitter', 'instagram.com': 'Instagram', 'linkedin.com': 'LinkedIn', 'youtube.com': 'YouTube', 'youtu.be': 'YouTube', 'github.com': 'GitHub', 'tiktok.com': 'TikTok', 'pinterest.com': 'Pinterest', 'threads.net': 'Threads', 't.me': 'Telegram', 'wa.me': 'WhatsApp', 'discord.gg': 'Discord', 'reddit.com': 'Reddit', 'medium.com': 'Medium', 'snapchat.com': 'Snapchat' };
export const socialPresence = async (ctx) => {
  const [doc, snap] = [await ctx.doc(), await ctx.snapshot()];
  const found = new Map();
  const add = (u, how) => { const x = abs(u, snap.url); if (!x) return; const n = SOCIAL[x.hostname.replace(/^(www|m)\./, '')]; if (n && x.pathname.length > 1 && !/\/(sharer|share|intent|dialog)/.test(x.pathname)) found.set(x.href, [n, how]); };
  doc.querySelectorAll('a[href]').forEach((a) => add(a.getAttribute('href'), 'Link on page'));
  doc.querySelectorAll('script[type="application/ld+json"]').forEach((s) => { try { const walk = (o) => { if (Array.isArray(o)) o.forEach(walk); else if (o && typeof o === 'object') { [].concat(o.sameAs || []).forEach((u) => add(u, 'Structured data (sameAs)')); Object.values(o).forEach(walk); } }; walk(JSON.parse(s.textContent)); } catch { /* ignore bad JSON-LD */ } });
  const site = doc.querySelector('meta[name="twitter:site"]')?.getAttribute('content');
  if (site) found.set(`https://x.com/${site.replace('@', '')}`, ['X / Twitter', 'twitter:site tag']);
  const rows = [...found].map(([u, [n, how]]) => [T(n, 'info'), L(u, u), how]);
  return res(rows.length ? 'good' : 'warn', rows.length ? `${rows.length} social profile link${rows.length > 1 ? 's' : ''} found` : 'No social profiles linked from the page', rows.length ? [{ table: { head: ['Platform', 'Profile', 'Found in'], rows } }, { note: 'Whether each profile links back to the site is not verified, because social networks block automated page reads.' }] : []);
};

const WAFS = [['Cloudflare', 'server', /cloudflare/i], ['Cloudflare', 'cf-ray', /./], ['Amazon CloudFront / AWS WAF', 'x-amz-cf-id', /./], ['AWS WAF', 'x-amzn-waf-action', /./], ['Akamai', 'server', /akamai/i], ['Akamai', 'x-akamai-transformed', /./], ['Imperva Incapsula', 'x-iinfo', /./], ['Imperva Incapsula', 'x-cdn', /incapsula|imperva/i], ['Sucuri', 'x-sucuri-id', /./], ['Sucuri', 'server', /sucuri/i], ['Fastly', 'x-fastly-request-id', /./], ['Azure Front Door', 'x-azure-ref', /./], ['Google Cloud Armor / GFE', 'via', /google/i], ['DDoS-Guard', 'server', /ddos-guard/i], ['F5 BIG-IP', 'server', /big-?ip/i], ['F5 BIG-IP', 'x-wa-info', /./], ['StackPath', 'x-sp-url', /./], ['ModSecurity', 'server', /mod_security|naxsi/i], ['Barracuda', 'server', /barracuda/i], ['Vercel Firewall', 'x-vercel-id', /./]];
export const firewall = async (ctx) => {
  const p = await ctx.page();
  const hits = new Map();
  WAFS.forEach(([n, k, re]) => { if (p.headers[k] != null && re.test(p.headers[k])) hits.set(n, `header ${k}`); });
  let probe;
  try { const r = await fetchT(`${ctx.origin}/?q=${encodeURIComponent('<script>alert(1)</script>')}&id=${encodeURIComponent("1' OR '1'='1")}`, {}, 12000); probe = r.status; } catch { probe = null; }
  const blocked = probe != null && [403, 406, 429, 501].includes(probe) && p.status < 400;
  const rows = [...hits].map(([n, w]) => [T(n, 'info'), w]);
  return res(hits.size || blocked ? 'good' : 'warn', hits.size ? `Detected: ${[...hits.keys()].join(', ')}` : blocked ? 'A firewall seems to block attack-like requests' : 'No web application firewall detected', [
    rows.length && { table: { head: ['Provider', 'Evidence'], rows } },
    { kv: [['Test request (XSS + SQLi pattern)', probe == null ? 'No response' : T(`HTTP ${probe}`, blocked ? 'good' : 'info')], ['Normal page', `HTTP ${p.status}`]] },
    { note: 'Detection uses response headers and one harmless test query. Some WAFs leave no visible trace.' }].filter(Boolean));
};

const SEC = [['strict-transport-security', 'HSTS', 'Forces HTTPS'], ['content-security-policy', 'Content-Security-Policy', 'Limits where scripts and content can load from'], ['x-frame-options', 'X-Frame-Options', 'Stops clickjacking (frame-ancestors in CSP also works)'], ['x-content-type-options', 'X-Content-Type-Options', 'Stops MIME sniffing (needs "nosniff")'], ['referrer-policy', 'Referrer-Policy', 'Controls what URL leaks to other sites'], ['permissions-policy', 'Permissions-Policy', 'Restricts camera, mic, geolocation etc.'], ['cross-origin-opener-policy', 'Cross-Origin-Opener-Policy', 'Isolates the window from popups'], ['cross-origin-resource-policy', 'Cross-Origin-Resource-Policy', 'Stops other sites embedding your resources']];
export const httpSecurity = async (ctx) => {
  const h = (await ctx.page()).headers;
  let score = 0;
  const rows = SEC.map(([k, n, why]) => {
    let v = h[k], tone = v ? 'good' : 'bad', note = why;
    if (k === 'content-security-policy' && v && /unsafe-(inline|eval)/.test(v)) { tone = 'warn'; note = 'Present but allows unsafe-inline or unsafe-eval'; }
    if (k === 'x-frame-options' && !v && /frame-ancestors/.test(h['content-security-policy'] || '')) { tone = 'good'; v = 'covered by CSP frame-ancestors'; }
    if (k === 'x-content-type-options' && v && !/nosniff/i.test(v)) { tone = 'warn'; }
    if (tone === 'good') score++; else if (tone === 'warn') score += 0.5;
    return [n, tone === 'bad' ? T('Missing', 'bad') : T(tone === 'warn' ? 'Weak' : 'Set', tone), v ? M(String(v).slice(0, 120)) : null, note];
  });
  return res(score >= 6 ? 'good' : score >= 4 ? 'warn' : 'bad', `${score} of ${SEC.length} protective headers in place`, [{ table: { head: ['Header', 'Status', 'Value', 'What it does'], rows } }]);
};

const ACTIVE = new Set(['script', 'link', 'iframe', 'object', 'embed']);
export const mixedSri = async (ctx) => {
  const [doc, snap] = [await ctx.doc(), await ctx.snapshot()];
  const mixed = [], noSri = [];
  doc.querySelectorAll('[src],[href],[action]').forEach((el) => {
    const tag = el.tagName.toLowerCase(), isLink = tag === 'a';
    const raw = el.getAttribute('src') || (tag === 'link' ? el.getAttribute('href') : tag === 'form' ? el.getAttribute('action') : null);
    if (!raw || isLink) return;
    const u = abs(raw, snap.url);
    if (!u) return;
    if (ctx.https && u.protocol === 'http:') mixed.push([T(ACTIVE.has(tag) ? 'Active (blocked)' : 'Passive', ACTIVE.has(tag) ? 'bad' : 'warn'), `<${tag}>`, M(u.href)]);
    const isScript = tag === 'script' && el.hasAttribute('src'), isCss = tag === 'link' && /stylesheet/i.test(el.getAttribute('rel') || '') && el.hasAttribute('href');
    if ((isScript || isCss) && u.hostname !== ctx.host && !el.hasAttribute('integrity')) noSri.push([`<${tag}>`, M(u.href)]);
  });
  (snap.resources || []).filter((r) => ctx.https && r.u.startsWith('http://') && !mixed.some((m) => m[2].t === r.u)).forEach((r) => mixed.push([T('Loaded at runtime', 'warn'), r.t, M(r.u)]));
  const tone = mixed.some((m) => m[0].tone === 'bad') ? 'bad' : mixed.length || noSri.length ? 'warn' : 'good';
  return res(tone, `${mixed.length} insecure resource${mixed.length === 1 ? '' : 's'}, ${noSri.length} third-party file${noSri.length === 1 ? '' : 's'} without SRI`, [
    { title: 'Mixed content', ...(mixed.length ? { table: { head: ['Type', 'Element', 'URL'], rows: mixed } } : { text: ctx.https ? 'None found.' : 'Page is not on HTTPS, so mixed content does not apply.' }) },
    { title: 'Third-party scripts and styles without integrity attribute', ...(noSri.length ? { table: { head: ['Element', 'URL'], rows: noSri } } : { text: 'None found.' }) },
    { note: 'Subresource Integrity (SRI) lets the browser reject a CDN file that was tampered with.' }]);
};

export const hsts = async (ctx) => {
  const p = await ctx.page();
  const v = p.headers['strict-transport-security'], h = parseHsts(v);
  const pre = await fetchJSON(`https://hstspreload.org/api/v2/status?domain=${ctx.domain}`, {}, 10000).then((j) => j.status).catch(() => 'unknown');
  if (!h) return res('bad', 'No HSTS header: browsers may still connect over plain HTTP first', [{ kv: [['Preload list', pre]] }]);
  const yr = h.maxAge >= 31536000;
  return res(yr && h.sub ? 'good' : 'warn', yr && h.sub ? 'HSTS is strongly configured' : 'HSTS is set but can be strengthened', [{ kv: [['Header', M(v)], ['max-age', T(`${h.maxAge} s (${Math.round(h.maxAge / 86400)} days)`, yr ? 'good' : 'warn')], ['includeSubDomains', h.sub ? T('Yes', 'good') : T('No', 'warn')], ['preload directive', h.preload ? T('Yes', 'good') : 'No'], ['In Chrome preload list', pre === 'preloaded' ? T('Yes', 'good') : pre]] }]);
};

export const techStack = async (ctx) => {
  const [p, snap] = [await ctx.page(), await ctx.snapshot()];
  const urls = [...new Set([...(snap.resources || []).map((r) => r.u), ...[...snap.html.matchAll(/(?:src|href)=["']([^"']+)["']/gi)].map((m) => m[1])])];
  const found = detectTech({ headers: p.headers, html: snap.html, urls, globals: snap.globals });
  return res('info', found.length ? `${found.length} technologies detected` : 'No known technologies recognised', [found.length && { table: { head: ['Technology', 'Category', 'Evidence'], rows: found.map((f) => [f.name, T(f.cat, 'info'), f.evidence]) } }, { note: snap.live ? 'Detected from the live page in your tab plus response headers.' : 'Detected from server HTML only. JavaScript-rendered sites show more when opened from a loaded tab.' }].filter(Boolean));
};

export const trackers = async (ctx) => {
  const snap = await ctx.snapshot();
  const urls = [...(snap.resources || []).map((r) => r.u), ...[...snap.html.matchAll(/(?:src)=["'](https?:\/\/[^"']+)["']/gi)].map((m) => m[1])];
  const by = new Map();
  for (const u of urls) {
    const x = abs(u, snap.url); if (!x || !/^https?:$/.test(x.protocol)) continue;
    const d = registrable(x.hostname); if (d === ctx.domain) continue;
    const hit = lookupThird(x.hostname);
    const e = by.get(d) || { n: hit?.[0] || d, c: hit?.[1] || 'Other', count: 0 };
    e.count++; by.set(d, e);
  }
  const list = [...by.entries()].sort((a, b) => b[1].count - a[1].count);
  const tr = list.filter(([, e]) => TRACKING_CATS.has(e.c));
  return res(tr.length > 5 ? 'bad' : tr.length ? 'warn' : 'good', `${list.length} third parties, ${tr.length} of them tracking or advertising`, [{ table: { head: ['Third party', 'Domain', 'Category', 'Requests'], rows: list.map(([d, e]) => [e.n, M(d), T(e.c, TRACKING_CATS.has(e.c) ? 'warn' : 'info'), e.count]) }, filter: true }, { note: snap.live ? 'Based on every request the live page made.' : 'Based on the HTML only. Scripts that load other scripts are missed. Open from a loaded tab for the full list.' }]);
};
