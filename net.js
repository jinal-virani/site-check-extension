import { fetchJSON, fetchT, fetchText, probeRedirects } from './core.js';
import { T, M, L, res } from './res.js';
import { fmtDate, daysUntil, fmtBytes, looksLikeHtml } from './util.js';

const PORT_NAMES = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP submission', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 2082: 'cPanel', 2083: 'cPanel SSL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8000: 'HTTP alt', 8080: 'HTTP proxy', 8443: 'HTTPS alt', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB' };
const RISKY = new Set([21, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017]);

// ---- certificate transparency (crt.sh, with certspotter fallback) ---------
async function ct(q, wildcard) {
  const key = `ct:${q}`;
  const run = async () => {
    try {
      const rows = await fetchJSON(`https://crt.sh/?q=${wildcard ? '%25.' : ''}${encodeURIComponent(q)}&output=json`, {}, 40000);
      return rows.map((r) => ({ issuer: r.issuer_name, from: r.not_before, to: r.not_after, serial: r.serial_number, names: String(r.name_value).split('\n') }));
    } catch (e1) {
      const rows = await fetchJSON(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(q)}&include_subdomains=${wildcard}&expand=dns_names&expand=issuer`, {}, 30000)
        .catch((e2) => { throw new Error(`crt.sh failed (${e1.message}) and so did Certspotter (${e2.message}).`); });
      return rows.map((r) => ({ issuer: r.issuer?.name || r.issuer?.friendly_name || '', from: r.not_before, to: r.not_after, serial: r.tbs_sha256?.slice(0, 16), names: r.dns_names || [] }));
    }
  };
  return { key, run };
}
const ctGet = async (ctx, q, wildcard) => {
  const { key, run } = await ct(q, wildcard);
  if (!ctx.memo[key]) { const p = run(); ctx.memo[key] = p; p.catch(() => delete ctx.memo[key]); }
  return ctx.memo[key];
};
const issuerName = (s) => (/O=([^,]+)/.exec(s || '')?.[1] || /CN=([^,]+)/.exec(s || '')?.[1] || s || '–').replace(/^"|"$/g, '');

export const ssl = async (ctx) => {
  if (!ctx.https) return res('bad', 'This page is served over plain HTTP, so there is no certificate', []);
  const [rows, conn] = await Promise.all([
    ctGet(ctx, ctx.host, false),
    fetchT(`https://${ctx.host}/`, { method: 'HEAD' }, 12000).then(() => true).catch(() => false),
  ]);
  const wildcard = '*.' + ctx.host.split('.').slice(1).join('.');
  const mine = rows.filter((r) => r.names.some((n) => n.toLowerCase() === ctx.host || n.toLowerCase() === wildcard));
  const seen = new Set(), uniq = [];
  for (const r of mine.sort((a, b) => new Date(b.from) - new Date(a.from))) { if (!seen.has(r.serial)) { seen.add(r.serial); uniq.push(r); } }
  const live = uniq.find((r) => daysUntil(r.to) >= 0);
  const left = live ? daysUntil(live.to) : null;
  const tone = !conn ? 'bad' : !live ? 'warn' : left < 14 ? 'warn' : 'good';
  const summary = !conn ? 'Chrome could not complete an HTTPS connection (certificate or network problem)'
    : live ? `Valid certificate from ${issuerName(live.issuer)}, expires in ${left} days` : 'Connected over HTTPS, but no unexpired certificate appears in public CT logs';
  return res(tone, summary, [
    { kv: [['HTTPS connection (trusted by Chrome)', conn ? T('Yes', 'good') : T('Failed', 'bad')], ['Issuer', live ? issuerName(live.issuer) : '–'], ['Valid from', live ? fmtDate(live.from) : '–'], ['Valid until', live ? T(fmtDate(live.to), left < 14 ? 'warn' : 'good') : '–'], ['Names covered', live ? [...new Set(live.names)].slice(0, 8).join(', ') : '–']] },
    { title: 'Recent certificates for this host', table: { head: ['Issued', 'Expires', 'Issuer', 'Serial'], rows: uniq.slice(0, 8).map((r) => [fmtDate(r.from), fmtDate(r.to), issuerName(r.issuer), M(String(r.serial).slice(0, 14))]) } },
    { note: 'Certificate data comes from public Certificate Transparency logs. Chrome extensions cannot read the live certificate directly. Run "TLS Security Audit" for the full chain.' }]);
};

export const subdomains = async (ctx) => {
  const rows = await ctGet(ctx, ctx.domain, true);
  const set = new Set();
  rows.forEach((r) => r.names.forEach((n) => { n = n.trim().toLowerCase().replace(/^\*\./, ''); if (n.endsWith(ctx.domain) && !n.includes(' ')) set.add(n); }));
  const list = [...set].sort();
  return res('info', `${list.length} hostname${list.length === 1 ? '' : 's'} seen in certificate logs`, [{ list: list.slice(0, 600).map((x) => M(x)), filter: true }, { note: list.length > 600 ? `Showing the first 600 of ${list.length}.` : 'Only names that appeared on public certificates are listed.' }]);
};

// ---- SSL Labs powered ------------------------------------------------------
const SSLFAIL = (ctx, e) => new Error(`${e.message}. SSL Labs may be rate limiting or its v3 API may be unavailable. Full report: https://www.ssllabs.com/ssltest/analyze.html?d=${ctx.host}`);
const sslScan = async (ctx, say) => { try { return await ctx.ssllabs(say); } catch (e) { throw SSLFAIL(ctx, e); } };
const gradeTone = (g) => (/^A/.test(g) ? 'good' : /^[BC]/.test(g) ? 'warn' : 'bad');
const PROTO = { 769: 'TLS 1.0', 770: 'TLS 1.1', 771: 'TLS 1.2', 772: 'TLS 1.3', 768: 'SSL 3.0', 512: 'SSL 2.0' };
const suitesOf = (d) => (Array.isArray(d.suites) ? d.suites : d.suites?.list ? [d.suites] : []);

export const tlsAudit = async (ctx, say) => {
  const r = await sslScan(ctx, say);
  const eps = r.endpoints || [], d = eps.find((e) => e.details)?.details || {};
  const worst = eps.map((e) => e.grade).filter(Boolean).sort().pop() || '?';
  const certMap = Object.fromEntries((r.certs || []).map((c) => [c.id, c]));
  const chain = (d.certChains?.[0]?.certIds || []).map((id) => certMap[id]).filter(Boolean);
  const vulns = [['Heartbleed', d.heartbleed], ['POODLE (SSL 3)', d.poodle], ['FREAK', d.freak], ['Logjam', d.logjam], ['DROWN', d.drownVulnerable], ['BEAST', d.vulnBeast], ['RC4 supported', d.supportsRc4]];
  return res(gradeTone(worst), `SSL Labs grade: ${worst}`, [
    { title: 'Grade per endpoint', table: { head: ['IP address', 'Grade', 'Warnings'], rows: eps.map((e) => [M(e.ipAddress), T(e.grade || e.statusMessage, gradeTone(e.grade || 'F')), e.hasWarnings ? T('Yes', 'warn') : 'No']) } },
    { title: 'Known weaknesses', table: { head: ['Test', 'Result'], rows: vulns.map(([n, v]) => [n, v ? T('Vulnerable', 'bad') : T('Not affected', 'good')]) } },
    { title: 'Certificate chain', table: { head: ['Subject', 'Issuer', 'Expires', 'Key'], rows: chain.map((c) => [c.subject?.replace(/^CN=/, '').slice(0, 60), issuerName(c.issuerSubject), fmtDate(c.notAfter), `${c.keyAlg} ${c.keySize}`]) } },
    { note: `Scan by Qualys SSL Labs. Full report: https://www.ssllabs.com/ssltest/analyze.html?d=${ctx.host}` }]);
};

export const tlsConn = async (ctx, say) => {
  const r = await sslScan(ctx, say);
  const d = r.endpoints?.find((e) => e.details)?.details || {};
  const protos = (d.protocols || []).map((p) => `${p.name} ${p.version}`);
  const old = protos.some((p) => /SSL|TLS 1\.[01]$/.test(p));
  const names = new Set(), rows = [];
  suitesOf(d).forEach((s) => (s.list || []).forEach((c) => { if (!names.has(c.name)) { names.add(c.name); rows.push([PROTO[s.protocol] || s.protocol, M(c.name), c.cipherStrength + ' bit']); } }));
  const fs = d.forwardSecrecy;
  return res(old ? 'warn' : 'good', old ? 'Accepts outdated protocol versions' : `Accepts ${protos.join(', ') || 'modern TLS only'}`, [
    { kv: [['Protocols accepted', protos.join(', ') || '–'], ['Forward secrecy', fs >= 4 ? T('Robust', 'good') : fs ? T('Partial', 'warn') : T('No', 'bad')], ['ALPN / HTTP/2', d.supportsAlpn ? T(`Yes ${(d.alpnProtocols || '').toString()}`, 'good') : 'No'], ['OCSP stapling', d.ocspStapling ? T('Yes', 'good') : 'No'], ['Session tickets', d.sessionTickets ? 'Supported' : 'No']] },
    { title: 'Cipher suites offered', table: { head: ['Protocol', 'Suite', 'Strength'], rows: rows.slice(0, 40) } }]);
};

export const tlsClients = async (ctx, say) => {
  const r = await sslScan(ctx, say);
  const d = r.endpoints?.find((e) => e.details)?.details || {};
  const sims = d.sims?.results || [];
  if (!sims.length) throw new Error('SSL Labs returned no client simulation data for this host.');
  const sn = {}; suitesOf(d).forEach((s) => (s.list || []).forEach((c) => { sn[c.id] = c.name; }));
  const fails = sims.filter((x) => x.errorCode !== 0);
  return res(fails.length ? 'warn' : 'good', fails.length ? `${fails.length} of ${sims.length} simulated clients cannot connect` : `All ${sims.length} simulated clients can connect`, [
    { table: { head: ['Client', 'Result', 'Protocol', 'Cipher suite'], rows: sims.map((x) => [`${x.client.name} ${x.client.version}${x.client.platform ? ' / ' + x.client.platform : ''}`, x.errorCode === 0 ? T('Works', 'good') : T('Fails', 'bad'), PROTO[x.protocolId] || '–', M(sn[x.suiteId] || '–')]) }, filter: true }]);
};

// ---- IP based ----------------------------------------------------------------
export const location = async (ctx) => {
  const g = await ctx.geo();
  return res('info', `Hosted in ${[g.city, g.country].filter(Boolean).join(', ')}`, [{ kv: [['IP', M(g.ip)], ['Country', `${g.flag?.emoji || ''} ${g.country}`.trim()], ['Region', g.region], ['City', g.city], ['Coordinates', M(`${g.latitude}, ${g.longitude}`)], ['Time zone', g.timezone?.id], ['Map', L('Open in OpenStreetMap', `https://www.openstreetmap.org/?mlat=${g.latitude}&mlon=${g.longitude}#map=8/${g.latitude}/${g.longitude}`)]] }, { note: 'For sites behind a CDN this is the CDN edge nearest to you, not the origin server.' }]);
};

export const associated = async (ctx) => {
  const s = await ctx.shodan();
  return res('info', s.hostnames?.length ? `${s.hostnames.length} hostnames share this IP` : 'Shodan has no hostnames recorded for this IP', [{ list: (s.hostnames || []).map((h) => M(h)), filter: true }, { note: `Source: Shodan InternetDB for ${s.ip || 'this IP'}.` }]);
};
export const ports = async (ctx) => {
  const s = await ctx.shodan();
  if (!s.ports?.length) return res('info', 'Shodan has seen no open ports on this IP', [{ note: 'This is Shodan\'s passive scan data, not a live scan. A CDN in front hides the origin.' }]);
  const risky = s.ports.filter((p) => RISKY.has(p));
  return res(risky.length ? 'warn' : 'good', risky.length ? `Risky ports exposed: ${risky.join(', ')}` : `${s.ports.length} common port${s.ports.length > 1 ? 's' : ''} open`, [{ table: { head: ['Port', 'Service', 'Note'], rows: s.ports.map((p) => [M(p), PORT_NAMES[p] || '–', RISKY.has(p) ? T('Should not be public', 'warn') : '']) } }, { note: 'Passive data from Shodan InternetDB, not a live port scan.' }]);
};
export const vulns = async (ctx) => {
  const s = await ctx.shodan();
  const v = s.vulns || [];
  return res(v.length ? 'bad' : 'good', v.length ? `${v.length} CVE${v.length > 1 ? 's' : ''} linked to services on this IP` : 'No CVEs linked to this IP by Shodan', [v.length && { table: { head: ['CVE', 'Details'], rows: v.map((c) => [M(c), L('View on NVD', `https://nvd.nist.gov/vuln/detail/${c}`)]) } }, s.cpes?.length && { title: 'Detected software', list: s.cpes.map((c) => M(c)) }, { note: 'Shodan matches version banners to CVEs, so entries can be false positives.' }].filter(Boolean));
};
export const traceroute = async (ctx, say) => {
  say('Running MTR from HackerTarget. This takes up to 40 seconds…');
  const { r, text } = await fetchText(`https://api.hackertarget.com/mtr/?q=${encodeURIComponent(ctx.host)}`, {}, 60000);
  if (!r.ok || /error|API count exceeded|invalid/i.test(text.slice(0, 120))) throw new Error(text.slice(0, 150) || `HTTP ${r.status}`);
  return res('info', 'Route traced from HackerTarget\'s server to the site', [{ pre: text.trim() }, { note: 'Browsers cannot send traceroute packets, so a public API traces from its own server. Free quota is about 50 per day.' }]);
};

// ---- HTTP level --------------------------------------------------------------
export const status = async (ctx) => {
  const t = [];
  let last;
  for (let i = 0; i < 3; i++) {
    const t0 = performance.now();
    try { last = await fetchT(ctx.url, { redirect: 'follow' }, 15000); await last.arrayBuffer(); t.push(performance.now() - t0); }
    catch (e) { if (!t.length) return res('bad', `Site did not respond: ${e.message}`, []); break; }
  }
  const avg = Math.round(t.reduce((a, b) => a + b, 0) / t.length), ok = last.status < 400;
  return res(!ok ? 'bad' : avg > 1500 ? 'warn' : 'good', ok ? `Site is up (HTTP ${last.status}), ${avg} ms average` : `Site responded with HTTP ${last.status}`, [{ kv: [['Status', T(`${last.status} ${last.statusText}`, ok ? 'good' : 'bad')], ['Response times', t.map((x) => Math.round(x) + ' ms').join(' · ')], ['Fastest', Math.round(Math.min(...t)) + ' ms'], ['Final URL', M(last.url)]] }, { note: 'Measured from your browser, so it includes your own network distance to the server.' }]);
};

export const serverInfo = async (ctx) => {
  const [p, g] = await Promise.all([ctx.page(), ctx.geo().catch(() => null)]);
  const h = p.headers, srv = h.server || '';
  const os = /ubuntu/i.test(srv) ? 'Ubuntu' : /debian/i.test(srv) ? 'Debian' : /centos/i.test(srv) ? 'CentOS' : /win(32|64)|iis/i.test(srv) ? 'Windows' : /unix/i.test(srv) ? 'Unix' : null;
  return res('info', srv ? `Server software: ${srv}` : 'Server software is hidden', [{ kv: [['Server header', srv ? M(srv) : 'Hidden'], ['X-Powered-By', h['x-powered-by'] ? M(h['x-powered-by']) : 'Hidden'], ['Operating system', os || 'Not disclosed'], ['IP address', g ? M(g.ip) : null], ['ASN', g ? `AS${g.connection?.asn}` : null], ['Organisation', g?.connection?.org], ['ISP', g?.connection?.isp], ['Via', h.via || null]] }, { note: 'The OS can only be inferred when the server announces it in its headers.' }]);
};

export const redirects = async (ctx) => {
  let start = ctx.https ? `http://${ctx.host}/` : ctx.url, httpOnlyFail = false, p;
  try { p = await probeRedirects(start); }
  catch (e) {
    if (!ctx.https) throw e;
    httpOnlyFail = true; start = ctx.url; p = await probeRedirects(start);
  }
  const rows = p.chain.map((e, i) => [i + 1, T(e.status, e.status === 301 || e.status === 308 ? 'good' : 'warn'), M(e.url), M(e.to)]);
  rows.push([rows.length + 1, T(p.status, p.ok ? 'good' : 'bad'), M(p.url), 'Final page']);
  const upgraded = start.startsWith('http:') && p.url.startsWith('https:');
  const n = p.chain.length;
  return res(httpOnlyFail ? 'good' : n > 3 ? 'warn' : 'good',
    httpOnlyFail ? 'Port 80 is not reachable: the site is HTTPS only' : n ? `${n} redirect${n > 1 ? 's' : ''} before the final page${upgraded ? ', upgrades to HTTPS' : ''}` : 'No redirects. The page loads directly',
    [{ table: { head: ['#', 'Status', 'From', 'To'], rows } }, { note: `Started from ${start}. Chrome may show an internal 307 when the site is on its HSTS list.` }]);
};

export const quality = async (ctx, say) => {
  say('Running Lighthouse through Google PageSpeed Insights. This takes 20 to 60 seconds…');
  const cats = ['PERFORMANCE', 'ACCESSIBILITY', 'SEO', 'BEST_PRACTICES'].map((c) => `category=${c}`).join('&');
  let j;
  try { j = await fetchJSON(`https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(ctx.url)}&strategy=mobile&${cats}`, {}, 120000); }
  catch (e) { throw new Error(e.status === 429 ? 'Google PageSpeed quota reached for keyless requests. Try again in a minute.' : `PageSpeed Insights failed: ${e.message}`); }
  const c = j.lighthouseResult.categories, a = j.lighthouseResult.audits;
  const sc = (x) => Math.round((x?.score ?? 0) * 100), tone = (n) => (n >= 90 ? 'good' : n >= 50 ? 'warn' : 'bad');
  const rows = Object.values(c).map((x) => [x.title, T(sc(x), tone(sc(x)))]);
  const met = ['first-contentful-paint', 'largest-contentful-paint', 'total-blocking-time', 'cumulative-layout-shift', 'speed-index'].map((k) => [a[k]?.title, a[k]?.displayValue]);
  const min = Math.min(...Object.values(c).map(sc));
  return res(tone(min), `Performance ${sc(c.performance)} · Accessibility ${sc(c.accessibility)} · SEO ${sc(c.seo)} · Best practice ${sc(c['best-practices'])}`, [{ title: 'Lighthouse scores (mobile)', table: { head: ['Category', 'Score / 100'], rows } }, { title: 'Key metrics', kv: met }]);
};

export const carbon = async (ctx) => {
  const snap = await ctx.snapshot();
  let bytes = (snap.resources || []).reduce((a, r) => a + (r.s || r.e || 0), 0) + (snap.nav?.s || 0), src = 'measured from the live tab';
  if (!bytes) { bytes = (await ctx.page()).bytes; src = 'HTML only (open the dashboard from a loaded tab for full page weight)'; }
  const gb = bytes / 1073741824, kwh = gb * 0.81, g = kwh * 442;
  const rows = [['Page weight', `${fmtBytes(bytes)} (${src})`], ['Energy per view', `${(kwh * 1000).toFixed(3)} Wh`], ['CO2 per view', `${g.toFixed(2)} g`], ['Per 10,000 views', `${(g * 10).toFixed(1)} kg CO2`]];
  return res(g < 0.3 ? 'good' : g < 1 ? 'warn' : 'bad', `About ${g.toFixed(2)} g of CO2 per page view`, [{ kv: rows }, { note: 'Estimated with the Sustainable Web Design model (0.81 kWh per GB, global grid average of 442 g/kWh). Cached assets and green hosting lower the real figure.' }]);
};

export const screenshot = async (ctx) => res('info', 'Rendered by an external screenshot service', [{ img: [`https://image.thum.io/get/width/1200/crop/900/noanimate/${ctx.url}`, `https://s0.wp.com/mshots/v1/${encodeURIComponent(ctx.url)}?w=1200&h=900`] }, { note: 'The URL is sent to thum.io (fallback: WordPress mShots) to take the picture.' }]);

export const archive = async (ctx, say) => {
  say('Querying the Wayback Machine…');
  const rows = await fetchJSON(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(ctx.host)}&output=json&fl=timestamp,statuscode&collapse=timestamp:6&limit=3000`, {}, 60000);
  const data = rows.slice(1);
  if (!data.length) return res('info', 'The Wayback Machine has no snapshots of this site', []);
  const by = {}; data.forEach(([t]) => { by[t.slice(0, 4)] = (by[t.slice(0, 4)] || 0) + 1; });
  const ts = (t) => `${t.slice(0, 4)}-${t.slice(4, 6)}-${t.slice(6, 8)}`;
  const first = data[0][0], last = data[data.length - 1][0];
  return res('info', `Archived since ${first.slice(0, 4)} (${data.length} months with snapshots)`, [
    { kv: [['First snapshot', L(ts(first), `https://web.archive.org/web/${first}/${ctx.url}`)], ['Latest snapshot', L(ts(last), `https://web.archive.org/web/${last}/${ctx.url}`)], ['Months captured', data.length]] },
    { title: 'Months with a snapshot, per year', table: { head: ['Year', 'Months'], rows: Object.entries(by).reverse() } }]);
};
