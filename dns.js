import { doh, answers, fetchJSON, fetchT, fetchText, dohAt, RESOLVERS } from './core.js';
import { T, M, L, res } from './res.js';
import { registrable, unquoteTxt, decodeCaa, analyzeSpf, reverseV4, fmtDate, daysUntil, vcardGet, isIPv4 } from './util.js';

const clean = (s) => String(s).replace(/\.$/, '');
const TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 43: 'DS', 48: 'DNSKEY', 257: 'CAA' };

export const ip = async (ctx) => {
  const i = await ctx.ips();
  const rows = [['Hostname', M(ctx.host)]];
  if (i.cname.length) rows.push(['CNAME', M(i.cname.join(', '))]);
  i.v4.forEach((x, n) => rows.push([n ? '' : 'IPv4', M(x)]));
  i.v6.forEach((x, n) => rows.push([n ? '' : 'IPv6', M(x)]));
  if (i.v4[0]) {
    const ptr = await doh(reverseV4(i.v4[0]), 'PTR').then((r) => answers(r, [12]).map((a) => clean(a.data))).catch(() => []);
    rows.push(['Reverse DNS', ptr.length ? M(ptr.join(', ')) : null]);
  }
  const geo = await ctx.geo().catch(() => null);
  if (geo) rows.push(['Network', `${geo.connection?.org || geo.connection?.isp || '–'} (AS${geo.connection?.asn ?? '?'})`]);
  return res('info', `${ctx.host} resolves to ${i.v4[0] || i.v6[0]}`, [{ kv: rows }]);
};

export const dns = async (ctx) => {
  const q = [['A', ctx.host], ['AAAA', ctx.host], ['CNAME', ctx.host], ['MX', ctx.domain], ['NS', ctx.domain], ['SOA', ctx.domain], ['SRV', `_sip._tcp.${ctx.domain}`]];
  const out = await Promise.all(q.map(([t, n]) => doh(n, t).then((r) => answers(r, [{ A: 1, AAAA: 28, CNAME: 5, MX: 15, NS: 2, SOA: 6, SRV: 33 }[t]])).catch(() => [])));
  const rows = out.flat().map((a) => [T(TYPES[a.type] || a.type, 'info'), M(clean(a.name)), a.TTL, M(a.data)]);
  if (!rows.length) throw new Error('No DNS records came back. The domain may not exist.');
  return res('info', `${rows.length} records found`, [{ table: { head: ['Type', 'Name', 'TTL (s)', 'Value'], rows } }, { note: 'Fetched through Google Public DNS (falls back to Cloudflare).' }]);
};

const TXT_KINDS = [[/^v=spf1/i, 'SPF'], [/^v=DMARC1/i, 'DMARC'], [/^google-site-verification/i, 'Google verification'], [/^MS=/i, 'Microsoft 365 verification'], [/^facebook-domain-verification/i, 'Facebook verification'], [/^apple-domain-verification/i, 'Apple verification'], [/^atlassian-domain-verification/i, 'Atlassian verification'], [/^docusign/i, 'DocuSign verification'], [/^stripe-verification/i, 'Stripe verification'], [/^_github-pages-challenge/i, 'GitHub Pages verification'], [/^v=DKIM1/i, 'DKIM'], [/^zoho-verification/i, 'Zoho verification'], [/^adobe-idp-site-verification/i, 'Adobe verification']];
export const txt = async (ctx) => {
  const names = [...new Set([ctx.domain, ctx.host])];
  const out = (await Promise.all(names.map((n) => doh(n, 'TXT').then((r) => answers(r, [16]).map((a) => [n, unquoteTxt(a.data)])).catch(() => [])))).flat();
  if (!out.length) return res('warn', 'No TXT records published', []);
  const rows = out.map(([n, v]) => [M(n), T(TXT_KINDS.find(([re]) => re.test(v))?.[1] || 'Other', 'info'), M(v)]);
  return res('info', `${rows.length} TXT record${rows.length > 1 ? 's' : ''}`, [{ table: { head: ['Name', 'Kind', 'Value'], rows } }]);
};

export const caa = async (ctx) => {
  const labels = ctx.host.split('.'), stop = ctx.domain.split('.').length;
  for (let i = 0; i <= labels.length - stop; i++) {
    const name = labels.slice(i).join('.');
    const recs = answers(await doh(name, 'CAA'), [257]).map((a) => decodeCaa(a.data));
    if (recs.length) {
      const issuers = recs.filter((r) => /^issue(wild)?$/i.test(r.tag)).map((r) => r.value).filter((v) => v && v !== ';');
      return res('good', `Only ${issuers.length ? issuers.join(', ') : 'listed CAs'} may issue certificates`, [
        { table: { head: ['Tag', 'Value', 'Flags'], rows: recs.map((r) => [T(r.tag, 'info'), M(r.value), r.flags]) } },
        { note: name !== ctx.host ? `Records found on ${name} and inherited by ${ctx.host}.` : '' }]);
    }
  }
  return res('warn', 'No CAA records: any certificate authority may issue certificates for this domain', [{ note: 'Adding a CAA record limits issuance to the CAs you trust.' }]);
};

const ALG = { 5: 'RSA/SHA-1', 7: 'RSASHA1-NSEC3', 8: 'RSA/SHA-256', 10: 'RSA/SHA-512', 13: 'ECDSA P-256', 14: 'ECDSA P-384', 15: 'Ed25519', 16: 'Ed448' };
export const dnssec = async (ctx) => {
  const [a, ds, key] = await Promise.all([doh(ctx.domain, 'A', { dnssec: true }), doh(ctx.domain, 'DS', { dnssec: true }), doh(ctx.domain, 'DNSKEY', { dnssec: true })]);
  const dsR = answers(ds, [43]), keyR = answers(key, [48]);
  const validated = a.AD === true;
  const rows = [['Signed (DS at parent)', dsR.length ? T('Yes', 'good') : T('No', 'bad')], ['DNSKEY records', keyR.length || T('none', 'bad')], ['Resolver validated the answer', validated ? T('Yes (AD flag set)', 'good') : T('No', dsR.length ? 'warn' : 'info')]];
  const tbl = dsR.map((r) => { const [tag, alg, dt] = r.data.split(' '); return [tag, ALG[alg] || `algorithm ${alg}`, `digest type ${dt}`]; });
  return res(validated ? 'good' : dsR.length ? 'warn' : 'bad',
    validated ? 'DNSSEC is enabled and validates' : dsR.length ? 'DS record found but validation did not confirm' : 'DNSSEC is not enabled for this domain',
    [{ kv: rows }, tbl.length && { title: 'DS records', table: { head: ['Key tag', 'Algorithm', 'Digest'], rows: tbl } }].filter(Boolean));
};

export const dnsServer = async (ctx) => {
  const ns = answers(await doh(ctx.domain, 'NS'), [2]).map((a) => clean(a.data));
  if (!ns.length) throw new Error('No NS records found for this domain.');
  const rows = await Promise.all(ns.map(async (n) => {
    const [a, aaaa] = await Promise.all([doh(n, 'A').catch(() => ({})), doh(n, 'AAAA').catch(() => ({}))]);
    return [M(n), M([...answers(a, [1]), ...answers(aaaa, [28])].map((x) => x.data).join('\n') || '–')];
  }));
  return res(ns.length >= 2 ? 'good' : 'warn', `${ns.length} nameserver${ns.length > 1 ? 's' : ''}${ns.length < 2 ? ' (RFC recommends at least two)' : ''}`, [{ table: { head: ['Nameserver', 'IP addresses'], rows } }]);
};

export const email = async (ctx) => {
  const [mx, txtR, dmarcR] = await Promise.all([doh(ctx.domain, 'MX'), doh(ctx.domain, 'TXT'), doh(`_dmarc.${ctx.domain}`, 'TXT').catch(() => ({}))]);
  const mxs = answers(mx, [15]).map((a) => a.data.split(' ')).sort((x, y) => x[0] - y[0]);
  const spf = answers(txtR, [16]).map((a) => unquoteTxt(a.data)).find((v) => /^v=spf1/i.test(v));
  const dmarc = answers(dmarcR, [16]).map((a) => unquoteTxt(a.data)).find((v) => /^v=DMARC1/i.test(v));
  const sel = ['default', 'google', 'selector1', 'selector2', 'k1', 's1', 's2', 'mail', 'dkim', 'smtp', 'mandrill', 'zoho', 'mxvault'];
  const dkim = (await Promise.all(sel.map((s) => doh(`${s}._domainkey.${ctx.domain}`, 'TXT').then((r) => (answers(r, [16, 5]).length ? s : null)).catch(() => null)))).filter(Boolean);
  const sections = [];
  let bad = 0, warn = 0;
  sections.push({ title: 'MX (receiving mail)', ...(mxs.length ? { table: { head: ['Priority', 'Mail server'], rows: mxs.map(([p, h]) => [p, M(clean(h))]) } } : { text: 'No MX records. This domain does not receive email.' }) });
  let spfRow;
  if (!spf) { bad++; spfRow = T('Missing: anyone can spoof this domain', 'bad'); }
  else { const a = analyzeSpf(spf); const strong = a.all === '-all', soft = a.all === '~all'; if (!strong && !soft) bad++; else if (soft) warn++; if (a.lookups > 10) warn++;
    spfRow = T(strong ? 'Strict (-all)' : soft ? 'Soft fail (~all)' : 'Weak or missing "all" rule', strong ? 'good' : soft ? 'warn' : 'bad'); sections.push({ note: `SPF: ${spf}  ·  about ${a.lookups} DNS lookups (limit is 10)` }); }
  let dmRow;
  if (!dmarc) { bad++; dmRow = T('Missing', 'bad'); }
  else { const p = /p=(\w+)/i.exec(dmarc)?.[1]?.toLowerCase(); if (p === 'none') warn++; dmRow = T(`Policy: ${p}`, p === 'none' ? 'warn' : 'good'); sections.push({ note: `DMARC: ${dmarc}` }); }
  sections.unshift({ title: 'Summary', kv: [['SPF', spfRow], ['DMARC', dmRow], ['DKIM', dkim.length ? T(`Found (selectors: ${dkim.join(', ')})`, 'good') : T('No common selector found (the real one may be custom)', 'warn')]] });
  return res(bad ? 'bad' : warn ? 'warn' : 'good', bad ? 'Email authentication has gaps' : warn ? 'Email authentication works but can be tightened' : 'SPF, DMARC and DKIM look healthy', sections);
};

const rdapGet = async (ctx) => {
  if (ctx.memo.rdap) return ctx.memo.rdap;
  const p = fetchJSON(`https://rdap.org/domain/${ctx.domain}`, { headers: { accept: 'application/rdap+json, application/json' } }, 20000);
  ctx.memo.rdap = p; p.catch(() => delete ctx.memo.rdap); return p;
};
const ev = (d, a) => d.events?.find((e) => e.eventAction === a)?.eventDate;
export const whois = async (ctx) => {
  let d;
  try { d = await rdapGet(ctx); } catch (e) { throw new Error(`RDAP lookup failed (${e.message}). Some registries don't publish RDAP.`); }
  const reg = d.entities?.find((e) => e.roles?.includes('registrar'));
  const exp = ev(d, 'expiration'), left = daysUntil(exp);
  const rows = [['Domain', M(d.ldhName || ctx.domain)], ['Registrar', vcardGet(reg, 'fn') || '–'], ['Registered', fmtDate(ev(d, 'registration'))], ['Last changed', fmtDate(ev(d, 'last changed'))],
    ['Expires', exp ? T(`${fmtDate(exp)}${left != null ? ` (${left} days)` : ''}`, left != null && left < 30 ? 'warn' : 'good') : '–'], ['Status', (d.status || []).join(', ') || '–']];
  return res(left != null && left < 30 ? 'warn' : 'info', `Registered with ${vcardGet(reg, 'fn') || 'unknown registrar'}`, [{ kv: rows }, { title: 'Nameservers', list: (d.nameservers || []).map((n) => M(n.ldhName?.toLowerCase())) }]);
};

export const domain = async (ctx) => {
  let d;
  try { d = await rdapGet(ctx); } catch (e) { throw new Error(`RDAP lookup failed (${e.message}).`); }
  const rows = (d.entities || []).map((e) => [T(e.roles?.join(', ') || '–', 'info'), vcardGet(e, 'fn') || '–', vcardGet(e, 'org') || '–', vcardGet(e, 'email') || '–']);
  const age = ev(d, 'registration') ? Math.floor((Date.now() - new Date(ev(d, 'registration'))) / (365.25 * 864e5)) : null;
  return res('info', age != null ? `${ctx.domain} is about ${age} year${age === 1 ? '' : 's'} old` : `Registration details for ${ctx.domain}`, [
    { kv: [['Registry handle', d.handle || '–'], ['DNSSEC delegation signed', d.secureDNS?.delegationSigned ? T('Yes', 'good') : T('No', 'warn')], ['Port 43 whois', d.port43 ? M(d.port43) : null]] },
    { title: 'Contacts published', ...(rows.length ? { table: { head: ['Role', 'Name', 'Organisation', 'Email'], rows } } : { text: 'None. The registry hides contact details.' }) },
    { note: 'Most registries redact personal contact data under GDPR, so "REDACTED" values are normal.' }]);
};

export const ranking = async (ctx) => {
  const j = await fetchJSON(`https://tranco-list.eu/api/ranks/domain/${ctx.domain}`, {}, 15000);
  const r = (j.ranks || []).slice().sort((a, b) => (a.date < b.date ? 1 : -1));
  if (!r.length) return res('info', `${ctx.domain} is not in the Tranco top 1 million`, [{ note: 'Tranco combines Chrome, Cloudflare, Majestic and Umbrella rankings.' }]);
  return res('good', `Global rank #${r[0].rank.toLocaleString()}`, [{ kv: [['Latest rank', `#${r[0].rank.toLocaleString()} (${r[0].date})`], ['Best in period', `#${Math.min(...r.map((x) => x.rank)).toLocaleString()}`], ['Worst in period', `#${Math.max(...r.map((x) => x.rank)).toLocaleString()}`]] }, { title: 'Recent ranks', table: { head: ['Date', 'Rank'], rows: r.slice(0, 14).map((x) => [x.date, '#' + x.rank.toLocaleString()]) } }]);
};

const BLOCKERS = [
  ['Cloudflare 1.1.1.1 (baseline)', 'https://cloudflare-dns.com/dns-query', true],
  ['Cloudflare Security (malware)', 'https://security.cloudflare-dns.com/dns-query'],
  ['Cloudflare Family (adult + malware)', 'https://family.cloudflare-dns.com/dns-query'],
  ['Quad9 (malware)', 'https://dns.quad9.net:5053/dns-query'],
  ['AdGuard (ads + trackers)', 'https://dns.adguard-dns.com/resolve'],
];
export const resolverVerdicts = async (ctx) => {
  const base = answers(await dohAt(RESOLVERS.google, ctx.host, 'A'), [1]);
  return Promise.all(BLOCKERS.map(async ([name, url]) => {
    try {
      const r = await dohAt(url, ctx.host, 'A');
      const a = answers(r, [1]).map((x) => x.data);
      const sinkhole = a.length && a.every((x) => x === '0.0.0.0' || x === '127.0.0.1');
      const blocked = base.length > 0 && (r.Status === 3 || sinkhole || (r.Status === 0 && !a.length && !answers(r, [5]).length));
      return { name, state: blocked ? 'blocked' : 'open' };
    } catch { return { name, state: 'unavailable' }; }
  }));
};
export const blocks = async (ctx) => {
  const v = await resolverVerdicts(ctx);
  const n = v.filter((x) => x.state === 'blocked').length;
  return res(n ? 'warn' : 'good', n ? `Blocked by ${n} of ${v.length} filtering resolvers` : 'Not blocked by any of the tested resolvers',
    [{ table: { head: ['Resolver', 'Result'], rows: v.map((x) => [x.name, x.state === 'blocked' ? T('Blocked', 'bad') : x.state === 'open' ? T('Resolves normally', 'good') : T('Could not be reached', 'info')]) } },
      { note: 'The site is resolved through each public DNS filter. A block means that filter treats it as malware, adult content, ads or trackers.' }]);
};

export const malware = async (ctx) => {
  const hostLine = (txt) => txt.split(/\r?\n/).some((l) => { const t = l.trim().split(/\s+/).pop(); return t && (t === ctx.host || t === ctx.domain); });
  const feed = async (url, parse) => { try { const { r, text } = await fetchText(url, {}, 25000); if (!r.ok) return 'unavailable'; return parse(text) ? 'listed' : 'clear'; } catch { return 'unavailable'; } };
  const [urlhaus, phish, dnsV] = await Promise.all([
    feed('https://urlhaus.abuse.ch/downloads/hostfile/', hostLine),
    feed('https://openphish.com/feed.txt', (t) => t.split(/\r?\n/).some((u) => { try { const h = new URL(u).hostname; return h === ctx.host || h === ctx.domain; } catch { return false; } })),
    resolverVerdicts(ctx).then((v) => v.filter((x) => /malware/i.test(x.name)).some((x) => x.state === 'blocked') ? 'listed' : v.every((x) => x.state === 'unavailable') ? 'unavailable' : 'clear'),
  ]);
  const cell = (s) => (s === 'listed' ? T('Listed', 'bad') : s === 'clear' ? T('Not listed', 'good') : T('Unavailable', 'info'));
  const rows = [['URLhaus (abuse.ch) malware hosts', cell(urlhaus)], ['OpenPhish phishing feed', cell(phish)], ['Cloudflare / Quad9 malware DNS filters', cell(dnsV)]];
  const hits = [urlhaus, phish, dnsV].filter((x) => x === 'listed').length;
  return res(hits ? 'bad' : 'good', hits ? `Flagged by ${hits} source${hits > 1 ? 's' : ''}` : 'Not found on the free malware and phishing lists', [{ table: { head: ['Source', 'Result'], rows } },
    { note: 'Free public lists only. Google Safe Browsing and VirusTotal need API keys and are not included. "Not listed" is not a guarantee of safety.' }]);
};

export const breaches = async (ctx) => {
  const j = await fetchJSON(`https://haveibeenpwned.com/api/v3/breaches?domain=${encodeURIComponent(ctx.domain)}`, {}, 15000);
  if (!j.length) return res('good', `No breaches recorded for ${ctx.domain}`, [{ note: 'Source: Have I Been Pwned. It only covers breaches that were reported and loaded there.' }]);
  return res('bad', `${j.length} known breach${j.length > 1 ? 'es' : ''}`, [{ table: { head: ['Breach', 'Date', 'Accounts', 'Data exposed'], rows: j.map((b) => [b.Title, b.BreachDate, b.PwnCount?.toLocaleString(), (b.DataClasses || []).join(', ')]) } }]);
};
