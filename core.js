import { registrable, isIPv4, sleep, stripInlineHandlers } from './util.js';

export async function fetchT(url, opts = {}, ms = 15000) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try { return await fetch(url, { cache: 'no-store', ...opts, signal: ac.signal }); }
  catch (e) {
    if (e.name === 'AbortError') throw new Error(`Timed out after ${Math.round(ms / 1000)}s`);
    throw e;
  } finally { clearTimeout(t); }
}
export async function fetchJSON(url, opts, ms) {
  const r = await fetchT(url, opts, ms);
  if (!r.ok) { const e = new Error(`HTTP ${r.status}`); e.status = r.status; throw e; }
  const txt = await r.text();
  try { return JSON.parse(txt); } catch { throw new Error('The service returned something that is not JSON.'); }
}
export async function fetchText(url, opts, ms) {
  const r = await fetchT(url, opts, ms);
  return { r, text: await r.text() };
}

// DNS over HTTPS ---------------------------------------------------------
export const RESOLVERS = {
  google: 'https://dns.google/resolve',
  cloudflare: 'https://cloudflare-dns.com/dns-query',
};
export const dohAt = (endpoint, name, type, { dnssec = false } = {}) =>
  fetchJSON(`${endpoint}?name=${encodeURIComponent(name)}&type=${type}${dnssec ? '&do=1' : ''}`,
    { headers: { accept: 'application/dns-json' } }, 10000);
export async function doh(name, type, opts) {
  try { return await dohAt(RESOLVERS.google, name, type, opts); }
  catch { return await dohAt(RESOLVERS.cloudflare, name, type, opts); }
}
export const answers = (r, types) => (r?.Answer || []).filter((a) => !types || types.includes(a.type));

// Redirect recorder (chrome.webRequest sees redirects that fetch() hides) ---
export const redirectEvents = [];
export function startRedirectRecorder() {
  try {
    chrome.webRequest.onBeforeRedirect.addListener((d) => {
      redirectEvents.push({ url: d.url, to: d.redirectUrl, status: d.statusCode, at: Date.now() });
      if (redirectEvents.length > 800) redirectEvents.shift();
    }, { urls: ['<all_urls>'] });
  } catch { /* not available (e.g. tests) */ }
}
export function walkRedirects(start, since) {
  const chain = []; let cur = start;
  for (let i = 0; i < 15; i++) {
    const e = [...redirectEvents].reverse().find((x) => x.at >= since && x.url === cur);
    if (!e) break;
    chain.push(e); cur = e.to;
  }
  return chain;
}

// Runs inside the user's real tab to read the live DOM and JS globals.
export function pageProbe() {
  const names = ['jQuery', 'React', 'Vue', 'angular', 'ng', '__NEXT_DATA__', '__NUXT__', 'Shopify', 'gtag', 'ga', 'dataLayer', 'fbq', '_gaq', 'Alpine', 'Ember', 'Backbone', 'Svelte', 'Drupal', 'Sentry', 'analytics', 'mixpanel', 'amplitude', 'heap', 'Intercom', 'Stripe', 'grecaptcha', 'THREE', 'Webflow', 'wp', 'hj', 'clarity', 'posthog', 'Livewire', 'htmx'];
  const globals = names.filter((k) => { try { return typeof window[k] !== 'undefined'; } catch { return false; } });
  if (document.querySelector('[data-reactroot], #root[data-reactroot], [data-react-helmet]')) globals.push('React(DOM)');
  return {
    html: document.documentElement.outerHTML.slice(0, 3000000),
    url: location.href, title: document.title, globals,
    resources: performance.getEntriesByType('resource').map((r) => ({ u: r.name, t: r.initiatorType, s: r.transferSize || 0, e: r.encodedBodySize || 0 })),
    nav: (() => { const n = performance.getEntriesByType('navigation')[0]; return n ? { s: n.transferSize || 0, e: n.encodedBodySize || 0 } : null; })(),
  };
}

export function makeCtx(urlStr, tabId) {
  const u = new URL(urlStr);
  const ctx = { url: u.href, origin: u.origin, host: u.hostname, domain: registrable(u.hostname), https: u.protocol === 'https:', tabId: tabId ?? null, memo: {}, sayers: new Set() };
  const memo = (k, fn) => () => {
    if (!ctx.memo[k]) {
      const p = fn();
      ctx.memo[k] = p;
      p.catch(() => { if (ctx.memo[k] === p) delete ctx.memo[k]; });
    }
    return ctx.memo[k];
  };
  const say = (m) => ctx.sayers.forEach((f) => f(m));

  ctx.page = memo('page', async () => {
    const t0 = performance.now();
    const r = await fetchT(ctx.url, { redirect: 'follow' }, 20000);
    const ttfb = performance.now() - t0;
    const html = await r.text();
    return {
      status: r.status, statusText: r.statusText, finalUrl: r.url || ctx.url, redirected: r.redirected,
      headers: Object.fromEntries([...r.headers.entries()]), html, ttfb, total: performance.now() - t0,
      bytes: new TextEncoder().encode(html).length,
    };
  });
  ctx.snapshot = memo('snap', async () => {
    if (ctx.tabId != null) {
      try {
        const [res] = await chrome.scripting.executeScript({ target: { tabId: ctx.tabId }, world: 'MAIN', func: pageProbe });
        const r = res?.result;
        if (r?.html && new URL(r.url).hostname === ctx.host) return { ...r, live: true };
      } catch { /* fall through to fetched HTML */ }
    }
    const p = await ctx.page();
    return { html: p.html, url: p.finalUrl, title: '', globals: [], resources: [], nav: null, live: false };
  });
  ctx.doc = memo('doc', async () => {
    const d = new DOMParser().parseFromString(stripInlineHandlers((await ctx.snapshot()).html), 'text/html');
    d.getElementById('__sitecheck_host__')?.remove();
    return d;
  });

  ctx.ips = memo('ips', async () => {
    if (isIPv4(ctx.host)) return { v4: [ctx.host], v6: [], cname: [] };
    const [a, aaaa] = await Promise.all([doh(ctx.host, 'A'), doh(ctx.host, 'AAAA').catch(() => ({}))]);
    const v4 = answers(a, [1]).map((x) => x.data), v6 = answers(aaaa, [28]).map((x) => x.data);
    if (!v4.length && !v6.length) throw new Error('This hostname has no A or AAAA record, so there is no IP address to look up.');
    return { v4, v6, cname: answers(a, [5]).map((x) => x.data.replace(/\.$/, '')) };
  });
  const firstIp = async () => { const i = await ctx.ips(); return i.v4[0] || i.v6[0]; };
  ctx.geo = memo('geo', async () => {
    const g = await fetchJSON(`https://ipwho.is/${await firstIp()}`, {}, 12000);
    if (g.success === false) throw new Error(g.message || 'IP lookup failed');
    return g;
  });
  ctx.shodan = memo('shodan', async () => {
    const r = await fetchT(`https://internetdb.shodan.io/${await firstIp()}`, {}, 12000);
    if (r.status === 404) return { ports: [], hostnames: [], vulns: [], cpes: [], tags: [], none: true };
    if (!r.ok) throw new Error(`Shodan InternetDB returned HTTP ${r.status}`);
    return r.json();
  });

  // Shared SSL Labs scan used by the three TLS checks.
  ctx.ssllabs = (sayFn) => {
    if (sayFn) ctx.sayers.add(sayFn);
    return memo('ssllabs', async () => {
      const base = `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(ctx.host)}&all=done&ignoreMismatch=on`;
      let r = await fetchJSON(`${base}&fromCache=on&maxAge=168`, {}, 30000);
      if (!['READY', 'DNS', 'IN_PROGRESS'].includes(r.status)) r = await fetchJSON(`${base}&startNew=on`, {}, 30000);
      const t0 = Date.now();
      while (r.status === 'DNS' || r.status === 'IN_PROGRESS') {
        say(`SSL Labs is scanning the server… ${r.endpoints?.[0]?.progress > 0 ? r.endpoints[0].progress + '%' : 'starting'}`);
        if (Date.now() - t0 > 9 * 60e3) throw new Error('SSL Labs scan took longer than 9 minutes.');
        await sleep(8000);
        r = await fetchJSON(base, {}, 30000);
      }
      if (r.status !== 'READY') throw new Error(r.statusMessage || 'SSL Labs could not scan this host.');
      return r;
    })();
  };
  return ctx;
}

// Probing http:// from the dashboard is blocked as mixed content (the dashboard is framed inside an https page),
// so the request is made by the background service worker instead.
export async function localProbe(start) {
  const since = Date.now() - 50;
  const r = await fetchT(start, { redirect: 'follow' }, 20000);
  await r.arrayBuffer();
  return { chain: walkRedirects(start, since), status: r.status, ok: r.ok, url: r.url };
}
export async function probeRedirects(start) {
  if (globalThis.chrome?.runtime?.sendMessage) {
    let reply;
    try { reply = await chrome.runtime.sendMessage({ type: 'sitecheck-redirects', start }); } catch { reply = null; }
    if (reply?.error) throw new Error(reply.error);
    if (reply) return reply;
  }
  return localProbe(start);
}
