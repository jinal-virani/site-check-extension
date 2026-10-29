// Technology + tracker signatures. Each rule matches on headers, HTML, resource URLs or JS globals.
const s = (n, c, o) => ({ n, c, ...o });
const SIGS = [
  s('Nginx', 'Web server', { h: [['server', /nginx/i]] }),
  s('Apache', 'Web server', { h: [['server', /apache/i]] }),
  s('Microsoft IIS', 'Web server', { h: [['server', /iis/i]] }),
  s('LiteSpeed', 'Web server', { h: [['server', /litespeed/i]] }),
  s('Caddy', 'Web server', { h: [['server', /caddy/i]] }),
  s('OpenResty', 'Web server', { h: [['server', /openresty/i]] }),
  s('Gunicorn', 'Web server', { h: [['server', /gunicorn/i]] }),
  s('Kestrel', 'Web server', { h: [['server', /kestrel/i]] }),
  s('Cloudflare', 'CDN', { h: [['server', /cloudflare/i], ['cf-ray', /./]] }),
  s('Amazon CloudFront', 'CDN', { h: [['x-amz-cf-id', /./], ['via', /cloudfront/i]] }),
  s('Fastly', 'CDN', { h: [['x-fastly-request-id', /./], ['x-served-by', /cache-/i]] }),
  s('Akamai', 'CDN', { h: [['server', /akamai/i], ['x-akamai-transformed', /./]] }),
  s('Vercel', 'Hosting', { h: [['x-vercel-id', /./], ['server', /vercel/i]] }),
  s('Netlify', 'Hosting', { h: [['x-nf-request-id', /./], ['server', /netlify/i]] }),
  s('GitHub Pages', 'Hosting', { h: [['x-github-request-id', /./]] }),
  s('Azure Front Door', 'CDN', { h: [['x-azure-ref', /./]] }),
  s('PHP', 'Language', { h: [['x-powered-by', /php/i]] }),
  s('ASP.NET', 'Framework', { h: [['x-powered-by', /asp\.net/i], ['x-aspnet-version', /./]] }),
  s('Express', 'Framework', { h: [['x-powered-by', /express/i]] }),
  s('Next.js', 'Framework', { h: [['x-powered-by', /next\.js/i]], html: /id="__next"|\/_next\/static/, g: '__NEXT_DATA__' }),
  s('Nuxt', 'Framework', { html: /id="__nuxt"|\/_nuxt\//, g: '__NUXT__' }),
  s('Gatsby', 'Framework', { html: /id="___gatsby"|gatsby-/ }),
  s('Astro', 'Framework', { html: /astro-island|data-astro-cid/ }),
  s('Remix', 'Framework', { html: /__remixContext/ }),
  s('SvelteKit', 'Framework', { html: /\/_app\/immutable\/|data-sveltekit/ }),
  s('Laravel', 'Framework', { g: 'Livewire', html: /laravel_session|csrf-token/ }),
  s('Ruby on Rails', 'Framework', { html: /csrf-param|data-turbo|data-turbolinks/ }),
  s('Django', 'Framework', { html: /csrfmiddlewaretoken/ }),
  s('React', 'JS framework', { g: 'React', html: /data-reactroot|__reactContainer|react(\.production|-dom)/i }),
  s('Vue.js', 'JS framework', { g: 'Vue', html: /data-v-[0-9a-f]{6,}|vue(\.runtime)?(\.min)?\.js/ }),
  s('Angular', 'JS framework', { g: 'ng', html: /ng-version=|<app-root/ }),
  s('Svelte', 'JS framework', { g: 'Svelte', html: /svelte-[a-z0-9]{5,}/ }),
  s('Alpine.js', 'JS framework', { g: 'Alpine', html: /x-data=|alpinejs/ }),
  s('htmx', 'JS framework', { g: 'htmx', html: /hx-(get|post)=/ }),
  s('jQuery', 'JS library', { g: 'jQuery', url: /jquery[-.\d]*(\.min)?\.js/i }),
  s('Bootstrap', 'UI framework', { url: /bootstrap[-.\d]*(\.min)?\.(css|js)/i, html: /class="[^"]*\b(container-fluid|navbar-expand)/ }),
  s('Tailwind CSS', 'UI framework', { html: /class="[^"]*\b(flex|grid) [^"]*\b(px|py|mt|mb)-\d/, url: /tailwind/i }),
  s('Font Awesome', 'Fonts', { url: /fontawesome|font-awesome/i }),
  s('Google Fonts', 'Fonts', { url: /fonts\.(googleapis|gstatic)\.com/ }),
  s('WordPress', 'CMS', { html: /wp-content\/|wp-includes\//, h: [['link', /api\.w\.org/]], g: 'wp' }),
  s('WooCommerce', 'E-commerce', { html: /woocommerce/i }),
  s('Shopify', 'E-commerce', { url: /cdn\.shopify\.com/, g: 'Shopify', h: [['x-shopid', /./]] }),
  s('Magento', 'E-commerce', { html: /Mage\.Cookies|\/static\/version\d+|magento/i }),
  s('Drupal', 'CMS', { html: /drupal-settings-json|Drupal\.settings/, h: [['x-drupal-cache', /./], ['x-generator', /drupal/i]], g: 'Drupal' }),
  s('Joomla', 'CMS', { html: /\/media\/jui\/|Joomla!/ }),
  s('Wix', 'Site builder', { url: /wixstatic\.com|parastorage\.com/, h: [['x-wix-request-id', /./]] }),
  s('Squarespace', 'Site builder', { url: /squarespace\.com|sqspcdn\.com/ }),
  s('Webflow', 'Site builder', { html: /data-wf-page|webflow\.com/, g: 'Webflow' }),
  s('Ghost', 'CMS', { html: /content="Ghost[ \d.]*"/ }),
  s('Google Analytics', 'Analytics', { url: /google-analytics\.com|gtag\/js|analytics\.js/, g: 'ga' }),
  s('Google Tag Manager', 'Tag manager', { url: /googletagmanager\.com\/gtm/ }),
  s('Meta Pixel', 'Analytics', { url: /connect\.facebook\.net.*(fbevents|sdk)/, g: 'fbq' }),
  s('Hotjar', 'Analytics', { url: /static\.hotjar\.com/ }),
  s('Microsoft Clarity', 'Analytics', { url: /clarity\.ms/ }),
  s('Segment', 'Analytics', { url: /cdn\.segment\.(com|io)/ }),
  s('Mixpanel', 'Analytics', { url: /mixpanel/i, g: 'mixpanel' }),
  s('PostHog', 'Analytics', { url: /posthog/i, g: 'posthog' }),
  s('Plausible', 'Analytics', { url: /plausible\.io/ }),
  s('Matomo', 'Analytics', { url: /matomo|piwik/i }),
  s('Sentry', 'Monitoring', { url: /sentry(-cdn)?\.(io|com)/, g: 'Sentry' }),
  s('Intercom', 'Chat', { url: /intercomcdn\.com|widget\.intercom\.io/, g: 'Intercom' }),
  s('Stripe', 'Payments', { url: /js\.stripe\.com/, g: 'Stripe' }),
  s('reCAPTCHA', 'Security', { url: /recaptcha/, g: 'grecaptcha' }),
  s('hCaptcha', 'Security', { url: /hcaptcha\.com/ }),
  s('Cloudflare Turnstile', 'Security', { url: /challenges\.cloudflare\.com\/turnstile/ }),
  s('Three.js', 'JS library', { g: 'THREE' }),
  s('Lodash', 'JS library', { url: /lodash(\.min)?\.js/ }),
  s('Axios', 'JS library', { url: /axios(\.min)?\.js/ }),
  s('Service Worker', 'PWA', { html: /serviceWorker\.register/ }),
];

export function detectTech({ headers = {}, html = '', urls = [], globals = [] }) {
  const g = new Set(globals), found = [];
  for (const sg of SIGS) {
    let ev = null;
    for (const [k, re] of sg.h || []) if (headers[k] != null && re.test(headers[k])) { ev = `header ${k}: ${String(headers[k]).slice(0, 60)}`; break; }
    if (!ev && sg.g && g.has(sg.g)) ev = `window.${sg.g} present`;
    if (!ev && sg.url) { const u = urls.find((x) => sg.url.test(x)); if (u) ev = `loads ${u.length > 70 ? u.slice(0, 70) + '…' : u}`; }
    if (!ev && sg.html && sg.html.test(html)) ev = 'found in page HTML';
    if (ev) found.push({ name: sg.n, cat: sg.c, evidence: ev });
  }
  const gen = /<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)/i.exec(html)?.[1];
  if (gen) found.unshift({ name: gen, cat: 'Generator tag', evidence: '<meta name="generator">' });
  return found;
}

// host suffix -> [name, category]
export const THIRD = {
  'google-analytics.com': ['Google Analytics', 'Analytics'], 'analytics.google.com': ['Google Analytics', 'Analytics'],
  'googletagmanager.com': ['Google Tag Manager', 'Tag manager'], 'doubleclick.net': ['Google Ads (DoubleClick)', 'Advertising'],
  'googlesyndication.com': ['Google AdSense', 'Advertising'], 'googleadservices.com': ['Google Ads', 'Advertising'],
  'facebook.net': ['Meta Pixel / SDK', 'Social'], 'facebook.com': ['Facebook', 'Social'],
  'hotjar.com': ['Hotjar', 'Session replay'], 'clarity.ms': ['Microsoft Clarity', 'Session replay'],
  'fullstory.com': ['FullStory', 'Session replay'], 'mouseflow.com': ['Mouseflow', 'Session replay'], 'crazyegg.com': ['Crazy Egg', 'Session replay'],
  'segment.com': ['Segment', 'Analytics'], 'segment.io': ['Segment', 'Analytics'], 'mixpanel.com': ['Mixpanel', 'Analytics'],
  'amplitude.com': ['Amplitude', 'Analytics'], 'heapanalytics.com': ['Heap', 'Analytics'], 'posthog.com': ['PostHog', 'Analytics'],
  'plausible.io': ['Plausible', 'Analytics'], 'matomo.cloud': ['Matomo', 'Analytics'], 'yandex.ru': ['Yandex Metrica', 'Analytics'],
  'hs-scripts.com': ['HubSpot', 'Analytics'], 'hs-analytics.net': ['HubSpot', 'Analytics'], 'hsforms.net': ['HubSpot', 'Analytics'],
  'snap.licdn.com': ['LinkedIn Insight', 'Advertising'], 'ads.linkedin.com': ['LinkedIn Ads', 'Advertising'],
  'ads-twitter.com': ['X / Twitter Ads', 'Advertising'], 'twitter.com': ['X / Twitter', 'Social'], 'platform.twitter.com': ['X / Twitter', 'Social'],
  'tiktok.com': ['TikTok', 'Advertising'], 'pinterest.com': ['Pinterest', 'Social'], 'snapchat.com': ['Snapchat', 'Advertising'], 'sc-static.net': ['Snapchat', 'Advertising'],
  'criteo.com': ['Criteo', 'Advertising'], 'taboola.com': ['Taboola', 'Advertising'], 'outbrain.com': ['Outbrain', 'Advertising'],
  'adnxs.com': ['Xandr', 'Advertising'], 'rubiconproject.com': ['Magnite', 'Advertising'], 'pubmatic.com': ['PubMatic', 'Advertising'],
  'amazon-adsystem.com': ['Amazon Ads', 'Advertising'], 'scorecardresearch.com': ['Comscore', 'Analytics'], 'quantserve.com': ['Quantcast', 'Advertising'],
  'bat.bing.com': ['Microsoft Ads', 'Advertising'], 'optimizely.com': ['Optimizely', 'Analytics'], 'cloudflareinsights.com': ['Cloudflare Web Analytics', 'Analytics'],
  'sentry.io': ['Sentry', 'Monitoring'], 'newrelic.com': ['New Relic', 'Monitoring'], 'nr-data.net': ['New Relic', 'Monitoring'], 'datadoghq.com': ['Datadog', 'Monitoring'],
  'intercom.io': ['Intercom', 'Chat'], 'intercomcdn.com': ['Intercom', 'Chat'], 'zendesk.com': ['Zendesk', 'Chat'], 'zdassets.com': ['Zendesk', 'Chat'],
  'crisp.chat': ['Crisp', 'Chat'], 'tawk.to': ['Tawk.to', 'Chat'], 'drift.com': ['Drift', 'Chat'],
  'stripe.com': ['Stripe', 'Payments'], 'paypal.com': ['PayPal', 'Payments'], 'razorpay.com': ['Razorpay', 'Payments'],
  'googleapis.com': ['Google APIs / Fonts', 'CDN & fonts'], 'gstatic.com': ['Google static', 'CDN & fonts'], 'typekit.net': ['Adobe Fonts', 'CDN & fonts'],
  'cloudflare.com': ['Cloudflare', 'CDN & fonts'], 'jsdelivr.net': ['jsDelivr', 'CDN & fonts'], 'unpkg.com': ['unpkg', 'CDN & fonts'],
  'bootstrapcdn.com': ['BootstrapCDN', 'CDN & fonts'], 'fontawesome.com': ['Font Awesome', 'CDN & fonts'], 'cloudfront.net': ['Amazon CloudFront', 'CDN & fonts'],
  'akamaihd.net': ['Akamai', 'CDN & fonts'], 'fastly.net': ['Fastly', 'CDN & fonts'], 'youtube.com': ['YouTube', 'Embed'], 'ytimg.com': ['YouTube', 'Embed'], 'vimeo.com': ['Vimeo', 'Embed'],
  'recaptcha.net': ['reCAPTCHA', 'Security'], 'hcaptcha.com': ['hCaptcha', 'Security'],
};
export const TRACKING_CATS = new Set(['Analytics', 'Advertising', 'Session replay', 'Social', 'Tag manager']);
export function lookupThird(host) {
  const parts = host.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const hit = THIRD[parts.slice(i).join('.')];
    if (hit) return hit;
  }
  return null;
}
