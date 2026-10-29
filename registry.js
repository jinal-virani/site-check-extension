import * as D from './dns.js';
import * as N from './net.js';
import * as W from './web.js';

// Order and wording follow the reference screenshot (left to right, top to bottom).
// src = where the data comes from (shown to the user for transparency).
const c = (id, title, desc, src, run) => ({ id, title, desc, src, run });
export const CHECKS = [
  c('ip', 'IP Info', 'The IP address the domain currently resolves to', 'Google DNS-over-HTTPS + ipwho.is', D.ip),
  c('ssl', 'SSL Certificate', 'Certificate issuer, validity dates and the chain of trust', 'Certificate Transparency logs (crt.sh) + a live HTTPS test', N.ssl),
  c('dns', 'DNS Records', 'A, AAAA, MX, NS, CNAME and other records held for the domain', 'Google DNS-over-HTTPS', D.dns),
  c('cookies', 'Cookies', 'Cookies set on arrival, and how tightly each one is scoped', 'Your browser cookie jar (values hidden)', W.cookies),
  c('crawl', 'Crawl Rules', 'The crawl rules the site publishes for search engines and AI crawlers', 'The site\'s /robots.txt', W.robots),
  c('headers', 'Headers', 'Every HTTP response header the server sends back', 'A direct request to the site', W.headers),
  c('quality', 'Quality Metrics', 'Lighthouse scores for performance, accessibility, SEO and best practice', 'Google PageSpeed Insights', N.quality),
  c('location', 'Server Location', 'Where in the world the server is physically hosted', 'ipwho.is', N.location),
  c('hosts', 'Associated Hosts', 'Other hostnames Shodan has seen on the same IP address', 'Shodan InternetDB', N.associated),
  c('redirects', 'Redirect Chain', 'The full chain of redirects before the final page loads', 'Live requests, watched with chrome.webRequest', N.redirects),
  c('txt', 'TXT Records', 'TXT records, including domain verification and policy entries', 'Google DNS-over-HTTPS', D.txt),
  c('status', 'Server Status', 'Whether the site is up, and how quickly it responded', '3 live requests from your browser', N.status),
  c('ports', 'Open Ports', 'Which common ports are open and reachable on the host', 'Shodan InternetDB (passive data)', N.ports),
  c('trace', 'Traceroute', 'The network path packets travel to reach the server', 'HackerTarget MTR API', N.traceroute),
  c('carbon', 'Carbon Footprint', 'Estimated CO2 from the data needed to load the page', 'Page weight from your tab + Sustainable Web Design model', N.carbon),
  c('server', 'Server Info', 'Operating system, ASN and the network the host sits on', 'Response headers + ipwho.is', N.serverInfo),
  c('vulns', 'Vulnerabilities', 'CVEs Shodan links to the services running on the host', 'Shodan InternetDB', N.vulns),
  c('whois', 'Whois Lookup', 'Registrar, registration dates and nameservers, from WHOIS', 'RDAP (the modern WHOIS) via rdap.org', D.whois),
  c('domain', 'Domain Info', 'Ownership and contact details published against the domain', 'RDAP via rdap.org', D.domain),
  c('dnssec', 'DNSSEC', 'DNSSEC records proving DNS answers have not been tampered with', 'Google DNS-over-HTTPS with DNSSEC flag', D.dnssec),
  c('caa', 'CAA Records', 'Which certificate authorities may issue certificates for the domain', 'Google DNS-over-HTTPS', D.caa),
  c('hsts', 'HSTS', 'Whether browsers are told to only ever connect over HTTPS', 'Response headers + hstspreload.org', W.hsts),
  c('dnsserver', 'DNS Server', 'Which nameservers answer for the domain, and their IP addresses', 'Google DNS-over-HTTPS', D.dnsServer),
  c('tech', 'Tech Stack', 'Frameworks, analytics and services the site is built with', 'Live page + headers, matched against ~70 signatures', W.techStack),
  c('sitemap', 'Sitemap', 'The pages a site lists in its own sitemap', 'The site\'s sitemap.xml', W.sitemap),
  c('securitytxt', 'Security.txt', 'The security.txt file, and who it says to contact about vulnerabilities', '/.well-known/security.txt', W.securityTxt),
  c('linked', 'Linked Pages', 'Internal and external links found in the page\'s anchor tags', 'Live page in your tab', W.linked),
  c('socialtags', 'Social Tags', 'Open Graph and Twitter tags used when the site is shared', 'Live page in your tab', W.socialTags),
  c('social', 'Social Presence', 'Social accounts the site claims, and whether they link back', 'Page links, JSON-LD and meta tags', W.socialPresence),
  c('email', 'Email Configuration', 'MX, SPF, DKIM and DMARC records for sending and receiving mail', 'Google DNS-over-HTTPS', D.email),
  c('firewall', 'Firewall', 'Which web application firewall, if any, sits in front of the site', 'Response headers + one test request', W.firewall),
  c('httpsec', 'HTTP Security', 'Protective headers such as CSP, X-Frame-Options and nosniff', 'Response headers', W.httpSecurity),
  c('mixed', 'Mixed Content & SRI', 'Insecure resources on the page, and third-party scripts without SRI', 'Live page in your tab', W.mixedSri),
  c('archive', 'Archive History', 'How the site has changed over time, via the Wayback Machine', 'Internet Archive CDX API', N.archive),
  c('rank', 'Global Ranking', 'Tranco rank, if the site is in the global top million', 'tranco-list.eu', D.ranking),
  c('blocks', 'Block Detection', 'Whether privacy, malware and parental-control resolvers block the site', 'Cloudflare, Quad9 and AdGuard DNS filters', D.blocks),
  c('malware', 'Malware & Phishing', 'Whether the site appears on common malware and phishing lists', 'URLhaus, OpenPhish and malware DNS filters', D.malware),
  c('breaches', 'Data Breaches', 'Known data breaches of the site, as recorded by Have I Been Pwned', 'haveibeenpwned.com', D.breaches),
  c('trackers', 'Trackers & Third Parties', 'Analytics, ad trackers and other third parties the page loads', 'Every request the live page made', W.trackers),
  c('tlsconn', 'TLS Connection', 'The TLS versions accepted, and the cipher and details of a live handshake', 'Qualys SSL Labs (a scan can take 1 to 3 minutes)', N.tlsConn),
  c('tlsaudit', 'TLS Security Audit', 'SSL Labs\' grade for the server\'s TLS configuration', 'Qualys SSL Labs (a scan can take 1 to 3 minutes)', N.tlsAudit),
  c('tlsclients', 'TLS Client Compatibility', 'Whether Chrome, Safari, Java and older Android can still connect', 'Qualys SSL Labs (a scan can take 1 to 3 minutes)', N.tlsClients),
  c('screenshot', 'Screenshot', 'A full-page render of the site, as a browser sees it', 'thum.io (fallback WordPress mShots)', N.screenshot),
  c('subdomains', 'Subdomains', 'Subdomains that have appeared in public Certificate Transparency logs', 'crt.sh (fallback Certspotter)', N.subdomains),
];

export const GROUPS = [
  ['Network & Hosting', ['ip', 'location', 'hosts', 'ports', 'vulns', 'trace', 'server', 'status']],
  ['DNS & Domain', ['dns', 'txt', 'dnssec', 'caa', 'dnsserver', 'whois', 'domain', 'email', 'rank', 'subdomains', 'archive']],
  ['Certificates & TLS', ['ssl', 'hsts', 'tlsconn', 'tlsaudit', 'tlsclients']],
  ['HTTP & Security', ['headers', 'httpsec', 'firewall', 'redirects', 'cookies', 'mixed', 'securitytxt', 'blocks', 'malware', 'breaches']],
  ['Page & Content', ['crawl', 'sitemap', 'linked', 'socialtags', 'social', 'tech', 'trackers', 'screenshot']],
  ['Performance', ['quality', 'carbon']],
];
CHECKS.forEach((c) => { c.group = GROUPS.find(([, ids]) => ids.includes(c.id))[0]; });
