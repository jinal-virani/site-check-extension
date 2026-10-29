// Injected into the website's own tab. Must stay self-contained (it is serialised by executeScript).
export function togglePanel(appUrl) {
  const ID = '__sitecheck_host__';
  const old = document.getElementById(ID);
  if (old) { old.dispatchEvent(new CustomEvent('sitecheck-close')); return 'closed'; }

  const host = document.createElement('div');
  host.id = ID;
  host.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483647;';
  const root = host.attachShadow({ mode: 'closed' });
  const backdrop = document.createElement('div');
  backdrop.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.45);opacity:0;transition:opacity .2s;';
  const panel = document.createElement('div');
  panel.style.cssText = 'position:fixed;top:0;right:0;height:100%;width:min(1180px,94vw);background:#111214;box-shadow:-12px 0 40px rgba(0,0,0,.5);transform:translateX(100%);transition:transform .22s ease-out;';
  const frame = document.createElement('iframe');
  frame.src = appUrl;
  frame.title = 'Site Check Panel';
  frame.style.cssText = 'width:100%;height:100%;border:0;display:block;background:#111214;color-scheme:dark;';
  panel.append(frame);
  root.append(backdrop, panel);

  const cleanup = () => {
    window.removeEventListener('message', onMsg);
    document.removeEventListener('keydown', onKey, true);
    document.removeEventListener('securitypolicyviolation', onCsp, true);
    host.remove();
  };
  const close = () => {
    panel.style.transform = 'translateX(100%)'; backdrop.style.opacity = '0';
    setTimeout(cleanup, 220);
  };
  const onMsg = (e) => { if (e.source === frame.contentWindow && e.data && e.data.type === 'sitecheck-close') close(); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  // Some sites forbid framing extension pages through their CSP; fall back to a normal tab.
  const onCsp = (e) => {
    if (String(e.blockedURI).startsWith('chrome-extension')) {
      cleanup();
      chrome.runtime.sendMessage({ type: 'sitecheck-fallback', url: appUrl.replace('&embed=1', '') });
    }
  };
  backdrop.addEventListener('click', close);
  host.addEventListener('sitecheck-close', close);
  window.addEventListener('message', onMsg);
  document.addEventListener('keydown', onKey, true);
  document.addEventListener('securitypolicyviolation', onCsp, true);
  (document.body || document.documentElement).append(host);
  requestAnimationFrame(() => requestAnimationFrame(() => { panel.style.transform = 'translateX(0)'; backdrop.style.opacity = '1'; }));
  return 'opened';
}
