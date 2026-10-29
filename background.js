import { togglePanel } from './panel.js';
import { startRedirectRecorder, localProbe } from './core.js';

startRedirectRecorder();

const openInTab = (url, index) => chrome.tabs.create({ url, index });

// Click on the icon: slide the dashboard in over the current website.
chrome.action.onClicked.addListener(async (tab) => {
  const base = chrome.runtime.getURL('app.html');
  if (!tab.url || !/^https?:\/\//i.test(tab.url)) { openInTab(base, tab.index + 1); return; }
  const appUrl = `${base}?url=${encodeURIComponent(tab.url)}&tab=${tab.id}&embed=1`;
  try {
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: togglePanel, args: [appUrl] });
  } catch {
    // Pages Chrome does not allow scripts on (Web Store, PDF viewer…): use a normal tab instead.
    openInTab(appUrl.replace('&embed=1', ''), tab.index + 1);
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === 'sitecheck-fallback' && sender.tab) openInTab(msg.url, sender.tab.index + 1);
  if (msg?.type === 'sitecheck-redirects') {
    // The panel sits inside an https page, so Chrome blocks its plain-http requests as mixed content.
    // The service worker is not part of the page, so it makes the request and reports the redirect chain.
    localProbe(msg.start).then(sendResponse, (e) => sendResponse({ error: e.message || String(e) }));
    return true; // keep the channel open for the async reply
  }
});
