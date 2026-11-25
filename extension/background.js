// Security Scanner Traffic Capture (SecScan CDP Bridge) — background service worker.
//
// Captures the network activity of the active browser tab through the chrome.debugger API
// (Network domain) and pushes text request/response pairs to the local Security Scanner
// ingest endpoint (`POST /api/traffic/ingest`) with live passive security analysis.

const FLUSH_AT = 10;
const MAX_BODY = 256 * 1024;
const SKIP_MIME = ['image/', 'font/', 'audio/', 'video/', 'application/octet-stream'];
const DEFAULT_SERVER_URL = 'http://127.0.0.1:4321';

let session = {
  capturing: false,
  tabId: null,
  queue: [],
  requests: new Map(),
  ingested: 0,
  passiveFindings: 0,
  failed: 0,
  lastError: ''
};

async function saveState() {
  await chrome.storage.session.set({
    capturing: session.capturing,
    tabId: session.tabId,
    ingested: session.ingested,
    passiveFindings: session.passiveFindings,
    failed: session.failed,
    lastError: session.lastError,
    queued: session.queue.length
  });
}

async function getConfig() {
  const { serverUrl = DEFAULT_SERVER_URL, token = '', passiveScan = true } =
    await chrome.storage.local.get(['serverUrl', 'token', 'passiveScan']);
  return {
    serverUrl: (serverUrl || DEFAULT_SERVER_URL).replace(/\/+$/, ''),
    token: String(token || '').trim(),
    passiveScan: passiveScan !== false
  };
}

async function getActiveTabId() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab ? tab.id : null;
}

async function start() {
  if (session.capturing) return { ok: true };
  const { serverUrl } = await getConfig();
  if (!serverUrl) {
    return { ok: false, error: 'Set the Security Scanner URL first (default: http://127.0.0.1:4321).' };
  }
  const tabId = await getActiveTabId();
  if (tabId == null) return { ok: false, error: 'No active tab.' };
  try {
    await chrome.debugger.attach({ tabId }, '1.3');
  } catch (e) {
    return { ok: false, error: `attach failed: ${e.message}` };
  }
  await chrome.debugger.sendCommand({ tabId }, 'Network.enable', {});
  session = {
    ...session,
    capturing: true,
    tabId,
    queue: [],
    requests: new Map(),
    ingested: 0,
    passiveFindings: 0,
    failed: 0,
    lastError: ''
  };
  chrome.action.setBadgeText({ text: 'REC' });
  chrome.action.setBadgeBackgroundColor({ color: '#c2410c' });
  await saveState();
  return { ok: true };
}

async function stop() {
  if (session.capturing && session.tabId != null) {
    await flush();
    try {
      await chrome.debugger.sendCommand({ tabId: session.tabId }, 'Network.disable', {});
      await chrome.debugger.detach({ tabId: session.tabId });
    } catch (_) {
      // tab may already be closed
    }
  }
  session.capturing = false;
  session.tabId = null;
  chrome.action.setBadgeText({ text: '' });
  await saveState();
  return { ok: true };
}

function skipBody(mimeType) {
  const mt = (mimeType || '').toLowerCase();
  return SKIP_MIME.some(p => mt.startsWith(p));
}

function truncate(s) {
  if (s.length <= MAX_BODY) return s;
  return s.slice(0, MAX_BODY) + '\n... [truncated by extension]';
}

async function queueExchange(info, response) {
  const respHeaders = {};
  const rawHeaders = response.headers || {};
  if (Array.isArray(rawHeaders)) {
    for (const h of rawHeaders) {
      if (h && h.name != null) respHeaders[String(h.name).toLowerCase()] = h.value;
    }
  } else {
    for (const [k, v] of Object.entries(rawHeaders)) respHeaders[String(k).toLowerCase()] = v;
  }
  const mime = respHeaders['content-type'] || '';

  let reqBody = info.postData || '';
  let respBody = '';
  if (!skipBody(mime)) {
    try {
      const body = await chrome.debugger.sendCommand(
        { tabId: session.tabId },
        'Network.getResponseBody',
        { requestId: info.requestId }
      );
      if (body && !body.base64Encoded) {
        reqBody = truncate(reqBody);
        respBody = truncate(body.body || '');
      }
    } catch (_) {
      // body already discarded by browser
    }
  }

  session.queue.push({
    source: 'extension',
    method: info.method,
    url: info.url,
    statusCode: response.status || 200,
    reqHeaders: info.headers || {},
    reqBody,
    resHeaders: respHeaders,
    resBody: respBody
  });
  if (session.queue.length >= FLUSH_AT) await flush();
}

async function flush() {
  if (session.queue.length === 0) return;
  const { serverUrl, token, passiveScan } = await getConfig();
  if (!serverUrl) {
    session.lastError = 'missing server URL';
    await saveState();
    return;
  }
  const batch = session.queue.splice(0, FLUSH_AT);
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(`${serverUrl}/api/traffic/ingest`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        source: 'extension',
        passiveScan,
        exchanges: batch
      })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const out = await res.json();
    session.ingested += out.ingested || out.count || batch.length;
    session.passiveFindings += Array.isArray(out.passiveFindings) ? out.passiveFindings.length : 0;
    session.lastError = '';
  } catch (e) {
    session.queue = batch.concat(session.queue).slice(0, 200);
    session.lastError = e.message;
  }
  await saveState();
}

chrome.debugger.onEvent.addListener((source, method, params) => {
  if (!session.capturing || !source.tabId || source.tabId !== session.tabId) return;
  if (method === 'Network.requestWillBeSent') {
    session.requests.set(params.requestId, {
      requestId: params.requestId,
      method: params.request.method,
      url: params.request.url,
      headers: params.request.headers,
      postData: params.request.postData || ''
    });
  } else if (method === 'Network.responseReceived') {
    const info = session.requests.get(params.requestId);
    if (info) info.response = params.response;
  } else if (method === 'Network.loadingFinished') {
    const info = session.requests.get(params.requestId);
    session.requests.delete(params.requestId);
    if (!info || !info.response) return;
    queueExchange(info, info.response).catch(e => {
      session.lastError = e.message;
      saveState();
    });
  }
});

chrome.debugger.onDetach.addListener(source => {
  if (session.capturing && source.tabId === session.tabId) {
    session.capturing = false;
    session.tabId = null;
    session.lastError = 'debugger detached (DevTools opened?)';
    chrome.action.setBadgeText({ text: '' });
    saveState();
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    switch (msg?.type) {
      case 'getState': {
        sendResponse({
          capturing: session.capturing,
          tabId: session.tabId,
          ingested: session.ingested,
          passiveFindings: session.passiveFindings,
          failed: session.failed,
          queued: session.queue.length,
          lastError: session.lastError,
          configured: !!(await getConfig()).serverUrl
        });
        return;
      }
      case 'start':
        sendResponse(await start());
        return;
      case 'stop':
        sendResponse(await stop());
        return;
      case 'flushNow':
        await flush();
        sendResponse({
          capturing: session.capturing,
          tabId: session.tabId,
          ingested: session.ingested,
          passiveFindings: session.passiveFindings,
          failed: session.failed,
          queued: session.queue.length,
          lastError: session.lastError
        });
        return;
      default:
        sendResponse({ ok: false, error: 'unknown message' });
    }
  })();
  return true;
});
