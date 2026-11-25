const $ = id => document.getElementById(id);

async function refreshState() {
  const st = await chrome.runtime.sendMessage({ type: 'getState' });
  if (!st) return;
  const lines = [];
  lines.push(st.capturing ? `● Recording tab ${st.tabId}` : '○ Idle (Not recording)');
  lines.push(`ingested: ${st.ingested || 0} · passive findings: ${st.passiveFindings || 0} · queued: ${st.queued || 0}`);
  if (st.lastError) lines.push(st.lastError);
  $('status').textContent = lines.join('\n');
  $('error').textContent = st.capturing ? '' : (st.lastError || '');
}

$('save').addEventListener('click', async () => {
  await chrome.storage.local.set({
    serverUrl: $('serverUrl').value.trim() || 'http://127.0.0.1:4321',
    token: $('token').value.trim(),
    passiveScan: $('passiveScan').checked
  });
  $('save').textContent = 'Saved ✓';
  setTimeout(() => ($('save').textContent = 'Save'), 1200);
});

$('start').addEventListener('click', async () => {
  const out = await chrome.runtime.sendMessage({ type: 'start' });
  if (out && out.ok === false) $('error').textContent = out.error || 'failed to start';
  refreshState();
});

$('stop').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'stop' });
  refreshState();
});

$('flush').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'flushNow' });
  refreshState();
});

(async () => {
  const { serverUrl = 'http://127.0.0.1:4321', token = '', passiveScan = true } =
    await chrome.storage.local.get(['serverUrl', 'token', 'passiveScan']);
  $('serverUrl').value = serverUrl;
  $('token').value = token;
  $('passiveScan').checked = passiveScan !== false;
  refreshState();
  setInterval(refreshState, 1500);
})();
