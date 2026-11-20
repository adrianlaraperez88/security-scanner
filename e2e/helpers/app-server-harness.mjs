import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startServer } from '../../core/server.js';

/**
 * Starts `core/server.js` bound strictly to `127.0.0.1:0` with isolated temp storage
 * and deterministic cleanup of keep-alive sockets, SQLite stores, and temp dirs.
 *
 * @param {object} [options]
 */
export async function startAppHarness(options = {}) {
  const ownTmpDir = !options.historyDir;
  const historyDir = options.historyDir || fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-e2e-srv-'));

  const serverOpts = {
    port: 0,
    host: '127.0.0.1',
    historyDir,
    ...options
  };

  const started = await startServer(serverOpts);
  const { server, port, host, url: baseUrl } = started;

  async function fetchApi(pathname, init = {}) {
    const targetUrl = pathname.startsWith('http://') || pathname.startsWith('https://')
      ? pathname
      : `${baseUrl}${pathname.startsWith('/') ? '' : '/'}${pathname}`;
    return fetch(targetUrl, init);
  }

  async function jsonFetch(pathname, init = {}) {
    const headers = { ...(init.headers || {}) };
    let body = init.body;
    if (body !== undefined && body !== null && typeof body !== 'string' && !Buffer.isBuffer(body)) {
      body = JSON.stringify(body);
      if (!Object.keys(headers).some(k => k.toLowerCase() === 'content-type')) {
        headers['Content-Type'] = 'application/json';
      }
    } else if (body !== undefined && !Object.keys(headers).some(k => k.toLowerCase() === 'content-type')) {
      headers['Content-Type'] = 'application/json';
    }

    const res = await fetchApi(pathname, { ...init, headers, body });
    const text = await res.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = null;
    }
    return {
      status: res.status,
      ok: res.ok,
      headers: res.headers,
      text,
      data
    };
  }

  async function readSse(pathname, sseOpts = {}) {
    const { timeoutMs = 30000, stopOnEvent = null } = sseOpts;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetchApi(pathname, { signal: controller.signal });
      if (!res.ok) {
        throw new Error(`SSE request failed with status ${res.status}`);
      }
      const events = [];
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      const processBlock = block => {
        const lines = block.split(/\r?\n/);
        let eventName = 'message';
        const dataLines = [];
        for (const line of lines) {
          if (line.startsWith('event:')) {
            eventName = line.slice(6).trim();
          } else if (line.startsWith('data:')) {
            dataLines.push(line.slice(5).trim());
          }
        }
        if (dataLines.length === 0) return null;
        const rawData = dataLines.join('\n');
        let parsed = rawData;
        try {
          parsed = JSON.parse(rawData);
        } catch {
          // keep raw string
        }
        const evt = { event: eventName, data: parsed, raw: rawData };
        events.push(evt);
        return evt;
      };

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let sepIdx;
        while ((sepIdx = buffer.search(/\r?\n\r?\n/)) !== -1) {
          const block = buffer.slice(0, sepIdx);
          const sepMatch = buffer.slice(sepIdx).match(/^\r?\n\r?\n/);
          buffer = buffer.slice(sepIdx + (sepMatch ? sepMatch[0].length : 2));
          const evt = processBlock(block);
          if (evt && stopOnEvent && evt.event === stopOnEvent) {
            await reader.cancel().catch(() => {});
            controller.abort();
            return events;
          }
        }
      }

      if (buffer.trim()) {
        processBlock(buffer.trim());
      }
      return events;
    } catch (err) {
      if (err.name === 'AbortError' && stopOnEvent) {
        return [];
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  async function close() {
    server.closeAllConnections?.();
    await new Promise(resolve => server.close(() => resolve()));
    if (ownTmpDir) {
      fs.rmSync(historyDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  }

  return {
    baseUrl,
    port,
    host,
    historyDir,
    server,
    fetchApi,
    jsonFetch,
    readSse,
    close
  };
}

export async function withAppHarness(options, fn) {
  const harness = await startAppHarness(options);
  try {
    return await fn(harness);
  } finally {
    await harness.close();
  }
}
