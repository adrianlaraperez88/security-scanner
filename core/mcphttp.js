import { URL } from 'node:url';
import { validateTargetUrl, resolveAndValidateTarget, voidsExemption } from './validator.js';

export const MCP_PROTOCOL_VERSIONS = [
  '2025-11-25',
  '2025-06-18',
  '2024-11-05'
];

function isLoopbackIp(ip) {
  const clean = String(ip || '').trim().replace(/^\[|\]$/g, '').toLowerCase();
  return (
    clean === '::1' ||
    clean === '::ffff:127.0.0.1' ||
    /^127\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(clean)
  );
}

/**
 * Validates an MCP server URL against SSRF policy, allowing localhost/127.0.0.1/::1
 * only when `allowLocalhost: true` is explicitly configured.
 *
 * @param {string} rawUrl
 * @param {object} [options={}]
 * @param {boolean} [options.allowLocalhost=false]
 * @returns {{ valid: boolean, normalized: string, hostname: string }}
 */
export function validateMcpServerUrl(rawUrl, options = {}) {
  const allowLocalhost = Boolean(options.allowLocalhost);
  const res = validateTargetUrl(rawUrl);

  if (res.valid) {
    return res;
  }

  if (allowLocalhost && typeof rawUrl === 'string' && rawUrl.trim()) {
    const trimmed = rawUrl.trim();
    const preQueryHash = trimmed.split(/[?#]/)[0];
    const rawAuthority = trimmed.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '').split(/[/?#]/)[0];
    if (!preQueryHash.includes('\\') && !rawAuthority.includes('@')) {
      try {
        const parsed = new URL(trimmed);
        const rawHostNoPort = rawAuthority.replace(/:\d*$/, '').replace(/^\[|\]$/g, '').toLowerCase();
        const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
        const isLocal = (host === 'localhost' || host === '127.0.0.1' || host === '::1') && rawHostNoPort === host;
        if (
          isLocal &&
          (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
          !parsed.username &&
          !parsed.password
        ) {
          return {
            valid: true,
            normalized: parsed.toString().replace(/\/+$/, ''),
            hostname: parsed.hostname
          };
        }
      } catch {
        // Fall through to error
      }
    }
  }

  throw new Error(`Invalid or blocked MCP server URL: ${res.error || rawUrl}`);
}

/**
 * Parses a `text/event-stream` SSE body into an array of `{ event, data, id }` events.
 *
 * @param {string} sseText
 * @returns {Array<{ event: string, data: string, id?: string }>}
 */
export function parseSseEvents(sseText) {
  const events = [];
  const blocks = String(sseText || '').split(/\r?\n\r?\n/);

  for (const block of blocks) {
    if (!block.trim()) continue;
    let eventName = 'message';
    let eventId;
    const dataLines = [];

    for (const rawLine of block.split(/\r?\n/)) {
      if (rawLine.startsWith(':')) continue;
      const colonIdx = rawLine.indexOf(':');
      const field = colonIdx === -1 ? rawLine : rawLine.slice(0, colonIdx);
      const val = colonIdx === -1 ? '' : rawLine.slice(colonIdx + 1).replace(/^ /, '');

      if (field === 'event') eventName = val.trim();
      else if (field === 'id') eventId = val.trim();
      else if (field === 'data') dataLines.push(val);
    }

    if (dataLines.length > 0 || eventName !== 'message') {
      events.push({
        event: eventName,
        data: dataLines.join('\n'),
        ...(eventId !== undefined ? { id: eventId } : {})
      });
    }
  }

  return events;
}

/**
 * Sanitizes a server or tool identifier for safe `mcp__<serverName>__<toolName>` namespacing.
 */
function sanitizeMcpIdentifier(name) {
  return String(name || 'default')
    .trim()
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .replace(/^_+|_+$/g, '') || 'default';
}

/**
 * Zero-dependency MCP HTTP Client supporting both Streamable HTTP (`2025-11-25` / `2025-06-18`)
 * and Legacy SSE (`2024-11-05`) transports with SSRF protection.
 */
export class McpHttpClient {
  /**
   * @param {string|object} urlOrOptions
   * @param {object} [maybeOptions={}]
   */
  constructor(urlOrOptions, maybeOptions = {}) {
    const opts = typeof urlOrOptions === 'object' && urlOrOptions !== null
      ? urlOrOptions
      : { ...maybeOptions, url: urlOrOptions };

    this.allowLocalhost = Boolean(opts.allowLocalhost);
    this.dnsResolver = opts.dnsResolver ?? opts.dnsLookup ?? opts.resolver ?? null;
    const validated = validateMcpServerUrl(opts.url, { allowLocalhost: this.allowLocalhost });

    this.url = validated.normalized;
    this.hostname = validated.hostname;
    this.serverName = sanitizeMcpIdentifier(opts.serverName || opts.name || validated.hostname.split('.')[0]);
    this.transport = String(opts.transport || 'streamable-http').toLowerCase();
    this.protocolVersion = opts.protocolVersion || (this.transport === 'sse' ? '2024-11-05' : '2025-11-25');
    this.headers = opts.headers && typeof opts.headers === 'object' ? { ...opts.headers } : {};
    this.timeoutMs = Number(opts.timeoutMs) > 0 ? Number(opts.timeoutMs) : 30_000;
    this.maxOutputBytes = Number(opts.maxOutputBytes) > 0 ? Number(opts.maxOutputBytes) : 65_536;
    this.fetchImpl = typeof opts.fetch === 'function'
      ? opts.fetch
      : ((...args) => globalThis.fetch(...args));

    this.sessionId = opts.sessionId || null;
    this.messageEndpoint = null;
    this.initialized = false;
    this.serverInfo = null;
    this.capabilities = null;
    this.tools = null;
    this._nextId = 1;
  }

  /**
   * Reads a header case-insensitively from a Fetch Response headers object or plain object.
   */
  _getHeader(headers, name) {
    if (!headers) return null;
    if (typeof headers.get === 'function') {
      return headers.get(name) || headers.get(name.toLowerCase()) || null;
    }
    const lower = name.toLowerCase();
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === lower) return v;
    }
    return null;
  }

  /**
   * Validates an MCP URL syntactically and via DNS resolution, keeping allowLocalhost
   * strictly limited to literal loopback hostnames and loopback resolved IPs.
   */
  async _validateMcpTarget(rawUrl) {
    let syncValid;
    try {
      syncValid = validateMcpServerUrl(rawUrl, { allowLocalhost: this.allowLocalhost });
    } catch (err) {
      err.isSsrfError = true;
      throw err;
    }

    const cleanHost = syncValid.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
    const allowPrivate = Boolean(
      this.allowLocalhost &&
      (cleanHost === 'localhost' || cleanHost === '127.0.0.1' || cleanHost === '::1')
    );

    const resolved = await resolveAndValidateTarget(syncValid.normalized, {
      resolver: this.dnsResolver,
      allowPrivate
    });

    if (!resolved.valid) {
      const err = new Error(`Invalid or blocked MCP server URL: ${resolved.reason || resolved.error}`);
      err.isSsrfError = true;
      throw err;
    }

    if (allowPrivate && Array.isArray(resolved.resolvedIps)) {
      for (const ip of resolved.resolvedIps) {
        if (voidsExemption(ip) && !isLoopbackIp(ip)) {
          const err = new Error(
            `Invalid or blocked MCP server URL: Localhost resolved to non-loopback internal IP (${ip})`
          );
          err.isSsrfError = true;
          throw err;
        }
      }
    }

    return resolved;
  }

  /**
   * Discovers the POST message endpoint for Legacy SSE (`2024-11-05`) servers.
   */
  async _ensureSseEndpoint() {
    if (this.messageEndpoint) return this.messageEndpoint;

    await this._validateMcpTarget(this.url);
    const res = await this.fetchImpl(this.url, {
      method: 'GET',
      redirect: 'manual',
      headers: {
        Accept: 'text/event-stream',
        ...this.headers
      }
    });

    if (res && ((res.status >= 300 && res.status < 400) || res.type === 'opaqueredirect')) {
      const err = new Error(`MCP SSE handshake rejected HTTP ${res.status || 'redirect'} redirect by SSRF policy`);
      err.isSsrfError = true;
      throw err;
    }

    if (!res.ok) {
      throw new Error(`MCP SSE handshake failed with HTTP ${res.status}`);
    }

    const bodyText = typeof res.text === 'function' ? await res.text() : String(res.body || '');
    const events = parseSseEvents(bodyText);
    const endpointEvt = events.find(e => e.event === 'endpoint' && e.data);

    if (endpointEvt) {
      const resolvedUrl = new URL(endpointEvt.data.trim(), this.url).toString();
      const validEndpoint = await this._validateMcpTarget(resolvedUrl);
      this.messageEndpoint = validEndpoint.normalized;
    } else {
      this.messageEndpoint = this.url;
    }

    return this.messageEndpoint;
  }

  /**
   * Sends a JSON-RPC 2.0 request or notification over Streamable HTTP or Legacy SSE.
   *
   * @param {string} method
   * @param {object} [params]
   * @param {object} [options={}]
   * @param {boolean} [options.isNotification=false]
   */
  async _sendRpc(method, params = undefined, { isNotification = false } = {}) {
    const targetUrl = this.transport === 'sse'
      ? await this._ensureSseEndpoint()
      : this.url;

    await this._validateMcpTarget(targetUrl);

    const reqId = isNotification ? undefined : this._nextId++;
    const rpcPayload = {
      jsonrpc: '2.0',
      ...(reqId !== undefined ? { id: reqId } : {}),
      method,
      ...(params !== undefined ? { params } : {})
    };

    const reqHeaders = {
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
      ...this.headers
    };

    if (this.sessionId) {
      reqHeaders['Mcp-Session-Id'] = this.sessionId;
    }
    if (this.protocolVersion) {
      reqHeaders['MCP-Protocol-Version'] = this.protocolVersion;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await this.fetchImpl(targetUrl, {
        method: 'POST',
        redirect: 'manual',
        headers: reqHeaders,
        body: JSON.stringify(rpcPayload),
        signal: controller.signal
      });

      if (res && ((res.status >= 300 && res.status < 400) || res.type === 'opaqueredirect')) {
        const err = new Error(`MCP HTTP request rejected HTTP ${res.status || 'redirect'} redirect by SSRF policy`);
        err.isSsrfError = true;
        throw err;
      }

      const respSessionId = this._getHeader(res.headers, 'mcp-session-id');
      if (respSessionId) {
        this.sessionId = respSessionId;
      }

      if (isNotification && (res.status === 202 || res.status === 204 || res.status === 200)) {
        return null;
      }

      if (!res.ok) {
        const errText = typeof res.text === 'function' ? await res.text() : '';
        throw new Error(`MCP HTTP error ${res.status}: ${errText.slice(0, 300)}`);
      }

      const contentType = String(this._getHeader(res.headers, 'content-type') || '').toLowerCase();
      const rawText = typeof res.text === 'function'
        ? await res.text()
        : (res.body && typeof res.body === 'object' ? JSON.stringify(res.body) : String(res.body || ''));

      if (!rawText.trim() && isNotification) {
        return null;
      }

      let rpcResponse = null;

      if (contentType.includes('text/event-stream') || rawText.trimStart().startsWith('event:') || rawText.trimStart().startsWith('data:')) {
        const events = parseSseEvents(rawText);
        for (const evt of events) {
          if (!evt.data) continue;
          try {
            const parsed = JSON.parse(evt.data);
            if (Array.isArray(parsed)) {
              const match = parsed.find(item => item && (item.id === reqId || item.result || item.error));
              if (match) rpcResponse = match;
            } else if (parsed && typeof parsed === 'object') {
              if (parsed.id === reqId || (!rpcResponse && (parsed.result !== undefined || parsed.error !== undefined))) {
                rpcResponse = parsed;
              }
            }
          } catch {
            // Ignore non-JSON SSE data frames
          }
        }
      } else {
        const parsed = typeof res.json === 'function' && !rawText
          ? await res.json()
          : JSON.parse(rawText);
        if (Array.isArray(parsed)) {
          rpcResponse = parsed.find(item => item && (item.id === reqId || item.result !== undefined || item.error !== undefined)) || parsed[0];
        } else {
          rpcResponse = parsed;
        }
      }

      if (!rpcResponse) {
        throw new Error(`Empty or unparseable JSON-RPC response from MCP server for method "${method}"`);
      }

      if (rpcResponse.error) {
        const errMsg = rpcResponse.error.message || JSON.stringify(rpcResponse.error);
        const err = new Error(`MCP RPC Error (${rpcResponse.error.code ?? 'unknown'}): ${errMsg}`);
        err.code = rpcResponse.error.code;
        err.data = rpcResponse.error.data;
        throw err;
      }

      return rpcResponse.result ?? rpcResponse;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Initializes the MCP session (`initialize` + `notifications/initialized`),
   * negotiating Streamable HTTP (`2025-11-25` / `2025-06-18`) or Legacy SSE (`2024-11-05`).
   *
   * @param {object} [clientInfo={ name: 'security-scanner', version: '2.1.0' }]
   */
  async initialize(clientInfo = { name: 'security-scanner', version: '2.1.0' }) {
    const requestedVersion = this.protocolVersion || '2025-11-25';
    let result;

    try {
      result = await this._sendRpc('initialize', {
        protocolVersion: requestedVersion,
        capabilities: {},
        clientInfo
      });
    } catch (err) {
      // Fallback from 2025-11-25 to 2025-06-18 if server rejects newest version (never retry SSRF/redirect blocks)
      if (requestedVersion === '2025-11-25' && !err?.isSsrfError) {
        this.protocolVersion = '2025-06-18';
        result = await this._sendRpc('initialize', {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo
        });
      } else {
        throw err;
      }
    }

    if (result && typeof result === 'object') {
      if (result.protocolVersion) {
        this.protocolVersion = result.protocolVersion;
      }
      this.capabilities = result.capabilities || {};
      this.serverInfo = result.serverInfo || null;
    }

    // Send initialized notification (ignore errors if mock server doesn't handle notifications)
    try {
      await this._sendRpc('notifications/initialized', {}, { isNotification: true });
    } catch {
      // Non-fatal if test stub only handles request/response methods
    }

    this.initialized = true;
    return {
      protocolVersion: this.protocolVersion,
      sessionId: this.sessionId,
      capabilities: this.capabilities,
      serverInfo: this.serverInfo
    };
  }

  /**
   * Lists available tools from the remote MCP server (`tools/list`).
   *
   * @returns {Promise<Array<{ name: string, description: string, inputSchema: object }>>}
   */
  async listTools() {
    const allTools = [];
    let cursor;

    do {
      const params = cursor ? { cursor } : {};
      const result = await this._sendRpc('tools/list', params);
      const pageTools = Array.isArray(result?.tools)
        ? result.tools
        : (Array.isArray(result) ? result : []);

      for (const t of pageTools) {
        if (!t || typeof t !== 'object' || !t.name) continue;
        allTools.push({
          name: String(t.name),
          description: String(t.description || ''),
          inputSchema: t.inputSchema && typeof t.inputSchema === 'object'
            ? t.inputSchema
            : { type: 'object', properties: {} }
        });
      }

      cursor = result?.nextCursor || null;
    } while (cursor);

    this.tools = allTools;
    return allTools;
  }

  /**
   * Invokes a tool on the remote MCP server (`tools/call`).
   *
   * @param {string} name
   * @param {object} [args={}]
   */
  async callTool(name, args = {}) {
    if (!name || typeof name !== 'string') {
      throw new Error('MCP tool name must be a non-empty string');
    }

    // Allow passing either raw tool name or namespaced `mcp__<server>__<tool>`
    let rawToolName = name.trim();
    const nsPrefix = /^mcp__[^_]+__(.+)$/;
    const match = rawToolName.match(nsPrefix);
    if (match) {
      rawToolName = match[1];
    }

    const result = await this._sendRpc('tools/call', {
      name: rawToolName,
      arguments: args && typeof args === 'object' ? args : {}
    });

    const content = Array.isArray(result?.content) ? result.content : [];
    const textParts = content
      .filter(c => c && c.type === 'text' && typeof c.text === 'string')
      .map(c => c.text);
    let combinedText = textParts.join('\n');

    if (Buffer.byteLength(combinedText, 'utf8') > this.maxOutputBytes) {
      combinedText = Buffer.from(combinedText, 'utf8')
        .subarray(0, this.maxOutputBytes)
        .toString('utf8')
        .replace(/\uFFFD+$/, '') + '\n...[truncated]';
    }

    return {
      ...result,
      content,
      isError: Boolean(result?.isError),
      text: combinedText
    };
  }

  /**
   * Formats a list of tools into `mcp__<serverName>__<toolName>` namespaced descriptors.
   */
  _formatNamespacedTools(serverName, toolsList) {
    const safeServer = sanitizeMcpIdentifier(serverName || this.serverName);
    return (Array.isArray(toolsList) ? toolsList : []).map(tool => {
      const safeTool = sanitizeMcpIdentifier(tool.name);
      const namespacedName = `mcp__${safeServer}__${safeTool}`;
      return {
        name: namespacedName,
        namespacedName,
        originalName: tool.name,
        serverName: safeServer,
        description: tool.description || '',
        inputSchema: tool.inputSchema || { type: 'object', properties: {} },
        call: (args = {}) => this.callTool(tool.name, args),
        execute: (args = {}) => this.callTool(tool.name, args)
      };
    });
  }

  /**
   * Mounts tools as `mcp__<serverName>__<toolName>`.
   * Works synchronously if `listTools()` has already been called (or if `toolsList` is passed),
   * and also works with `await client.getNamespacedTools(serverName)` by auto-fetching `listTools()` when needed.
   *
   * @param {string} [serverName=this.serverName]
   * @param {Array<object>} [toolsList]
   */
  getNamespacedTools(serverName = this.serverName, toolsList = undefined) {
    if (Array.isArray(toolsList)) {
      return this._formatNamespacedTools(serverName, toolsList);
    }
    if (Array.isArray(this.tools)) {
      return this._formatNamespacedTools(serverName, this.tools);
    }
    return this.listTools().then(fetched => this._formatNamespacedTools(serverName, fetched));
  }

  /**
   * Closes the Streamable HTTP session via HTTP DELETE if a session ID is active.
   */
  async close() {
    if (this.sessionId && this.transport !== 'sse') {
      try {
        await this._validateMcpTarget(this.url);
        const res = await this.fetchImpl(this.url, {
          method: 'DELETE',
          redirect: 'manual',
          headers: {
            'Mcp-Session-Id': this.sessionId,
            ...this.headers
          }
        });
        if (res && ((res.status >= 300 && res.status < 400) || res.type === 'opaqueredirect')) {
          const err = new Error(`MCP session close rejected HTTP ${res.status || 'redirect'} redirect by SSRF policy`);
          err.isSsrfError = true;
          throw err;
        }
      } catch (err) {
        if (err?.isSsrfError) {
          throw err;
        }
        // Ignore transport errors on session close
      } finally {
        this.sessionId = null;
        this.initialized = false;
      }
    } else {
      this.sessionId = null;
      this.initialized = false;
    }
  }
}
