import crypto from 'node:crypto';
import { types } from 'node:util';
import vm from 'node:vm';

export const DOM_CANARY = 'secscan_dom_canary_9182';

const MAX_INPUT_CHARS = 131072;
const MAX_SCRIPT_BLOCKS = 40;
const MAX_SINK_CALLS = 50;
const MAX_SANDBOX_ERRORS = 20;
const DEFAULT_TIMEOUT_MS = 120;
const DEFAULT_TOTAL_BUDGET_MS = 600;

const ALLOWED_SINKS = new Set([
  'innerHTML',
  'outerHTML',
  'insertAdjacentHTML',
  'document.write',
  'document.writeln',
  'eval',
  'setTimeout',
  'setInterval'
]);

const ALLOWED_SCRIPT_TYPES = new Set([
  '',
  'text/javascript',
  'application/javascript',
  'application/ecmascript',
  'text/ecmascript',
  'module'
]);

/**
 * Extracts executable JS script blocks from HTML using an O(n) linear scan,
 * or treats non-markup raw JS input as a single script block.
 *
 * @param {string} rawInput
 * @returns {string[]}
 */
function extractScriptBlocks(rawInput) {
  const bounded = String(rawInput || '').slice(0, MAX_INPUT_CHARS);
  if (!bounded.trim()) return [];

  const lower = bounded.toLowerCase();
  const blocks = [];
  let cursor = 0;

  while (cursor < lower.length && blocks.length < MAX_SCRIPT_BLOCKS) {
    const startIdx = lower.indexOf('<script', cursor);
    if (startIdx === -1) break;

    const afterTag = lower[startIdx + 7];
    if (afterTag && afterTag !== '>' && afterTag !== '/' && !/\s/.test(afterTag)) {
      cursor = startIdx + 7;
      continue;
    }

    const openEnd = bounded.indexOf('>', startIdx + 7);
    if (openEnd === -1) break;

    const attrs = bounded.slice(startIdx + 7, openEnd);
    const trimmedAttrs = attrs.trimEnd();
    if (trimmedAttrs.endsWith('/')) {
      cursor = openEnd + 1;
      continue;
    }

    const typeMatch = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);
    const scriptType = (typeMatch?.[1] ?? typeMatch?.[2] ?? typeMatch?.[3] ?? '').trim().toLowerCase();

    const closeIdx = lower.indexOf('</script', openEnd + 1);
    if (closeIdx === -1) break;
    const closeEnd = bounded.indexOf('>', closeIdx + 8);
    if (closeEnd === -1) break;

    if (ALLOWED_SCRIPT_TYPES.has(scriptType)) {
      const code = bounded.slice(openEnd + 1, closeIdx);
      if (code.trim().length > 0) {
        blocks.push(code);
      }
    }

    cursor = closeEnd + 1;
  }

  if (blocks.length === 0 && lower.indexOf('<script') === -1 && !/^\s*</.test(bounded)) {
    blocks.push(bounded);
  }

  return blocks;
}

const SANDBOX_BOOTSTRAP_SOURCE = `
'use strict';
(function (g) {
  const CANARY = ${JSON.stringify(DOM_CANARY)};
  const HTML_TAINT_TAG = '<' + CANARY + '>';
  const MAX_CALLS = ${MAX_SINK_CALLS};
  const _String = String;
  const _create = Object.create;
  const _defineProperty = Object.defineProperty;
  const _freeze = Object.freeze;
  const _stringify = JSON.stringify;
  const _push = Array.prototype.push;
  const _includes = String.prototype.includes;
  const _slice = String.prototype.slice;
  const _toLowerCase = String.prototype.toLowerCase;
  const _split = String.prototype.split;
  const _replace = String.prototype.replace;
  const _decodeURIComponent = decodeURIComponent;

  const HTML_SINKS = _create(null);
  HTML_SINKS.innerHTML = true;
  HTML_SINKS.outerHTML = true;
  HTML_SINKS.insertAdjacentHTML = true;
  HTML_SINKS['document.write'] = true;
  HTML_SINKS['document.writeln'] = true;

  const JS_SINKS = _create(null);
  JS_SINKS.eval = true;
  JS_SINKS.setTimeout = true;
  JS_SINKS.setInterval = true;

  let runNonce = '';
  let nonceLocked = false;
  let currentSourceType = 'direct_dom';
  let serializedEntries = '';
  let entryCount = 0;
  const messageListeners = [];
  const readyListeners = [];
  const elementsById = _create(null);
  const elementsBySelector = _create(null);

  function safeToString(val) {
    if (typeof val === 'string') return val;
    if (val === null || val === undefined) return '';
    try {
      return _String(val);
    } catch {
      return '';
    }
  }

  function recordSink(sink, rawValue) {
    if (entryCount >= MAX_CALLS || typeof sink !== 'string') return;
    const str = safeToString(rawValue);
    if (!str) return;
    if (HTML_SINKS[sink]) {
      if (!_includes.call(str, HTML_TAINT_TAG)) return;
    } else if (JS_SINKS[sink]) {
      if (!_includes.call(str, CANARY)) return;
    } else {
      return;
    }
    const preview = _slice.call(str, 0, 160);
    const phase = typeof currentSourceType === 'string' ? currentSourceType : 'direct_dom';
    const rowJson =
      '{"sink":' + _stringify(sink) +
      ',"valuePreview":' + _stringify(preview) +
      ',"sourceType":' + _stringify(phase) +
      ',"nonce":' + _stringify(runNonce) + '}';
    serializedEntries += (entryCount > 0 ? ',' : '') + rowJson;
    entryCount++;
  }

  function createMockElement(tagName) {
    const el = {
      tagName: safeToString(tagName || 'DIV').toUpperCase(),
      id: '',
      className: '',
      textContent: '',
      innerText: '',
      value: '',
      style: {},
      dataset: {},
      attributes: {},
      children: [],
      setAttribute: function (k, v) {
        this.attributes[safeToString(k)] = safeToString(v);
      },
      getAttribute: function (k) {
        return this.attributes[safeToString(k)] ?? null;
      },
      appendChild: function (child) {
        _push.call(this.children, child);
        return child;
      },
      removeChild: function (child) {
        return child;
      },
      addEventListener: function () {},
      removeEventListener: function () {},
      focus: function () {},
      click: function () {},
      querySelector: function (sel) {
        return getOrCreateSelectorElement(sel);
      },
      querySelectorAll: function (sel) {
        return [getOrCreateSelectorElement(sel)];
      },
      insertAdjacentHTML: function (_position, html) {
        recordSink('insertAdjacentHTML', html);
      }
    };

    let innerVal = '';
    let outerVal = '';
    _defineProperty(el, 'innerHTML', {
      enumerable: true,
      configurable: true,
      get: function () { return innerVal; },
      set: function (v) {
        innerVal = safeToString(v);
        recordSink('innerHTML', v);
      }
    });
    _defineProperty(el, 'outerHTML', {
      enumerable: true,
      configurable: true,
      get: function () { return outerVal; },
      set: function (v) {
        outerVal = safeToString(v);
        recordSink('outerHTML', v);
      }
    });
    return el;
  }

  function getOrCreateSelectorElement(sel) {
    const key = safeToString(sel || 'div');
    if (!elementsBySelector[key]) {
      elementsBySelector[key] = createMockElement('DIV');
    }
    return elementsBySelector[key];
  }

  const locationHref = 'https://target.local/?q=' + HTML_TAINT_TAG + '#' + HTML_TAINT_TAG;
  const locationObj = {
    href: locationHref,
    hash: '#' + HTML_TAINT_TAG,
    search: '?q=' + HTML_TAINT_TAG,
    pathname: '/',
    origin: 'https://target.local',
    hostname: 'target.local',
    host: 'target.local',
    protocol: 'https:',
    port: '',
    assign: function () {},
    replace: function () {},
    reload: function () {},
    toString: function () { return this.href; }
  };

  const documentObj = {
    URL: locationHref,
    documentURI: locationHref,
    referrer: 'https://target.local/' + HTML_TAINT_TAG,
    domain: 'target.local',
    title: '',
    cookie: '',
    readyState: 'complete',
    location: locationObj,
    body: createMockElement('BODY'),
    head: createMockElement('HEAD'),
    documentElement: createMockElement('HTML'),
    getElementById: function (id) {
      const key = safeToString(id);
      if (!elementsById[key]) {
        const el = createMockElement('DIV');
        el.id = key;
        elementsById[key] = el;
      }
      return elementsById[key];
    },
    querySelector: function (sel) {
      return getOrCreateSelectorElement(sel);
    },
    querySelectorAll: function (sel) {
      return [getOrCreateSelectorElement(sel)];
    },
    getElementsByClassName: function (cls) {
      return [getOrCreateSelectorElement('.' + safeToString(cls))];
    },
    getElementsByTagName: function (tag) {
      return [createMockElement(tag)];
    },
    createElement: function (tag) {
      return createMockElement(tag);
    },
    createTextNode: function (txt) {
      return { nodeType: 3, textContent: safeToString(txt) };
    },
    write: function () {
      let combined = '';
      for (let i = 0; i < arguments.length; i++) {
        combined += safeToString(arguments[i]);
      }
      recordSink('document.write', combined);
    },
    writeln: function () {
      let combined = '';
      for (let i = 0; i < arguments.length; i++) {
        combined += safeToString(arguments[i]);
      }
      recordSink('document.writeln', combined);
    },
    addEventListener: function (type, fn) {
      const ev = _toLowerCase.call(safeToString(type));
      if (ev === 'domcontentloaded' && typeof fn === 'function' && readyListeners.length < 20) {
        _push.call(readyListeners, fn);
      }
    },
    removeEventListener: function () {}
  };

  function MockURLSearchParams(init) {
    this._pairs = [];
    let raw = safeToString(init);
    if (raw.charAt(0) === '?') raw = _slice.call(raw, 1);
    if (!raw) return;
    const parts = _split.call(raw, '&');
    for (let i = 0; i < parts.length; i++) {
      if (!parts[i]) continue;
      const eq = parts[i].indexOf('=');
      const k = eq === -1 ? parts[i] : _slice.call(parts[i], 0, eq);
      const v = eq === -1 ? '' : _slice.call(parts[i], eq + 1);
      let dk = k;
      let dv = v;
      try { dk = _decodeURIComponent(_replace.call(k, /\\+/g, ' ')); } catch {}
      try { dv = _decodeURIComponent(_replace.call(v, /\\+/g, ' ')); } catch {}
      _push.call(this._pairs, [dk, dv]);
    }
  }
  MockURLSearchParams.prototype.get = function (name) {
    const key = safeToString(name);
    for (let i = 0; i < this._pairs.length; i++) {
      if (this._pairs[i][0] === key) return this._pairs[i][1];
    }
    return null;
  };
  MockURLSearchParams.prototype.getAll = function (name) {
    const key = safeToString(name);
    const out = [];
    for (let i = 0; i < this._pairs.length; i++) {
      if (this._pairs[i][0] === key) _push.call(out, this._pairs[i][1]);
    }
    return out;
  };
  MockURLSearchParams.prototype.has = function (name) {
    return this.get(name) !== null;
  };

  function MockURL(raw, base) {
    const str = safeToString(raw || base || locationHref);
    const qIdx = str.indexOf('?');
    const hIdx = str.indexOf('#');
    let searchPart = '';
    let hashPart = '';
    if (qIdx !== -1 && (hIdx === -1 || qIdx < hIdx)) {
      searchPart = hIdx === -1 ? _slice.call(str, qIdx) : _slice.call(str, qIdx, hIdx);
    }
    if (hIdx !== -1) {
      hashPart = _slice.call(str, hIdx);
    }
    this.href = str;
    this.origin = 'https://target.local';
    this.protocol = 'https:';
    this.host = 'target.local';
    this.hostname = 'target.local';
    this.pathname = '/';
    this.search = searchPart;
    this.hash = hashPart;
    this.searchParams = new MockURLSearchParams(searchPart);
  }
  MockURL.prototype.toString = function () { return this.href; };

  const mockEval = function (code) {
    if (typeof code === 'string') {
      recordSink('eval', code);
      return undefined;
    }
    return code;
  };

  const mockSetTimeout = function (fnOrStr) {
    if (typeof fnOrStr === 'string') {
      recordSink('setTimeout', fnOrStr);
    }
    return 1;
  };

  const mockSetInterval = function (fnOrStr) {
    if (typeof fnOrStr === 'string') {
      recordSink('setInterval', fnOrStr);
    }
    return 1;
  };

  const addWindowListener = function (type, fn) {
    const ev = _toLowerCase.call(safeToString(type));
    if (ev === 'message' && typeof fn === 'function' && messageListeners.length < 20) {
      _push.call(messageListeners, fn);
    } else if ((ev === 'load' || ev === 'domcontentloaded') && typeof fn === 'function' && readyListeners.length < 20) {
      _push.call(readyListeners, fn);
    }
  };

  g.globalThis = g;
  g.window = g;
  g.self = g;
  g.name = HTML_TAINT_TAG;
  g.origin = 'https://target.local';
  g.location = locationObj;
  g.document = documentObj;
  g.eval = mockEval;
  g.setTimeout = mockSetTimeout;
  g.setInterval = mockSetInterval;
  g.clearTimeout = function () {};
  g.clearInterval = function () {};
  g.requestAnimationFrame = function () { return 1; };
  g.addEventListener = addWindowListener;
  g.removeEventListener = function () {};
  g.postMessage = function () {};
  g.URL = MockURL;
  g.URLSearchParams = MockURLSearchParams;
  g.navigator = { userAgent: 'Mozilla/5.0', language: 'en-US' };
  g.console = { log: function () {}, warn: function () {}, error: function () {}, info: function () {}, debug: function () {} };

  function SyncPromise(executor) {
    let state = 'pending';
    let value;
    function resolve(v) {
      if (state === 'pending') {
        state = 'fulfilled';
        value = v;
      }
    }
    function reject(e) {
      if (state === 'pending') {
        state = 'rejected';
        value = e;
      }
    }
    if (typeof executor === 'function') {
      try {
        executor(resolve, reject);
      } catch (e) {
        reject(e);
      }
    }
    this.then = function (onFulfilled, onRejected) {
      if (state === 'fulfilled' && typeof onFulfilled === 'function') {
        return SyncPromise.resolve(onFulfilled(value));
      }
      if (state === 'rejected' && typeof onRejected === 'function') {
        return SyncPromise.resolve(onRejected(value));
      }
      return this;
    };
    this.catch = function (onRejected) {
      return this.then(null, onRejected);
    };
    this.finally = function (onFinally) {
      if (typeof onFinally === 'function') onFinally();
      return this;
    };
  }
  SyncPromise.resolve = function (v) {
    return new SyncPromise(function (res) {
      res(v);
    });
  };
  SyncPromise.reject = function (e) {
    return new SyncPromise(function (_res, rej) {
      rej(e);
    });
  };
  SyncPromise.all = function () {
    return SyncPromise.resolve([]);
  };
  SyncPromise.race = function () {
    return SyncPromise.resolve(undefined);
  };
  g.Promise = SyncPromise;
  g.queueMicrotask = function (fn) {
    if (typeof fn === 'function') fn();
  };

  _defineProperty(g, '__secscan_bridge__', {
    value: _freeze({
      getReadyCount: function () {
        return readyListeners.length;
      },
      dispatchReadyAt: function (idx) {
        const fn = readyListeners[idx];
        if (typeof fn === 'function') {
          fn.call(g, { type: 'DOMContentLoaded', target: documentObj });
        }
      },
      beginPostMessagePhase: function () {
        currentSourceType = 'postmessage';
        return messageListeners.length;
      },
      dispatchMessageAt: function (idx) {
        const fn = messageListeners[idx];
        if (typeof fn === 'function') {
          fn.call(g, {
            type: 'message',
            data: HTML_TAINT_TAG,
            origin: 'https://untrusted.secscan.invalid',
            source: null
          });
        }
      },
      extractJson: function () {
        return '[' + serializedEntries + ']';
      }
    }),
    writable: false,
    configurable: false,
    enumerable: false
  });

  return function setRunNonce(nonce) {
    if (nonceLocked) return;
    runNonce = safeToString(nonce);
    nonceLocked = true;
  };
})(this);
`;

const BOOTSTRAP_SCRIPT = new vm.Script(SANDBOX_BOOTSTRAP_SOURCE);
const READY_COUNT_SCRIPT = new vm.Script('__secscan_bridge__.getReadyCount()');
const BEGIN_PM_SCRIPT = new vm.Script('__secscan_bridge__.beginPostMessagePhase()');
const EXTRACT_JSON_SCRIPT = new vm.Script('__secscan_bridge__.extractJson()');

function extractSafeSandboxErrorMessage(err) {
  if (typeof err === 'string') {
    return err.slice(0, 200);
  }
  if (!err || typeof err !== 'object' || types.isProxy(err)) {
    return 'Sandbox guest exception';
  }
  if (err instanceof Error || types.isNativeError(err)) {
    const desc = Object.getOwnPropertyDescriptor(err, 'message');
    if (desc && !desc.get && !desc.set && typeof desc.value === 'string' && desc.value) {
      return desc.value.slice(0, 200);
    }
    return 'Sandbox native error';
  }
  return 'Sandbox guest exception';
}

/**
 * Executes script blocks from an HTML or JS payload inside a hardened `node:vm`
 * sandbox (`codeGeneration: { strings: false, wasm: false }`, `microtaskMode: 'afterEvaluate'`)
 * to verify whether tainted DOM sources or untrusted `postMessage` events actually reach execution sinks.
 *
 * @param {string} htmlOrScriptText
 * @param {{ timeoutMs?: number, totalBudgetMs?: number }} [options={}]
 * @returns {{
 *   executedScriptsCount: number,
 *   taintedSinkCalls: Array<{
 *     sink: string,
 *     valuePreview: string,
 *     sourceType: 'direct_dom' | 'postmessage',
 *     runtimeVerified: true
 *   }>,
 *   sandboxErrors: string[]
 * }}
 */
export function verifyDomSinksInSandbox(htmlOrScriptText, options = {}) {
  const scripts = extractScriptBlocks(htmlOrScriptText);
  if (scripts.length === 0) {
    return {
      executedScriptsCount: 0,
      taintedSinkCalls: [],
      sandboxErrors: []
    };
  }

  const timeoutMs = Number.isFinite(Number(options.timeoutMs)) && Number(options.timeoutMs) > 0
    ? Math.min(Number(options.timeoutMs), 1000)
    : DEFAULT_TIMEOUT_MS;
  const totalBudgetMs = Number.isFinite(Number(options.totalBudgetMs)) && Number(options.totalBudgetMs) > 0
    ? Math.min(Number(options.totalBudgetMs), 3000)
    : DEFAULT_TOTAL_BUDGET_MS;

  const sandboxErrors = [];
  const pushError = (err) => {
    if (sandboxErrors.length < MAX_SANDBOX_ERRORS) {
      sandboxErrors.push(extractSafeSandboxErrorMessage(err));
    }
  };

  const runOpts = { timeout: timeoutMs, displayErrors: false };
  const runNonce = crypto.randomBytes(16).toString('hex');
  const ctx = vm.createContext(Object.create(null), {
    codeGeneration: { strings: false, wasm: false },
    microtaskMode: 'afterEvaluate'
  });

  const startedAt = Date.now();
  let executedScriptsCount = 0;

  try {
    const setRunNonce = BOOTSTRAP_SCRIPT.runInContext(ctx, runOpts);
    if (typeof setRunNonce === 'function') {
      setRunNonce(runNonce);
    }

    for (const rawCode of scripts) {
      if (Date.now() - startedAt >= totalBudgetMs) {
        pushError('Sandbox total execution budget exceeded');
        break;
      }
      try {
        const code = String(rawCode)
          .replace(/\basync\s+(?=function\b|\([^)]*\)\s*=>|[A-Za-z_$][A-Za-z0-9_$]*\s*=>)/g, '')
          .replace(/\bawait\s+/g, '');
        const script = new vm.Script(code);
        executedScriptsCount++;
        script.runInContext(ctx, runOpts);
      } catch (err) {
        pushError(err);
      }
    }

    // Dispatch DOMContentLoaded / load handlers registered during script evaluation
    try {
      const readyCount = Number(READY_COUNT_SCRIPT.runInContext(ctx, runOpts)) || 0;
      for (let i = 0; i < readyCount; i++) {
        if (Date.now() - startedAt >= totalBudgetMs) break;
        try {
          new vm.Script(`__secscan_bridge__.dispatchReadyAt(${i})`).runInContext(ctx, runOpts);
        } catch (err) {
          pushError(err);
        }
      }
    } catch (err) {
      pushError(err);
    }

    // Dispatch synthetic untrusted MessageEvent to each registered 'message' listener
    try {
      const listenerCount = Number(BEGIN_PM_SCRIPT.runInContext(ctx, runOpts)) || 0;
      for (let i = 0; i < listenerCount; i++) {
        if (Date.now() - startedAt >= totalBudgetMs) {
          pushError('Sandbox total execution budget exceeded during postMessage dispatch');
          break;
        }
        try {
          new vm.Script(`__secscan_bridge__.dispatchMessageAt(${i})`).runInContext(ctx, runOpts);
        } catch (err) {
          pushError(err);
        }
      }
    } catch (err) {
      pushError(err);
    }

    let taintedSinkCalls = [];
    try {
      const jsonStr = EXTRACT_JSON_SCRIPT.runInContext(ctx, runOpts);
      const parsed = JSON.parse(String(jsonStr || '[]'));
      if (Array.isArray(parsed)) {
        taintedSinkCalls = parsed
          .filter(
            c =>
              c &&
              typeof c === 'object' &&
              c.nonce === runNonce &&
              typeof c.sink === 'string' &&
              ALLOWED_SINKS.has(c.sink)
          )
          .map(c => ({
            sink: c.sink,
            valuePreview: String(c.valuePreview || '').slice(0, 160),
            sourceType: c.sourceType === 'postmessage' ? 'postmessage' : 'direct_dom',
            runtimeVerified: true
          }));
      }
    } catch (err) {
      pushError(err);
    }

    return {
      executedScriptsCount,
      taintedSinkCalls,
      sandboxErrors
    };
  } catch (err) {
    pushError(err);
    return {
      executedScriptsCount,
      taintedSinkCalls: [],
      sandboxErrors
    };
  }
}
