import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';

import {
  INLINE_BODY_LIMIT,
  TrafficStore,
  isValidSha256,
  stripHopByHopHeaders
} from '../../core/traffic.js';

import {
  MAX_DECOMPRESS_BYTES,
  decompressBodyBuffer,
  normalizeEvidenceWhitespace,
  assessFindingVerification,
  EvidenceStore
} from '../../core/evidence.js';

describe('Step 2.3 — TrafficStore (SQLite + FTS5, Blob Spill, Rewrite Engine & RFC-9110 Replay)', () => {
  let tmpDir;
  let store;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-traffic-test-'));
    store = new TrafficStore({
      dbPath: ':memory:',
      blobDir: path.join(tmpDir, 'traffic-blobs'),
      hmacSecret: 'test-hmac-secret-key-for-traffic'
    });
  });

  afterEach(() => {
    if (store) store.close();
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('records inline exchanges, indexes in FTS5, supports substring LIKE fallback, and aggregates hosts', () => {
    const ex1 = store.recordExchange({
      taskId: 'task-1',
      source: 'scanner',
      method: 'POST',
      url: 'https://api.example.com/v1/auth/login?debug=1',
      statusCode: 200,
      reqHeaders: {
        'Content-Type': 'application/json',
        'X-Correlation-Id': 'corr-alpha-98765'
      },
      resHeaders: {
        'Content-Type': 'application/json',
        'Set-Cookie': 'sid=sec_tok_abcdef123456; HttpOnly'
      },
      reqBody: JSON.stringify({ username: 'auditor', role: 'security_reviewer' }),
      resBody: JSON.stringify({ ok: true, banner: 'Welcome to ExampleCorp Internal Gateway' }),
      durationMs: 42.5
    });

    const ex2 = store.recordExchange({
      taskId: 'task-1',
      source: 'scanner',
      method: 'GET',
      url: 'https://api.example.com/v1/users/profile',
      statusCode: 403,
      reqHeaders: { Authorization: 'Bearer jwt_eyJhbGciOiJIUzI1NiJ9' },
      resHeaders: { 'Content-Type': 'text/plain' },
      reqBody: '',
      resBody: 'Access denied: insufficient privileges for administrative endpoint',
      durationMs: 15.2
    });

    const ex3 = store.recordExchange({
      taskId: 'task-2',
      source: 'extension',
      method: 'GET',
      url: 'https://cdn.other.org/assets/app.js',
      statusCode: 502,
      reqHeaders: {},
      resHeaders: { 'Content-Type': 'text/html' },
      reqBody: '',
      resBody: 'Bad Gateway upstream timeout',
      durationMs: 120.0
    });

    assert.ok(ex1.id);
    assert.equal(ex1.reqBlobSha256, null);
    assert.equal(ex1.resBlobSha256, null);
    assert.equal(ex1.host, 'api.example.com');
    assert.equal(ex1.path, '/v1/auth/login?debug=1');

    // FTS5 token search across headers and bodies
    const ftsHits = store.queryExchanges({ search: 'ExampleCorp Internal Gateway' });
    assert.equal(ftsHits.length, 1);
    assert.equal(ftsHits[0].id, ex1.id);
    assert.equal(ftsHits.total, 1);

    // FTS5 search with punctuation / special tokens that require safe quoting
    const specialSearchHits = store.queryExchanges({ search: 'corr-alpha-98765 "security_reviewer"' });
    assert.equal(specialSearchHits.length, 1);
    assert.equal(specialSearchHits[0].id, ex1.id);

    // Arbitrary mid-word substring search via LIKE fallback
    const substringHits = store.queryExchanges({ search: 'tok_abcdef12' });
    assert.equal(substringHits.length, 1);
    assert.equal(substringHits[0].id, ex1.id);

    // Filter facets: taskId, host, method, status class ('4xx')
    const facetHits = store.queryExchanges({
      taskId: 'task-1',
      host: 'api.example.com',
      method: 'GET',
      status: '4xx'
    });
    assert.equal(facetHits.length, 1);
    assert.equal(facetHits[0].id, ex2.id);

    // Host aggregation and status breakdown
    const hosts = store.listHosts();
    assert.equal(hosts.length, 2);
    const apiHost = hosts.find(h => h.host === 'api.example.com');
    assert.ok(apiHost);
    assert.equal(apiHost.count, 2);
    assert.equal(apiHost.statusBreakdown['2xx'], 1);
    assert.equal(apiHost.statusBreakdown['4xx'], 1);

    const cdnHost = hosts.find(h => h.host === 'cdn.other.org');
    assert.ok(cdnHost);
    assert.equal(cdnHost.count, 1);
    assert.equal(cdnHost.statusBreakdown['5xx'], 1);
    assert.equal(ex3.source, 'extension');
  });

  it('spills request and response bodies > 256 KiB to content-addressed SHA-256 blobs and rejects path traversal', () => {
    const largeReqPayload = 'REQ_START_' + 'A'.repeat(INLINE_BODY_LIMIT + 4096) + '_REQ_END';
    const largeResPayload = 'RES_START_' + 'B'.repeat(INLINE_BODY_LIMIT + 8192) + '_RES_END';

    const expectedReqSha = crypto.createHash('sha256').update(largeReqPayload).digest('hex');
    const expectedResSha = crypto.createHash('sha256').update(largeResPayload).digest('hex');

    const recorded = store.recordExchange({
      method: 'POST',
      url: 'https://upload.example.com/bulk',
      statusCode: 201,
      reqBody: largeReqPayload,
      resBody: largeResPayload
    });

    assert.equal(recorded.reqBlobSha256, expectedReqSha);
    assert.equal(recorded.resBlobSha256, expectedResSha);

    // Verify inline columns in SQLite are NULL when spilled to disk
    const rawBodyRow = store.db
      .prepare('SELECT req_body_inline, res_body_inline, req_blob_sha256, res_blob_sha256 FROM exchange_bodies WHERE exchange_id = ?')
      .get(recorded.id);
    assert.equal(rawBodyRow.req_body_inline, null);
    assert.equal(rawBodyRow.res_body_inline, null);
    assert.equal(rawBodyRow.req_blob_sha256, expectedReqSha);
    assert.equal(rawBodyRow.res_blob_sha256, expectedResSha);

    // Verify exact file paths on disk: <blobDir>/sha256/<first2>/<sha256>.bin
    const reqBlobFile = path.join(
      tmpDir,
      'traffic-blobs',
      'sha256',
      expectedReqSha.slice(0, 2),
      `${expectedReqSha}.bin`
    );
    const resBlobFile = path.join(
      tmpDir,
      'traffic-blobs',
      'sha256',
      expectedResSha.slice(0, 2),
      `${expectedResSha}.bin`
    );
    assert.equal(fs.existsSync(reqBlobFile), true);
    assert.equal(fs.existsSync(resBlobFile), true);

    // Read back via getExchange and getBlob
    const loaded = store.getExchange(recorded.id, { includeBodies: true });
    assert.equal(loaded.reqBody, largeReqPayload);
    assert.equal(loaded.resBody, largeResPayload);
    assert.equal(store.getBlob(expectedResSha).toString('utf8'), largeResPayload);

    // Recording same large body increments ref_count in blob_refs
    store.recordExchange({
      method: 'POST',
      url: 'https://upload.example.com/bulk-retry',
      statusCode: 201,
      reqBody: largeReqPayload,
      resBody: 'small'
    });
    const refRow = store.db
      .prepare('SELECT ref_count, size FROM blob_refs WHERE sha256 = ?')
      .get(expectedReqSha);
    assert.equal(Number(refRow.ref_count), 2);
    assert.equal(Number(refRow.size), Buffer.byteLength(largeReqPayload));

    // Path traversal & invalid SHA-256 rejection
    assert.equal(isValidSha256('../../etc/passwd'), false);
    assert.equal(isValidSha256('A'.repeat(64)), false); // uppercase rejected
    assert.throws(() => store.getBlob('../../etc/passwd'), /Invalid SHA-256 hash/);
    assert.throws(
      () => store.getBlob('../../../windows/system32/drivers/etc/hosts'),
      /Invalid SHA-256 hash/
    );
    assert.throws(() => store.getBlob('deadbeef'), /Invalid SHA-256 hash/);
  });

  it('ingests external / HAR / browser extension traffic via recordExternal', () => {
    const extEx = store.recordExternal({
      source: 'extension',
      method: 'GET',
      url: 'https://app.example.com/dashboard',
      statusCode: 200,
      reqHeaders: { 'User-Agent': 'SecScan-Extension/1.0' },
      resBody: '<html>Dashboard</html>'
    });
    assert.equal(extEx.source, 'extension');

    const harBatch = store.recordExternal({
      log: {
        entries: [
          {
            request: {
              method: 'POST',
              url: 'https://app.example.com/api/graphql',
              headers: [{ name: 'Content-Type', value: 'application/json' }],
              postData: { text: '{"query":"{ me { id } }"}' }
            },
            response: {
              status: 200,
              headers: [{ name: 'Content-Type', value: 'application/json' }],
              content: { text: '{"data":{"me":{"id":"u-1"}}}', mimeType: 'application/json' }
            },
            time: 33
          }
        ]
      }
    });
    assert.equal(Array.isArray(harBatch), true);
    assert.equal(harBatch.length, 1);
    assert.equal(harBatch[0].source, 'har');
    assert.equal(harBatch[0].reqBody, '{"query":"{ me { id } }"}');
  });

  it('applies rewrite rules with HMAC-SHA256 sensitive tainting and preserves original_req_json', () => {
    const r1 = store.addRewriteRule({
      name: 'Inject Secret API Key',
      scopeHost: '*.example.com',
      phase: 'request',
      target: 'header',
      matchPattern: 'X-Api-Key',
      replaceValue: 'live_secret_token_999',
      isRegex: false,
      isSensitive: true
    });

    const r2 = store.addRewriteRule({
      name: 'Upgrade API Environment Query',
      scopeHost: 'api.example.com',
      phase: 'request',
      target: 'query',
      matchPattern: 'env',
      replaceValue: 'staging',
      isRegex: false,
      isSensitive: false
    });

    const r3 = store.addRewriteRule({
      name: 'Rewrite Body Role',
      scopeHost: 'api.example.com',
      phase: 'request',
      target: 'body',
      matchPattern: '"role":"guest"',
      replaceValue: '"role":"auditor"',
      isRegex: false,
      isSensitive: false
    });

    assert.equal(store.listRewriteRules().length, 3);

    const rewritten = store.applyRewrites(
      {
        method: 'POST',
        url: 'https://api.example.com/v1/session?env=dev',
        headers: {
          'Content-Type': 'application/json',
          'X-Api-Key': 'placeholder'
        },
        body: '{"user":"alice","role":"guest"}'
      },
      'request'
    );

    assert.equal(rewritten.rewriteApplied, true);
    assert.equal(rewritten.taintedSensitive, true);
    assert.ok(rewritten.taintHmac);
    assert.match(rewritten.taintHmac, /^[a-f0-9]{64}$/);
    assert.equal(rewritten.headers['X-Api-Key'], 'live_secret_token_999');
    assert.equal(rewritten.url, 'https://api.example.com/v1/session?env=staging');
    assert.equal(rewritten.body, '{"user":"alice","role":"auditor"}');

    // Pre-rewrite snapshot is preserved in original_req_json
    assert.ok(rewritten.original_req_json);
    const originalParsed = JSON.parse(rewritten.original_req_json);
    assert.equal(originalParsed.headers['X-Api-Key'], 'placeholder');
    assert.equal(originalParsed.url, 'https://api.example.com/v1/session?env=dev');
    assert.equal(originalParsed.body, '{"user":"alice","role":"guest"}');

    // Recording exchange preserves taint and original_req_json
    const storedEx = store.recordExchange({
      ...rewritten,
      statusCode: 200,
      resBody: '{"status":"authenticated"}'
    });
    assert.equal(storedEx.taintedSensitive, true);
    assert.equal(storedEx.rewriteApplied, true);
    assert.equal(storedEx.originalReq.headers['X-Api-Key'], 'placeholder');

    // Deleting rules works
    assert.equal(store.deleteRewriteRule(r1.id), true);
    assert.equal(store.deleteRewriteRule(r2.id), true);
    assert.equal(store.deleteRewriteRule(r3.id), true);
    assert.equal(store.listRewriteRules().length, 0);
  });

  it('replays requests per RFC-9110: strips hop-by-hop headers, blocks SSRF targets, and records replay exchange', async () => {
    const orig = store.recordExchange({
      taskId: 'task-replay',
      method: 'POST',
      url: 'https://api.example.com/v1/items',
      statusCode: 200,
      reqHeaders: {
        'Content-Type': 'application/json',
        Connection: 'keep-alive, X-Custom-Hop',
        'Keep-Alive': 'timeout=5',
        'Transfer-Encoding': 'chunked',
        'Content-Length': '18',
        Upgrade: 'h2c',
        'Proxy-Connection': 'keep-alive',
        'X-Custom-Hop': 'should-be-stripped',
        'X-Trace-Id': 'trace-001'
      },
      resHeaders: { 'Content-Type': 'application/json' },
      reqBody: '{"item":"initial"}',
      resBody: '{"created":true}'
    });

    let capturedFetchCall = null;
    const mockFetcher = async (url, options) => {
      capturedFetchCall = { url, options };
      return {
        status: 201,
        headers: { 'content-type': 'application/json', 'x-replayed': '1' },
        text: async () => '{"created":true,"replayed":true}'
      };
    };

    const { replayExchange, response } = await store.replayRequest(
      orig.id,
      {
        headers: { 'X-Trace-Id': 'trace-002' },
        body: '{"item":"overridden"}'
      },
      { fetcher: mockFetcher, dnsResolver: async () => ['93.184.216.34'] }
    );

    assert.ok(capturedFetchCall);
    assert.equal(capturedFetchCall.url, 'https://api.example.com/v1/items');
    assert.equal(capturedFetchCall.options.method, 'POST');
    assert.equal(capturedFetchCall.options.body, '{"item":"overridden"}');

    // Verify hop-by-hop headers were stripped
    const sentHeaders = capturedFetchCall.options.headers;
    assert.equal(sentHeaders['Connection'], undefined);
    assert.equal(sentHeaders['Keep-Alive'], undefined);
    assert.equal(sentHeaders['Transfer-Encoding'], undefined);
    assert.equal(sentHeaders['Content-Length'], undefined);
    assert.equal(sentHeaders['Upgrade'], undefined);
    assert.equal(sentHeaders['Proxy-Connection'], undefined);
    assert.equal(sentHeaders['X-Custom-Hop'], undefined);
    assert.equal(sentHeaders['X-Trace-Id'], 'trace-002');
    assert.equal(sentHeaders['Content-Type'], 'application/json');

    assert.equal(replayExchange.source, 'replay');
    assert.equal(replayExchange.statusCode, 201);
    assert.equal(response.body, '{"created":true,"replayed":true}');

    // Verify SSRF protection blocks private/loopback/metadata replay overrides
    await assert.rejects(
      () =>
        store.replayRequest(
          orig.id,
          { url: 'http://127.0.0.1:8080/admin' },
          { fetcher: mockFetcher }
        ),
      /Replay blocked by URL validator/
    );

    await assert.rejects(
      () =>
        store.replayRequest(
          orig.id,
          { url: 'http://169.254.169.254/latest/meta-data/iam' },
          { fetcher: mockFetcher }
        ),
      /Replay blocked by URL validator/
    );

    // Verify optional scope guard blocks out-of-scope target
    await assert.rejects(
      () =>
        store.replayRequest(
          orig.id,
          { url: 'https://forbidden.gov/portal' },
          {
            fetcher: mockFetcher,
            guard: {
              evaluateAssetGate: () => ({
                allowed: false,
                reason: '[SECSCAN platform control, not target defense] Blocked .gov domain'
              })
            }
          }
        ),
      /Replay blocked by guard/
    );
  });

  it('FINDING-4: replayRequest defaults to resolveAndValidateTarget, blocks DNS rebinding to 127.0.0.1 / 169.254.169.254, and enforces redirect safety', async () => {
    const orig = store.recordExchange({
      taskId: 'task-ssrf-replay',
      method: 'GET',
      url: 'https://public.example.com/health',
      statusCode: 200,
      resBody: 'ok'
    });

    let fetchCalls = 0;
    const mockFetcher = async (_url, init) => {
      fetchCalls += 1;
      assert.equal(init.redirect, 'manual');
      return {
        status: 302,
        headers: { location: 'http://169.254.169.254/latest/meta-data/' },
        text: async () => ''
      };
    };

    // Hostname resolving to loopback 127.0.0.1 is blocked by default validator
    await assert.rejects(
      () =>
        store.replayRequest(
          orig.id,
          { url: 'https://rebind-loopback.example/admin' },
          { fetcher: mockFetcher, dnsResolver: async () => ['127.0.0.1'] }
        ),
      /Replay blocked by URL validator.*127\.0\.0\.1/
    );
    assert.equal(fetchCalls, 0);

    // Hostname resolving to cloud metadata 169.254.169.254 is blocked by default validator
    await assert.rejects(
      () =>
        store.replayRequest(
          orig.id,
          { url: 'https://rebind-meta.example/latest/meta-data/' },
          { fetcher: mockFetcher, dnsResolver: async () => ['169.254.169.254'] }
        ),
      /Replay blocked by URL validator.*169\.254\.169\.254/
    );
    assert.equal(fetchCalls, 0);

    // Without custom validateUrl/dnsResolver, non-existent/rebind domain fails closed without calling fetcher
    await assert.rejects(
      () =>
        store.replayRequest(
          orig.id,
          { url: 'https://rebind-default.invalid/secret' },
          { fetcher: mockFetcher }
        ),
      /Replay blocked by URL validator/
    );
    assert.equal(fetchCalls, 0);

    // Default replay passes redirect: 'manual' and returns 302 without pivoting to metadata
    const manualRes = await store.replayRequest(
      orig.id,
      {},
      { fetcher: mockFetcher, dnsResolver: async () => ['93.184.216.34'] }
    );
    assert.equal(manualRes.response.status, 302);
    assert.equal(fetchCalls, 1);

    // When followRedirects is enabled, 3xx redirect to internal/metadata target is blocked
    await assert.rejects(
      () =>
        store.replayRequest(
          orig.id,
          {},
          {
            fetcher: mockFetcher,
            dnsResolver: async () => ['93.184.216.34'],
            followRedirects: true
          }
        ),
      /Replay redirect blocked by URL validator/
    );
    assert.equal(fetchCalls, 2);
  });

  it('replayRequest allows internal targets when allowPrivate: true while blocking metadata even when allowPrivate: true', async () => {
    const internalEx = store.recordExchange({
      taskId: 'task-internal-replay',
      method: 'GET',
      url: 'http://10.1.2.3/api',
      statusCode: 200,
      resBody: '{"ok":true}'
    });

    let fetchCalls = 0;
    const mockFetcher = async (url, init) => {
      fetchCalls += 1;
      assert.equal(init.redirect, 'manual');
      if (url === 'http://10.1.2.3/redirect-meta') {
        return {
          status: 302,
          headers: { location: 'http://169.254.169.254/latest/meta-data/' },
          text: async () => ''
        };
      }
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: async () => '{"ok":true,"replayed":true}'
      };
    };

    // 1. Default allowPrivate: false blocks http://10.1.2.3/api
    await assert.rejects(
      () => store.replayRequest(internalEx.id, {}, { fetcher: mockFetcher }),
      /Replay blocked by URL validator/
    );
    assert.equal(fetchCalls, 0);

    // 2. Explicit allowPrivate: true permits http://10.1.2.3/api
    const okRes = await store.replayRequest(
      internalEx.id,
      {},
      { fetcher: mockFetcher, allowPrivate: true }
    );
    assert.equal(okRes.response.status, 200);
    assert.equal(okRes.replayExchange.url, 'http://10.1.2.3/api');
    assert.equal(fetchCalls, 1);

    // 3. Explicit allowPrivate: true also permits http://localhost:3000 and https://app.internal
    const okInternalDomain = await store.replayRequest(
      internalEx.id,
      { url: 'https://app.internal/v1/status' },
      {
        fetcher: mockFetcher,
        allowPrivate: true,
        dnsResolver: async () => ['192.168.10.20']
      }
    );
    assert.equal(okInternalDomain.response.status, 200);
    assert.equal(fetchCalls, 2);

    // 4. Even when allowPrivate: true, cloud metadata targets and DNS resolution to metadata remain blocked
    for (const metaUrl of [
      'http://169.254.169.254/latest/meta-data/',
      'http://[fd00:ec2::254]/latest/meta-data/',
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://100.100.100.200/latest/meta-data/'
    ]) {
      await assert.rejects(
        () =>
          store.replayRequest(
            internalEx.id,
            { url: metaUrl },
            { fetcher: mockFetcher, allowPrivate: true }
          ),
        /Replay blocked by URL validator/
      );
    }

    await assert.rejects(
      () =>
        store.replayRequest(
          internalEx.id,
          { url: 'https://rebind.internal/meta' },
          {
            fetcher: mockFetcher,
            allowPrivate: true,
            dnsResolver: async () => ['169.254.169.254']
          }
        ),
      /Replay blocked by URL validator/
    );

    // 5. Redirect to metadata under followRedirects + allowPrivate: true is blocked
    await assert.rejects(
      () =>
        store.replayRequest(
          internalEx.id,
          { url: 'http://10.1.2.3/redirect-meta' },
          {
            fetcher: mockFetcher,
            allowPrivate: true,
            followRedirects: true
          }
        ),
      /Replay redirect blocked by URL validator/
    );
    assert.equal(fetchCalls, 3);
  });
});

describe('Step 2.3 — EvidenceStore, Decompression Guardrails, S1 Receipt Verifier & Finding Retests', () => {
  let tmpDir;
  let trafficStore;
  let evidenceStore;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-evidence-test-'));
    trafficStore = new TrafficStore({
      dbPath: ':memory:',
      blobDir: path.join(tmpDir, 'traffic-blobs')
    });
    evidenceStore = new EvidenceStore({
      dbPath: ':memory:',
      blobDir: path.join(tmpDir, 'evidence-blobs'),
      trafficStore
    });
  });

  afterEach(() => {
    if (evidenceStore) evidenceStore.close();
    if (trafficStore) trafficStore.close();
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('decompresses gzip, deflate, raw-deflate, and brotli bodies and blocks >16 MiB decompression bombs', () => {
    const sampleText = 'Secret database configuration leak: DB_PASS=super_secret_value_2026';
    const gzipped = zlib.gzipSync(Buffer.from(sampleText, 'utf8'));
    const deflated = zlib.deflateSync(Buffer.from(sampleText, 'utf8'));
    const rawDeflated = zlib.deflateRawSync(Buffer.from(sampleText, 'utf8'));
    const brotlied = zlib.brotliCompressSync(Buffer.from(sampleText, 'utf8'));

    assert.equal(decompressBodyBuffer(gzipped, 'gzip').toString('utf8'), sampleText);
    assert.equal(decompressBodyBuffer(gzipped, 'x-gzip').toString('utf8'), sampleText);
    assert.equal(decompressBodyBuffer(deflated, 'deflate').toString('utf8'), sampleText);
    assert.equal(decompressBodyBuffer(rawDeflated, 'deflate').toString('utf8'), sampleText);
    assert.equal(decompressBodyBuffer(brotlied, 'br').toString('utf8'), sampleText);

    // Decompression bomb > MAX_DECOMPRESS_BYTES (16 MiB)
    const oversizedPlain = Buffer.alloc(MAX_DECOMPRESS_BYTES + 1024, 'A');
    const gzipBomb = zlib.gzipSync(oversizedPlain);
    assert.ok(gzipBomb.byteLength < 100 * 1024); // compressed is tiny (<100 KiB)

    assert.throws(
      () => decompressBodyBuffer(gzipBomb, 'gzip'),
      err => err.code === 'ERR_BUFFER_TOO_LARGE' || /maxOutputLength|MAX_DECOMPRESS_BYTES/i.test(err.message)
    );
  });

  it('enforces ARTEX S1 Machine-Checked Receipt Verification rules (poeLevel >= 3, bound proof snapshot, gzipped quote >= 8 chars)', () => {
    const htmlBody = `
      <html>
        <body>
          <div class="debug-dump">
            SQLSTATE[42000]:   Syntax   error   or   access   violation:   1064
          </div>
        </body>
      </html>
    `;
    const gzippedBody = zlib.gzipSync(Buffer.from(htmlBody, 'utf8'));

    const proofSnapshot = {
      id: 'snap-1',
      role: 'proof',
      method: 'GET',
      url: 'https://target.example.com/item?id=1%27',
      statusCode: 500,
      resHeaders: { 'Content-Encoding': 'gzip', 'Content-Type': 'text/html' },
      resEncoding: 'gzip',
      resBodyBuffer: gzippedBody
    };

    // 1. Valid S1 verification: poeLevel 3, bound proof snapshot, whitespace-normalized quote >= 8 chars
    const validRes = assessFindingVerification(
      {
        id: 'find-sqli-1',
        poeLevel: 3,
        evidenceQuotes: ['SQLSTATE[42000]: Syntax error or access violation: 1064']
      },
      [proofSnapshot]
    );
    assert.equal(validRes.verified, true);
    assert.equal(validRes.status, 'verified');
    assert.equal(validRes.matchedQuotes.length, 1);
    assert.equal(validRes.missingQuotes.length, 0);

    // 2. Rejects when poeLevel < 3
    const lowPoeRes = assessFindingVerification(
      {
        id: 'find-sqli-1',
        poeLevel: 2,
        evidenceQuotes: ['SQLSTATE[42000]: Syntax error or access violation: 1064']
      },
      [proofSnapshot]
    );
    assert.equal(lowPoeRes.verified, false);
    assert.equal(lowPoeRes.status, 'unverified');
    assert.match(lowPoeRes.reason, /PoE level 2/i);

    // 3. Rejects when no proof or verification snapshot is bound (e.g., only baseline)
    const noProofRes = assessFindingVerification(
      {
        id: 'find-sqli-1',
        poeLevel: 3,
        evidenceQuotes: ['SQLSTATE[42000]: Syntax error or access violation: 1064']
      },
      [{ ...proofSnapshot, role: 'baseline' }]
    );
    assert.equal(noProofRes.verified, false);
    assert.equal(noProofRes.status, 'unverified');

    // 4. Rejects when quote normalized length < 8 characters
    const shortQuoteRes = assessFindingVerification(
      {
        id: 'find-sqli-1',
        poeLevel: 3,
        evidenceQuotes: ['  1064  ']
      },
      [proofSnapshot]
    );
    assert.equal(shortQuoteRes.verified, false);
    assert.equal(shortQuoteRes.status, 'rejected');
    assert.match(shortQuoteRes.reason, /8 characters/i);

    // 5. Rejects when quote >= 8 chars is missing from snapshot
    const missingQuoteRes = assessFindingVerification(
      {
        id: 'find-sqli-1',
        poeLevel: 4,
        evidenceQuotes: ['uid=0(root) gid=0(root) groups=0(root)']
      },
      [proofSnapshot]
    );
    assert.equal(missingQuoteRes.verified, false);
    assert.equal(missingQuoteRes.status, 'rejected');
    assert.deepEqual(missingQuoteRes.missingQuotes, ['uid=0(root) gid=0(root) groups=0(root)']);
  });

  it('tracks evidenceVersion vs reportEvidenceVersion staleness, stores atomic blobs, and garbage-collects orphans', () => {
    const ex = trafficStore.recordExchange({
      taskId: 'task-ev',
      method: 'GET',
      url: 'https://api.example.com/v1/debug/env',
      statusCode: 200,
      resHeaders: { 'Content-Type': 'text/plain' },
      resBody: 'APP_ENV=production\nAWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLEKEY'
    });

    const snap1 = evidenceStore.captureSnapshotFromExchange(ex.id);
    assert.ok(snap1.id);
    assert.match(snap1.resSha256, /^[a-f0-9]{64}$/);

    // Verify blob file exists in <blobDir>/<aa>/<sha256>.bin
    const expectedBlobPath = path.join(
      tmpDir,
      'evidence-blobs',
      snap1.resSha256.slice(0, 2),
      `${snap1.resSha256}.bin`
    );
    assert.equal(fs.existsSync(expectedBlobPath), true);

    // Path traversal rejection on EvidenceStore.readBlob
    assert.throws(() => evidenceStore.readBlob('../outside.bin'), /Invalid SHA-256 hash/);

    // Bind first evidence snapshot -> evidenceVersion = 1, reportEvidenceVersion = 0 -> reportStale = true
    const bind1 = evidenceStore.bindEvidence({
      findingId: 'finding-env-leak',
      snapshotId: snap1.id,
      role: 'proof',
      quote: 'AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLEKEY',
      note: 'Initial environment leak capture'
    });
    assert.equal(bind1.evidenceVersion, 1);
    assert.equal(bind1.reportEvidenceVersion, 0);
    assert.equal(bind1.reportStale, true);

    let evData = evidenceStore.getFindingEvidence('finding-env-leak');
    assert.equal(evData.reportStale, true);
    assert.equal(evData.state.evidenceVersion, 1);

    // Synchronize report -> reportEvidenceVersion = 1 -> reportStale = false
    evidenceStore.markReportSynchronized('finding-env-leak');
    evData = evidenceStore.getFindingEvidence('finding-env-leak');
    assert.equal(evData.reportStale, false);
    assert.equal(evData.state.reportEvidenceVersion, 1);

    // Bind second supporting snapshot -> evidenceVersion = 2 -> reportStale = true again
    const snap2 = evidenceStore.createSnapshot({
      method: 'GET',
      url: 'https://api.example.com/v1/health',
      statusCode: 200,
      resBody: '{"healthy":true}'
    });
    const bind2 = evidenceStore.bindEvidence({
      findingId: 'finding-env-leak',
      snapshotId: snap2.id,
      role: 'supporting',
      note: 'Health check baseline'
    });
    assert.equal(bind2.evidenceVersion, 2);
    assert.equal(bind2.reportStale, true);

    // Verify S1 receipts on the finding
    const receiptAssessment = evidenceStore.verifyFindingReceipts('finding-env-leak', {
      poeLevel: 3
    });
    assert.equal(receiptAssessment.verified, true);
    assert.equal(receiptAssessment.status, 'verified');

    evData = evidenceStore.getFindingEvidence('finding-env-leak');
    assert.equal(evData.state.verificationStatus, 'verified');

    // Write an unbound orphan blob and test gcOrphanBlobs
    const orphanHash = evidenceStore.writeBlob('orphan-unreferenced-payload-data');
    const orphanFile = path.join(
      tmpDir,
      'evidence-blobs',
      orphanHash.slice(0, 2),
      `${orphanHash}.bin`
    );
    assert.equal(fs.existsSync(orphanFile), true);

    // Within 24h grace period -> orphan is kept
    const gcWithinGrace = evidenceStore.gcOrphanBlobs({
      graceMs: 24 * 3600 * 1000,
      now: Date.now()
    });
    assert.equal(gcWithinGrace.deletedCount, 0);
    assert.equal(fs.existsSync(orphanFile), true);

    // After 24h grace period -> orphan is deleted while bound blobs are kept
    const gcAfterGrace = evidenceStore.gcOrphanBlobs({
      graceMs: 24 * 3600 * 1000,
      now: Date.now() + 25 * 3600 * 1000
    });
    assert.equal(gcAfterGrace.deletedBlobs.includes(orphanHash), true);
    assert.equal(fs.existsSync(orphanFile), false);
    assert.equal(fs.existsSync(expectedBlobPath), true);
  });

  it('executes retestFinding and records reproduced, fixed, and inconclusive verdicts', async () => {
    const ex = trafficStore.recordExchange({
      taskId: 'task-retest',
      method: 'GET',
      url: 'https://portal.example.com/api/config.json',
      statusCode: 200,
      reqHeaders: { Accept: 'application/json', Connection: 'keep-alive' },
      resHeaders: { 'Content-Type': 'application/json' },
      resBody: '{"debug":true,"private_signing_key":"rsa_priv_key_exposed_998877"}'
    });

    const snap = evidenceStore.captureSnapshotFromExchange(ex.id);
    evidenceStore.bindEvidence({
      findingId: 'finding-key-exposure',
      snapshotId: snap.id,
      role: 'proof',
      quote: '"private_signing_key":"rsa_priv_key_exposed_998877"'
    });

    // 1. Retest where target still returns the vulnerable quote -> 'reproduced'
    const retestReproduced = await evidenceStore.retestFinding('finding-key-exposure', {
      dnsResolver: async () => ['93.184.216.34'],
      fetcher: async () => ({
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: async () => '{"debug":true,"private_signing_key":"rsa_priv_key_exposed_998877"}'
      })
    });
    assert.equal(retestReproduced.verdict, 'reproduced');
    assert.equal(retestReproduced.statusCode, 200);
    assert.equal(retestReproduced.matchedQuotes.length, 1);

    // 2. Retest where target returns 200 OK without the vulnerable quote -> 'fixed'
    const retestFixed = await evidenceStore.retestFinding('finding-key-exposure', {
      dnsResolver: async () => ['93.184.216.34'],
      fetcher: async () => ({
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: async () => '{"debug":false}'
      })
    });
    assert.equal(retestFixed.verdict, 'fixed');
    assert.equal(retestFixed.statusCode, 200);
    assert.equal(retestFixed.matchedQuotes.length, 0);

    // 3. Retest where target returns 503 Service Unavailable -> 'inconclusive'
    const retest503 = await evidenceStore.retestFinding('finding-key-exposure', {
      dnsResolver: async () => ['93.184.216.34'],
      fetcher: async () => ({
        status: 503,
        headers: { 'content-type': 'text/plain' },
        text: async () => 'Service temporarily unavailable'
      })
    });
    assert.equal(retest503.verdict, 'inconclusive');
    assert.equal(retest503.statusCode, 503);

    // 4. Retest where network connection fails -> 'inconclusive'
    const retestNetErr = await evidenceStore.retestFinding('finding-key-exposure', {
      dnsResolver: async () => ['93.184.216.34'],
      fetcher: async () => {
        throw new Error('ECONNRESET socket hang up');
      }
    });
    assert.equal(retestNetErr.verdict, 'inconclusive');
    assert.match(retestNetErr.notes, /ECONNRESET/);

    // Verify all 4 retests and new verification snapshots were bound and persisted
    const finalEvidence = evidenceStore.getFindingEvidence('finding-key-exposure');
    assert.equal(finalEvidence.retests.length, 4);
    const verificationBindings = finalEvidence.bindings.filter(b => b.role === 'verification');
    assert.equal(verificationBindings.length, 3);
  });

  it('FINDING-4: retestFinding defaults to resolveAndValidateTarget and blocks DNS resolution to 127.0.0.1 / 169.254.169.254', async () => {
    let fetchCalls = 0;
    const mockFetcher = async (_url, init) => {
      fetchCalls += 1;
      assert.equal(init.redirect, 'manual');
      return {
        status: 302,
        headers: { location: 'http://127.0.0.1:8080/internal' },
        text: async () => ''
      };
    };

    // A) Linked to trafficStore exchange resolving to 127.0.0.1
    const exLoopback = trafficStore.recordExchange({
      taskId: 'task-ssrf-1',
      method: 'GET',
      url: 'https://rebind-loopback.example/.env',
      statusCode: 200,
      resBody: 'DB_PASS=secret123456'
    });
    const snapLoopback = evidenceStore.captureSnapshotFromExchange(exLoopback.id);
    evidenceStore.bindEvidence({
      findingId: 'finding-rebind-1',
      snapshotId: snapLoopback.id,
      role: 'proof',
      quote: 'DB_PASS=secret123456'
    });

    await assert.rejects(
      () =>
        evidenceStore.retestFinding('finding-rebind-1', {
          fetcher: mockFetcher,
          dnsResolver: async () => ['127.0.0.1']
        }),
      /blocked by URL validator.*127\.0\.0\.1/
    );
    assert.equal(fetchCalls, 0);

    // B) Standalone snapshot (no trafficStore exchange) resolving to 169.254.169.254
    const snapMeta = evidenceStore.createSnapshot({
      taskId: 'task-ssrf-2',
      method: 'GET',
      url: 'https://rebind-meta.example/latest/meta-data/',
      statusCode: 200,
      resBody: 'ami-1234567890'
    });
    evidenceStore.bindEvidence({
      findingId: 'finding-rebind-2',
      snapshotId: snapMeta.id,
      role: 'proof',
      quote: 'ami-1234567890'
    });

    await assert.rejects(
      () =>
        evidenceStore.retestFinding('finding-rebind-2', {
          fetcher: mockFetcher,
          dnsResolver: async () => ['169.254.169.254']
        }),
      /blocked by URL validator.*169\.254\.169\.254/
    );
    assert.equal(fetchCalls, 0);

    // C) Without custom validateUrl/dnsResolver, standalone snapshot fails closed before calling fetcher
    await assert.rejects(
      () =>
        evidenceStore.retestFinding('finding-rebind-2', {
          fetcher: mockFetcher
        }),
      /blocked by URL validator/
    );
    assert.equal(fetchCalls, 0);

    // D) Standalone snapshot with followRedirects: true blocks 302 -> 127.0.0.1
    const snapRedirect = evidenceStore.createSnapshot({
      taskId: 'task-ssrf-3',
      method: 'GET',
      url: 'https://redirect-ssrf.example/check',
      statusCode: 200,
      resBody: 'vulnerable-quote-12345'
    });
    evidenceStore.bindEvidence({
      findingId: 'finding-rebind-3',
      snapshotId: snapRedirect.id,
      role: 'proof',
      quote: 'vulnerable-quote-12345'
    });

    await assert.rejects(
      () =>
        evidenceStore.retestFinding('finding-rebind-3', {
          fetcher: mockFetcher,
          dnsResolver: async () => ['93.184.216.34'],
          followRedirects: true
        }),
      /Retest redirect blocked by URL validator/
    );
    assert.equal(fetchCalls, 1);
  });

  it('retestFinding allows internal targets when allowPrivate: true while blocking metadata even when allowPrivate: true', async () => {
    let fetchCalls = 0;
    const mockFetcher = async () => {
      fetchCalls += 1;
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: async () => '{"internal_secret":"exposed_internal_token_123"}'
      };
    };

    // A) TrafficStore-backed internal finding on http://10.1.2.3/api
    const internalEx = trafficStore.recordExchange({
      taskId: 'task-internal-retest',
      method: 'GET',
      url: 'http://10.1.2.3/api',
      statusCode: 200,
      resBody: '{"internal_secret":"exposed_internal_token_123"}'
    });
    const internalSnap = evidenceStore.captureSnapshotFromExchange(internalEx.id);
    evidenceStore.bindEvidence({
      findingId: 'finding-internal-1',
      snapshotId: internalSnap.id,
      role: 'proof',
      quote: '"internal_secret":"exposed_internal_token_123"'
    });

    // Default allowPrivate: false blocks http://10.1.2.3/api
    await assert.rejects(
      () => evidenceStore.retestFinding('finding-internal-1', { fetcher: mockFetcher }),
      /blocked by URL validator/
    );
    assert.equal(fetchCalls, 0);

    // Explicit allowPrivate: true succeeds and reproduces finding
    const okRetest = await evidenceStore.retestFinding('finding-internal-1', {
      fetcher: mockFetcher,
      allowPrivate: true
    });
    assert.equal(okRetest.verdict, 'reproduced');
    assert.equal(fetchCalls, 1);

    // B) Standalone snapshot on http://192.168.1.50/config
    const standaloneSnap = evidenceStore.createSnapshot({
      taskId: 'task-internal-standalone',
      method: 'GET',
      url: 'http://192.168.1.50/config',
      statusCode: 200,
      resBody: 'DEBUG_SECRET=internal_debug_key_999'
    });
    evidenceStore.bindEvidence({
      findingId: 'finding-internal-2',
      snapshotId: standaloneSnap.id,
      role: 'proof',
      quote: 'DEBUG_SECRET=internal_debug_key_999'
    });

    await assert.rejects(
      () => evidenceStore.retestFinding('finding-internal-2', { fetcher: mockFetcher }),
      /blocked by URL validator/
    );
    const okStandalone = await evidenceStore.retestFinding('finding-internal-2', {
      fetcher: mockFetcher,
      allowPrivate: true
    });
    assert.equal(okStandalone.verdict, 'fixed'); // mock returns JSON without DEBUG_SECRET
    assert.equal(fetchCalls, 2);

    // C) Cloud metadata IP 169.254.169.254 remains blocked even when allowPrivate: true
    const metaSnap = evidenceStore.createSnapshot({
      taskId: 'task-internal-meta',
      method: 'GET',
      url: 'http://169.254.169.254/latest/meta-data/',
      statusCode: 200,
      resBody: 'ami-0123456789abcdef'
    });
    evidenceStore.bindEvidence({
      findingId: 'finding-internal-meta',
      snapshotId: metaSnap.id,
      role: 'proof',
      quote: 'ami-0123456789abcdef'
    });

    await assert.rejects(
      () =>
        evidenceStore.retestFinding('finding-internal-meta', {
          fetcher: mockFetcher,
          allowPrivate: true
        }),
      /blocked by URL validator/
    );
    assert.equal(fetchCalls, 2);
  });
});
