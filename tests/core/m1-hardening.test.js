import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { DatabaseSync } from 'node:sqlite';

import { createGovernedFetch, fetchWithRetry, mergeGovernedFetchOptions } from '../../core/fetch.js';
import { NoiseGovernor } from '../../core/egress.js';
import { mergeConfig } from '../../core/config.js';
import { formatChannelPayloads } from '../../core/notify.js';
import { EvidenceStore } from '../../core/evidence.js';
import { GraphStore } from '../../core/graph-store.js';
import { TrafficStore } from '../../core/traffic.js';
import { EnrichEngine, ingestScanOutput, buildFindingAssetTree } from '../../core/enrich.js';
import { AgentEngine } from '../../core/agent-engine.js';
import { TargetPinStore } from '../../core/guard.js';

describe('M1 Hardening Regressions (Features #1-#6)', () => {
  it('Feature #1: createGovernedFetch locks governance options, isolates TrafficStore errors, and uses SecurityScanner/2.2 UA', async () => {
    let seenHeaders = null;
    let fetchCalls = 0;
    const mockFetcher = async (_url, init) => {
      fetchCalls += 1;
      seenHeaders = init.headers;
      return {
        status: 200,
        headers: new Headers({ 'content-type': 'text/plain' }),
        text: async () => 'ok'
      };
    };

    const throwingTrafficStore = {
      recordExchange() {
        throw new Error('SQLITE_BUSY: database is locked');
      }
    };

    const governed = createGovernedFetch({
      allowPrivate: false,
      enforceDnsValidation: true,
      dnsResolver: async () => ['93.184.216.34'],
      trafficStore: throwingTrafficStore,
      scopeRules: [{ rule_type: 'domain', pattern: 'example.com', is_allowed: true }],
      fetcher: mockFetcher
    });

    assert.equal(Object.isFrozen(governed.governance), true);

    // Attempt to override bound governance via callOptions
    await assert.rejects(
      () => governed('http://127.0.0.1/admin', {
        allowPrivate: true,
        enforceDnsValidation: false,
        scopeRules: [],
        guard: () => ({ allowed: true }),
        fetcher: async () => ({ status: 200, headers: {}, text: async () => 'bypassed' })
      }),
      /SSRF policy/i
    );

    const merged = mergeGovernedFetchOptions(
      { allowPrivate: false, taskId: null, guard: { id: 'g1' }, fetcher: mockFetcher },
      { allowPrivate: true, resolver: () => ['127.0.0.1'], taskId: 'agent-task-1', method: 'POST' }
    );
    assert.equal(merged.allowPrivate, false);
    assert.equal(merged.taskId, 'agent-task-1');
    assert.equal(merged.method, 'POST');
    assert.equal(merged.fetcher, mockFetcher);

    // TrafficStore failure must not abort HTTP response or trigger retries
    const res = await governed('https://example.com/health');
    assert.equal(res.status, 200);
    assert.equal(res.text, 'ok');
    assert.equal(fetchCalls, 1);
    assert.equal(seenHeaders['User-Agent'], 'Mozilla/5.0 (compatible; SecurityScanner/2.2)');
  });

  it('Feature #2: EvidenceStore handles gzip-header plain text, disk blob memory avoidance, maxRedirects:0, timeout, quote check, and close()', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-m1-ev-'));
    try {
      const store = new EvidenceStore({ dbPath: path.join(tmpDir, 'ev.db'), blobDir: path.join(tmpDir, 'blobs') });
      const busyTimeout = store.db.prepare('PRAGMA busy_timeout').get();
      assert.equal(busyTimeout.timeout, 5000);

      // Plain text response with Content-Encoding: gzip (as produced by Undici fetch auto-decompression)
      const snap = store.createSnapshot({
        taskId: 't-gzip',
        method: 'GET',
        url: 'https://example.com/api',
        statusCode: 200,
        resHeaders: { 'content-encoding': 'gzip', 'content-type': 'application/json' },
        resBody: '{"secret_token":"exposed_secret_value_12345"}'
      });
      assert.equal(snap.resEncoding, 'identity');
      assert.equal(snap.resHeaders['content-encoding'], 'gzip');
      assert.equal(store._memoryBlobs.size, 0);

      const binding = store.bindEvidence({
        findingId: 'find-gzip-1',
        snapshotId: snap.id,
        role: 'proof',
        quote: '"secret_token":"exposed_secret_value_12345"'
      });
      assert.ok(binding.id);

      const verified = store.verifyFindingReceipts('find-gzip-1', { poeLevel: 3 });
      assert.equal(verified.verified, true);
      assert.equal(verified.status, 'verified');

      // Genuine decompression bomb (>16 MiB) must still reject with ERR_BUFFER_TOO_LARGE
      const bomb = zlib.gzipSync(Buffer.alloc(17 * 1024 * 1024, 'A'));
      assert.throws(
        () => store.createSnapshot({
          method: 'GET',
          url: 'https://example.com/bomb',
          statusCode: 200,
          resHeaders: { 'content-encoding': 'gzip' },
          resBodyBuffer: bomb
        }),
        (err) => err?.code === 'ERR_BUFFER_TOO_LARGE'
      );

      // retestFinding: maxRedirects: 0 must not be coerced to 5
      await assert.rejects(
        () => store.retestFinding('find-gzip-1', {
          dnsResolver: async () => ['93.184.216.34'],
          followRedirects: true,
          maxRedirects: 0,
          fetcher: async () => ({
            status: 302,
            headers: { location: 'https://example.com/next' },
            text: async () => ''
          })
        }),
        /Maximum redirect limit \(0\) exceeded/
      );

      // retestFinding: AbortController timeout aborts hanging fetcher
      const timedOut = await store.retestFinding('find-gzip-1', {
        dnsResolver: async () => ['93.184.216.34'],
        timeout: 40,
        fetcher: (_u, init) => new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(new Error('Aborted by timeout')), { once: true });
        })
      });
      assert.equal(timedOut.verdict, 'inconclusive');
      assert.match(timedOut.notes, /Aborted by timeout/);

      // retestFinding: 0 valid >=8 char quotes must return inconclusive, never fixed
      const noQuoteSnap = store.createSnapshot({
        method: 'GET',
        url: 'https://example.com/empty-quote',
        statusCode: 200,
        resBody: 'short'
      });
      store.bindEvidence({
        findingId: 'find-no-quote',
        snapshotId: noQuoteSnap.id,
        role: 'proof',
        quote: 'short'
      });
      const noQuoteRetest = await store.retestFinding('find-no-quote', {
        dnsResolver: async () => ['93.184.216.34'],
        fetcher: async () => ({ status: 200, headers: {}, text: async () => 'clean page' })
      });
      assert.equal(noQuoteRetest.verdict, 'inconclusive');

      // close() is idempotent
      store.close();
      store.close();

      // :memory: mode caps _memoryBlobs
      const memStore = new EvidenceStore({ maxMemoryBlobs: 3 });
      memStore.writeBlob('blob-1-aaaa');
      memStore.writeBlob('blob-2-bbbb');
      memStore.writeBlob('blob-3-cccc');
      memStore.writeBlob('blob-4-dddd');
      assert.equal(memStore._memoryBlobs.size, 3);
      memStore.close();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('Feature #3: GraphStore persists/migrates allow_private, restores activity in importSnapshot, deduplicates ingestStaticScanResult, and fixes scope globs', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-m1-gs-'));
    try {
      // Simulate legacy DB without allow_private column
      const legacyPath = path.join(tmpDir, 'legacy.db');
      const rawDb = new DatabaseSync(legacyPath);
      rawDb.exec(`
        CREATE TABLE tasks (
          id TEXT PRIMARY KEY,
          title TEXT,
          target TEXT,
          goal TEXT,
          status TEXT NOT NULL DEFAULT 'pending',
          mode TEXT NOT NULL DEFAULT 'auto',
          noise_profile TEXT NOT NULL DEFAULT 'balanced',
          llm_profile_ids_json TEXT NOT NULL DEFAULT '[]',
          llm_rotate INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
      `);
      rawDb.close();

      const gs = new GraphStore({ dbPath: legacyPath });
      const busyTimeout = gs.db.prepare('PRAGMA busy_timeout').get();
      assert.equal(busyTimeout.timeout, 5000);

      const created = gs.createTask({
        id: 'priv-task-1',
        target: 'http://10.0.0.5:8080',
        allowPrivate: true
      });
      assert.equal(created.allowPrivate, true);
      assert.equal(created.allow_private, true);

      const fetched = gs.getTask('priv-task-1');
      assert.equal(fetched.allowPrivate, true);
      gs.appendActivity('priv-task-1', { actor: 'agent', eventType: 'todo_added', summary: 'Check internal API' });
      gs.appendActivity('priv-task-1', { actor: 'agent', eventType: 'todo_done', summary: 'Checked internal API' });

      const snapshot = gs.exportSnapshot('priv-task-1');
      const gs2 = new GraphStore({ dbPath: ':memory:' });
      // Seed an unrelated task activity row at seq=1 to verify no seq collision
      gs2.createTask({ id: 'other-task', target: 'https://other.example' });
      gs2.appendActivity('other-task', { actor: 'system', eventType: 'init', summary: 'Other task' });

      const imp = gs2.importSnapshot(snapshot);
      assert.equal(imp.counts.activity, 2);
      assert.equal(gs2.getTask('priv-task-1').allowPrivate, true);
      assert.equal(gs2.listActivity('priv-task-1').length, 2);
      assert.equal(gs2.listActivity('other-task').length, 1);

      // Re-importing same snapshot is idempotent for activity
      gs2.importSnapshot(snapshot);
      assert.equal(gs2.listActivity('priv-task-1').length, 2);

      // ingestStaticScanResult idempotency & no per-check Verified Safe fact bloat
      const report = {
        taskId: 'static-idem-1',
        targets: ['https://app.example.com'],
        allowPrivate: false,
        results: [
          { name: 'env', status: 'SAFE', severity: 'NONE', target: 'https://app.example.com' },
          { name: 'git', status: 'SAFE', severity: 'NONE', target: 'https://app.example.com' },
          { name: 'cors', status: 'VULNERABLE', severity: 'HIGH', target: 'https://app.example.com', detail: 'Wildcard ACAO' }
        ]
      };
      const ing1 = gs2.ingestStaticScanResult(report);
      const ing2 = gs2.ingestStaticScanResult(report);
      assert.equal(ing1.nodes.length, ing2.nodes.length);
      assert.equal(ing1.findings.length, 1);
      assert.equal(ing2.nodes.some(n => String(n.title).startsWith('Verified Safe:')), false);

      // declaredScopeFilter: .gov denies agency.gov.uk & ReDoS-safe glob
      const scopeTask = gs2.createTask({ id: 'scope-gov-task', target: 'https://example.com' });
      gs2.setTaskScope(scopeTask.id, [
        { rule_type: 'domain', pattern: '.gov', is_allowed: false, source: 'declared' },
        { rule_type: 'url', pattern: `*${'a*'.repeat(40)}z`, is_allowed: true, source: 'declared' }
      ]);
      const filter = gs2.declaredScopeFilter(scopeTask.id);
      assert.equal(filter.matchesAsset({ host: 'agency.gov.uk', asset_type: 'subdomain', key: 'agency.gov.uk' }), false);
      const t0 = performance.now();
      assert.equal(filter.matchesAsset({ url: 'https://example.com/' + 'a'.repeat(80) + 'x', key: 'k' }), false);
      assert.ok(performance.now() - t0 < 50);

      gs.close();
      gs2.close();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('Feature #4: TrafficStore atomic recordExchange, blob_refs decrement, gcOrphanBlobs, rewrite valPart validation, maxRedirects:0, timeout', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-m1-ts-'));
    try {
      const ts = new TrafficStore({ dbPath: path.join(tmpDir, 'traffic.db'), blobDir: path.join(tmpDir, 'blobs') });
      const busyTimeout = ts.db.prepare('PRAGMA busy_timeout').get();
      assert.equal(busyTimeout.timeout, 5000);

      const bigA = 'A'.repeat(300 * 1024);
      const bigB = 'B'.repeat(300 * 1024);
      const ex1 = ts.recordExchange({ id: 'ex-overwrite', method: 'GET', url: 'https://example.com/a', statusCode: 200, resBody: bigA });
      const body1 = ts.db.prepare('SELECT res_blob_sha256 FROM exchange_bodies WHERE exchange_id = ?').get('ex-overwrite');
      assert.ok(body1.res_blob_sha256);

      ts.recordExchange({ id: 'ex-overwrite', method: 'GET', url: 'https://example.com/a', statusCode: 200, resBody: bigB });
      const oldRef = ts.db.prepare('SELECT * FROM blob_refs WHERE sha256 = ?').get(body1.res_blob_sha256);
      assert.equal(oldRef, undefined);

      // Touch file mtime past grace period and run gcOrphanBlobs
      const gcRes = ts.gcOrphanBlobs({ graceMs: 0, now: Date.now() + 10000 });
      assert.equal(gcRes.deletedBlobs.includes(body1.res_blob_sha256), true);

      // addRewriteRule validation
      assert.throws(() => ts.addRewriteRule({ name: 'bad1', target: 'header', matchPattern: '(X-Foo:bar)', isRegex: true }), /Invalid rewrite rule/);
      assert.throws(() => ts.addRewriteRule({ name: 'bad2', target: 'header', matchPattern: ':val', isRegex: false }), /header name/);
      assert.throws(() => ts.addRewriteRule({ name: 'bad3', target: 'header', matchPattern: 'X-Foo:(a+)+$', isRegex: true }), /ReDoS/);

      // replayRequest maxRedirects: 0 and timeout
      const exRedir = ts.recordExchange({ method: 'GET', url: 'https://example.com/redir', statusCode: 200, resBody: 'ok' });
      await assert.rejects(
        () => ts.replayRequest(exRedir.id, {}, {
          dnsResolver: async () => ['93.184.216.34'],
          followRedirects: true,
          maxRedirects: 0,
          fetcher: async () => ({ status: 302, headers: { location: 'https://example.com/b' }, text: async () => '' })
        }),
        /Maximum redirect limit \(0\) exceeded/
      );

      await assert.rejects(
        () => ts.replayRequest(exRedir.id, {}, {
          dnsResolver: async () => ['93.184.216.34'],
          timeout: 30,
          fetcher: (_u, init) => new Promise((_resolve, reject) => {
            init.signal.addEventListener('abort', () => reject(new Error('Replay aborted by timeout')), { once: true });
          })
        }),
        /Replay aborted by timeout/
      );

      assert.ok(ex1.id);
      ts.close();
      ts.close();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('Feature #5: EnrichEngine allowPrivate/pinStore, bounded cooldownCache, bounded stream reading, nmap XML decoding, ingestion sanitization, asset tree labels', async () => {
    const pinStore = new TargetPinStore({ allowPrivate: true });
    let seenUa = null;
    let streamCancelled = false;

    const engine = new EnrichEngine({
      allowPrivate: true,
      targetPinStore: pinStore,
      maxCacheSize: 2,
      maxBodyBytes: 64,
      cooldownMs: 60_000,
      dns: {
        resolve4: async (h) => (h === 'internal.corp' ? ['10.1.2.3'] : ['93.184.216.34']),
        resolve6: async () => [],
        resolveCname: async () => []
      },
      fetch: async (_url, init) => {
        seenUa = init.headers['User-Agent'];
        const encoder = new TextEncoder();
        let pulls = 0;
        const stream = new ReadableStream({
          pull(controller) {
            pulls += 1;
            if (pulls === 1) {
              controller.enqueue(encoder.encode('<html><title>Internal</title>'));
            } else {
              controller.enqueue(encoder.encode('A'.repeat(200)));
            }
          },
          cancel() {
            streamCancelled = true;
          }
        });
        return new Response(stream, { status: 200, headers: { 'content-type': 'text/html' } });
      }
    });

    const dnsPriv = await engine.resolveDomain('internal.corp', { now: 1000 });
    assert.deepEqual(dnsPriv.ipv4, ['10.1.2.3']);
    // Downgrading allowPrivate: false must NOT serve cached private entry
    const dnsDowngrade = await engine.resolveDomain('internal.corp', { allowPrivate: false, now: 1500 });
    assert.equal(dnsDowngrade.cached, false);
    assert.deepEqual(dnsDowngrade.ipv4, []);

    const httpPriv = await engine.probeHttp('http://internal.corp/app', { now: 1000 });
    assert.equal(httpPriv.title, 'Internal');
    assert.equal(seenUa, 'SecurityScanner-Enrich/2.2');
    assert.equal(streamCancelled, true);
    assert.ok(httpPriv.contentLength <= 64);
    await assert.rejects(
      () => engine.probeHttp('http://internal.corp/app', { allowPrivate: false, now: 1500 }),
      /SSRF policy/
    );

    // cooldownCache bounded by maxCacheSize=2
    await engine.resolveDomain('a.example.com', { now: 2000 });
    await engine.resolveDomain('b.example.com', { now: 2001 });
    assert.ok(engine.cooldownCache.size <= 2);

    // parseNmapOutput XML entity decoding before sanitization
    const nmapRes = ingestScanOutput('nmap', `
      <nmaprun>
        <host>
          <address addr="10.0.0.5" />
          <ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache &amp; SSL &lt;|im_start|&gt;&#x27;" version="2.4"/></port></ports>
        </host>
      </nmaprun>
    `);
    assert.equal(nmapRes.assets[1].banner.includes('&amp;'), false);
    assert.equal(nmapRes.assets[1].banner.includes('<|im_start|>'), false);

    // nuclei/httpx/ffuf URL/host/path sanitization
    const nucleiRes = ingestScanOutput('nuclei', JSON.stringify({
      'template-id': 'test',
      'matched-at': 'https://example.com/a`b"c<|im_start|>',
      info: { severity: 'high' }
    }));
    assert.equal(nucleiRes.assets[1].url.includes('`'), false);
    assert.equal(nucleiRes.assets[1].path.includes('<|im_start|>'), false);

    // buildFindingAssetTree aligns service labels and pushes unlinked at most once
    const tree = buildFindingAssetTree(
      [
        { name: 'xss', status: 'VULNERABLE', severity: 'HIGH', target: 'https://app.example.com:443/search' },
        { name: 'bad-target', status: 'VULNERABLE', severity: 'LOW', pages: ['', null] }
      ],
      [{ kind: 'service', host: 'app.example.com', port: 443, service: 'https' }]
    );
    const sub = tree.roots[0].children[0];
    assert.equal(sub.children.length, 1);
    assert.equal(sub.children[0].name, 'https://app.example.com:443');
    assert.equal(tree.unlinked.length, 1);
  });

  it('Feature #6: AgentEngine SUSPICIOUS/trafficId forwarding, redirect targetHost lock, map LRU bounds, NoiseGovernor bounds, mergeConfig & v2.2.0 alignment', async () => {
    // 1. Package version & notify v2.2
    const pkg = JSON.parse(fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
    assert.equal(pkg.version, '2.2.0');
    const [wh] = formatChannelPayloads('webhook', { findings: [] });
    assert.equal(wh.scanner, 'security-scanner/2.2');
    const [slack] = formatChannelPayloads('slack', { findings: [] });
    assert.match(slack.blocks.at(-1).elements[0].text, /Security Scanner v2\.2/);

    // 2. mergeConfig parity
    const mergedCfg = mergeConfig(
      { agent: true },
      { goal: 'audit', noiseProfile: 'quiet', scopeRules: [{ rule_type: 'domain', pattern: 'example.com' }], markdown: true, csv: 'out.csv', allowPrivate: true, ui: true, techOverride: 'nextjs' }
    );
    assert.equal(mergedCfg.agent, true);
    assert.equal(mergedCfg.goal, 'audit');
    assert.equal(mergedCfg.noiseProfile, 'quiet');
    assert.equal(mergedCfg.scopeRules.length, 1);
    assert.equal(mergedCfg.markdown, true);
    assert.equal(mergedCfg.csv, 'out.csv');
    assert.equal(mergedCfg.allowPrivate, true);
    assert.equal(mergedCfg.ui, true);
    assert.equal(mergedCfg.techOverride, 'nextjs');

    // 3. NoiseGovernor bounded hosts (preserving active semaphore) & bounded cache
    let now = 1000;
    const gov = new NoiseGovernor('balanced', { maxHosts: 2, maxCacheEntries: 2, cacheTtlMs: 5000, nowFn: () => now, sleepFn: async () => {} });
    let releaseBusy;
    const busyPromise = gov.execute('https://busy.example/1', () => new Promise(r => { releaseBusy = r; }));
    await gov.execute('https://idle1.example/1', async () => ({ status: 200, headers: {}, text: '1' }));
    await gov.execute('https://idle2.example/1', async () => ({ status: 200, headers: {}, text: '2' }));
    assert.equal(gov.hosts.has('busy.example'), true);
    assert.equal(gov.hosts.size, 2);
    releaseBusy({ status: 200, headers: {}, text: 'busy' });
    await busyPromise;
    assert.equal(gov.cache.size, 2);

    // 4. AgentEngine: SUSPICIOUS forwarding + trafficId receipt promotion + redirect targetHost lock + LRU task bounds
    const gs = new GraphStore({ dbPath: ':memory:' });
    const ts = new TrafficStore({ dbPath: ':memory:' });
    const es = new EvidenceStore({ dbPath: ':memory:', trafficStore: ts });
    const ex = ts.recordExchange({
      method: 'GET',
      url: 'https://target.example/vuln',
      statusCode: 200,
      resHeaders: { 'content-type': 'text/plain' },
      resBody: 'CONFIRMED_LEAK_TOKEN_XYZ_987654'
    });

    const mockChecks = [
      {
        name: 'vuln-with-receipt',
        run: async () => ({
          name: 'vuln-with-receipt',
          status: 'VULNERABLE',
          severity: 'HIGH',
          detail: 'Confirmed leak',
          trafficId: ex.id,
          evidenceQuotes: ['CONFIRMED_LEAK_TOKEN_XYZ_987654']
        })
      },
      {
        name: 'suspicious-check',
        run: async () => ({
          name: 'suspicious-check',
          status: 'SUSPICIOUS',
          severity: 'MEDIUM',
          detail: 'Potential issue',
          trafficId: ex.id,
          evidenceQuotes: ['CONFIRMED_LEAK_TOKEN_XYZ_987654']
        })
      }
    ];

    const engine = new AgentEngine({
      graphStore: gs,
      trafficStore: ts,
      evidenceStore: es,
      checks: mockChecks,
      maxCachedTasks: 2,
      debounceMs: 0,
      dnsResolver: async () => ['93.184.216.34'],
      fetchImpl: async (u) => {
        if (u.includes('/off-host-redir')) {
          return { status: 302, headers: { location: 'https://evil.example/steal' }, text: async () => '' };
        }
        return { status: 200, headers: {}, text: async () => 'ok' };
      }
    });

    const task = gs.createTask({ target: 'https://target.example', goal: 'Test M1' });
    const intent = gs.addNode({
      taskId: task.id,
      nodeType: 'intent',
      title: 'Run checks',
      status: 'pending',
      data: { kind: 'checks', category: 'exposure', checks: ['vuln-with-receipt', 'suspicious-check'] }
    });

    await engine.executeIntent(task.id, intent.id, { deterministic: true });
    const findings = gs.listNodes(task.id, { nodeType: 'finding' });
    assert.equal(findings.length, 2);
    const verifiedFinding = findings.find(f => f.title.includes('vuln-with-receipt'));
    const suspiciousFinding = findings.find(f => f.title.includes('suspicious-check'));
    assert.equal(verifiedFinding.status, 'verified');
    assert.equal(verifiedFinding.poe_level, 3);
    assert.equal(suspiciousFinding.status, 'suspected');
    assert.ok(suspiciousFinding.poe_level <= 2);

    // Off-host redirect blocked while .gov SSRF message remains intact
    await assert.rejects(
      () => engine._fetch('https://target.example/off-host-redir', { targetHost: 'target.example', targetUrl: 'https://target.example', followRedirects: true }),
      /Redirect blocked: off-target host "evil\.example"/
    );

    // Task LRU bounds + cleanupTask
    const t2 = gs.createTask({ target: 'https://t2.example' });
    const t3 = gs.createTask({ target: 'https://t3.example' });
    engine.getLedger(t2.id);
    engine.getLedger(t3.id);
    assert.ok(engine.ledgers.size <= 2);
    engine.cleanupTask(t3.id);
    assert.equal(engine.ledgers.has(t3.id), false);

    es.close();
    ts.close();
    gs.close();
  });
});
