import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
   FIELD_SPECS,
  AssetDslError,
  compileAssetDsl,
} from '../../core/asset-dsl.js';
import {
  GraphStore,
  createGraphStore,
  computeCSegment,
  extractRootDomain,
} from '../../core/graph-store.js';

describe('Step 2.1: Asset Query DSL (core/asset-dsl.js)', () => {
  it('exports all 19 ARTEX fields plus asset and key in FIELD_SPECS', () => {
    const requiredFields = [
      'domain', 'host', 'ip', 'port', 'service', 'protocol', 'url', 'path',
      'title', 'status', 'source', 'company', 'c_segment', 'type', 'scope',
      'confidence', 'verified', 'severity', 'finding', 'asset', 'key',
    ];
    for (const field of requiredFields) {
      assert.ok(FIELD_SPECS[field], `Expected FIELD_SPECS to define "${field}"`);
      assert.equal(FIELD_SPECS[field].name, field);
    }
  });

  it('compiles empty or whitespace queries to 1=1 with empty params', () => {
    const res1 = compileAssetDsl('');
    assert.equal(res1.whereSql, '1=1');
    assert.deepEqual(res1.params, []);
    assert.equal(res1.ast, null);

    const res2 = compileAssetDsl('   ');
    assert.equal(res2.whereSql, '1=1');
    assert.deepEqual(res2.params, []);
  });

  it('compiles boolean AND/OR, parentheses, bare tokens, and field operators to parameterized SQL', () => {
    const query = '(domain = "example.com" AND port >= 443) OR (type == "ip" && c_segment = "192.168.1.0/24" && status != 404)';
    const compiled = compileAssetDsl(query);

    assert.ok(compiled.whereSql.includes('AND'));
    assert.ok(compiled.whereSql.includes('OR'));
    assert.ok(!compiled.whereSql.includes('example.com'), 'Raw user value must not be interpolated into SQL');
    assert.ok(!compiled.whereSql.includes('192.168.1.0/24'), 'Raw user value must not be interpolated into SQL');
    assert.deepEqual(compiled.params, ['%example.com%', 443, 'ip', '192.168.1.0/24', 404]);
    assert.equal(compiled.ast.type, 'or');
  });

  it('compiles bare search tokens across text columns with ? placeholders', () => {
    const compiled = compileAssetDsl('admin-portal');
    assert.ok(compiled.whereSql.includes('LIKE LOWER(?)'));
    assert.ok(compiled.params.length >= 5);
    assert.ok(compiled.params.every((p) => p === '%admin-portal%'));
  });

  it('throws descriptive AssetDslError with position on syntax errors or unknown fields', () => {
    assert.throws(
      () => compileAssetDsl('unknown_col = "test"'),
      (err) => err instanceof AssetDslError && /Unknown asset DSL field/i.test(err.message) && typeof err.position === 'number'
    );

    assert.throws(
      () => compileAssetDsl('(host = "example.com" AND port = 80'),
      (err) => err instanceof AssetDslError && /closing parenthesis/i.test(err.message)
    );

    assert.throws(
      () => compileAssetDsl('host = "unterminated'),
      (err) => err instanceof AssetDslError && /Unterminated quoted string/i.test(err.message)
    );

    assert.throws(
      () => compileAssetDsl('port = "not_a_number"'),
      (err) => err instanceof AssetDslError && /numeric value/i.test(err.message)
    );

    assert.throws(
      () => compileAssetDsl('host = "example.com" AND'),
      (err) => err instanceof AssetDslError && /Expected expression/i.test(err.message)
    );
  });
});

describe('Step 2.1: Embedded Dual-Graph Store (core/graph-store.js)', () => {
  let store;

  beforeEach(() => {
    store = createGraphStore({ dbPath: ':memory:' });
  });

  afterEach(() => {
    store.close();
  });

  it('computes IPv4 /24 and IPv6 /48 C-segments and extracts root domains', () => {
    assert.equal(computeCSegment('192.168.10.55'), '192.168.10.0/24');
    assert.equal(computeCSegment('10.20.30.254'), '10.20.30.0/24');
    assert.equal(computeCSegment('2001:0db8:85a3:1234:5678:8a2e:0370:7334'), '2001:db8:85a3::/48');
    assert.equal(computeCSegment('2606:4700:4700::1111'), '2606:4700:4700::/48');
    assert.equal(computeCSegment('not-an-ip'), null);

    assert.equal(extractRootDomain('api.v2.example.com'), 'example.com');
    assert.equal(extractRootDomain('portal.gov.co.uk'), 'gov.co.uk');
    assert.equal(extractRootDomain('192.168.1.1'), null);
  });

  it('upserts assets, deduplicates on (asset_type, key), and links parent host chain via linkHostAssets', () => {
    const task = store.createTask({
      title: 'Asset Graph Test',
      target: 'https://api.shop.example.com',
      goal: 'Verify asset hierarchy',
    });

    const endpoint = store.upsertAsset(
      {
        asset_type: 'endpoint',
        url: 'https://api.shop.example.com:8443/v1/checkout?debug=1',
        ip: '203.0.113.45',
        title: 'Checkout API',
        status_code: 200,
        service: 'https',
        verified: true,
        metadata: { tech: ['Node.js', 'Express'] },
      },
      { taskId: task.id }
    );

    assert.equal(endpoint.asset_type, 'endpoint');
    assert.equal(endpoint.host, 'api.shop.example.com');
    assert.equal(endpoint.port, 8443);
    assert.equal(endpoint.path, '/v1/checkout?debug=1');
    assert.equal(endpoint.c_segment, '203.0.113.0/24');
    assert.ok(endpoint.parent_asset_id, 'Endpoint should automatically link to parent subdomain asset');

    const parentSubdomain = store.getAsset(endpoint.parent_asset_id);
    assert.ok(parentSubdomain);
    assert.equal(parentSubdomain.asset_type, 'subdomain');
    assert.equal(parentSubdomain.key, 'api.shop.example.com');
    assert.ok(parentSubdomain.parent_asset_id, 'Subdomain should automatically link to parent root_domain asset');

    const rootDomain = store.getAsset(parentSubdomain.parent_asset_id);
    assert.ok(rootDomain);
    assert.equal(rootDomain.asset_type, 'root_domain');
    assert.equal(rootDomain.key, 'example.com');

    // Verify associated IP asset was also registered with /24 c_segment
    const ipQuery = store.queryAssets({ dsl: 'type == "ip" AND c_segment = "203.0.113.0/24"' });
    assert.equal(ipQuery.total, 1);
    assert.equal(ipQuery.items[0].ip, '203.0.113.45');

    // Upserting the same endpoint again merges metadata and preserves ID
    const updatedEndpoint = store.upsertAsset(
      {
        asset_type: 'endpoint',
        key: endpoint.key,
        status_code: 201,
        metadata: { waf: 'Cloudflare' },
      },
      { taskId: task.id }
    );
    assert.equal(updatedEndpoint.id, endpoint.id);
    assert.equal(updatedEndpoint.status_code, 201);
    assert.deepEqual(updatedEndpoint.metadata.tech, ['Node.js', 'Express']);
    assert.equal(updatedEndpoint.metadata.waf, 'Cloudflare');
  });

  it('executes DSL queries and enforces declaredScopeFilter when inScopeOnly is true', () => {
    const task = store.createTask({
      title: 'Scope Filter Test',
      target: 'https://example.com',
    });

    store.upsertAsset({ asset_type: 'subdomain', key: 'app.example.com', host: 'app.example.com', port: 443 }, { taskId: task.id });
    store.upsertAsset({ asset_type: 'subdomain', key: 'dev.internal.example.com', host: 'dev.internal.example.com', port: 8080 }, { taskId: task.id });
    store.upsertAsset({ asset_type: 'subdomain', key: 'cdn.thirdparty.net', host: 'cdn.thirdparty.net', port: 443 }, { taskId: task.id });
    store.upsertAsset({ asset_type: 'ip', key: '2001:db8:abcd:0001::5', ip: '2001:db8:abcd:0001::5' }, { taskId: task.id });

    // Set declared scope: allow example.com, deny dev.internal.example.com, plus an unanchored 'auto' rule for thirdparty.net
    store.setTaskScope(task.id, [
      { rule_type: 'root_domain', pattern: 'example.com', is_allowed: true, source: 'manual' },
      { rule_type: 'subdomain', pattern: 'dev.internal.example.com', is_allowed: false, source: 'manual' },
      { rule_type: 'subdomain', pattern: 'cdn.thirdparty.net', is_allowed: true, source: 'auto' },
      { rule_type: 'subdomain', pattern: 'app.example.com', is_allowed: true, source: 'auto' },
    ]);

    const scoped = store.queryAssets({
      taskId: task.id,
      inScopeOnly: true,
    });

    const scopedKeys = scoped.items.map((a) => a.key).sort();
    // example.com (auto-derived root_domain) and app.example.com are in scope;
    // dev.internal.example.com is blocked by deny rule;
    // cdn.thirdparty.net is an 'auto' rule outside any declared root and must be excluded by declaredScopeFilter!
    assert.deepEqual(scopedKeys, ['app.example.com', 'example.com']);

    // DSL filter with severity & finding predicates
    const appAsset = scoped.items.find((a) => a.key === 'app.example.com');
    const findingNode = store.addNode({
      taskId: task.id,
      nodeType: 'finding',
      title: 'SQL Injection in Login',
      severity: 'CRITICAL',
      poeLevel: 3,
      summary: 'Time-based blind SQLi confirmed',
      assetIds: [appAsset.id],
    });
    assert.ok(findingNode.id);

    const critAssets = store.queryAssets({
      dsl: 'severity == "CRITICAL" AND finding = "SQL Injection"',
    });
    assert.equal(critAssets.total, 1);
    assert.equal(critAssets.items[0].id, appAsset.id);
  });

  it('builds Exploration DAG, traces getFindingLineage, and computes getCoverageGraph', () => {
    const task = store.createTask({
      title: 'Exploration Lineage Test',
      target: 'https://portal.example.com',
      goal: 'Verify auth bypass',
    });

    const asset = store.upsertAsset(
      {
        asset_type: 'endpoint',
        url: 'https://portal.example.com/api/admin',
        status_code: 200,
      },
      { taskId: task.id }
    );

    const begin = store.addNode({ taskId: task.id, nodeType: 'begin', title: 'Begin' });
    const goal = store.addNode({ taskId: task.id, nodeType: 'goal', title: 'Verify Admin API Access Control' });
    const intent = store.addNode({
      taskId: task.id,
      nodeType: 'intent',
      title: 'Probe /api/admin without session token',
      assetIds: [asset.id],
    });
    const fact = store.addNode({
      taskId: task.id,
      nodeType: 'fact',
      title: 'Unauthenticated 200 OK on /api/admin',
      summary: 'Endpoint returned admin user list without Authorization header',
      assetIds: [asset.id],
    });
    const finding = store.addNode({
      taskId: task.id,
      nodeType: 'finding',
      title: 'Broken Function Level Authorization on /api/admin',
      severity: 'HIGH',
      poeLevel: 3,
      summary: 'Direct access to /api/admin yields administrative records',
      assetIds: [asset.id],
    });

    store.addEdge({ taskId: task.id, fromNodeId: begin.id, toNodeId: goal.id, edgeType: 'spawns' });
    store.addEdge({ taskId: task.id, fromNodeId: goal.id, toNodeId: intent.id, edgeType: 'spawns' });
    store.addEdge({ taskId: task.id, fromNodeId: intent.id, toNodeId: fact.id, edgeType: 'yields' });
    store.addEdge({ taskId: task.id, fromNodeId: fact.id, toNodeId: finding.id, edgeType: 'yields' });
    store.addEdge({ taskId: task.id, fromNodeId: finding.id, toNodeId: goal.id, edgeType: 'proves' });

    const lineage = store.getFindingLineage(task.id, finding.id);
    assert.equal(lineage.finding.id, finding.id);
    assert.deepEqual(
      lineage.chain.map((n) => n.node_type),
      ['begin', 'goal', 'intent', 'fact', 'finding']
    );
    assert.equal(lineage.assets.length, 1);
    assert.equal(lineage.assets[0].id, asset.id);

    const covGraph = store.getCoverageGraph({ taskId: task.id });
    assert.equal(covGraph.nodes.length, 3); // root_domain + subdomain + endpoint
    assert.equal(covGraph.edges.length, 2); // root->sub, sub->endpoint
    assert.equal(covGraph.stats.totalFindings, 1);
    assert.ok(covGraph.stats.totalAnchors >= 3);
  });

  it('enforces atomic intent lease fencing (15s heartbeat / 90s expiry) and stale token rejection', () => {
    const task = store.createTask({ title: 'Lease Fencing Test' });
    const intent = store.addNode({
      taskId: task.id,
      nodeType: 'intent',
      title: 'Fenced Verification Intent',
      status: 'pending',
    });

    const t0 = 1_700_000_000_000;
    // Worker 1 claims intent
    const claim1 = store.claimIntentToken(intent.id, 'worker-1', { ttlMs: 90_000, now: t0 });
    assert.equal(claim1.claimed, true);
    assert.ok(claim1.unclaimToken);
    assert.equal(claim1.node.status, 'running');
    assert.equal(claim1.node.claim_owner, 'worker-1');
    assert.equal(claim1.node.claim_expires_at, t0 + 90_000);

    // Worker 2 attempts to claim while lease is still active -> rejected
    const claim2 = store.claimIntentToken(intent.id, 'worker-2', { ttlMs: 90_000, now: t0 + 10_000 });
    assert.equal(claim2.claimed, false);
    assert.equal(claim2.unclaimToken, null);

    // Worker 1 sends 15s heartbeat -> succeeds
    const hbOk = store.heartbeatIntentClaim(intent.id, claim1.unclaimToken, {
      ttlMs: 90_000,
      now: t0 + 15_000,
    });
    assert.equal(hbOk, true);
    assert.equal(store.getNode(intent.id).claim_expires_at, t0 + 105_000);

    // Stale/wrong token heartbeat -> fails
    assert.equal(store.heartbeatIntentClaim(intent.id, 'wrong-token', { now: t0 + 20_000 }), false);

    // Simulate lease expiry after 90s without heartbeat (now = t0 + 110_000)
    const resetCount = store.resetExpiredIntents(task.id, { now: t0 + 110_000 });
    assert.equal(resetCount, 1);

    const afterReset = store.getNode(intent.id);
    assert.equal(afterReset.status, 'pending');
    assert.notEqual(afterReset.unclaim_token, claim1.unclaimToken, 'unclaim_token must be rotated on reset');

    // Worker 1 tries to settle with its old token -> fenced out (returns false)
    const staleSettle = store.settleIntentClaim(intent.id, claim1.unclaimToken, {
      status: 'completed',
      summary: 'Late write from zombie worker-1',
    });
    assert.equal(staleSettle, false);

    // Worker 2 claims the reset intent and settles it cleanly
    const claim3 = store.claimIntentToken(intent.id, 'worker-2', { ttlMs: 90_000, now: t0 + 111_000 });
    assert.equal(claim3.claimed, true);
    assert.notEqual(claim3.unclaimToken, claim1.unclaimToken);

    const validSettle = store.settleIntentClaim(intent.id, claim3.unclaimToken, {
      status: 'completed',
      summary: 'Completed cleanly by worker-2',
      data: { checksRun: 5 },
    });
    assert.equal(validSettle, true);

    const finalNode = store.getNode(intent.id);
    assert.equal(finalNode.status, 'completed');
    assert.equal(finalNode.summary, 'Completed cleanly by worker-2');
    assert.equal(finalNode.data.checksRun, 5);
  });

  it('performs exclusive cascade delete in cancelIntent, preserving shared facts/findings and goals', () => {
    const task = store.createTask({ title: 'Exclusive Cascade Delete Test' });
    const goal = store.addNode({ taskId: task.id, nodeType: 'goal', title: 'Root Goal' });
    const intentA = store.addNode({ taskId: task.id, nodeType: 'intent', title: 'Intent A (to cancel)' });
    const intentB = store.addNode({ taskId: task.id, nodeType: 'intent', title: 'Intent B (keep)' });

    const exclusiveFactA = store.addNode({ taskId: task.id, nodeType: 'fact', title: 'Exclusive Fact of A' });
    const exclusiveFindingA = store.addNode({ taskId: task.id, nodeType: 'finding', title: 'Exclusive Finding of A' });
    const sharedFact = store.addNode({ taskId: task.id, nodeType: 'fact', title: 'Shared Fact (A and B)' });
    const sharedFinding = store.addNode({ taskId: task.id, nodeType: 'finding', title: 'Finding from Shared Fact' });

    store.addEdge({ taskId: task.id, fromNodeId: goal.id, toNodeId: intentA.id, edgeType: 'spawns' });
    store.addEdge({ taskId: task.id, fromNodeId: goal.id, toNodeId: intentB.id, edgeType: 'spawns' });

    // Exclusive chain under Intent A
    store.addEdge({ taskId: task.id, fromNodeId: intentA.id, toNodeId: exclusiveFactA.id, edgeType: 'yields' });
    store.addEdge({ taskId: task.id, fromNodeId: exclusiveFactA.id, toNodeId: exclusiveFindingA.id, edgeType: 'yields' });

    // Shared chain supported by both Intent A and Intent B
    store.addEdge({ taskId: task.id, fromNodeId: intentA.id, toNodeId: sharedFact.id, edgeType: 'yields' });
    store.addEdge({ taskId: task.id, fromNodeId: intentB.id, toNodeId: sharedFact.id, edgeType: 'yields' });
    store.addEdge({ taskId: task.id, fromNodeId: sharedFact.id, toNodeId: sharedFinding.id, edgeType: 'yields' });

    const cancelRes = store.cancelIntent(task.id, intentA.id);
    assert.equal(cancelRes.cancelled, true);
    assert.equal(cancelRes.deletedCount, 3); // intentA, exclusiveFactA, exclusiveFindingA

    // Exclusive nodes are gone
    assert.equal(store.getNode(intentA.id), null);
    assert.equal(store.getNode(exclusiveFactA.id), null);
    assert.equal(store.getNode(exclusiveFindingA.id), null);

    // Goal, Intent B, Shared Fact, and Shared Finding remain intact
    assert.ok(store.getNode(goal.id));
    assert.ok(store.getNode(intentB.id));
    assert.ok(store.getNode(sharedFact.id));
    assert.ok(store.getNode(sharedFinding.id));
  });

  it('detects missing category verification gaps in buildCoverageLedger', () => {
    const task = store.createTask({ title: 'Coverage Ledger Test' });
    const asset1 = store.upsertAsset({ asset_type: 'subdomain', key: 'api.example.com' }, { taskId: task.id });
    const asset2 = store.upsertAsset({ asset_type: 'subdomain', key: 'auth.example.com' }, { taskId: task.id });

    store.setTaskScope(task.id, [
      { rule_type: 'subdomain', pattern: 'api.example.com', is_allowed: true },
      { rule_type: 'subdomain', pattern: 'auth.example.com', is_allowed: true },
    ]);

    const requiredCategories = ['recon', 'auth', 'injection'];
    store.recordCoverage({ taskId: task.id, assetId: asset1.id, checkCategory: 'recon', status: 'tested' });
    store.recordCoverage({ taskId: task.id, assetId: asset1.id, checkCategory: 'auth', status: 'tested' });
    store.recordCoverage({ taskId: task.id, assetId: asset1.id, checkCategory: 'injection', status: 'tested' });
    store.recordCoverage({ taskId: task.id, assetId: asset2.id, checkCategory: 'recon', status: 'tested' });

    const ledger = store.buildCoverageLedger(task.id, { requiredCategories });
    assert.equal(ledger.totalAssets, 2);
    assert.equal(ledger.entries.length, 4);
    assert.equal(ledger.gaps.length, 2); // auth.example.com missing 'auth' and 'injection'
    assert.deepEqual(
      ledger.gaps.map((g) => `${g.assetKey}:${g.checkCategory}`).sort(),
      ['auth.example.com:auth', 'auth.example.com:injection']
    );
    assert.equal(ledger.coveragePct, 66.67);
  });

  it('enforces SHA-256 deduplication and evidence gating on rsi_lessons and gap-free seq on activity', () => {
    const task = store.createTask({ title: 'Lessons & Activity Test' });

    const act1 = store.appendActivity(task.id, { actor: 'planner', eventType: 'plan_round', summary: 'Round 1' });
    const act2 = store.appendActivity(task.id, { actor: 'worker-1', eventType: 'intent_done', summary: 'Checked headers' });
    assert.equal(act2.seq, act1.seq + 1);

    const delta = store.listActivity(task.id, { sinceSeq: act1.seq });
    assert.equal(delta.length, 1);
    assert.equal(delta[0].seq, act2.seq);

    // 1. Unverified lesson without evidence -> recorded, but excluded from listVerifiedLessons
    const unverified = store.recordLesson({
      category: 'nextjs',
      title: 'Check _next/data exposure',
      lesson: 'Inspect buildId routes for unauthenticated SSR props',
      verified: false,
    });
    assert.equal(unverified.verified, false);
    assert.equal(store.listVerifiedLessons().length, 0);

    // 2. Lesson with verified: true but NO evidenceNodeId -> still gated out!
    const missingEvidence = store.recordLesson({
      category: 'spring',
      title: 'Actuator heapdump check',
      lesson: 'Check /actuator/heapdump with HEAD request',
      verified: true,
      evidenceNodeId: null,
    });
    assert.equal(missingEvidence.verified, false);
    assert.equal(store.listVerifiedLessons().length, 0);

    // 3. Re-recording the first lesson with a valid evidenceNodeId & verified: true -> deduplicates, increments hit_count, and unlocks verification
    const findingNode = store.addNode({
      taskId: task.id,
      nodeType: 'finding',
      title: 'Next.js SSR Props Exposure',
      severity: 'HIGH',
    });
    const verifiedLesson = store.recordLesson({
      category: 'nextjs',
      title: 'Check _next/data exposure',
      lesson: 'Inspect buildId routes for unauthenticated SSR props',
      evidenceNodeId: findingNode.id,
      verified: true,
    });

    assert.equal(verifiedLesson.id, unverified.id);
    assert.equal(verifiedLesson.hit_count, 2);
    assert.equal(verifiedLesson.verified, true);

    const verifiedList = store.listVerifiedLessons();
    assert.equal(verifiedList.length, 1);
    assert.equal(verifiedList[0].id, unverified.id);
    assert.equal(verifiedList[0].evidence_node_id, findingNode.id);
  });

  it('ingests static scan.js reports via ingestStaticScanResult and round-trips snapshots', () => {
    const scanReport = {
      target: 'https://app.example.com',
      fingerprint: {
        summary: 'Next.js(90), Node.js(80)',
        detectedTags: ['nextjs', 'node'],
      },
      risk: { score: 75, level: 'HIGH', grade: 'D' },
      results: [
        {
          target: 'https://app.example.com/.env',
          checkId: 'env-exposure',
          name: 'Environment File Exposure',
          status: 'VULNERABLE',
          severity: 'CRITICAL',
          reason: 'Exposed .env file containing secrets',
          path: '/.env',
        },
        {
          target: 'https://app.example.com',
          checkId: 'security-headers',
          name: 'Security Headers Check',
          status: 'SAFE',
          severity: 'NONE',
          reason: 'All required headers present',
        },
      ],
    };

    const ingested = store.ingestStaticScanResult(scanReport);
    assert.ok(ingested.taskId);
    assert.equal(ingested.findings.length, 1);
    assert.equal(ingested.findings[0].severity, 'CRITICAL');

    const lineage = store.getFindingLineage(ingested.taskId, ingested.findings[0].id);
    assert.deepEqual(
      lineage.chain.map((n) => n.node_type),
      ['begin', 'goal', 'intent', 'fact', 'finding']
    );

    // Export and import into a second GraphStore instance
    const snapshot = store.exportSnapshot(ingested.taskId);
    const store2 = createGraphStore({ dbPath: ':memory:' });
    try {
      const importRes = store2.importSnapshot(snapshot);
      assert.equal(importRes.imported, true);
      assert.equal(importRes.counts.tasks, 1);
      assert.ok(importRes.counts.assets >= 3);

      const importedGraph = store2.getExplorationGraph(ingested.taskId);
      assert.equal(importedGraph.task.target, 'https://app.example.com');
      assert.equal(importedGraph.nodes.length, ingested.nodes.length);
      assert.equal(importedGraph.edges.length, ingested.edges.length);
    } finally {
      store2.close();
    }
  });

  it('CANDIDATE-7: upsertAsset honors asset.kind precedence for ingested nmap/httpx/ffuf assets', () => {
    const task = store.createTask({ title: 'Ingest Kind Precedence Test', target: 'https://example.com' });

    const nmapIp = store.upsertAsset(
      { kind: 'ip', value: '93.184.216.34', host: 'example.com' },
      { taskId: task.id }
    );
    assert.equal(nmapIp.asset_type, 'ip');
    assert.equal(nmapIp.key, '93.184.216.34');
    assert.equal(nmapIp.ip, '93.184.216.34');

    const nmapService = store.upsertAsset(
      { kind: 'service', value: '93.184.216.34:80/tcp', host: '93.184.216.34', port: 80, protocol: 'tcp', service: 'http' },
      { taskId: task.id }
    );
    assert.equal(nmapService.asset_type, 'service');
    assert.equal(nmapService.port, 80);

    const httpxService = store.upsertAsset(
      { kind: 'service', value: 'https://example.com/app', url: 'https://example.com/app', host: 'example.com', status: 200 },
      { taskId: task.id }
    );
    assert.equal(httpxService.asset_type, 'service');
    assert.equal(httpxService.url, 'https://example.com/app');

    const ffufEndpoint = store.upsertAsset(
      { kind: 'endpoint', value: 'https://example.com/api/v1', url: 'https://example.com/api/v1', host: 'example.com', path: '/api/v1' },
      { taskId: task.id }
    );
    assert.equal(ffufEndpoint.asset_type, 'endpoint');

    const serviceQuery = store.queryAssets({ taskId: task.id, dsl: 'kind=service' });
    assert.equal(serviceQuery.total, 2);
    assert.deepEqual(
      serviceQuery.items.map((a) => a.key).sort(),
      ['https://example.com/app', 'tcp://93.184.216.34:80']
    );
  });
});
