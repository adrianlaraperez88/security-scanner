import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  runDecoderStep,
  runDecoderPipeline,
  inspectJwtToken,
  smartInspectValue,
  compareResponses
} from '../../core/decoder-comparer.js';
import {
  parseIntruderTemplate,
  buildIntruderPayloads,
  runIntruderCampaign,
  runAutorizeMatrix
} from '../../core/intruder.js';
import {
  TrafficStore,
  templateUrlPath,
  analyzePassiveExchange
} from '../../core/traffic.js';

test('decoder-comparer: runDecoderPipeline, smartInspectValue, inspectJwtToken & compareResponses work accurately', () => {
  // 1. Multi-stage pipeline (URL encode -> Base64 encode -> Base64 decode -> URL decode)
  const original = '{"user":"admin","id":42}';
  const encoded = runDecoderPipeline(original, ['url_encode', 'base64_encode']);
  const decoded = runDecoderPipeline(encoded.output, ['base64_decode', 'url_decode']);
  assert.equal(decoded.output, original);
  assert.equal(decoded.history.length, 2);

  // 2. Smart Auto-Decode unwraps nested Base64 + URL + JSON automatically
  const smart = smartInspectValue(Buffer.from(encodeURIComponent(original), 'utf8').toString('base64'));
  assert.ok(smart.detectedTypes.includes('base64'));
  assert.ok(smart.detectedTypes.includes('url'));
  assert.ok(smart.detectedTypes.includes('json'));
  assert.equal(smart.parsedJson.user, 'admin');

  // 3. JWT Inspector detects alg:none, kid path traversal, and jku external key URL
  const unsafeHeader = Buffer.from(JSON.stringify({ alg: 'none', kid: '../../etc/passwd', jku: 'https://evil.example/jwks.json' })).toString('base64url');
  const unsafePayload = Buffer.from(JSON.stringify({ sub: '123', role: 'admin' })).toString('base64url');
  const jwtRes = inspectJwtToken(`Bearer ${unsafeHeader}.${unsafePayload}.`);
  assert.equal(jwtRes.valid, true);
  assert.equal(jwtRes.riskLevel, 'CRITICAL');
  assert.ok(jwtRes.securityNotes.some(n => n.includes('unsigned algorithm')));
  assert.ok(jwtRes.securityNotes.some(n => n.includes('"kid" header')));
  assert.ok(jwtRes.securityNotes.some(n => n.includes('"jku" header')));

  // 4. Burp Comparer computes similarityRatio, statusDelta, byteDelta, and JSON structural diff
  const leftRes = {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id: 1, email: 'alice@example.com', role: 'user' })
  };
  const rightRes = {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'X-Extra': '1' },
    body: JSON.stringify({ id: 1, email: 'alice@example.com', role: 'admin', permissions: ['all'] })
  };
  const diff = compareResponses(leftRes, rightRes);
  assert.equal(diff.identical, false);
  assert.ok(diff.similarityRatio > 0.4 && diff.similarityRatio < 1);
  assert.deepEqual(diff.headerDiff.addedHeaders, ['x-extra']);
  assert.equal(diff.jsonDiff.isJson, true);
  assert.deepEqual(diff.jsonDiff.addedKeys, ['permissions']);
  assert.equal(diff.jsonDiff.changedKeys[0].key, 'role');
});

test('intruder: supports Sniper, Battering Ram, Pitchfork, and Cluster Bomb across URL/Header/Body §markers§', async () => {
  const tpl = parseIntruderTemplate({
    url: 'https://api.example.com/items/§10§',
    method: 'POST',
    headers: { 'X-Role': '§guest§' },
    body: '{"filter":"§default§"}'
  });
  assert.equal(tpl.positions.length, 3);

  // Sniper: 3 positions * 2 payloads = 6 requests
  const sniperPlan = buildIntruderPayloads({
    positions: tpl.positions,
    payloadSets: [['admin', 'test']],
    attackMode: 'sniper'
  });
  assert.equal(sniperPlan.length, 6);
  assert.deepEqual(sniperPlan[0].positionValues, ['admin', 'guest', 'default']);
  assert.deepEqual(sniperPlan[2].positionValues, ['10', 'admin', 'default']);

  // Battering Ram: 2 payloads placed in all 3 positions simultaneously = 2 requests
  const ramPlan = buildIntruderPayloads({
    positions: tpl.positions,
    payloadSets: [['ram1', 'ram2']],
    attackMode: 'battering_ram'
  });
  assert.equal(ramPlan.length, 2);
  assert.deepEqual(ramPlan[0].positionValues, ['ram1', 'ram1', 'ram1']);

  // Pitchfork: lockstep across 3 lists = 2 requests
  const pitchforkPlan = buildIntruderPayloads({
    positions: tpl.positions,
    payloadSets: [['1', '2'], ['user', 'admin'], ['a', 'b']],
    attackMode: 'pitchfork'
  });
  assert.equal(pitchforkPlan.length, 2);
  assert.deepEqual(pitchforkPlan[1].positionValues, ['2', 'admin', 'b']);

  // Cluster Bomb: 2 * 2 * 2 = 8 requests
  const bombPlan = buildIntruderPayloads({
    positions: tpl.positions,
    payloadSets: [['1', '2'], ['user', 'admin'], ['a', 'b']],
    attackMode: 'cluster_bomb'
  });
  assert.equal(bombPlan.length, 8);

  // Campaign runner with mock fetch scoring status/grep/length anomalies
  const campaign = await runIntruderCampaign(
    {
      url: 'https://api.example.com/users/§1§',
      payloadSets: [['2', 'admin', '999']],
      attackMode: 'sniper',
      grepMatch: ['SUPERSECRET_TOKEN']
    },
    {
      fetchWithRetry: async (url) => {
        if (url.endsWith('/admin')) {
          return {
            status: 200,
            headers: { 'content-type': 'application/json' },
            text: '{"user":"admin","secret":"SUPERSECRET_TOKEN","notes":"' + 'A'.repeat(200) + '"}'
          };
        }
        if (url.endsWith('/999')) {
          return { status: 404, headers: {}, text: 'Not Found' };
        }
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          text: '{"user":"regular"}'
        };
      }
    }
  );
  assert.equal(campaign.totalPayloads, 3);
  assert.ok(campaign.interestingCount >= 2);
  const adminHit = campaign.results.find(r => r.payloads[0] === 'admin');
  assert.equal(adminHit.isInteresting, true);
  assert.deepEqual(adminHit.matchedGrep, ['SUPERSECRET_TOKEN']);
});

test('autorize: 3-Context Differential Matrix detects BYPASSED_LOW_PRIV (BOLA/IDOR) and BYPASSED_UNAUTH while marking enforced endpoints SAFE', async () => {
  const mockFetch = async (url, opts = {}) => {
    const auth = opts.headers?.Authorization || '';
    if (url.includes('.secscan-autorize-canary-404')) {
      return { status: 404, headers: {}, text: '{"error":"not found"}' };
    }
    if (url.endsWith('/api/orders/101')) {
      // Vulnerable to low-privilege BOLA: blocks unauthenticated, but returns User A's order to User B!
      if (!auth) return { status: 401, headers: {}, text: '{"error":"unauthorized"}' };
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: JSON.stringify({ id: 101, userId: 'user-a', email: 'alice@example.com', total: 499.99, items: ['laptop'] })
      };
    }
    if (url.endsWith('/api/admin/users')) {
      // Properly enforced: only admin token gets 200
      if (auth === 'Bearer admin-token') {
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          text: JSON.stringify({ users: [{ id: 1, email: 'admin@example.com', role: 'admin' }] })
        };
      }
      return { status: 403, headers: {}, text: '{"error":"forbidden"}' };
    }
    return { status: 404, headers: {}, text: 'Not found' };
  };

  const report = await runAutorizeMatrix(
    {
      endpoints: [
        'https://api.example.com/api/orders/101',
        'https://api.example.com/api/admin/users'
      ],
      primaryHeaders: { Authorization: 'Bearer admin-token' },
      secondaryHeaders: { Authorization: 'Bearer user-b-low-priv-token' }
    },
    { fetchWithRetry: mockFetch }
  );

  assert.equal(report.totalEndpoints, 2);
  assert.equal(report.vulnerableCount, 1);
  const bolaRow = report.matrix.find(m => m.url.endsWith('/api/orders/101'));
  const enforcedRow = report.matrix.find(m => m.url.endsWith('/api/admin/users'));
  assert.equal(bolaRow.verdict, 'BYPASSED_LOW_PRIV');
  assert.equal(bolaRow.status, 'VULNERABLE');
  assert.equal(enforcedRow.verdict, 'ENFORCED');
  assert.equal(enforcedRow.status, 'SAFE');
});

test('traffic: templateUrlPath, listUrlTemplates, exportHar (HAR 1.2), and analyzePassiveExchange work accurately', () => {
  assert.equal(
    templateUrlPath('/api/v1/users/4812/orders/550e8400-e29b-41d4-a716-446655440000/items/507f1f77bcf86cd799439011'),
    '/api/v1/users/{id}/orders/{uuid}/items/{oid}'
  );

  const store = new TrafficStore({ dbPath: ':memory:' });
  try {
    store.recordExchange({
      method: 'GET',
      url: 'https://api.example.com/api/users/101?api_key=secret123456',
      statusCode: 200,
      reqHeaders: { Host: 'api.example.com' },
      resHeaders: {
        'Content-Type': 'application/json',
        'Set-Cookie': 'session_id=xyz987654; Path=/',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
        'X-Origin-IP': '10.20.30.40'
      },
      resBody: '{"id":101,"name":"Alice"}'
    });
    store.recordExchange({
      method: 'GET',
      url: 'https://api.example.com/api/users/202',
      statusCode: 200,
      reqHeaders: { Host: 'api.example.com' },
      resHeaders: { 'Content-Type': 'application/json' },
      resBody: '{"id":202,"name":"Bob"}'
    });

    // Both /api/users/101 and /api/users/202 collapse into 1 URL template (/api/users/{id}) with count=2
    const templates = store.listUrlTemplates({ host: 'api.example.com' });
    assert.equal(templates.length, 1);
    assert.equal(templates[0].urlTemplate, '/api/users/{id}');
    assert.equal(templates[0].count, 2);

    // HAR 1.2 export
    const har = store.exportHar({ host: 'api.example.com' });
    assert.equal(har.log.version, '1.2');
    assert.equal(har.log.entries.length, 2);
    assert.equal(har.log.entries[0]._urlTemplate, '/api/users/{id}');

    // Passive security analysis on the first exchange
    const passive = analyzePassiveExchange({
      url: 'https://api.example.com/api/users/101?api_key=secret123456',
      resHeaders: {
        'Set-Cookie': 'session_id=xyz987654; Path=/',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
        'X-Origin-IP': '10.20.30.40'
      },
      resBody: '{"id":101}'
    });
    const ruleIds = passive.map(f => f.ruleId);
    assert.ok(ruleIds.includes('passive-url-secret'));
    assert.ok(ruleIds.includes('passive-cookie-httponly'));
    assert.ok(ruleIds.includes('passive-cors-credentials'));
    assert.ok(ruleIds.includes('passive-origin-ip-leak'));
  } finally {
    store.close();
  }
});
