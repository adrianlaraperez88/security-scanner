import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { performance } from 'node:perf_hooks';

import { createAppServer } from '../../core/server.js';
import { LlmPool } from '../../core/llmpool.js';
import { LlmRecorder, sanitizePayload } from '../../core/llmrec.js';
import { GraphStore } from '../../core/graph-store.js';
import {
  generateReport,
  generateMarkdownReport,
  generateSingleFindingMarkdown,
  generateCsvReport,
  generateHtmlReport,
  generateSarifReport
} from '../../core/report.js';
import { runScanner, normalizeScopeRules } from '../../scan.js';

const execFileAsync = promisify(execFile);

function createTestServer(options = {}) {
  const server = createAppServer({ inMemory: true, ...options });
  return {
    server,
    close: () => {
      server.emit('close');
    }
  };
}

function dispatch(server, pathname, { method = 'GET', body = undefined, headers = {} } = {}) {
  return new Promise((resolve) => {
    const rawBody = body === undefined
      ? ''
      : (typeof body === 'string' ? body : JSON.stringify(body));

    const chunks = rawBody ? [Buffer.from(rawBody, 'utf8')] : [];
    const req = Object.assign(Readable.from(chunks), {
      url: pathname,
      method,
      headers: {
        host: '127.0.0.1:4321',
        ...(body !== undefined ? { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(rawBody)) } : {}),
        ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]))
      }
    });

    const resHeaders = {};
    const bodyChunks = [];
    const res = {
      statusCode: 200,
      headersSent: false,
      setHeader(name, val) {
        resHeaders[name.toLowerCase()] = val;
      },
      getHeader(name) {
        return resHeaders[name.toLowerCase()];
      },
      writeHead(code, hdrs) {
        this.statusCode = code;
        this.headersSent = true;
        if (hdrs) {
          for (const [k, v] of Object.entries(hdrs)) {
            resHeaders[k.toLowerCase()] = v;
          }
        }
      },
      write(chunk) {
        if (chunk) bodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8'));
      },
      end(chunk) {
        if (chunk) bodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), 'utf8'));
        this.headersSent = true;
        const text = Buffer.concat(bodyChunks).toString('utf8');
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {}
        resolve({
          status: this.statusCode,
          headers: {
            get(name) {
              return resHeaders[String(name).toLowerCase()] ?? null;
            },
            raw: resHeaders
          },
          text,
          json
        });
      }
    };

    server.emit('request', req, res);
  });
}

test('Static serving & security headers: serves /components/*.js and rejects traversal & disallowed Origin', async () => {
  const { server, close } = createTestServer();
  try {
    // 1. Valid component ES module
    const compRes = await dispatch(server, '/components/exploration-graph.js');
    assert.equal(compRes.status, 200);
    assert.equal(compRes.headers.get('content-type'), 'application/javascript; charset=utf-8');
    assert.equal(compRes.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(compRes.headers.get('x-frame-options'), 'DENY');
    const csp = compRes.headers.get('content-security-policy');
    assert.ok(csp.includes("object-src 'none'"));
    assert.ok(csp.includes("base-uri 'none'"));
    assert.ok(csp.includes("frame-ancestors 'none'"));
    assert.ok(compRes.text.includes('export'));

    // 2. Non-existent valid-pattern component -> 404
    const missingRes = await dispatch(server, '/components/nonexistent-widget.js');
    assert.equal(missingRes.status, 404);

    // 3. Invalid component filename / traversal -> 403
    for (const badPath of [
      '/components/../app.js',
      '/components/%2e%2e%2fapp.js',
      '/components/BadCase.js',
      '/components/sub/file.js',
      '/components/secret.json'
    ]) {
      const badRes = await dispatch(server, badPath);
      assert.equal(badRes.status, 403, `Expected 403 for ${badPath}`);
    }

    // 4. Origin/CSRF rejection on mutating requests
    const csrfRes = await dispatch(server, '/api/tasks', {
      method: 'POST',
      headers: { Origin: 'https://attacker.example.com' },
      body: { target: 'https://example.com', goal: 'Test' }
    });
    assert.equal(csrfRes.status, 403);

    // 5. /api/meta returns v2.2.0, totalChecks, sorted categories, and cveCoverageSummary
    const metaRes = await dispatch(server, '/api/meta');
    assert.equal(metaRes.status, 200);
    assert.equal(metaRes.json.version, '2.2.0');
    assert.ok(Array.isArray(metaRes.json.checks));
    assert.equal(metaRes.json.totalChecks, metaRes.json.checks.length);
    assert.ok(Array.isArray(metaRes.json.categories) && metaRes.json.categories.length >= 14);
    assert.ok(metaRes.json.cveCoverageSummary && typeof metaRes.json.cveCoverageSummary.totalAdvisories === 'number');

    // 6. IPv6 loopback Host [::1] and Origin http://[::1] allowed
    const ipv6Res = await dispatch(server, '/api/meta', {
      headers: {
        Host: '[::1]:4321',
        Origin: 'http://[::1]:4321'
      }
    });
    assert.equal(ipv6Res.status, 200);
  } finally {
    close();
  }
});

test('Tasks, Agentic Planning, Steer/Cancel & Read-only Sidequestion (/api/tasks/*)', async () => {
  const llmRecorder = new LlmRecorder();
  const mockLlmFetcher = async () => ({
    ok: true,
    status: 200,
    text: async () =>
      JSON.stringify({
        choices: [{ message: { content: 'Read-only answer: check CORS headers.' } }],
        usage: { prompt_tokens: 40, completion_tokens: 15, total_tokens: 55 }
      })
  });
  const llmPool = new LlmPool({ recorder: llmRecorder, fetcher: mockLlmFetcher });
  llmPool.upsertProfile({
    id: 'openai-primary',
    name: 'OpenAI Primary',
    provider: 'openai',
    model: 'gpt-4o-mini',
    apiKey: 'sk-secret-key-123456',
    rank: 1
  });

  const { server, close } = createTestServer({ llmPool, llmRecorder });
  try {
    // 1. Create task
    const created = await dispatch(server, '/api/tasks', {
      method: 'POST',
      body: {
        title: 'Audit Example App',
        target: 'https://example.com',
        goal: 'Verify headers and endpoints',
        llm_profile_ids: ['openai-primary'],
        llm_rotate: true
      }
    });
    assert.equal(created.status, 201);
    assert.ok(created.json.task.id);
    assert.ok(created.json.graph.nodes.length >= 2);
    const taskId = created.json.task.id;

    // 2. List tasks
    const listed = await dispatch(server, '/api/tasks');
    assert.equal(listed.status, 200);
    assert.ok(listed.json.tasks.some(t => t.id === taskId));

    // 3. Get task details
    const detail = await dispatch(server, `/api/tasks/${encodeURIComponent(taskId)}`);
    assert.equal(detail.status, 200);
    assert.equal(detail.json.task.id, taskId);
    assert.ok(Array.isArray(detail.json.activity));
    assert.ok(detail.json.coverage);

    // 4. Update task LLM chain
    const llmUpd = await dispatch(server, `/api/tasks/${encodeURIComponent(taskId)}/llm`, {
      method: 'PUT',
      body: { llm_profile_ids: ['openai-primary'], llm_rotate: false }
    });
    assert.equal(llmUpd.status, 200);
    assert.equal(llmUpd.json.llmChain.llmRotate, false);

    // 5. Trigger planner round
    const planned = await dispatch(server, `/api/tasks/${encodeURIComponent(taskId)}/plan`, {
      method: 'POST',
      body: { force: true }
    });
    assert.equal(planned.status, 200);
    assert.ok(planned.json.plan);

    // 6. Ask ephemeral read-only /btw sidequestion
    const sideQ = await dispatch(server, `/api/tasks/${encodeURIComponent(taskId)}/sidequestion`, {
      method: 'POST',
      body: { question: 'What should we verify next?' }
    });
    assert.equal(sideQ.status, 200);
    assert.ok(sideQ.json.answer.includes('CORS'));
    assert.deepEqual(sideQ.json.tools, []);

    // 7. Steer & cancel an intent node
    const intentNode = detail.json.graph.nodes.find(n => n.node_type === 'intent');
    assert.ok(intentNode);

    const steered = await dispatch(
      server,
      `/api/tasks/${encodeURIComponent(taskId)}/intents/${encodeURIComponent(intentNode.id)}/steer`,
      { method: 'POST', body: { instruction: 'Focus on /api/v1' } }
    );
    assert.equal(steered.status, 200);
    assert.equal(steered.json.ok, true);

    const cancelled = await dispatch(
      server,
      `/api/tasks/${encodeURIComponent(taskId)}/intents/${encodeURIComponent(intentNode.id)}/cancel`,
      { method: 'POST' }
    );
    assert.equal(cancelled.status, 200);
    assert.equal(cancelled.json.ok, true);
  } finally {
    close();
  }
});

test('Dual-Graph, Lineage, Asset DSL & External Ingestion (/api/graph/*, /api/assets*)', async () => {
  const { server, close } = createTestServer();
  try {
    const { graphStore } = server.context;
    const ingested = graphStore.ingestStaticScanResult({
      taskId: 'scan_test_1',
      targets: ['https://api.example.com/v1/users'],
      results: [
        {
          checkId: 'cors',
          name: 'CORS Misconfiguration',
          target: 'https://api.example.com/v1/users',
          status: 'VULNERABLE',
          severity: 'HIGH',
          reason: 'Wildcard origin with credentials'
        }
      ],
      risk: { grade: 'C', level: 'HIGH', score: 20 }
    });

    // 1. Exploration graph & cold folding
    const expGraph = await dispatch(server, '/api/graph/exploration/scan_test_1');
    assert.equal(expGraph.status, 200);
    assert.equal(expGraph.json.folded, false);
    assert.ok(expGraph.json.nodes.length >= 4);

    const foldedGraph = await dispatch(server, '/api/graph/exploration/scan_test_1?fold=true&round=10');
    assert.equal(foldedGraph.status, 200);
    assert.equal(foldedGraph.json.folded, true);

    // 2. Coverage graph
    const covGraph = await dispatch(server, '/api/graph/coverage?taskId=scan_test_1');
    assert.equal(covGraph.status, 200);
    assert.ok(Array.isArray(covGraph.json.nodes));
    assert.ok(covGraph.json.stats.totalAssets >= 1);

    // 3. Finding lineage
    const findingId = ingested.findings[0].id;
    const lineage = await dispatch(server, `/api/graph/lineage/scan_test_1/${encodeURIComponent(findingId)}`);
    assert.equal(lineage.status, 200);
    assert.equal(lineage.json.finding.id, findingId);
    assert.ok(lineage.json.chain.length >= 2);

    // 4. Asset DSL query
    const assetsRes = await dispatch(server, '/api/assets?dsl=domain=example.com&taskId=scan_test_1');
    assert.equal(assetsRes.status, 200);
    assert.ok(assetsRes.json.total >= 1);
    assert.ok(assetsRes.json.fields.domain);

    // Invalid DSL -> 400
    const badDsl = await dispatch(server, '/api/assets?dsl=unknown_field=foo');
    assert.equal(badDsl.status, 400);

    // 5. External tool output ingestion
    const httpxSample = JSON.stringify({
      url: 'https://sub.example.com/health',
      host: 'sub.example.com',
      port: '443',
      status_code: 200,
      title: 'Health'
    });
    const ingestRes = await dispatch(server, '/api/assets/ingest', {
      method: 'POST',
      body: { format: 'httpx', rawInput: httpxSample, taskId: 'scan_test_1' }
    });
    assert.equal(ingestRes.status, 200);
    assert.ok(ingestRes.json.counts.assets >= 1);
  } finally {
    close();
  }
});

test('Findings Evidence, Verify, Retest, Asset Tree & Scan Export (/api/findings/*, /api/scan/:id/export)', async () => {
  const { server, close } = createTestServer({
    retestOptions: {
      validateUrl: async () => ({ valid: true }),
      fetcher: async () => ({
        status: 200,
        headers: { 'content-type': 'text/plain' },
        text: async () => 'DB_PASSWORD=supersecret_token_value_123'
      })
    }
  });

  try {
    // 1. Bind evidence to a finding
    const bindRes = await dispatch(server, '/api/findings/finding-env-1/evidence', {
      method: 'POST',
      body: {
        url: 'https://example.com/.env',
        method: 'GET',
        statusCode: 200,
        resHeaders: { 'content-type': 'text/plain' },
        resBody: 'APP_ENV=production\nDB_PASSWORD=supersecret_token_value_123',
        role: 'proof',
        quote: 'DB_PASSWORD=supersecret_token_value_123',
        poeLevel: 3
      }
    });
    assert.equal(bindRes.status, 200);
    assert.equal(bindRes.json.evidence.state.verificationStatus, 'verified');

    // 2. Get evidence
    const getEv = await dispatch(server, '/api/findings/finding-env-1/evidence');
    assert.equal(getEv.status, 200);
    assert.equal(getEv.json.bindings.length, 1);

    // 3. Verify receipts
    const verifyRes = await dispatch(server, '/api/findings/finding-env-1/verify', {
      method: 'POST',
      body: { poeLevel: 3 }
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.json.assessment.status, 'verified');

    // 4. Retest finding
    const retestRes = await dispatch(server, '/api/findings/finding-env-1/retest', {
      method: 'POST'
    });
    assert.equal(retestRes.status, 200);
    assert.equal(retestRes.json.retest.verdict, 'reproduced');

    // 5. Asset tree & Export (markdown + csv)
    const { jobs, graphStore } = server.context;
    const sampleResults = [
      {
        checkId: 'env',
        name: 'Exposed .env File',
        target: 'https://example.com/.env',
        status: 'VULNERABLE',
        severity: 'CRITICAL',
        reason: 'Exposed secrets'
      }
    ];
    jobs.set('job_export_1', {
      id: 'job_export_1',
      status: 'completed',
      targets: ['https://example.com'],
      result: {
        results: sampleResults,
        risk: { grade: 'F', level: 'CRITICAL', score: 50 },
        stacks: [{ target: 'https://example.com', summary: 'Laravel' }]
      }
    });
    graphStore.ingestStaticScanResult({
      taskId: 'scan_job_export_1',
      targets: ['https://example.com'],
      results: sampleResults,
      risk: { grade: 'F', level: 'CRITICAL', score: 50 }
    });

    const treeRes = await dispatch(server, '/api/findings/asset-tree?scanId=job_export_1');
    assert.equal(treeRes.status, 200);
    assert.ok(treeRes.json.totalFindings >= 1);

    const mdRes = await dispatch(server, '/api/scan/job_export_1/export?format=markdown');
    assert.equal(mdRes.status, 200);
    assert.ok(mdRes.headers.get('content-type').includes('text/markdown'));
    assert.ok(mdRes.text.includes('# Security Verification Report'));
    assert.ok(mdRes.text.includes('(`env`)'));
    assert.ok(mdRes.text.includes('Exposed secrets'));

    const csvRes = await dispatch(server, '/api/scan/job_export_1/export?format=csv');
    assert.equal(csvRes.status, 200);
    assert.ok(csvRes.headers.get('content-type').includes('text/csv'));
    assert.ok(csvRes.text.startsWith('\uFEFF'));
    assert.ok(csvRes.text.includes('env'));
  } finally {
    close();
  }
});

test('Traffic Store, Rewrite Rules & RFC-9110 Replay (/api/traffic/*)', async () => {
  const { server, close } = createTestServer({
    retestOptions: {
      validateUrl: async () => ({ valid: true }),
      fetcher: async (url, init) => ({
        status: 200,
        headers: { 'x-replayed': 'true', 'x-injected': init?.headers?.['x-test'] || '' },
        text: async () => `replayed ${url}`
      })
    }
  });

  try {
    // 1. Ingest HAR/external exchange
    const ingestRes = await dispatch(server, '/api/traffic/ingest', {
      method: 'POST',
      body: {
        source: 'har',
        request: {
          method: 'GET',
          url: 'https://api.example.com/items?q=hello',
          headers: { accept: 'application/json' }
        },
        response: {
          status: 200,
          headers: { 'content-type': 'application/json' },
          content: { text: '{"items":["alpha","beta"]}', mimeType: 'application/json' }
        }
      }
    });
    assert.equal(ingestRes.status, 201);
    const exchangeId = ingestRes.json.recorded.id;

    // 2. Query traffic & hosts
    const queryRes = await dispatch(server, '/api/traffic?host=api.example.com&search=alpha');
    assert.equal(queryRes.status, 200);
    assert.ok(queryRes.json.exchanges.some(e => e.id === exchangeId));

    const hostsRes = await dispatch(server, '/api/traffic/hosts');
    assert.equal(hostsRes.status, 200);
    assert.ok(hostsRes.json.hosts.some(h => h.host === 'api.example.com'));

    const singleRes = await dispatch(server, `/api/traffic/${encodeURIComponent(exchangeId)}`);
    assert.equal(singleRes.status, 200);
    assert.equal(singleRes.json.exchange.id, exchangeId);

    // 3. Rewrite rules CRUD
    const addRule = await dispatch(server, '/api/traffic/rewrite-rules', {
      method: 'POST',
      body: {
        name: 'Inject X-Test',
        scopeHost: 'api.example.com',
        phase: 'request',
        target: 'header',
        matchPattern: 'x-test:.*',
        replaceValue: 'rewritten-1',
        isSensitive: true
      }
    });
    assert.equal(addRule.status, 201);
    const ruleId = addRule.json.rule.id;

    const listRules = await dispatch(server, '/api/traffic/rewrite-rules');
    assert.equal(listRules.status, 200);
    assert.ok(listRules.json.rules.some(r => r.id === ruleId));

    // 4. Replay request with rewrite applied
    const replayRes = await dispatch(server, `/api/traffic/${encodeURIComponent(exchangeId)}/replay`, {
      method: 'POST',
      body: { method: 'GET' }
    });
    assert.equal(replayRes.status, 200);
    assert.equal(replayRes.json.replayExchange.statusCode, 200);
    assert.equal(replayRes.json.rewrite.applied, true);
    assert.equal(replayRes.json.rewrite.taintedSensitive, true);
    assert.equal(replayRes.json.response.headers['x-injected'], 'rewritten-1');

    // 5. Delete rewrite rule
    const delRule = await dispatch(server, `/api/traffic/rewrite-rules/${encodeURIComponent(ruleId)}`, {
      method: 'DELETE'
    });
    assert.equal(delRule.status, 200);
    assert.equal(delRule.json.deleted, true);
  } finally {
    close();
  }
});

test('Multi-LLM Pool & Guardrails/Noise Settings (/api/llm/*, /api/guard/*)', async () => {
  const { server, close } = createTestServer();
  try {
    // 1. Upsert LLM profile and verify API key masking
    const upsert = await dispatch(server, '/api/llm/profiles', {
      method: 'POST',
      body: {
        id: 'anthropic-1',
        name: 'Claude',
        provider: 'anthropic',
        model: 'claude-sonnet',
        apiKey: 'sk-ant-very-secret-token-9999',
        rank: 1
      }
    });
    assert.equal(upsert.status, 200);
    assert.ok(upsert.json.profile);
    assert.ok(!upsert.json.profile.apiKey.includes('very-secret-token'));

    const pool = await dispatch(server, '/api/llm/pool');
    assert.equal(pool.status, 200);
    assert.ok(pool.json.usage);

    const reset = await dispatch(server, '/api/llm/profiles/anthropic-1/reset', { method: 'POST' });
    assert.equal(reset.status, 200);
    assert.equal(reset.json.reset, true);

    const del = await dispatch(server, '/api/llm/profiles/anthropic-1', { method: 'DELETE' });
    assert.equal(del.status, 200);
    assert.equal(del.json.deleted, true);

    // 2. Guard settings & evaluation
    const guardGet = await dispatch(server, '/api/guard/settings');
    assert.equal(guardGet.status, 200);
    assert.equal(guardGet.json.noiseProfile, 'balanced');
    assert.ok(Array.isArray(guardGet.json.skills));

    const guardPut = await dispatch(server, '/api/guard/settings', {
      method: 'PUT',
      body: {
        noiseProfile: 'quiet',
        scopeRules: [{ ruleType: 'fuzzy_domain', pattern: 'example.com', isAllowed: true }]
      }
    });
    assert.equal(guardPut.status, 200);
    assert.equal(guardPut.json.noiseProfile, 'quiet');

    const evalGov = await dispatch(server, '/api/guard/evaluate', {
      method: 'POST',
      body: { mode: 'asset', target: 'https://agency.gov/login' }
    });
    assert.equal(evalGov.status, 200);
    assert.equal(evalGov.json.allowed, false);

    const evalRisk = await dispatch(server, '/api/guard/evaluate', {
      method: 'POST',
      body: { mode: 'risk', toolName: 'DELETE', input: { url: 'https://example.com/user/1' } }
    });
    assert.equal(evalRisk.status, 200);
    assert.ok(['low', 'medium', 'high'].includes(evalRisk.json.level));

    const evalJevFail = await dispatch(server, '/api/guard/evaluate', {
      method: 'POST',
      body: { mode: 'jev', jevAnswers: { q1_in_scope: true } }
    });
    assert.equal(evalJevFail.status, 200);
    assert.equal(evalJevFail.json.approved, false);

    const evalJevPass = await dispatch(server, '/api/guard/evaluate', {
      method: 'POST',
      body: {
        mode: 'jev',
        jevAnswers: {
          q1_in_scope: true,
          q2_no_destructive_side_effects: true,
          q3_reversible: true,
          q4_within_rate_budget: true,
          q5_no_credential_exfil: true,
          q6_no_cross_tenant_impact: true,
          q7_valid_verification_intent: true,
          q8_least_privilege: true
        }
      }
    });
    assert.equal(evalJevPass.status, 200);
    assert.equal(evalJevPass.json.approved, true);
  } finally {
    close();
  }
});

test('runScanner & CLI enhancements: enrichment, GraphStore ingestion, Markdown/CSV reports, scope & agent mode', async () => {
  const rules = normalizeScopeRules(['allow:*.example.com', 'deny:admin.example.com']);
  assert.equal(rules.length, 2);
  assert.equal(rules[0].isAllowed, true);
  assert.equal(rules[1].isAllowed, false);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-cli-test-'));
  const mdPath = path.join(tmpDir, 'out.md');
  const csvPath = path.join(tmpDir, 'out.csv');
  const graphStore = new GraphStore({ dbPath: ':memory:' });

  const mockFetcher = async () => ({
    status: 200,
    headers: new Headers({ 'content-type': 'text/html' }),
    text: async () => '<html><head><title>Test</title></head><body>ok</body></html>'
  });

  try {
    const full = await runScanner({
      targets: ['https://example.com'],
      profile: 'quick',
      maxDepth: 1,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      noiseProfile: 'off',
      scopeRules: rules,
      graphStore,
      markdown: mdPath,
      csv: csvPath,
      agent: true,
      goal: 'Verify headers',
      maxAgentRounds: 1,
      fetcher: mockFetcher,
      dnsResolver: async () => ['93.184.216.34']
    });

    assert.ok(Array.isArray(full.results));
    assert.ok(full.results.length > 0);
    assert.ok(full.results[0].cwe);
    assert.ok(full.results[0].owasp);
    assert.ok(Number.isFinite(full.results[0].cvssScore));
    assert.ok(fs.existsSync(mdPath));
    assert.ok(fs.existsSync(csvPath));
    assert.ok(fs.readFileSync(mdPath, 'utf8').includes('# Security Verification Report'));
    assert.ok(fs.readFileSync(csvPath, 'utf8').startsWith('\uFEFF'));
    assert.ok(full.graphIngestion?.taskId);
    assert.ok(full.agentSummary);
    assert.ok(graphStore.listTasks().length >= 2);

    await assert.rejects(
      () =>
        runScanner({
          targets: ['https://admin.example.com'],
          scopeRules: rules,
          noHistory: true,
          silent: true,
          setExitCode: false
        }),
      /platform control/i
    );

    let exitCode = 0;
    try {
      await execFileAsync(process.execPath, ['bin/cli.js', 'https://example.com', '--noise-profile', 'invalid-prof'], {
        cwd: process.cwd()
      });
    } catch (err) {
      exitCode = err.code;
    }
    assert.equal(exitCode, 1);
  } finally {
    graphStore.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('FINDING-4: server replay, retest, fingerprint, and runScanner enforce DNS SSRF validation by default', async () => {
  let fetchCalls = 0;
  const countingFetcher = async () => {
    fetchCalls += 1;
    return {
      status: 200,
      headers: { 'content-type': 'text/plain' },
      text: async () => 'secret-internal-data'
    };
  };

  const dnsMap = {
    'safe.example.com': ['93.184.216.34'],
    'rebind-loopback.invalid': ['127.0.0.1'],
    'rebind-metadata.invalid': ['169.254.169.254']
  };

  const { server, close } = createTestServer({
    dnsResolver: async (host) => dnsMap[host] || ['169.254.169.254'],
    fetcher: countingFetcher,
    retestOptions: {
      fetcher: countingFetcher
    }
  });

  try {
    // 1. Ingest a traffic exchange and attempt replay against a DNS-rebound loopback host
    const ingestRes = await dispatch(server, '/api/traffic/ingest', {
      method: 'POST',
      body: {
        source: 'har',
        request: { method: 'GET', url: 'https://safe.example.com/api' },
        response: { status: 200, content: { text: 'ok' } }
      }
    });
    assert.equal(ingestRes.status, 201);
    const exchangeId = ingestRes.json.recorded.id;

    const replayBlocked = await dispatch(server, `/api/traffic/${encodeURIComponent(exchangeId)}/replay`, {
      method: 'POST',
      body: { url: 'https://rebind-loopback.invalid/admin' }
    });
    assert.equal(replayBlocked.status, 403);
    assert.match(replayBlocked.json.error, /blocked by URL validator/i);
    assert.equal(fetchCalls, 0);

    // 2. Bind finding evidence for a metadata-rebound hostname and attempt retest
    const bindRes = await dispatch(server, '/api/findings/finding-ssrf-retest/evidence', {
      method: 'POST',
      body: {
        url: 'https://rebind-metadata.invalid/latest/meta-data/',
        method: 'GET',
        statusCode: 200,
        resBody: 'SECRET_METADATA_TOKEN_1234',
        role: 'proof',
        quote: 'SECRET_METADATA_TOKEN_1234',
        poeLevel: 3
      }
    });
    assert.equal(bindRes.status, 200);

    const retestBlocked = await dispatch(server, '/api/findings/finding-ssrf-retest/retest', {
      method: 'POST'
    });
    assert.equal(retestBlocked.status, 403);
    assert.match(retestBlocked.json.error, /blocked by URL validator/i);
    assert.equal(fetchCalls, 0);

    // 3. POST /api/fingerprint blocks DNS-rebound metadata host before fetching
    const fpBlocked = await dispatch(server, '/api/fingerprint', {
      method: 'POST',
      body: { target: 'https://rebind-metadata.invalid/' }
    });
    assert.equal(fpBlocked.status, 403);
    assert.match(fpBlocked.json.error, /169\.254\.169\.254/);
    assert.equal(fetchCalls, 0);
  } finally {
    close();
  }

  // 4. Server routes without custom dnsResolver/validateUrl also fail closed on .invalid hosts
  const { server: defaultServer, close: closeDefault } = createTestServer({
    retestOptions: { fetcher: countingFetcher }
  });
  try {
    const ingestRes = await dispatch(defaultServer, '/api/traffic/ingest', {
      method: 'POST',
      body: {
        source: 'har',
        request: { method: 'GET', url: 'https://unresolvable-rebind.invalid/secret' },
        response: { status: 200, content: { text: 'ok' } }
      }
    });
    const replayDefault = await dispatch(
      defaultServer,
      `/api/traffic/${encodeURIComponent(ingestRes.json.recorded.id)}/replay`,
      { method: 'POST' }
    );
    assert.equal(replayDefault.status, 403);
    assert.equal(fetchCalls, 0);
  } finally {
    closeDefault();
  }

  // 5. runScanner blocks hostnames resolving to 169.254.169.254
  const res = await runScanner({
    targets: ['https://rebind-metadata.invalid'],
    profile: 'quick',
    maxDepth: 0,
    noHistory: true,
    silent: true,
    setExitCode: false,
    fetcher: countingFetcher,
    dnsResolver: async () => ['169.254.169.254']
  });
  assert.ok(Array.isArray(res));
  assert.equal(fetchCalls, 0);
});

test('FINDING-5: runScanner masks sensitive webhook query tokens in CLI log output', async () => {
  const loggedLines = [];
  const origLog = console.log;
  const origWarn = console.warn;
  const mockFetcher = async () => ({
    status: 200,
    headers: new Headers({ 'content-type': 'text/html' }),
    text: async () => '<html><body>ok</body></html>'
  });

  console.log = (...args) => {
    loggedLines.push(args.map(a => String(a)).join(' '));
  };
  console.warn = () => {};

  try {
    await runScanner({
      targets: ['https://example.com'],
      profile: 'quick',
      maxDepth: 0,
      noHistory: true,
      silent: false,
      setExitCode: false,
      timeout: 500,
      webhook: 'https://oapi.dingtalk.com/robot/send?access_token=supersecret123456',
      dnsResolver: async () => ['93.184.216.34'],
      fetcher: mockFetcher
    });
  } finally {
    console.log = origLog;
    console.warn = origWarn;
  }

  const combined = loggedLines.join('\n');
  assert.ok(combined.includes('📣  Webhook:'), 'Expected Webhook banner line in CLI logs');
  assert.ok(combined.includes('__masked__:123456'), 'Expected masked webhook token suffix in CLI logs');
  assert.ok(!combined.includes('supersecret123456'), 'Raw webhook access_token must not appear in CLI logs');
});

test('allowPrivate: rejects RFC1918 by default, permits when allowPrivate: true, and always blocks metadata', async () => {
  const privateUrl = 'http://192.168.10.20/app';
  const metadataUrl = 'http://169.254.169.254/latest/meta-data/';

  let fetchCalls = 0;
  const mockFetcher = async (url) => {
    fetchCalls += 1;
    return {
      status: 200,
      headers: new Headers({ 'content-type': 'text/html' }),
      text: async () => `<html><title>Internal App</title><body>INTERNAL_SECRET_PROOF_1234 ${url}</body></html>`
    };
  };

  const { server, close } = createTestServer({
    noiseProfile: 'off',
    fetcher: mockFetcher,
    retestOptions: {
      fetcher: mockFetcher
    }
  });

  try {
    // Prepare traffic exchange & finding bound to privateUrl and metadataUrl
    const ingestPrivate = await dispatch(server, '/api/traffic/ingest', {
      method: 'POST',
      body: {
        source: 'har',
        request: { method: 'GET', url: privateUrl },
        response: { status: 200, content: { text: 'ok' } }
      }
    });
    assert.equal(ingestPrivate.status, 201);
    const privateExchangeId = ingestPrivate.json.recorded.id;

    const bindPrivate = await dispatch(server, '/api/findings/finding-private-1/evidence', {
      method: 'POST',
      body: {
        url: privateUrl,
        method: 'GET',
        statusCode: 200,
        resBody: 'INTERNAL_SECRET_PROOF_1234',
        role: 'proof',
        quote: 'INTERNAL_SECRET_PROOF_1234',
        poeLevel: 3
      }
    });
    assert.equal(bindPrivate.status, 200);

    const bindMeta = await dispatch(server, '/api/findings/finding-meta-1/evidence', {
      method: 'POST',
      body: {
        url: metadataUrl,
        method: 'GET',
        statusCode: 200,
        resBody: 'AMI_SECRET_METADATA_1234',
        role: 'proof',
        quote: 'AMI_SECRET_METADATA_1234',
        poeLevel: 3
      }
    });
    assert.equal(bindMeta.status, 200);

    // 1. Default (allowPrivate omitted/false) rejects http://192.168.10.20/app everywhere
    const scanDefault = await dispatch(server, '/api/scan', {
      method: 'POST',
      body: { target: privateUrl }
    });
    assert.equal(scanDefault.status, 400);

    const fpDefault = await dispatch(server, '/api/fingerprint', {
      method: 'POST',
      body: { target: privateUrl }
    });
    assert.equal(fpDefault.status, 400);

    const taskDefault = await dispatch(server, '/api/tasks', {
      method: 'POST',
      body: { target: privateUrl, goal: 'Check internal app' }
    });
    assert.equal(taskDefault.status, 400);

    const replayDefault = await dispatch(server, `/api/traffic/${encodeURIComponent(privateExchangeId)}/replay`, {
      method: 'POST',
      body: {}
    });
    assert.equal(replayDefault.status, 403);

    const retestDefault = await dispatch(server, '/api/findings/finding-private-1/retest', {
      method: 'POST',
      body: {}
    });
    assert.equal(retestDefault.status, 403);

    assert.equal(fetchCalls, 0);

    await assert.rejects(
      () =>
        runScanner({
          targets: [privateUrl],
          profile: 'quick',
          maxDepth: 0,
          noHistory: true,
          silent: true,
          setExitCode: false,
          fetcher: mockFetcher
        }),
      /Private, loopback, or metadata IPv4 address is blocked/i
    );
    assert.equal(fetchCalls, 0);

    // 2. Explicit allowPrivate: true permits http://192.168.10.20/app
    const fpAllowed = await dispatch(server, '/api/fingerprint', {
      method: 'POST',
      body: { target: privateUrl, allowPrivate: true }
    });
    assert.equal(fpAllowed.status, 200);
    assert.equal(fpAllowed.json.target, privateUrl);

    const taskAllowed = await dispatch(server, '/api/tasks', {
      method: 'POST',
      body: { target: privateUrl, goal: 'Check internal app', allowPrivate: true }
    });
    assert.equal(taskAllowed.status, 201);
    assert.equal(taskAllowed.json.task.allowPrivate, true);

    const replayAllowed = await dispatch(server, `/api/traffic/${encodeURIComponent(privateExchangeId)}/replay`, {
      method: 'POST',
      body: { allowPrivate: true }
    });
    assert.equal(replayAllowed.status, 200);
    assert.equal(replayAllowed.json.replayExchange.statusCode, 200);

    const retestAllowed = await dispatch(server, '/api/findings/finding-private-1/retest', {
      method: 'POST',
      body: { allowPrivate: true }
    });
    assert.equal(retestAllowed.status, 200);
    assert.equal(retestAllowed.json.retest.verdict, 'reproduced');

    const scanAllowed = await dispatch(server, '/api/scan', {
      method: 'POST',
      body: { target: privateUrl, profile: 'quick', maxDepth: 1, timeout: 1000, noHistory: true, allowPrivate: true }
    });
    assert.equal(scanAllowed.status, 202);
    assert.equal(scanAllowed.json.allowPrivate, true);

    // Poll until background scan job finishes so server resources stay clean
    let scanStatus = null;
    for (let i = 0; i < 80; i += 1) {
      const statusRes = await dispatch(server, `/api/scan/${encodeURIComponent(scanAllowed.json.scanId)}`);
      if (statusRes.json.status === 'completed' || statusRes.json.status === 'failed') {
        scanStatus = statusRes.json.status;
        break;
      }
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(scanStatus, 'completed');

    const scannerAllowed = await runScanner({
      targets: [privateUrl],
      profile: 'quick',
      maxDepth: 0,
      timeout: 500,
      noiseProfile: 'off',
      noHistory: true,
      silent: true,
      setExitCode: false,
      allowPrivate: true,
      fetcher: mockFetcher
    });
    assert.ok(Array.isArray(scannerAllowed));
    assert.ok(scannerAllowed.length > 0);

    // 3. Even with allowPrivate: true, cloud metadata http://169.254.169.254/latest/meta-data/ is STILL rejected
    const callsBeforeMeta = fetchCalls;

    const scanMeta = await dispatch(server, '/api/scan', {
      method: 'POST',
      body: { target: metadataUrl, allowPrivate: true }
    });
    assert.equal(scanMeta.status, 400);

    const fpMeta = await dispatch(server, '/api/fingerprint', {
      method: 'POST',
      body: { target: metadataUrl, allowPrivate: true }
    });
    assert.equal(fpMeta.status, 400);

    const taskMeta = await dispatch(server, '/api/tasks', {
      method: 'POST',
      body: { target: metadataUrl, goal: 'Meta check', allowPrivate: true }
    });
    assert.equal(taskMeta.status, 400);

    const replayMeta = await dispatch(server, `/api/traffic/${encodeURIComponent(privateExchangeId)}/replay`, {
      method: 'POST',
      body: { url: metadataUrl, allowPrivate: true }
    });
    assert.equal(replayMeta.status, 403);

    const retestMeta = await dispatch(server, '/api/findings/finding-meta-1/retest', {
      method: 'POST',
      body: { allowPrivate: true }
    });
    assert.equal(retestMeta.status, 403);

    await assert.rejects(
      () =>
        runScanner({
          targets: [metadataUrl],
          profile: 'quick',
          maxDepth: 0,
          noHistory: true,
          silent: true,
          setExitCode: false,
          allowPrivate: true,
          fetcher: mockFetcher
        }),
      /Cloud metadata or forbidden (?:hostname|IPv4 address) is blocked/i
    );
    assert.equal(fetchCalls, callsBeforeMeta);

    // 4. Verify CLI usage mentions --allow-private and UI contains #allow-private-toggle without inline handlers
    let helpStdout = '';
    try {
      await execFileAsync(process.execPath, ['bin/cli.js'], { cwd: process.cwd() });
    } catch (err) {
      helpStdout = err.stdout || '';
    }
    assert.ok(helpStdout.includes('--allow-private'));

    const indexHtml = fs.readFileSync(path.join(process.cwd(), 'ui', 'index.html'), 'utf8');
    assert.ok(indexHtml.includes('id="allow-private-toggle"'));
    assert.ok(!indexHtml.includes('id="allow-private-toggle" checked'));
  } finally {
    close();
  }
});

test('FINDING-3: createAppServer enforces post-DNS CIDR deny rules on POST /api/tasks and dynamic scope updates on agentEngine', async () => {
  let fetchCalls = 0;
  const dnsMap = {
    'internal.corp.local': ['192.168.10.20'],
    'rebind-meta.corp.local': ['169.254.169.254'],
    'allowed.corp.local': ['10.20.30.40'],
    'agency.gov': ['93.184.216.34']
  };

  const { server, close } = createTestServer({
    scopeRules: [{ ruleType: 'cidr', pattern: '192.168.10.0/24', isAllowed: false }],
    dnsResolver: async (host) => dnsMap[host] || ['93.184.216.34'],
    agentOptions: {
      checks: [
        {
          name: 'corp-probe',
          tags: ['all'],
          meta: {},
          run: async (target, fetchFn) => {
            const res = await fetchFn(target);
            return { name: 'corp-probe', status: res.status === 200 ? 'VULNERABLE' : 'SAFE', severity: 'HIGH' };
          }
        }
      ],
      fetchImpl: async (url) => {
        fetchCalls += 1;
        if (url === 'http://allowed.corp.local/redirect-gov') {
          return { status: 302, headers: { location: 'https://agency.gov/secret' }, text: '' };
        }
        return { status: 200, headers: {}, text: `ok:${url}` };
      }
    }
  });

  try {
    // 1. POST /api/tasks rejects hostname resolving into denied CIDR (192.168.10.0/24) even with allowPrivate: true
    const cidrBlockedTask = await dispatch(server, '/api/tasks', {
      method: 'POST',
      body: { target: 'http://internal.corp.local', allowPrivate: true, autoRun: true }
    });
    assert.equal(cidrBlockedTask.status, 403);
    assert.match(cidrBlockedTask.json.error, /192\.168\.10\.0\/24/);

    // 2. POST /api/tasks rejects hostname resolving to cloud metadata 169.254.169.254
    const metaBlockedTask = await dispatch(server, '/api/tasks', {
      method: 'POST',
      body: { target: 'http://rebind-meta.corp.local', allowPrivate: true, autoRun: true }
    });
    assert.equal(metaBlockedTask.status, 403);
    assert.match(metaBlockedTask.json.error, /169\.254\.169\.254/);
    assert.equal(fetchCalls, 0);

    // 3. Task created for allowed.corp.local respects live PUT /api/guard/settings updates and .gov redirect blocks
    const allowedTaskRes = await dispatch(server, '/api/tasks', {
      method: 'POST',
      body: { target: 'http://allowed.corp.local', allowPrivate: true }
    });
    assert.equal(allowedTaskRes.status, 201);
    const taskId = allowedTaskRes.json.task.id;

    const { agentEngine, trafficStore } = server.context;
    const ex = trafficStore.recordExchange({
      taskId,
      method: 'GET',
      url: 'http://allowed.corp.local/api',
      statusCode: 200,
      resBody: 'ok'
    });

    const ctx = {
      taskId,
      intentNodeId: 'intent-srv-f3',
      allowPrivate: true,
      targetHost: 'allowed.corp.local',
      targetUrl: 'http://allowed.corp.local',
      allowedChecks: new Set(['corp-probe']),
      unlockedChecks: new Set(),
      mcpNames: new Set(),
      checkResults: [],
      factIds: [],
      findingIds: [],
      blocked: [],
      errors: [],
      writebacks: 0,
      coverageCount: 0,
      lastAssetId: null,
      meter: agentEngine.getLedger(taskId).createIntentMeter('m-srv')
    };

    // Redirect to .gov is blocked on agentEngine.http_probe
    const govRedirect = await agentEngine._invoke('http_probe', { url: 'http://allowed.corp.local/redirect-gov' }, ctx);
    assert.equal(govRedirect.ok, false);
    assert.match(govRedirect.error, /Redirect blocked by SSRF policy:.*\.gov/i);

    // Update guard settings dynamically to deny 10.20.0.0/16 -> agentEngine immediately enforces updated scopeRules
    const updGuard = await dispatch(server, '/api/guard/settings', {
      method: 'PUT',
      body: { scopeRules: [{ ruleType: 'cidr', pattern: '10.20.0.0/16', isAllowed: false }] }
    });
    assert.equal(updGuard.status, 200);

    const callsBeforeDynamicDeny = fetchCalls;
    const probeAfterDeny = await agentEngine._invoke('http_probe', { url: 'http://allowed.corp.local/api' }, ctx);
    assert.equal(probeAfterDeny.ok, false);
    assert.match(probeAfterDeny.error, /10\.20\.0\.0\/16/);

    const checkAfterDeny = await agentEngine._invoke('run_check', { check: 'corp-probe' }, ctx);
    assert.equal(checkAfterDeny.ok, false);
    assert.match(checkAfterDeny.error, /10\.20\.0\.0\/16/);

    const replayAfterDeny = await agentEngine._invoke('replay_request', { exchangeId: ex.id }, ctx);
    assert.equal(replayAfterDeny.ok, false);
    assert.match(replayAfterDeny.error, /10\.20\.0\.0\/16/);
    assert.equal(fetchCalls, callsBeforeDynamicDeny);
  } finally {
    close();
  }
});

test('M4 Upgrades: CVE audit endpoints, guard mode:all, traffic ?status=2xx, body limits, maxDepth:0 & allowPrivate persistence', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-m4-srv-'));
  try {
    // 1. /api/cves/coverage & /api/cves/audit, guard mode:all, traffic status=2xx, body limits, maxDepth:0
    const crawledPaths = [];
    const { server, close } = createTestServer({
      fetcher: async (url) => {
        const u = new URL(url);
        crawledPaths.push(u.pathname);
        if (u.pathname === '/') {
          return {
            status: 200,
            headers: new Headers({ 'content-type': 'text/html' }),
            text: async () => '<html><body><a href="/sub-should-not-crawl">Sub</a></body></html>'
          };
        }
        return { status: 404, headers: new Headers(), text: async () => 'Not Found' };
      }
    });

    try {
      const covRes = await dispatch(server, '/api/cves/coverage?tech=nextjs,spring&feed=0');
      assert.equal(covRes.status, 200);
      assert.deepEqual(covRes.json.filter.techTags, ['nextjs', 'spring']);
      assert.ok(covRes.json.summary.totalAdvisories >= 2);

      const unknownCov = await dispatch(server, '/api/cves/coverage?tech=nonexistent_stack_xyz');
      assert.equal(unknownCov.status, 200);
      assert.equal(unknownCov.json.summary.totalAdvisories, 0);
      assert.equal(unknownCov.json.summary.coveragePercent, 100);

      const auditOk = await dispatch(server, '/api/cves/audit', {
        method: 'POST',
        body: {
          techTags: ['nextjs'],
          advisories: [
            {
              cveId: 'CVE-2099-91234',
              ecosystem: 'nextjs',
              severity: 'CRITICAL',
              cvssScore: 9.8,
              kev: true,
              title: 'Test Custom Missing CVE'
            }
          ]
        }
      });
      assert.equal(auditOk.status, 200);
      assert.ok(auditOk.json.missing.some(m => m.cveId === 'CVE-2099-91234'));

      const auditBadAdv = await dispatch(server, '/api/cves/audit', {
        method: 'POST',
        body: { advisories: 'not-an-array' }
      });
      assert.equal(auditBadAdv.status, 400);

      const auditBadTags = await dispatch(server, '/api/cves/audit', {
        method: 'POST',
        body: { techTags: 'nextjs' }
      });
      assert.equal(auditBadTags.status, 400);

      // Guard mode:all (both explicit and omitted with combined fields)
      await dispatch(server, '/api/guard/settings', {
        method: 'PUT',
        body: {
          noiseProfile: 'quiet',
          scopeRules: [{ action: 'allow', pattern: 'example.com' }]
        }
      });

      const evalCombined = await dispatch(server, '/api/guard/evaluate', {
        method: 'POST',
        body: {
          target: 'https://example.com/api',
          toolName: 'GET',
          jevAnswers: {
            q1_in_scope: true,
            q2_authorized: true,
            q3_non_destructive: true,
            q4_rate_bounded: true,
            q5_no_exfiltration: true,
            q6_evidence_only: true,
            q7_rollback_safe: true,
            q8_least_privilege: true
          }
        }
      });
      assert.equal(evalCombined.status, 200);
      assert.equal(evalCombined.json.mode, 'all');
      assert.equal(evalCombined.json.allowed, true);
      assert.equal(evalCombined.json.gate.allowed, true);
      assert.equal(typeof evalCombined.json.risk.score, 'number');
      assert.equal(evalCombined.json.jev.approved, true);

      const evalBlocked = await dispatch(server, '/api/guard/evaluate', {
        method: 'POST',
        body: {
          mode: 'all',
          target: 'https://agency.gov/admin',
          toolName: 'POST',
          jevAnswers: { q1_in_scope: true }
        }
      });
      assert.equal(evalBlocked.status, 200);
      assert.equal(evalBlocked.json.mode, 'all');
      assert.equal(evalBlocked.json.allowed, false);
      assert.equal(evalBlocked.json.gate.allowed, false);
      assert.equal(evalBlocked.json.jev.approved, false);

      // Traffic ?status=2xx & numeric total
      await dispatch(server, '/api/traffic/ingest', {
        method: 'POST',
        body: { source: 'external', method: 'GET', url: 'https://example.com/ok', statusCode: 204, resBody: '' }
      });
      await dispatch(server, '/api/traffic/ingest', {
        method: 'POST',
        body: { source: 'external', method: 'GET', url: 'https://example.com/err', statusCode: 500, resBody: 'err' }
      });
      const traffic2xx = await dispatch(server, '/api/traffic?status=2xx');
      assert.equal(traffic2xx.status, 200);
      assert.equal(typeof traffic2xx.json.total, 'number');
      assert.ok(traffic2xx.json.exchanges.length >= 1);
      assert.ok(traffic2xx.json.exchanges.every(e => e.statusCode >= 200 && e.statusCode < 300));

      // parseOptionalJsonBody 413 without Content-Type & 415 with non-JSON Content-Type & non-empty body
      const huge = 'x'.repeat(70 * 1024);
      const opt413NoCt = await dispatch(server, '/api/findings/test-finding/verify', {
        method: 'POST',
        headers: { 'Content-Type': '', 'Content-Length': String(Buffer.byteLength(huge)) },
        body: huge
      });
      // Rebuild request explicitly without content-type
      assert.equal(opt413NoCt.status, 413);

      const opt415 = await dispatch(server, '/api/findings/test-finding/verify', {
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: '{"poeLevel":3}'
      });
      assert.equal(opt415.status, 415);

      const optEmptyText = await dispatch(server, '/api/findings/test-finding/verify', {
        method: 'POST',
        headers: { 'content-type': 'text/plain' }
      });
      assert.equal(optEmptyText.status, 200);

      const scanBadNoise = await dispatch(server, '/api/scan', {
        method: 'POST',
        body: { target: 'http://127.0.0.1:4321', allowPrivate: true, noiseProfile: 'turbo_invalid' }
      });
      assert.equal(scanBadNoise.status, 400);

      // POST /api/scan honors maxDepth: 0 and per-scan noiseProfile
      await dispatch(server, '/api/guard/settings', {
        method: 'PUT',
        body: { scopeRules: [] }
      });
      const scanZero = await dispatch(server, '/api/scan', {
        method: 'POST',
        body: {
          target: 'http://127.0.0.1:4321',
          profile: 'quick',
          allowPrivate: true,
          noHistory: true,
          maxDepth: 0,
          noiseProfile: 'quiet'
        }
      });
      assert.equal(scanZero.status, 202);
      const scanId = scanZero.json.scanId;
      let finishedStatus = null;
      for (let i = 0; i < 400; i++) {
        const st = await dispatch(server, `/api/scan/${scanId}`);
        if (st.json.status === 'completed' || st.json.status === 'failed') {
          finishedStatus = st.json.status;
          assert.equal(st.json.status, 'completed');
          assert.equal(st.json.progress, 100);
          assert.ok(st.json.result.cveCoverage && typeof st.json.result.cveCoverage.totalAdvisories === 'number');
          break;
        }
        await new Promise(r => setTimeout(r, 50));
      }
      assert.equal(finishedStatus, 'completed', 'Scan job should reach completed status before server closes');
      assert.equal(crawledPaths.includes('/sub-should-not-crawl'), false, 'maxDepth: 0 must not crawl sublinks');

      const expJson = await dispatch(server, `/api/scan/${scanId}/export?format=json`);
      assert.equal(expJson.status, 200);
      assert.ok(expJson.json.cveCoverage && typeof expJson.json.cveCoverage.totalAdvisories === 'number');

      for (const [fmt, pattern] of [
        ['markdown', /## CVE Coverage Summary/],
        ['csv', /^[\uFEFF]Check ID,Title,Status,Severity,CWE,OWASP,CVSS,CVE IDs/],
        ['html', /CVE Coverage Audit Summary/]
      ]) {
        const expFmt = await dispatch(server, `/api/scan/${scanId}/export?format=${fmt}`);
        assert.equal(expFmt.status, 200);
        assert.match(expFmt.text, pattern);
      }

      const sseStream = await dispatch(server, `/api/scan/${scanId}/stream`);
      assert.equal(sseStream.status, 200);
      assert.match(sseStream.text, /event: start/);
      assert.match(sseStream.text, /event: fingerprint/);
      assert.match(sseStream.text, /event: check/);
      assert.match(sseStream.text, /event: complete/);

      // Scope deny rule blocks POST /api/scan synchronously with 403
      await dispatch(server, '/api/guard/settings', {
        method: 'PUT',
        body: { scopeRules: [{ action: 'deny', pattern: '*127.0.0.1*' }] }
      });
      const blockedScan = await dispatch(server, '/api/scan', {
        method: 'POST',
        body: { target: 'http://127.0.0.1:4321', allowPrivate: true, noHistory: true }
      });
      assert.equal(blockedScan.status, 403);
    } finally {
      close();
    }

    // 2. File-backed allowPrivate persistence across server restarts
    const srv1 = createAppServer({ historyDir: tmpDir });
    let createdTaskId;
    try {
      const created = await dispatch(srv1, '/api/tasks', {
        method: 'POST',
        body: { title: 'Restart Persist', target: 'http://127.0.0.1:4321', allowPrivate: true }
      });
      assert.equal(created.status, 201);
      createdTaskId = created.json.task.id;
      assert.equal(created.json.task.allowPrivate, true);
    } finally {
      srv1.emit('close');
    }

    const srv2 = createAppServer({ historyDir: tmpDir });
    try {
      const loaded = await dispatch(srv2, `/api/tasks/${encodeURIComponent(createdTaskId)}`);
      assert.equal(loaded.status, 200);
      assert.equal(loaded.json.task.allowPrivate, true);
    } finally {
      srv2.emit('close');
    }

    // 3. Report integration: CVE badges & cveCoverage summary in JSON, Markdown, CSV, HTML
    const sampleFindings = [
      {
        checkId: 'cve-2026-123007',
        name: 'NGINX HTTP/2 Flow-Control Heap Overflow (CVE-2026-123007)',
        status: 'VULNERABLE',
        severity: 'CRITICAL',
        cvssScore: 9.2,
        cveIds: ['CVE-2026-123007'],
        target: 'https://example.com',
        detail: 'NGINX 1.25.0 HTTP/2 enabled'
      }
    ];
    const sampleCov = {
      totalAdvisories: 42,
      coveredCount: 40,
      partialCount: 0,
      missingCount: 2,
      coveragePercent: 95,
      kevTotal: 10,
      kevCovered: 9,
      kevMissing: 1,
      techTags: ['nginx']
    };
    const jsonRep = generateReport(sampleFindings, { grade: 'F', level: 'CRITICAL', score: 20 }, null, { cveCoverage: sampleCov });
    assert.equal(jsonRep.cveCoverage.totalAdvisories, 42);
    const mdRep = generateMarkdownReport({ targets: ['https://example.com'], results: sampleFindings, cveCoverage: sampleCov });
    assert.match(mdRep, /CVE-2026-123007/);
    assert.match(mdRep, /## CVE Coverage Summary/);
    const csvRep = generateCsvReport(sampleFindings);
    assert.match(csvRep, /CVE IDs/);
    assert.match(csvRep, /CVE-2026-123007/);
    const htmlRep = generateHtmlReport(sampleFindings, { grade: 'F', level: 'CRITICAL', score: 20 }, null, { cveCoverage: sampleCov });
    assert.match(htmlRep, /CVE-2026-123007/);
    assert.match(htmlRep, /CVE Coverage Audit Summary/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('M6 Hardening Regressions: guard/scan prototype noiseProfile 400, CVE feed governance & prototype safety, and kind=service ingestion query', async () => {
  // 1. CANDIDATE-4 & CANDIDATE-7 & CANDIDATE-3 against standard in-memory server
  const { server, close } = createTestServer();
  try {
    for (const protoProfile of ['constructor', '__proto__', 'toString', 'valueOf']) {
      const putRes = await dispatch(server, '/api/guard/settings', {
        method: 'PUT',
        body: { noiseProfile: protoProfile }
      });
      assert.equal(putRes.status, 400, `PUT /api/guard/settings must reject "${protoProfile}" with HTTP 400`);

      const scanRes = await dispatch(server, '/api/scan', {
        method: 'POST',
        body: { target: 'http://127.0.0.1:4321', allowPrivate: true, noiseProfile: protoProfile }
      });
      assert.equal(scanRes.status, 400, `POST /api/scan must reject "${protoProfile}" with HTTP 400`);
    }

    const badConfigRes = await dispatch(server, '/api/guard/settings', {
      method: 'PUT',
      body: { noiseProfile: 'quiet', scopeRules: 'not-an-array' }
    });
    assert.equal(badConfigRes.status, 400);

    // Ensure guard state remained untouched after rejected updates
    const guardState = await dispatch(server, '/api/guard/settings');
    assert.equal(guardState.status, 200);
    assert.equal(guardState.json.noiseProfile, 'balanced');

    // CANDIDATE-3: POST /api/cves/audit must not pollute Object.prototype or Object
    const protoAuditRes = await dispatch(server, '/api/cves/audit', {
      method: 'POST',
      body: {
        techTags: ['__proto__', 'constructor'],
        advisories: [
          { cveId: 'CVE-2099-77771', ecosystem: '__proto__', severity: 'HIGH', title: 'Proto Test' },
          { cveId: 'CVE-2099-77772', ecosystem: 'constructor', severity: 'HIGH', title: 'Constructor Test' }
        ]
      }
    });
    assert.equal(protoAuditRes.status, 200);
    assert.equal(Object.hasOwn(Object.prototype, 'total'), false);
    assert.equal(({}).total, undefined);
    assert.equal(Object.total, undefined);
    assert.equal(protoAuditRes.json.byEcosystem.constructor.total, 1);

    // CANDIDATE-7: nmap & httpx ingestion retain asset_type='service' and are queryable via ?dsl=kind=service
    const nmapIngest = await dispatch(server, '/api/assets/ingest', {
      method: 'POST',
      body: {
        format: 'nmap',
        rawInput: 'Nmap scan report for 93.184.216.34\n80/tcp open http nginx'
      }
    });
    assert.equal(nmapIngest.status, 200);
    assert.ok(nmapIngest.json.assets.some(a => a.asset_type === 'service' && a.port === 80));

    const httpxIngest = await dispatch(server, '/api/assets/ingest', {
      method: 'POST',
      body: {
        format: 'httpx',
        rawInput: JSON.stringify({ url: 'https://example.com/app', status_code: 200, title: 'App' })
      }
    });
    assert.equal(httpxIngest.status, 200);
    assert.ok(httpxIngest.json.assets.some(a => a.asset_type === 'service' && a.url === 'https://example.com/app'));

    const serviceQuery = await dispatch(server, '/api/assets?dsl=kind%3Dservice');
    assert.equal(serviceQuery.status, 200);
    assert.ok(serviceQuery.json.total >= 2, `Expected >= 2 service assets, got ${serviceQuery.json.total}`);
    assert.ok(serviceQuery.json.items.some(a => a.key === 'tcp://93.184.216.34:80'));
    assert.ok(serviceQuery.json.items.some(a => a.key === 'https://example.com/app'));
  } finally {
    close();
  }

  // 2. CANDIDATE-1: server forwards dnsResolver, scopeRules, and allowPrivate into CVE feed governance
  let feedFetcherCalls = 0;
  const { server: rebindServer, close: closeRebind } = createTestServer({
    cveFeedUrl: 'https://rebind-feed.example/kev.json',
    dnsResolver: async () => ['169.254.169.254'],
    fetcher: async () => {
      feedFetcherCalls += 1;
      return { status: 200, ok: true, json: async () => ({ vulnerabilities: [] }) };
    }
  });
  try {
    const covRes = await dispatch(rebindServer, '/api/cves/coverage?feed=1');
    assert.equal(covRes.status, 200);
    assert.equal(covRes.json.source.feedStatus, 'error');
    assert.match(covRes.json.source.feedError, /169\.254\.169\.254/);

    const postAuditRes = await dispatch(rebindServer, '/api/cves/audit', {
      method: 'POST',
      body: { includeFeed: true }
    });
    assert.equal(postAuditRes.status, 200);
    assert.equal(postAuditRes.json.source.feedStatus, 'error');
    assert.equal(feedFetcherCalls, 0);
  } finally {
    closeRebind();
  }

  const { server: scopeServer, close: closeScope } = createTestServer({
    allowPrivate: true,
    cveFeedUrl: 'http://127.0.0.1:8080/kev.json',
    scopeRules: [{ action: 'deny', pattern: '*127.0.0.1*' }],
    fetcher: async () => {
      throw new Error('Should not execute blocked feed fetch');
    }
  });
  try {
    const blockedFeed = await dispatch(scopeServer, '/api/cves/coverage?feed=1');
    assert.equal(blockedFeed.status, 200);
    assert.equal(blockedFeed.json.source.feedStatus, 'error');
    assert.match(blockedFeed.json.source.feedError, /Target blocked by deny rule/i);
  } finally {
    closeScope();
  }
});

test('v2.3 Upgrades: llmrec redaction, SARIF 2.1.0, Markdown aiSolution, System Doctor, AI Advisor APIs, custom headers & CLI', async () => {
  // 1. core/llmrec.js: x-goog-api-key, proxy-authorization, x-auth-token redaction
  const geminiKey = 'AIzaSyD-Secret-Gemini-Key-9876';
  const proxyToken = 'ProxySecretToken_4321';
  const authTok = 'AuthTok_5566';
  const sanitized = sanitizePayload({
    headers: {
      'x-goog-api-key': geminiKey,
      'proxy-authorization': `Bearer ${proxyToken}`,
      'x-auth-token': authTok,
      'x-safe': 'keep-me'
    }
  });
  const serialized = JSON.stringify(sanitized);
  assert.equal(serialized.includes(geminiKey), false);
  assert.equal(serialized.includes(proxyToken), false);
  assert.equal(serialized.includes(authTok), false);
  assert.equal(sanitized.headers['x-goog-api-key'], '__masked__:9876');
  assert.equal(sanitized.headers['proxy-authorization'], 'Bearer __masked__:4321');
  assert.equal(sanitized.headers['x-auth-token'], '__masked__:5566');
  assert.equal(sanitized.headers['x-safe'], 'keep-me');

  // 2. core/report.js: generateSarifReport & generateSingleFindingMarkdown with aiSolution
  const findingsForSarif = [
    {
      checkId: 'security-headers',
      name: 'Missing Security Headers',
      status: 'VULNERABLE',
      severity: 'MEDIUM',
      cvssScore: 5.3,
      cwe: 'CWE-693',
      owasp: 'A05:2021-Security Misconfiguration',
      target: 'https://example.com/',
      detail: 'Missing CSP header',
      reproduction: {
        method: 'GET',
        url: 'https://example.com/',
        requestHeaders: {
          Authorization: 'Bearer super_secret_token_9999',
          'x-goog-api-key': geminiKey,
          'X-Trace': 'ok'
        },
        curl: "curl -i -H 'Authorization: Bearer super_secret_token_9999' 'https://example.com/'"
      },
      aiSolution: {
        mode: 'ai',
        audience: 'pro',
        provider: 'gemini',
        model: 'gemini-2.5-flash',
        plainExplanation: 'Add Content-Security-Policy header.',
        rootCause: 'Server omits CSP.',
        solutionSteps: ['Add CSP header in nginx.'],
        patchSnippet: "add_header Content-Security-Policy \"default-src 'self'\" always;\n```unclosed",
        patchLanguage: 'nginx',
        verifyCommand: 'curl -sI https://example.com/'
      }
    },
    {
      checkId: 'security-headers',
      name: 'Missing Security Headers',
      status: 'SUSPICIOUS',
      severity: 'LOW',
      target: 'https://example.com/login',
      detail: 'Missing Referrer-Policy'
    },
    {
      checkId: 'ssl-tls',
      name: 'SSL/TLS Check',
      status: 'SAFE',
      severity: 'NONE',
      target: 'https://example.com/'
    }
  ];

  const sarifDefault = generateSarifReport({ results: findingsForSarif });
  assert.equal(sarifDefault.version, '2.1.0');
  assert.equal(sarifDefault.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
  assert.equal(sarifDefault.runs[0].tool.driver.name, 'Security Scanner');
  assert.equal(sarifDefault.runs[0].tool.driver.rules.length, 1); // deduplicated by checkId
  assert.equal(sarifDefault.runs[0].results.length, 2); // SAFE excluded by default
  assert.equal(sarifDefault.runs[0].results[0].level, 'error');
  assert.equal(sarifDefault.runs[0].results[1].level, 'warning');
  const sarifJson = JSON.stringify(sarifDefault);
  assert.equal(sarifJson.includes('super_secret_token_9999'), false);
  assert.equal(sarifJson.includes(geminiKey), false);
  assert.equal(sarifDefault.runs[0].results[0].properties.reproduction.requestHeaders.Authorization, '<REDACTED>');
  assert.equal(sarifDefault.runs[0].results[0].properties.reproduction.requestHeaders['x-goog-api-key'], '<REDACTED>');
  assert.equal(sarifDefault.runs[0].results[0].properties.aiSolution.mode, 'ai');

  const sarifWithSafe = generateSarifReport({ results: findingsForSarif }, { includeSafe: true, version: '2.3.0' });
  assert.equal(sarifWithSafe.runs[0].tool.driver.version, '2.3.0');
  assert.equal(sarifWithSafe.runs[0].results.length, 3);
  assert.equal(sarifWithSafe.runs[0].results[2].level, 'none');

  const singleMd = generateSingleFindingMarkdown(findingsForSarif[0]);
  assert.match(singleMd, /AI Remediation Guidance/);
  assert.match(singleMd, /Add Content-Security-Policy header\./);
  assert.equal((singleMd.match(/`{3,}/g) || []).length % 2, 0, 'Markdown fences must stay balanced');

  // 3. Server endpoints: /api/meta ai, /api/system/doctor, /api/system/diagnose-target,
  //    /api/ai/remediate, /api/ai/summary, /api/scan/:id/export?format=sarif, POST /api/scan headers
  const capturedReqHeaders = [];
  const { server: playbookServer, close: closePlaybook } = createTestServer({
    noiseProfile: 'off',
    dnsResolver: async () => ['93.184.216.34'],
    fetcher: async (_url, init) => {
      capturedReqHeaders.push(init?.headers || {});
      return {
        status: 200,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: async () => '<html><body>ok</body></html>'
      };
    }
  });

  try {
    // GET /api/meta includes ai pool status
    const metaRes = await dispatch(playbookServer, '/api/meta');
    assert.equal(metaRes.status, 200);
    assert.ok(metaRes.json.ai && Array.isArray(metaRes.json.ai.profiles));

    // GET /api/system/doctor
    const docRes = await dispatch(playbookServer, '/api/system/doctor');
    assert.equal(docRes.status, 200);
    assert.equal(typeof docRes.json.ok, 'boolean');
    assert.ok(docRes.json.environment && docRes.json.checks);

    // POST /api/system/diagnose-target
    const diagBad = await dispatch(playbookServer, '/api/system/diagnose-target', {
      method: 'POST',
      body: {}
    });
    assert.equal(diagBad.status, 400);

    const diagOk = await dispatch(playbookServer, '/api/system/diagnose-target', {
      method: 'POST',
      body: { target: 'https://example.com' }
    });
    assert.equal(diagOk.status, 200);
    assert.equal(diagOk.json.ok, true);
    assert.equal(diagOk.json.stage, 'http_probe');

    const diagMeta = await dispatch(playbookServer, '/api/system/diagnose-target', {
      method: 'POST',
      body: { target: 'http://169.254.169.254/latest/meta-data/' }
    });
    assert.equal(diagMeta.status, 200);
    assert.equal(diagMeta.json.ok, false);
    assert.equal(diagMeta.json.issueOrigin, 'policy_block');

    // POST /api/ai/remediate (playbook 200, missing 400, invalid audience 400)
    const remMissing = await dispatch(playbookServer, '/api/ai/remediate', {
      method: 'POST',
      body: {}
    });
    assert.equal(remMissing.status, 400);

    const remBadAud = await dispatch(playbookServer, '/api/ai/remediate', {
      method: 'POST',
      body: { finding: findingsForSarif[0], audience: 'invalid_aud' }
    });
    assert.equal(remBadAud.status, 400);

    const remPlaybook = await dispatch(playbookServer, '/api/ai/remediate', {
      method: 'POST',
      body: { finding: findingsForSarif[0], audience: 'beginner' }
    });
    assert.equal(remPlaybook.status, 200);
    assert.equal(remPlaybook.json.mode, 'playbook');
    assert.equal(remPlaybook.json.audience, 'beginner');
    assert.ok(remPlaybook.json.patchSnippet);

    // POST /api/ai/summary (missing 400, unknown scanId 404, invalid audience 400, scanResult 200, scanId 200)
    const sumMissing = await dispatch(playbookServer, '/api/ai/summary', {
      method: 'POST',
      body: {}
    });
    assert.equal(sumMissing.status, 400);

    const sumNotFound = await dispatch(playbookServer, '/api/ai/summary', {
      method: 'POST',
      body: { scanId: 'nonexistent-scan-id' }
    });
    assert.equal(sumNotFound.status, 404);

    const sumBadAud = await dispatch(playbookServer, '/api/ai/summary', {
      method: 'POST',
      body: { scanResult: { results: findingsForSarif }, audience: 'guru' }
    });
    assert.equal(sumBadAud.status, 400);

    const sumDirect = await dispatch(playbookServer, '/api/ai/summary', {
      method: 'POST',
      body: { scanResult: { results: findingsForSarif }, audience: 'beginner' }
    });
    assert.equal(sumDirect.status, 200);
    assert.equal(sumDirect.json.mode, 'playbook');
    assert.equal(sumDirect.json.audience, 'beginner');

    // POST /api/scan custom headers validation (400 on CR/LF/NUL) & forwarding
    const scanBadHdr = await dispatch(playbookServer, '/api/scan', {
      method: 'POST',
      body: {
        target: 'https://example.com',
        headers: { 'X-Custom': "evil\r\nInjected: 1" }
      }
    });
    assert.equal(scanBadHdr.status, 400);

    const scanOkHdr = await dispatch(playbookServer, '/api/scan', {
      method: 'POST',
      body: {
        target: 'https://example.com',
        profile: 'quick',
        maxDepth: 0,
        noHistory: true,
        noiseProfile: 'off',
        headers: { 'X-Scanner-Test': 'custom-val-123' }
      }
    });
    assert.equal(scanOkHdr.status, 202);
    const hdrScanId = scanOkHdr.json.scanId;
    let hdrJobStatus = null;
    for (let i = 0; i < 400; i++) {
      const st = await dispatch(playbookServer, `/api/scan/${encodeURIComponent(hdrScanId)}`);
      if (st.json.status === 'completed' || st.json.status === 'failed') {
        hdrJobStatus = st.json.status;
        break;
      }
      await new Promise(r => setTimeout(r, 50));
    }
    assert.equal(hdrJobStatus, 'completed');
    assert.ok(capturedReqHeaders.some(h => h['X-Scanner-Test'] === 'custom-val-123'));

    // POST /api/ai/summary from scanId and GET /api/scan/:id/export?format=sarif
    const sumByScanId = await dispatch(playbookServer, '/api/ai/summary', {
      method: 'POST',
      body: { scanId: hdrScanId, audience: 'pro' }
    });
    assert.equal(sumByScanId.status, 200);
    assert.equal(sumByScanId.json.audience, 'pro');

    const sarifExport = await dispatch(playbookServer, `/api/scan/${encodeURIComponent(hdrScanId)}/export?format=sarif`);
    assert.equal(sarifExport.status, 200);
    assert.equal(sarifExport.headers.get('content-type'), 'application/sarif+json; charset=utf-8');
    assert.equal(sarifExport.json.version, '2.1.0');
    assert.ok(Array.isArray(sarifExport.json.runs[0].results));
  } finally {
    closePlaybook();
  }

  // 4. POST /api/ai/remediate with mock LlmPool ('ai' mode 200)
  const mockAiPool = new LlmPool({
    profiles: [{ id: 'mock-gemini', provider: 'gemini', model: 'gemini-2.5-flash', apiKey: 'AIza-mock-1234', rank: 1 }],
    fetcher: async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({
        candidates: [{
          content: {
            parts: [{
              text: JSON.stringify({
                plainExplanation: 'AI explanation: configure CSP on Nginx.',
                rootCause: 'Missing Content-Security-Policy response header.',
                solutionSteps: ['Add add_header Content-Security-Policy directive.', 'Reload nginx.'],
                patchSnippet: "add_header Content-Security-Policy \"default-src 'self'\" always;",
                patchLanguage: 'nginx',
                verifyCommand: 'curl -sI https://example.com/',
                verifyExpected: 'Content-Security-Policy header present.'
              })
            }]
          },
          finishReason: 'STOP'
        }],
        usageMetadata: { promptTokenCount: 20, candidatesTokenCount: 30, totalTokenCount: 50 }
      })
    })
  });
  const { server: aiServer, close: closeAi } = createTestServer({ llmPool: mockAiPool });
  try {
    const remAi = await dispatch(aiServer, '/api/ai/remediate', {
      method: 'POST',
      body: { finding: findingsForSarif[0], audience: 'pro', stack: 'nginx' }
    });
    assert.equal(remAi.status, 200);
    assert.equal(remAi.json.mode, 'ai');
    assert.equal(remAi.json.provider, 'gemini');
    assert.match(remAi.json.plainExplanation, /AI explanation/i);
  } finally {
    closeAi();
  }

  // 5. runScanner with { headers, sarif, aiFix, audience, llmPool }
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-v23-test-'));
  const sarifOut = path.join(tmpDir, 'out.sarif');
  const seenHeaders = [];
  try {
    const full = await runScanner({
      targets: ['https://example.com'],
      profile: 'quick',
      maxDepth: 0,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      noiseProfile: 'off',
      headers: { 'X-Api-Test': 'v23-ok' },
      sarif: sarifOut,
      aiFix: true,
      audience: 'beginner',
      llmPool: mockAiPool,
      dnsResolver: async () => ['93.184.216.34'],
      fetcher: async (_u, init) => {
        seenHeaders.push(init?.headers || {});
        return {
          status: 200,
          headers: new Headers({ 'content-type': 'text/html' }),
          text: async () => '<html><body>ok</body></html>'
        };
      }
    });
    assert.ok(seenHeaders.some(h => h['X-Api-Test'] === 'v23-ok'));
    assert.equal(full.sarifFile, sarifOut);
    assert.ok(fs.existsSync(sarifOut));
    const parsedSarif = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
    assert.equal(parsedSarif.version, '2.1.0');
    assert.ok(full.aiSummary && full.aiSummary.audience === 'beginner');
    const nonSafe = full.results.filter(r => r.status !== 'SAFE');
    if (nonSafe.length > 0) {
      assert.ok(nonSafe.every(r => r.aiSolution && r.aiSolution.audience === 'beginner'));
    }

    // 6. CLI flags: --doctor --json, invalid --header, invalid --audience
    const docCli = await execFileAsync(process.execPath, ['bin/cli.js', '--doctor', '--json'], {
      cwd: process.cwd()
    });
    const docJson = JSON.parse(docCli.stdout);
    assert.equal(docJson.ok, true);
    assert.ok(docJson.doctor.checks.count >= 63);

    for (const badArgs of [
      ['bin/cli.js', 'https://example.com', '--header', 'InvalidNoColon'],
      ['bin/cli.js', 'https://example.com', '--header', ': emptyname'],
      ['bin/cli.js', 'https://example.com', '--audience', 'invalid']
    ]) {
      let code = 0;
      try {
        await execFileAsync(process.execPath, badArgs, { cwd: process.cwd() });
      } catch (err) {
        code = err.code;
      }
      assert.equal(code, 1, `Expected exit 1 for ${badArgs.join(' ')}`);
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('v2.3 security regressions (CANDIDATE-5, 9, 10, 11, 12): headers/config, SARIF deep redaction, doctor non-mutating, summary scanId priority & LLM key guard', async () => {
  // CANDIDATE-9: generateSarifReport redacts secrets in rules, raw f.detail, repro url/body, and aiSolution
  const googleKey = 'AIzaSyB1234567890abcdefGHIJKLMNOPQRSTUV';
  const stripeLive = ['sk', 'live', '51AbCdEfGhIjKlMnOpQrSt'].join('_');
  const slackPrefix = ['xoxb', '123456789012'].join('-');
  const slackTok = `${slackPrefix}-123456789012-abcdefABCDEF`;
  const sarif = generateSarifReport({
    results: [
      {
        checkId: 'env',
        title: `Exposed .env DB_PASSWORD=topSecretDb99`,
        status: 'VULNERABLE',
        severity: 'CRITICAL',
        target: 'https://user:urlPass123@example.com/.env',
        detail: `GEMINI_API_KEY=${googleKey}`,
        remediation: 'Rotate DB_PASSWORD=topSecretDb99 immediately',
        meta: { id: 'env', title: 'Exposed .env' }, // plainExplanation omitted so rule.fullDescription uses f.detail
        reproduction: {
          method: 'POST',
          url: 'https://user:urlPass123@example.com/.env',
          requestHeaders: { 'X-Custom-Token': `Bearer ${googleKey}` },
          body: `STRIPE_SECRET=${stripeLive}`
        },
        aiSolution: {
          mode: 'ai',
          plainExplanation: `Remove GEMINI_API_KEY=${googleKey}`,
          developerPrompt: `Rotate ${slackTok}`
        }
      }
    ]
  });
  const sarifStr = JSON.stringify(sarif);
  for (const secret of [googleKey, 'topSecretDb99', 'urlPass123', stripeLive, slackPrefix]) {
    assert.equal(sarifStr.includes(secret), false, `SARIF leaked secret: ${secret}`);
  }

  // CANDIDATE-5 (CLI config.headers + --header), CANDIDATE-10 (doctor non-mutating), CANDIDATE-11 (scanId priority), CANDIDATE-12 (upsert API)
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-v23-reg-'));
  const nonExistentHist = path.join(tmpDir, 'never-created-history');
  const pool = new LlmPool({
    autoDiscoverEnv: true,
    env: { GEMINI_API_KEY: googleKey }
  });
  const emptyPool = new LlmPool();

  const { server: srvNoLlm, close: closeNoLlm } = createTestServer({
    historyDir: nonExistentHist,
    llmPool: emptyPool
  });
  try {
    // C10: GET /api/system/doctor is non-mutating and sets configured:false for 0 profiles
    const docGet = await dispatch(srvNoLlm, '/api/system/doctor');
    assert.equal(docGet.status, 200);
    assert.equal(fs.existsSync(nonExistentHist), false);
    assert.equal(docGet.json.ai.configured, false);
    assert.equal(docGet.json.ai.activeProfilesCount, 0);
    assert.ok(!docGet.json.storage.historyDir.path.includes(tmpDir));

    // C10: POST /api/system/doctor performs write probe when explicitly triggered
    const docPost = await dispatch(srvNoLlm, '/api/system/doctor', { method: 'POST' });
    assert.equal(docPost.status, 200);
    assert.equal(fs.existsSync(nonExistentHist), true);

    // C5: POST /api/scan rejects forbidden headers, invalid token names, >32 headers, and >8KB headers
    for (const badHeaders of [
      { Host: 'evil.internal' },
      { 'Transfer-Encoding': 'chunked' },
      { 'Keep-Alive': 'timeout=5' },
      { 'X[Bad]': '1' },
      Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`X-H-${i}`, '1'])),
      { 'X-Huge': 'A'.repeat(9000) }
    ]) {
      const r = await dispatch(srvNoLlm, '/api/scan', {
        method: 'POST',
        body: { target: 'https://example.com', headers: badHeaders }
      });
      assert.equal(r.status, 400, `Expected 400 for headers ${JSON.stringify(Object.keys(badHeaders).slice(0, 3))}`);
    }

    // C5: runScanner also rejects forbidden headers
    await assert.rejects(
      () => runScanner({
        targets: ['https://example.com'],
        headers: { 'Transfer-Encoding': 'chunked' },
        silent: true,
        setExitCode: false
      }),
      /Forbidden header/
    );

    // C11: POST /api/ai/summary resolves scanId FIRST (unknown scanId + valid scanResult returns 404)
    const sumBypassAttempt = await dispatch(srvNoLlm, '/api/ai/summary', {
      method: 'POST',
      body: {
        scanId: 'missing-scan-id-xyz',
        scanResult: { results: [{ checkId: 'cors', status: 'VULNERABLE', severity: 'HIGH', target: 'https://example.com' }] },
        audience: 'beginner'
      }
    });
    assert.equal(sumBypassAttempt.status, 404);
  } finally {
    closeNoLlm();
  }

  // C12: Server API profile upsert preserves key on model edit, returns 400 on baseUrl change with blank key
  const { server: srvLlm, close: closeLlm } = createTestServer({ llmPool: pool });
  try {
    const poolGet = await dispatch(srvLlm, '/api/llm/pool');
    assert.equal(poolGet.status, 200);
    const geminiMeta = poolGet.json.profiles.find((p) => p.id === 'gemini');
    assert.equal(geminiMeta.autoDiscovered, true);
    assert.equal(geminiMeta.source, 'env');

    const editModel = await dispatch(srvLlm, '/api/llm/profiles', {
      method: 'POST',
      body: { id: 'gemini', provider: 'gemini', model: 'gemini-2.5-pro', enabled: true }
    });
    assert.equal(editModel.status, 200);
    assert.equal(pool.getProfile('gemini').apiKey, googleKey);
    assert.equal(pool.getProfile('gemini').model, 'gemini-2.5-pro');

    const exfilAttempt = await dispatch(srvLlm, '/api/llm/profiles', {
      method: 'POST',
      body: { id: 'gemini', provider: 'gemini', model: 'gemini-2.5-pro', baseUrl: 'https://attacker.example/' }
    });
    assert.equal(exfilAttempt.status, 400);
    assert.equal(pool.getProfile('gemini').baseUrl, '');
  } finally {
    closeLlm();
  }

  // C5: CLI rejects invalid --header AND invalid config.headers in .secscanrc
  try {
    for (const badHeaderArg of ['Host: evil.example', 'Transfer-Encoding: chunked', 'X[Bad]: 1']) {
      let exitCode = 0;
      try {
        await execFileAsync(process.execPath, ['bin/cli.js', 'https://example.com', '--header', badHeaderArg], {
          cwd: process.cwd()
        });
      } catch (err) {
        exitCode = err.code;
      }
      assert.equal(exitCode, 1, `Expected exit 1 for --header "${badHeaderArg}"`);
    }

    const rcDir = path.join(tmpDir, 'rc-test');
    fs.mkdirSync(rcDir, { recursive: true });
    fs.writeFileSync(path.join(rcDir, '.secscanrc'), JSON.stringify({
      headers: { Host: 'evil.example' }
    }), 'utf8');
    let rcExit = 0;
    try {
      await execFileAsync(process.execPath, [path.resolve(process.cwd(), 'bin/cli.js'), 'https://example.com'], {
        cwd: rcDir
      });
    } catch (err) {
      rcExit = err.code;
    }
    assert.equal(rcExit, 1, 'Expected exit 1 when .secscanrc contains forbidden Host header');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('SPA API Communication: POST /api/fingerprint Angular detection, scan route crawl discovery, and POST /api/ai/analyze-api', async () => {
  const visitedUrls = [];
  const angularMockFetcher = async (url) => {
    visitedUrls.push(url);
    if (url === 'https://ng-app.example.com' || url === 'https://ng-app.example.com/') {
      return {
        status: 200,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: async () => `
          <!doctype html>
          <html>
            <head>
              <script src="/polyfills-AB12CD34.js" type="module"></script>
              <script src="/main-EF56GH78.js" type="module"></script>
            </head>
            <body>
              <app-root ng-server-context="ssr"></app-root>
            </body>
          </html>
        `
      };
    }
    if (url === 'https://ng-app.example.com/main-EF56GH78.js') {
      return {
        status: 200,
        headers: new Headers({ 'content-type': 'application/javascript' }),
        text: async () => `
          import { HttpClient, provideHttpClient } from "@angular/common/http";
          provideHttpClient();
          http.get("/api/v1/catalog");
          fetch("https://api.external-backend.example.com/v2/orders");
        `
      };
    }
    if (url === 'https://ng-app.example.com/assets/config.json') {
      return {
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        text: async () => JSON.stringify({ apiBaseUrl: 'https://api.external-backend.example.com' })
      };
    }
    if (url.startsWith('https://ng-app.example.com/api/v1/catalog')) {
      return {
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        text: async () => JSON.stringify({ items: [{ id: 1, name: 'Widget' }] })
      };
    }
    return {
      status: 404,
      headers: new Headers({ 'content-type': 'text/plain' }),
      text: async () => 'Not Found'
    };
  };

  const { server, close } = createTestServer({
    noiseProfile: 'off',
    dnsResolver: async () => ['93.184.216.34'],
    fetcher: angularMockFetcher
  });

  try {
    // 1. POST /api/fingerprint returns Angular stack and apiCommunication
    const fpRes = await dispatch(server, '/api/fingerprint', {
      method: 'POST',
      body: { target: 'https://ng-app.example.com' }
    });
    assert.equal(fpRes.status, 200);
    assert.equal(fpRes.json.fingerprint.primary, 'angular');
    assert.equal(fpRes.json.recommendedProfile, 'frontend');
    assert.ok(fpRes.json.fingerprint.apiCommunication);
    assert.equal(fpRes.json.fingerprint.apiCommunication.usesApi, true);
    assert.ok(fpRes.json.fingerprint.apiCommunication.clients.includes('Angular HttpClient'));
    assert.ok(fpRes.json.fingerprint.apiCommunication.sameOriginEndpoints.includes('/api/v1/catalog'));
    assert.ok(fpRes.json.fingerprint.apiCommunication.externalApiOrigins.includes('https://api.external-backend.example.com'));

    // 2. POST /api/ai/analyze-api validation: 400 missing body fields, 404 missing scanId, 400 invalid audience
    const analyzeMissing = await dispatch(server, '/api/ai/analyze-api', {
      method: 'POST',
      body: {}
    });
    assert.equal(analyzeMissing.status, 400);

    const analyzeMissingScanId = await dispatch(server, '/api/ai/analyze-api', {
      method: 'POST',
      body: {
        scanId: 'nonexistent-scan-id-999',
        apiCommunication: fpRes.json.fingerprint.apiCommunication
      }
    });
    assert.equal(analyzeMissingScanId.status, 404);

    const analyzeBadAudience = await dispatch(server, '/api/ai/analyze-api', {
      method: 'POST',
      body: {
        target: 'https://ng-app.example.com',
        apiCommunication: fpRes.json.fingerprint.apiCommunication,
        audience: 'invalid-audience'
      }
    });
    assert.equal(analyzeBadAudience.status, 400);

    // 3. POST /api/ai/analyze-api 200 OK with direct apiCommunication
    const analyzeOk = await dispatch(server, '/api/ai/analyze-api', {
      method: 'POST',
      body: {
        target: 'https://ng-app.example.com',
        apiCommunication: fpRes.json.fingerprint.apiCommunication,
        audience: 'beginner'
      }
    });
    assert.equal(analyzeOk.status, 200);
    assert.equal(analyzeOk.json.mode, 'playbook');
    assert.equal(analyzeOk.json.usesApi, true);
    assert.ok(Array.isArray(analyzeOk.json.recommendations) && analyzeOk.json.recommendations.length > 0);
    assert.ok(analyzeOk.json.nextScanTargets.includes('https://api.external-backend.example.com'));
    assert.ok(analyzeOk.json.developerPrompt.includes('Angular'));

    // 4. POST /api/scan crawls discovered SPA same-origin routes and populates job.result.apiCommunication
    const scanStart = await dispatch(server, '/api/scan', {
      method: 'POST',
      body: {
        target: 'https://ng-app.example.com',
        profile: 'frontend',
        maxDepth: 1,
        noHistory: true,
        noiseProfile: 'off'
      }
    });
    assert.equal(scanStart.status, 202);
    const scanId = scanStart.json.scanId;

    let completedJob = null;
    for (let i = 0; i < 400; i++) {
      const poll = await dispatch(server, `/api/scan/${encodeURIComponent(scanId)}`);
      if (poll.json.status === 'completed' || poll.json.status === 'failed') {
        completedJob = poll.json;
        break;
      }
      await new Promise(r => setTimeout(r, 40));
    }
    assert.ok(completedJob);
    assert.equal(completedJob.status, 'completed');
    assert.ok(completedJob.result.apiCommunication);
    assert.equal(completedJob.result.apiCommunication.usesApi, true);
    assert.ok(completedJob.result.apiCommunication.sameOriginEndpoints.includes('/api/v1/catalog'));
    assert.ok(
      visitedUrls.some(u => u.startsWith('https://ng-app.example.com/api/v1/catalog')),
      'Expected crawler/scanner to visit discovered same-origin SPA API route /api/v1/catalog'
    );

    // 5. POST /api/ai/analyze-api 200 OK resolving scanId
    const analyzeFromScanId = await dispatch(server, '/api/ai/analyze-api', {
      method: 'POST',
      body: {
        scanId,
        audience: 'pro'
      }
    });
    assert.equal(analyzeFromScanId.status, 200);
    assert.equal(analyzeFromScanId.json.usesApi, true);
    assert.equal(analyzeFromScanId.json.audience, 'pro');
    assert.ok(analyzeFromScanId.json.sameOriginEndpoints.includes('/api/v1/catalog'));
    assert.ok(analyzeFromScanId.json.nextScanTargets.includes('https://api.external-backend.example.com'));
  } finally {
    close();
  }
});

test('CANDIDATE-2, 3, 4, 5 & 6: server /api/ai/analyze-api resists DoS (<200ms) and multi-page scan memoizes bundles, avoids duplicate page fetches, blocks 302 thirdparty & %6c/%64 routes, and redacts query secrets', async () => {
  const fetchCounts = new Map();
  const mockFetcher = async (url) => {
    fetchCounts.set(url, (fetchCounts.get(url) || 0) + 1);
    if (url === 'https://hardened-spa.example.com' || url === 'https://hardened-spa.example.com/') {
      return new Response(`
        <html>
          <head>
            <script src="/main.js"></script>
            <script src="/redir.js"></script>
          </head>
          <body>
            <app-root ng-version="18.2.0"></app-root>
            <a href="/about">About</a>
            <a href="/pricing">Pricing</a>
            <a href="/team">Team</a>
            <a href="/contact">Contact</a>
          </body>
        </html>
      `, { status: 200, headers: { 'content-type': 'text/html' } });
    }
    if (
      url === 'https://hardened-spa.example.com/about' ||
      url === 'https://hardened-spa.example.com/pricing' ||
      url === 'https://hardened-spa.example.com/team' ||
      url === 'https://hardened-spa.example.com/contact'
    ) {
      return new Response(`
        <html>
          <head><script src="/main.js"></script></head>
          <body><h1>Subpage</h1></body>
        </html>
      `, { status: 200, headers: { 'content-type': 'text/html' } });
    }
    if (url === 'https://hardened-spa.example.com/main.js') {
      return new Response(`
        import { HttpClient } from "@angular/common/http";
        http.get("/api/x?access_token=SECRET_XYZ&foo=bar");
        http.get("/api/y?sig=SECRET_SIG");
        http.get("/api/%6cogout");
        http.get("/api/u/%64elete");
        http.get("/api/v1/catalog");
      `, { status: 200, headers: { 'content-type': 'application/javascript' } });
    }
    if (url === 'https://hardened-spa.example.com/redir.js') {
      return new Response('', {
        status: 302,
        headers: { location: 'https://thirdparty.example/evil.js' }
      });
    }
    if (url.startsWith('https://thirdparty.example/')) {
      return new Response('fetch("https://leaked-redirect.example/api");', {
        status: 200,
        headers: { 'content-type': 'application/javascript' }
      });
    }
    if (url.startsWith('https://hardened-spa.example.com/api/v1/catalog')) {
      return new Response(JSON.stringify({ items: [{ id: 1 }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      });
    }
    return new Response('Not Found', { status: 404 });
  };

  const { server, close } = createTestServer({
    noiseProfile: 'off',
    dnsResolver: async () => ['93.184.216.34'],
    fetcher: mockFetcher
  });

  try {
    // 1. CANDIDATE-2: /api/ai/analyze-api handles ~60KB a- and -eyJ payloads (under 64KB limit) in < 200ms
    const t0 = performance.now();
    const dosRes1 = await dispatch(server, '/api/ai/analyze-api', {
      method: 'POST',
      body: {
        target: 'https://hardened-spa.example.com',
        apiCommunication: {
          usesApi: true,
          architecture: 'spa_api_client',
          sameOriginEndpoints: ['a-'.repeat(30720)]
        }
      }
    });
    const dosRes2 = await dispatch(server, '/api/ai/analyze-api', {
      method: 'POST',
      body: {
        target: 'https://hardened-spa.example.com',
        apiCommunication: {
          usesApi: true,
          architecture: 'spa_api_client',
          clients: ['-eyJ'.repeat(15000)]
        }
      }
    });
    const elapsedMs = performance.now() - t0;
    assert.equal(dosRes1.status, 200);
    assert.equal(dosRes2.status, 200);
    assert.ok(elapsedMs < 200, `Expected /api/ai/analyze-api < 200ms, got ${elapsedMs.toFixed(1)}ms`);

    // 2. CANDIDATE-3, 4, 5, 6: /api/scan crawl + SSE fingerprint + job result
    const scanStart = await dispatch(server, '/api/scan', {
      method: 'POST',
      body: {
        target: 'https://hardened-spa.example.com',
        profile: 'frontend',
        maxDepth: 2,
        noHistory: true,
        noiseProfile: 'off'
      }
    });
    assert.equal(scanStart.status, 202);
    const scanId = scanStart.json.scanId;

    let completedJob = null;
    for (let i = 0; i < 400; i++) {
      const poll = await dispatch(server, `/api/scan/${encodeURIComponent(scanId)}`);
      if (poll.json.status === 'completed' || poll.json.status === 'failed') {
        completedJob = poll.json;
        break;
      }
      await new Promise(r => setTimeout(r, 40));
    }
    assert.ok(completedJob);
    assert.equal(completedJob.status, 'completed');

    const job = server.context.jobs.get(scanId);
    const fpEvent = job.events.find(e => e.type === 'fingerprint');
    assert.ok(fpEvent && fpEvent.apiCommunication);
    const allSerialized = JSON.stringify({ fpEvent, result: completedJob.result });
    assert.ok(!allSerialized.includes('SECRET_XYZ'), 'Raw access_token must not leak in SSE fingerprint or job result');
    assert.ok(!allSerialized.includes('SECRET_SIG'), 'Raw sig must not leak in SSE fingerprint or job result');
    assert.ok(!allSerialized.includes('leaked-redirect.example'), 'Cross-origin 302 bundle must not be scanned');

    const calledUrls = Array.from(fetchCounts.keys());
    assert.ok(!calledUrls.some(u => u.includes('thirdparty.example')), '302 thirdparty.example must never be fetched');
    assert.ok(!calledUrls.some(u => u.includes('%6cogout') || u.includes('%64elete')), 'Percent-encoded destructive routes must never be crawled/probed');

    // Subpages (/about, /pricing, /team, /contact) must NOT cause discoverApiRoutesFromPage to re-fetch /main.js;
    // total /main.js fetches across fingerprint + crawl + api-communication check stay constant (<= 3).
    const mainJsFetches = fetchCounts.get('https://hardened-spa.example.com/main.js') || 0;
    assert.ok(mainJsFetches <= 3, `Expected /main.js memoized across 4-subpage crawl (<=3 total), got ${mainJsFetches}`);

    // 3. Also verify scan.js runScanner directly (with single domain check so subpages aren't re-fetched by fuzzing checks):
    // /about, /pricing, /team, /contact must be fetched exactly 1x each and /main.js <= 3x total.
    const cliCounts = new Map();
    const cliReport = await runScanner({
      targets: ['https://hardened-spa.example.com'],
      checks: ['api-communication'],
      maxDepth: 2,
      noHistory: true,
      silent: true,
      setExitCode: false,
      returnFull: true,
      dnsResolver: async () => ['93.184.216.34'],
      fetcher: async (url) => {
        cliCounts.set(url, (cliCounts.get(url) || 0) + 1);
        return mockFetcher(url);
      }
    });
    const cliSerialized = JSON.stringify(cliReport);
    assert.ok(!cliSerialized.includes('SECRET_XYZ'), 'CLI scan must redact access_token');
    assert.ok(!cliSerialized.includes('SECRET_SIG'), 'CLI scan must redact sig');
    assert.ok(!cliSerialized.includes('leaked-redirect.example'), 'CLI scan must block cross-origin 302 bundle');
    for (const sub of ['/about', '/pricing', '/team', '/contact']) {
      assert.equal(cliCounts.get(`https://hardened-spa.example.com${sub}`), 1, `Expected ${sub} fetched exactly 1x (crawl HTML reused)`);
    }
    assert.ok((cliCounts.get('https://hardened-spa.example.com/main.js') || 0) <= 3, 'Expected /main.js memoized across CLI crawl');
  } finally {
    close();
  }
});
