import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ALLOWED_LOCAL_BINARIES,
  HIGH_RISK_WILDCARD_PORTS,
  assertAllowedLocalBinary,
  execAllowedLocalBinary,
  resolveTrustedBinaryExecution,
  parseListeningSockets,
  parseFirewallStatus,
  parseEndpointProtectionStatus,
  parseUnquotedWindowsServices,
  runLocalPcAudit,
  formatLocalPcAuditText
} from '../../core/pc-local-auditor.js';

import { OastServer, withOastServer } from '../../core/oast-server.js';
import runSsrfCheck from '../../checks/ssrf-surface.js';
import runXxeCheck from '../../checks/xxe-injection.js';

import {
  TemplateValidationError,
  hasNestedQuantifiers,
  parseDeclarativeTemplate,
  validateDeclarativeTemplate,
  loadTemplatesFromPath,
  runDeclarativeTemplate
} from '../../core/template-loader.js';

import { DOM_CANARY, verifyDomSinksInSandbox } from '../../core/dom-sandbox-verifier.js';
import runDomXssCheck from '../../checks/dom-xss-sinks.js';
import { CveLabError, scaffoldCveLab } from '../../core/cve-lab-runner.js';
import { startServer } from '../../core/server.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../..');
const TEMPLATES_DIR = path.join(REPO_ROOT, 'templates');

function localHttpRequest(targetUrl, { method = 'GET', headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: `${parsed.pathname}${parsed.search}`,
        method,
        headers
      },
      res => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            text: Buffer.concat(chunks).toString('utf8')
          });
        });
      }
    );
    req.on('error', reject);
    if (body !== null && body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

// ============================================================================
// 1. core/pc-local-auditor.js
// ============================================================================

describe('Local PC Security Auditor (core/pc-local-auditor.js)', () => {
  test('parseListeningSockets parses Windows netstat -ano, Linux ss -tulnp, and macOS lsof outputs', () => {
    const winNetstat = [
      'Active Connections',
      '  Proto  Local Address          Foreign Address        State           PID',
      '  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4',
      '  TCP    127.0.0.1:6379         0.0.0.0:0              LISTENING       1920',
      '  TCP    [::]:3389              [::]:0                 LISTENING       1044',
      '  TCP    192.168.1.50:50122     93.184.216.34:443      ESTABLISHED     2210'
    ].join('\r\n');

    const winSockets = parseListeningSockets(winNetstat, 'win32');
    assert.equal(winSockets.length, 3);

    const smb = winSockets.find(s => s.port === 445);
    assert.ok(smb);
    assert.equal(smb.protocol, 'TCP');
    assert.equal(smb.address, '0.0.0.0');
    assert.equal(smb.pid, 4);
    assert.equal(smb.isWildcardBind, true);
    assert.equal(smb.riskInfo?.service, 'SMB');
    assert.equal(smb.riskInfo?.severity, 'CRITICAL');

    const localRedis = winSockets.find(s => s.port === 6379);
    assert.ok(localRedis);
    assert.equal(localRedis.isWildcardBind, false);
    assert.equal(localRedis.riskInfo, null);

    const rdp = winSockets.find(s => s.port === 3389);
    assert.ok(rdp);
    assert.equal(rdp.isWildcardBind, true);
    assert.equal(rdp.riskInfo?.service, 'RDP');

    const linuxSs = [
      'Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process',
      'tcp   LISTEN 0      511    0.0.0.0:6379       0.0.0.0:*         users:(("redis-server",pid=1120,fd=6))',
      'tcp   LISTEN 0      128    127.0.0.1:5432     0.0.0.0:*         users:(("postgres",pid=902,fd=5))',
      'tcp   LISTEN 0      4096   [::]:11434         [::]:*            users:(("ollama",pid=3100,fd=3))'
    ].join('\n');

    const linuxSockets = parseListeningSockets(linuxSs, 'linux');
    assert.equal(linuxSockets.length, 3);
    const redis = linuxSockets.find(s => s.port === 6379);
    assert.equal(redis?.processName, 'redis-server');
    assert.equal(redis?.pid, 1120);
    assert.equal(redis?.isWildcardBind, true);
    assert.equal(redis?.riskInfo?.service, 'Redis');
    const ollama = linuxSockets.find(s => s.port === 11434);
    assert.equal(ollama?.processName, 'ollama');
    assert.equal(ollama?.isWildcardBind, true);
    assert.equal(ollama?.riskInfo?.service, 'Ollama LLM API');

    const macLsof = [
      'COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME',
      'dockerd  4210 root   10u  IPv4 0x9988776655443322      0t0  TCP *:2375 (LISTEN)',
      'node     5100 dev    22u  IPv4 0x1122334455667788      0t0  TCP 127.0.0.1:3000 (LISTEN)'
    ].join('\n');

    const macSockets = parseListeningSockets(macLsof, 'darwin');
    assert.equal(macSockets.length, 2);
    const dockerSock = macSockets.find(s => s.port === 2375);
    assert.equal(dockerSock?.processName, 'dockerd');
    assert.equal(dockerSock?.pid, 4210);
    assert.equal(dockerSock?.isWildcardBind, true);
    assert.equal(dockerSock?.riskInfo?.service, 'Docker Daemon TCP');
    assert.equal(HIGH_RISK_WILDCARD_PORTS.has(2375), true);
  });

  test('parseFirewallStatus and parseEndpointProtectionStatus distinguish active vs disabled profiles', () => {
    const winFwActive = JSON.stringify([
      { Name: 'Domain', Enabled: true },
      { Name: 'Private', Enabled: true },
      { Name: 'Public', Enabled: true }
    ]);
    const parsedWinFwActive = parseFirewallStatus(winFwActive, 'win32');
    assert.equal(parsedWinFwActive.enabled, true);
    assert.deepEqual(parsedWinFwActive.disabledProfiles, []);

    const winFwDisabled = JSON.stringify([
      { Name: 'Domain', Enabled: true },
      { Name: 'Private', Enabled: false },
      { Name: 'Public', Enabled: false }
    ]);
    const parsedWinFwDisabled = parseFirewallStatus(winFwDisabled, 'win32');
    assert.equal(parsedWinFwDisabled.enabled, false);
    assert.deepEqual(parsedWinFwDisabled.disabledProfiles, ['Private', 'Public']);

    const ufwActive = parseFirewallStatus('Status: active\nLogging: on (low)', 'linux');
    assert.equal(ufwActive.enabled, true);
    assert.deepEqual(ufwActive.disabledProfiles, []);

    const ufwInactive = parseFirewallStatus('Status: inactive', 'linux');
    assert.equal(ufwInactive.enabled, false);
    assert.deepEqual(ufwInactive.disabledProfiles, ['ufw']);

    const macFwDisabled = parseFirewallStatus('Firewall is disabled. (State = 0)', 'darwin');
    assert.equal(macFwDisabled.enabled, false);
    assert.deepEqual(macFwDisabled.disabledProfiles, ['global']);

    const defenderEnabled = parseEndpointProtectionStatus(
      JSON.stringify({ AntivirusEnabled: true, RealTimeProtectionEnabled: true }),
      'win32'
    );
    assert.equal(defenderEnabled.antivirusEnabled, true);
    assert.equal(defenderEnabled.realTimeProtectionEnabled, true);

    const defenderDisabled = parseEndpointProtectionStatus(
      JSON.stringify({ AntivirusEnabled: true, RealTimeProtectionEnabled: false }),
      'win32'
    );
    assert.equal(defenderDisabled.antivirusEnabled, true);
    assert.equal(defenderDisabled.realTimeProtectionEnabled, false);

    const linuxAppArmor = parseEndpointProtectionStatus('apparmor=install ok installed\n', 'linux');
    assert.equal(linuxAppArmor.realTimeProtectionEnabled, true);

    const linuxDisabled = parseEndpointProtectionStatus('SELinux status: disabled', 'linux');
    assert.equal(linuxDisabled.realTimeProtectionEnabled, false);
    assert.equal(linuxDisabled.antivirusEnabled, false);
  });

  test('parseUnquotedWindowsServices detects CWE-428 paths outside System32 and ignores properly quoted paths', () => {
    const servicesJson = JSON.stringify([
      {
        Name: 'AcmeBackupAgent',
        PathName: 'C:\\Program Files\\Acme Corp\\Backup Agent\\agent.exe --daemon',
        StartMode: 'Auto'
      },
      {
        Name: 'ProperlyQuotedSvc',
        PathName: '"C:\\Program Files\\Safe Vendor\\service.exe" -k run',
        StartMode: 'Auto'
      },
      {
        Name: 'WindowsSystemSvc',
        PathName: 'C:\\Windows\\System32\\My Folder\\svchost.exe -k netsvcs',
        StartMode: 'Auto'
      },
      {
        Name: 'NoSpacesSvc',
        PathName: 'C:\\Services\\App\\daemon.exe --port 8080',
        StartMode: 'Manual'
      }
    ]);

    const vulnerable = parseUnquotedWindowsServices(servicesJson);
    assert.equal(vulnerable.length, 1);
    assert.equal(vulnerable[0].serviceName, 'AcmeBackupAgent');
    assert.equal(vulnerable[0].startMode, 'Auto');
    assert.ok(vulnerable[0].quote.includes('AcmeBackupAgent'));
    assert.ok(vulnerable[0].quote.includes('agent.exe'));
  });

  test('runLocalPcAudit with injected commandRunner returns VULNERABLE, SUSPICIOUS, and SAFE findings and rejects non-allowlisted binaries', async () => {
    // 1. Verify ALLOWED_LOCAL_BINARIES immutability and strict rejection
    assert.throws(() => ALLOWED_LOCAL_BINARIES.add('bash'), TypeError);
    assert.throws(
      () => assertAllowedLocalBinary('cmd', ['/c', 'whoami']),
      err => err.code === 'DISALLOWED_LOCAL_BINARY'
    );
    assert.throws(
      () => assertAllowedLocalBinary('/usr/bin/netstat', ['-ano']),
      err => err.code === 'DISALLOWED_LOCAL_BINARY'
    );
    await assert.rejects(
      () => execAllowedLocalBinary('sh', ['-c', 'id'], { commandRunner: async () => 'uid=0' }),
      err => err.code === 'DISALLOWED_LOCAL_BINARY'
    );

    // 2. VULNERABLE Windows host via injected commandRunner
    const invokedBinaries = [];
    const vulnerableReport = await runLocalPcAudit({
      platform: 'win32',
      hostname: 'test-win-host',
      commandRunner: async (binary, args) => {
        invokedBinaries.push(binary);
        assert.ok(ALLOWED_LOCAL_BINARIES.has(binary));
        if (binary === 'netstat') {
          return '  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\n';
        }
        const cmdText = args.join(' ');
        if (cmdText.includes('Get-NetFirewallProfile')) {
          return JSON.stringify([
            { Name: 'Domain', Enabled: true },
            { Name: 'Public', Enabled: false }
          ]);
        }
        if (cmdText.includes('Get-MpComputerStatus')) {
          return JSON.stringify({ AntivirusEnabled: true, RealTimeProtectionEnabled: false });
        }
        if (cmdText.includes('Win32_Service')) {
          return JSON.stringify([
            {
              Name: 'LegacyUpdater',
              PathName: 'C:\\Program Files\\Legacy Corp\\Updater\\updater.exe',
              StartMode: 'Auto'
            }
          ]);
        }
        return '';
      }
    });

    assert.equal(vulnerableReport.summary.overallStatus, 'VULNERABLE');
    assert.equal(vulnerableReport.summary.vulnerableCount, 4);
    assert.equal(vulnerableReport.summary.safeCount, 0);
    assert.ok(vulnerableReport.summary.riskScore >= 90);
    assert.ok(invokedBinaries.includes('netstat'));
    assert.ok(invokedBinaries.includes('powershell'));

    const textOut = formatLocalPcAuditText(vulnerableReport);
    assert.ok(textOut.includes('test-win-host'));
    assert.ok(textOut.includes('VULNERABLE'));

    // 3. SUSPICIOUS host when firewall & endpoint telemetry are unavailable
    const suspiciousReport = await runLocalPcAudit({
      platform: 'linux',
      hostname: 'test-linux-suspicious',
      commandRunner: async (binary) => {
        if (binary === 'ss') {
          return 'tcp LISTEN 0 128 127.0.0.1:6379 0.0.0.0:* users:(("redis-server",pid=99,fd=6))\n';
        }
        return '';
      }
    });
    assert.equal(suspiciousReport.summary.overallStatus, 'SUSPICIOUS');
    assert.equal(suspiciousReport.summary.vulnerableCount, 0);
    assert.equal(suspiciousReport.summary.suspiciousCount, 2);
    assert.equal(suspiciousReport.summary.safeCount, 2);

    // 4. SAFE hardened Linux host
    const safeReport = await runLocalPcAudit({
      platform: 'linux',
      hostname: 'test-linux-hardened',
      commandRunner: async (binary) => {
        if (binary === 'ss') {
          return 'tcp LISTEN 0 128 127.0.0.1:6379 0.0.0.0:* users:(("redis-server",pid=99,fd=6))\n';
        }
        if (binary === 'ufw') return 'Status: active\n';
        if (binary === 'dpkg-query') return 'apparmor=install ok installed\n';
        return '';
      }
    });
    assert.equal(safeReport.summary.overallStatus, 'SAFE');
    assert.equal(safeReport.summary.vulnerableCount, 0);
    assert.equal(safeReport.summary.suspiciousCount, 0);
    assert.equal(safeReport.summary.safeCount, 4);
    assert.equal(safeReport.summary.riskScore, 0);
  });
});

// ============================================================================
// 2. core/oast-server.js + checks/ssrf-surface.js + checks/xxe-injection.js
// ============================================================================

describe('OAST Callback Server & Blind SSRF / XXE Checks', () => {
  test('OastServer lifecycle (start, issueProbe, verifyToken, waitForInteraction, stop) and forged HMAC 403 rejection', async () => {
    const oast = new OastServer({ host: '127.0.0.1', port: 0 });
    const started = await oast.start();
    try {
      assert.equal(started.running, true);
      assert.ok(started.port > 0);
      assert.ok(started.baseUrl.startsWith('http://127.0.0.1:'));

      const probe = oast.issueProbe({
        checkId: 'ssrf-surface',
        target: 'https://target.example.com/fetch',
        parameter: 'url'
      });

      assert.equal(oast.verifyToken(probe.tokenId, probe.hmacSig), true);
      assert.equal(oast.verifyToken(probe.tokenId, '00000000000000000000'), false);
      assert.equal(oast.verifyToken('unknown-token-id', probe.hmacSig), false);

      // Forged/tampered HMAC callback must return HTTP 403 and NOT be recorded
      const tamperedSig = probe.hmacSig.slice(0, -1) + (probe.hmacSig.endsWith('0') ? '1' : '0');
      const forgedRes = await localHttpRequest(`${oast.baseUrl}/oast/${probe.tokenId}/${tamperedSig}`);
      assert.equal(forgedRes.status, 403);
      assert.equal(oast.getInteractions(probe.tokenId).length, 0);
      assert.equal(oast.getStatus().verifiedInteractionsCount, 0);

      // Unknown path must also return HTTP 403
      const unknownPathRes = await localHttpRequest(`${oast.baseUrl}/not-oast`);
      assert.equal(unknownPathRes.status, 403);

      // Valid signed callback wakes waitForInteraction immediately and returns HTTP 200
      const waitPromise = oast.waitForInteraction(probe.tokenId, 2000);
      const validRes = await localHttpRequest(probe.callbackUrl, {
        method: 'GET',
        headers: { 'User-Agent': 'SecScan-OAST-Test/1.0' }
      });
      assert.equal(validRes.status, 200);
      assert.equal(validRes.text, `oast_ack_${probe.tokenId}`);

      const interaction = await waitPromise;
      assert.ok(interaction);
      assert.equal(interaction.verified, true);
      assert.equal(interaction.tokenId, probe.tokenId);
      assert.equal(interaction.method, 'GET');
      assert.equal(interaction.userAgent, 'SecScan-OAST-Test/1.0');
      assert.equal(oast.getInteractions(probe.tokenId).length, 1);
      assert.equal(oast.getStatus().verifiedInteractionsCount, 1);
    } finally {
      await oast.stop();
    }

    assert.equal(oast.getStatus().running, false);
    assert.equal(oast.getStatus().baseUrl, null);
  });

  test('Blind SSRF (checks/ssrf-surface.js) promotes silent HTTP 200 target with OAST callback to CRITICAL VULNERABLE', async () => {
    await withOastServer({ host: '127.0.0.1', port: 0 }, async (oastServer) => {
      // Simulated silent backend that fetches ?url= server-side and always returns HTTP 200 {"ok":true}
      const mockFetch = async (requestedUrl) => {
        const parsed = new URL(requestedUrl);
        const paramUrl = parsed.searchParams.get('url');
        if (paramUrl && paramUrl.startsWith(oastServer.baseUrl)) {
          await localHttpRequest(paramUrl);
        }
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          text: '{"status":"queued","ok":true}',
          trafficId: 'tr-ssrf-oast-1'
        };
      };

      const result = await runSsrfCheck(
        'https://target.example.com/api/preview?url=https://example.org',
        mockFetch,
        { oastServer, oastWaitMs: 1000 }
      );

      assert.equal(result.status, 'VULNERABLE');
      assert.equal(result.severity, 'CRITICAL');
      assert.equal(result.poeLevel, 3);
      assert.equal(result.oastVerified, true);
      assert.equal(result.reproVerified, true);
      assert.ok(Array.isArray(result.evidenceQuotes) && result.evidenceQuotes.length >= 1);
      assert.match(result.evidenceQuotes[0], /OAST callback verified token=/);
    });
  });

  test('Blind XXE (checks/xxe-injection.js) promotes silent HTTP 200 XML target with OAST callback to CRITICAL VULNERABLE', async () => {
    await withOastServer({ host: '127.0.0.1', port: 0 }, async (oastServer) => {
      // Simulated silent XML processor that fetches external SYSTEM entity URI without echoing it
      const mockFetch = async (_targetUrl, fetchOpts = {}) => {
        const body = String(fetchOpts.body || '');
        const sysMatch = /SYSTEM\s+"([^"]+)"/i.exec(body);
        if (sysMatch && sysMatch[1].startsWith(oastServer.baseUrl)) {
          await localHttpRequest(sysMatch[1]);
        }
        return {
          status: 200,
          headers: { 'content-type': 'application/xml' },
          text: '<response><status>accepted</status></response>',
          trafficId: 'tr-xxe-oast-1'
        };
      };

      const result = await runXxeCheck(
        'https://target.example.com/soap/import',
        mockFetch,
        { oastServer, oastWaitMs: 1000 }
      );

      assert.equal(result.status, 'VULNERABLE');
      assert.equal(result.severity, 'CRITICAL');
      assert.equal(result.poeLevel, 3);
      assert.equal(result.oastVerified, true);
      assert.equal(result.reproVerified, true);
      assert.ok(Array.isArray(result.evidenceQuotes) && result.evidenceQuotes.length >= 1);
      assert.match(result.evidenceQuotes[0], /OAST callback verified token=/);
    });
  });

  test('Blind SSRF and Blind XXE remain SAFE when no authenticated OAST callback is received', async () => {
    await withOastServer({ host: '127.0.0.1', port: 0 }, async (oastServer) => {
      const silentNoCallbackFetch = async () => ({
        status: 200,
        headers: { 'content-type': 'application/json' },
        text: '{"ok":true}'
      });

      const ssrfSafe = await runSsrfCheck(
        'https://safe.example.com/api/fetch',
        silentNoCallbackFetch,
        { oastServer, oastWaitMs: 50 }
      );
      assert.equal(ssrfSafe.status, 'SAFE');

      const xxeSafe = await runXxeCheck(
        'https://safe.example.com/api/xml',
        silentNoCallbackFetch,
        { oastServer, oastWaitMs: 50 }
      );
      assert.equal(xxeSafe.status, 'SAFE');
    });
  });
});

// ============================================================================
// 3. core/template-loader.js
// ============================================================================

describe('Declarative CVE Template Engine (core/template-loader.js)', () => {
  test('parses and executes templates/cve-2025-29927-template.yaml and templates/spring-actuator-exposure.yaml', async () => {
    const nextjsPath = path.join(TEMPLATES_DIR, 'cve-2025-29927-template.yaml');
    const springPath = path.join(TEMPLATES_DIR, 'spring-actuator-exposure.yaml');

    const [nextjsTpl] = loadTemplatesFromPath(nextjsPath);
    const [springTpl] = loadTemplatesFromPath(springPath);

    assert.equal(nextjsTpl.id, 'cve-2025-29927-template');
    assert.equal(nextjsTpl.info.severity, 'CRITICAL');
    assert.deepEqual(nextjsTpl.info.cveIds, ['CVE-2025-29927']);
    assert.equal(nextjsTpl.requests[0].headers['x-middleware-subrequest'], 'middleware:middleware:middleware:middleware:middleware');

    assert.equal(springTpl.id, 'spring-actuator-exposure-template');
    assert.equal(springTpl.info.severity, 'HIGH');
    assert.deepEqual(springTpl.requests[0].paths, ['/actuator/env', '/actuator/info']);

    // Execute Next.js template against vulnerable mock target
    const nextjsMockFetch = async (url, opts = {}) => {
      if (url.includes('.secscan_tpl_404_canary')) {
        return { status: 404, headers: {}, text: 'Not Found' };
      }
      if (url.endsWith('/admin') && opts.headers?.['x-middleware-subrequest']) {
        return {
          status: 200,
          headers: { 'content-type': 'text/html' },
          text: '<html><body><h1>Internal Admin Dashboard</h1><p>Users & Roles</p></body></html>'
        };
      }
      return { status: 307, headers: { location: '/login' }, text: '' };
    };

    const nextjsFinding = await runDeclarativeTemplate(nextjsTpl, 'https://app.example.com', nextjsMockFetch);
    assert.equal(nextjsFinding.status, 'VULNERABLE');
    assert.equal(nextjsFinding.severity, 'CRITICAL');
    assert.equal(nextjsFinding.cve, 'CVE-2025-29927');
    assert.equal(nextjsFinding.poeLevel, 3);
    assert.ok(nextjsFinding.confidenceScore >= 90);

    // Execute Spring Actuator template against vulnerable mock target
    const springMockFetch = async (url) => {
      if (url.includes('.secscan_tpl_404_canary')) {
        return { status: 404, headers: {}, text: 'Whitelabel Error Page' };
      }
      if (url.endsWith('/actuator/env')) {
        return {
          status: 200,
          headers: { 'content-type': 'application/vnd.spring-boot.actuator.v3+json' },
          text: '{"activeProfiles":["prod"],"propertySources":[{"name":"server.ports"}]}'
        };
      }
      return { status: 404, headers: {}, text: 'Not Found' };
    };

    const springFinding = await runDeclarativeTemplate(springTpl, 'https://api.example.com', springMockFetch);
    assert.equal(springFinding.status, 'VULNERABLE');
    assert.equal(springFinding.severity, 'HIGH');
    assert.equal(springFinding.path, '/actuator/env');
    assert.ok(springFinding.evidenceQuotes.some(q => q.includes('propertySources')));
  });

  test('rejects templates with external SSRF paths or ReDoS nested-quantifier regexes with TemplateValidationError', () => {
    const ssrfTemplate = {
      id: 'evil-ssrf-tpl',
      info: { name: 'SSRF Escape', severity: 'high' },
      http: [
        {
          method: 'GET',
          path: ['http://169.254.169.254/latest/meta-data/'],
          matchers: [{ type: 'status', status: [200] }]
        }
      ]
    };

    assert.throws(
      () => validateDeclarativeTemplate(ssrfTemplate),
      err => err instanceof TemplateValidationError && /external URLs are blocked|SSRF/i.test(err.message)
    );

    const protocolRelativeSsrf = {
      id: 'evil-proto-relative',
      info: { name: 'Protocol Relative SSRF', severity: 'high' },
      http: [
        {
          method: 'GET',
          path: ['//169.254.169.254/latest'],
          matchers: [{ type: 'status', status: [200] }]
        }
      ]
    };
    assert.throws(
      () => validateDeclarativeTemplate(protocolRelativeSsrf),
      err => err instanceof TemplateValidationError && /SSRF blocked/i.test(err.message)
    );

    assert.equal(hasNestedQuantifiers('(a+)+$'), true);
    assert.equal(hasNestedQuantifiers('([a-z]*)*'), true);
    assert.equal(hasNestedQuantifiers('^HTTP/[12]\\.\\d\\s+200$'), false);

    const redosTemplate = parseDeclarativeTemplate(JSON.stringify({
      id: 'evil-redos-tpl',
      info: { name: 'ReDoS Pattern', severity: 'medium' },
      http: [
        {
          method: 'GET',
          path: ['{{BaseURL}}/status'],
          matchers: [{ type: 'regex', regex: ['(a+)+$'] }]
        }
      ]
    }));

    assert.throws(
      () => validateDeclarativeTemplate(redosTemplate),
      err => err instanceof TemplateValidationError && /ReDoS/i.test(err.message)
    );
  });

  test('automatically suppresses HTTP 200 Soft-404 responses via isSoft404Response', async () => {
    const template = {
      id: 'soft404-guard-check',
      info: { name: 'Admin Exposure Check', severity: 'high' },
      http: [
        {
          method: 'GET',
          path: ['{{BaseURL}}/admin'],
          'matchers-condition': 'and',
          matchers: [
            { type: 'status', status: [200] },
            { type: 'word', words: ['Application Portal'] }
          ]
        }
      ]
    };

    // 1. Explicit Next.js HTTP 200 soft-404 marker
    const nextSoft404Fetch = async (url) => {
      if (url.includes('.secscan_tpl_404_canary')) {
        return { status: 404, headers: {}, text: 'Not found' };
      }
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        text: '<html><head><title>404: This page could not be found</title></head><body><h1 class="next-error-h1">404</h1><p>Application Portal</p></body></html>'
      };
    };

    const nextSuppressed = await runDeclarativeTemplate(template, 'https://soft404.example.com', nextSoft404Fetch);
    assert.equal(nextSuppressed.status, 'SAFE');

    // 2. Custom SPA HTTP 200 fallback identical in structure to canary baseline
    const spaTemplate = (route) => `<!DOCTYPE html>
<html>
<head><title>Application Portal</title></head>
<body>
  <header><nav><a href="/">Home</a><a href="/docs">Docs</a><a href="/help">Help</a></nav></header>
  <main class="spa-fallback">
    <h1>Application Portal</h1>
    <p>This single-page application renders a generic shell for every unknown route and handles navigation on the client side.</p>
    <span data-path="${route}">Client Router Fallback</span>
  </main>
</body>
</html>`;

    const spaSoft404Fetch = async (url) => ({
      status: 200,
      headers: { 'content-type': 'text/html' },
      text: spaTemplate(new URL(url).pathname)
    });

    const spaSuppressed = await runDeclarativeTemplate(template, 'https://spa.example.com', spaSoft404Fetch);
    assert.equal(spaSuppressed.status, 'SAFE');
  });
});

// ============================================================================
// 4. core/dom-sandbox-verifier.js + checks/dom-xss-sinks.js
// ============================================================================

describe('DOM Sandbox Runtime Verifier & dom-xss-sinks Check', () => {
  test('detects multi-variable runtime DOM taint flow and unvalidated postMessage handlers with runtimeVerified: true', async () => {
    const multiVarHtml = `<!DOCTYPE html>
<html>
<body>
  <div id="greeting"></div>
  <script>
    const raw = location.hash.slice(1);
    const cleaned = decodeURIComponent(raw);
    const markup = '<div class="banner">' + cleaned + '</div>';
    document.body.innerHTML = markup;
  </script>
</body>
</html>`;

    const directSandbox = verifyDomSinksInSandbox(multiVarHtml);
    assert.equal(directSandbox.executedScriptsCount, 1);
    assert.equal(directSandbox.taintedSinkCalls.length, 1);
    assert.equal(directSandbox.taintedSinkCalls[0].sink, 'innerHTML');
    assert.equal(directSandbox.taintedSinkCalls[0].sourceType, 'direct_dom');
    assert.equal(directSandbox.taintedSinkCalls[0].runtimeVerified, true);
    assert.ok(directSandbox.taintedSinkCalls[0].valuePreview.includes(DOM_CANARY));

    const directCheckResult = await runDomXssCheck('https://spa.example.com/profile', async () => ({
      status: 200,
      headers: { 'content-type': 'text/html' },
      text: multiVarHtml
    }));
    assert.equal(directCheckResult.status, 'VULNERABLE');
    assert.equal(directCheckResult.severity, 'HIGH');
    assert.ok(directCheckResult.findings.some(f => f.type === 'dom_source_to_sink' && f.runtimeVerified === true));

    // Unvalidated postMessage handler (indirection across helper function so static regex alone wouldn't see direct event.data)
    const postMsgHtml = `<!DOCTYPE html>
<html>
<body>
  <div id="widget"></div>
  <script>
    function renderPayload(payload) {
      document.getElementById('widget').innerHTML = payload;
    }
    window.addEventListener('message', function (evt) {
      renderPayload(evt.data);
    });
  </script>
</body>
</html>`;

    const pmSandbox = verifyDomSinksInSandbox(postMsgHtml);
    assert.ok(
      pmSandbox.taintedSinkCalls.some(
        c => c.sink === 'innerHTML' && c.sourceType === 'postmessage' && c.runtimeVerified === true
      )
    );

    const pmCheckResult = await runDomXssCheck('https://spa.example.com/embed', async () => ({
      status: 200,
      headers: { 'content-type': 'text/html' },
      text: postMsgHtml
    }));
    assert.equal(pmCheckResult.status, 'VULNERABLE');
    assert.ok(
      pmCheckResult.findings.some(
        f => f.type === 'unsafe_postmessage_listener' && f.runtimeVerified === true
      )
    );

    // Properly origin-validated postMessage listener must NOT trigger a runtime tainted call
    const safePostMsgHtml = `<!DOCTYPE html>
<html>
<body>
  <div id="widget"></div>
  <script>
    window.addEventListener('message', function (evt) {
      if (evt.origin !== 'https://trusted.example.com') return;
      document.getElementById('widget').innerHTML = evt.data;
    });
  </script>
</body>
</html>`;

    const safePmSandbox = verifyDomSinksInSandbox(safePostMsgHtml);
    assert.equal(safePmSandbox.taintedSinkCalls.length, 0);
  });

  test('blocks sandbox escape attempts (Function constructor, prototype constructor chain, and infinite loops)', () => {
    const escapeHtml = `<!DOCTYPE html>
<html>
<body>
  <script>
    const p1 = Function("return process")();
    document.body.innerHTML = String(p1 && p1.version);
  </script>
  <script>
    const p2 = ({}).constructor.constructor("return process")();
    document.body.innerHTML = String(p2 && p2.env);
  </script>
  <script>
    while (true) {}
  </script>
</body>
</html>`;

    const startedAt = Date.now();
    const result = verifyDomSinksInSandbox(escapeHtml, { timeoutMs: 80, totalBudgetMs: 400 });
    const elapsedMs = Date.now() - startedAt;

    assert.equal(result.executedScriptsCount, 3);
    assert.equal(result.taintedSinkCalls.length, 0);
    assert.ok(result.sandboxErrors.length >= 3, `Expected >= 3 sandbox errors, got ${result.sandboxErrors.length}`);
    assert.ok(
      result.sandboxErrors.some(e => /code generation from strings disallowed|EvalError/i.test(e)),
      `Expected codeGeneration block error, got: ${JSON.stringify(result.sandboxErrors)}`
    );
    assert.ok(
      result.sandboxErrors.some(e => /timed out/i.test(e)),
      `Expected infinite loop timeout error, got: ${JSON.stringify(result.sandboxErrors)}`
    );
    assert.ok(elapsedMs < 1500, `Expected sandbox to enforce timeout promptly, took ${elapsedMs}ms`);
  });
});

// ============================================================================
// 5. Step 2D Security Remediation Regression Tests (FINDING-1..9)
// ============================================================================

describe('Next-Gen Step 2D Security Remediation Regression Tests (FINDING-1..9)', () => {
  test('FINDING-1 & FINDING-2: DOM sandbox blocks microtask Promise hangs and guest-thrown getter execution on host', () => {
    // FINDING-1: Promise.then microtask loop must terminate within VM timeout without hanging host
    const t0 = Date.now();
    const microtaskRes = verifyDomSinksInSandbox(
      '<script>Promise.resolve().then(() => { while (true) {} });</script>',
      { timeoutMs: 60, totalBudgetMs: 300 }
    );
    const microElapsed = Date.now() - t0;
    assert.ok(microElapsed < 1000, `Expected microtask timeout promptly, took ${microElapsed}ms`);
    assert.ok(
      microtaskRes.sandboxErrors.some(e => /timed out/i.test(e)),
      `Expected microtask timeout error, got: ${JSON.stringify(microtaskRes.sandboxErrors)}`
    );

    // FINDING-2: Guest-thrown object with expensive getter must not execute on host
    const t1 = Date.now();
    const getterRes = verifyDomSinksInSandbox(
      '<script>throw { get message() { const end = Date.now() + 450; while (Date.now() < end) {} return "pwned_getter"; } };</script>',
      { timeoutMs: 60, totalBudgetMs: 300 }
    );
    const getterElapsed = Date.now() - t1;
    assert.ok(getterElapsed < 400, `Guest getter must not run on host; elapsed=${getterElapsed}ms`);
    assert.equal(
      getterRes.sandboxErrors.some(e => e.includes('pwned_getter')),
      false,
      'Host must not evaluate guest-thrown object getters'
    );
  });

  test('FINDING-3 & FINDING-4: DOM sandbox requires unescaped metacharacters for HTML sinks and blocks prototype toJSON forgery', async () => {
    // FINDING-3: HTML-escaped or encodeURIComponent flows must NOT trigger innerHTML XSS
    const escapedHtml = `<!DOCTYPE html><html><body><div id="out"></div><script>
      function esc(s) { return String(s).replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
      document.getElementById('out').innerHTML = esc(location.hash.slice(1));
      document.body.innerHTML = encodeURIComponent(new URLSearchParams(location.search).get('q') || '');
    </script></body></html>`;

    const escapedSandbox = verifyDomSinksInSandbox(escapedHtml);
    assert.equal(escapedSandbox.taintedSinkCalls.length, 0);

    const escapedCheck = await runDomXssCheck('https://safe-esc.example.com/', async () => ({
      status: 200,
      headers: { 'content-type': 'text/html' },
      text: escapedHtml
    }));
    assert.equal(escapedCheck.status, 'SAFE');

    // FINDING-4: Array.prototype.toJSON / Object.prototype.toJSON tampering must NOT forge sink results
    const forgedHtml = `<!DOCTYPE html><html><body><script>
      Array.prototype.toJSON = function() {
        return [{ sink: 'eval', valuePreview: 'forged_canary', sourceType: 'direct_dom', runtimeVerified: true }];
      };
      Object.prototype.toJSON = Array.prototype.toJSON;
    </script></body></html>`;

    const forgedSandbox = verifyDomSinksInSandbox(forgedHtml);
    assert.equal(forgedSandbox.taintedSinkCalls.length, 0);

    const forgedCheck = await runDomXssCheck('https://forged.example.com/', async () => ({
      status: 200,
      headers: { 'content-type': 'text/html' },
      text: forgedHtml
    }));
    assert.equal(forgedCheck.status, 'SAFE');
  });

  test('FINDING-5: Template ReDoS guard rejects quantified alternation and bounds matcher corpus to 64KB', async () => {
    for (const redosPattern of ['^(a|a)*$', '^(\\w|\\d)+$', '^(a|ab)*c']) {
      assert.equal(hasNestedQuantifiers(redosPattern), true, `Expected ${redosPattern} to be flagged`);
      assert.throws(
        () =>
          validateDeclarativeTemplate({
            id: 'redos-alt-test',
            info: { name: 'ReDoS Alt', severity: 'medium' },
            http: [
              {
                method: 'GET',
                path: ['{{BaseURL}}/'],
                matchers: [{ type: 'regex', regex: [redosPattern] }]
              }
            ]
          }),
        err => err instanceof TemplateValidationError && /ReDoS/i.test(err.message)
      );
    }

    // Corpus beyond 65536 chars is bounded and does not match tail marker
    const tpl = validateDeclarativeTemplate({
      id: 'bounded-corpus-tpl',
      info: { name: 'Corpus Bound Test', severity: 'low' },
      http: [
        {
          method: 'GET',
          path: ['{{BaseURL}}/big'],
          matchers: [{ type: 'word', words: ['TAIL_BEYOND_64KB_MARKER'] }]
        }
      ]
    });
    const bigRes = await runDeclarativeTemplate(tpl, 'https://example.com', async url => {
      if (url.includes('.secscan_tpl_404_canary')) return { status: 404, headers: {}, text: 'Not Found' };
      return {
        status: 200,
        headers: { 'content-type': 'text/plain' },
        text: 'A'.repeat(70000) + 'TAIL_BEYOND_64KB_MARKER'
      };
    });
    assert.equal(bigRes.status, 'SAFE');
  });

  test('FINDING-6: execAllowedLocalBinary resolves trusted absolute OS paths and ignores planted CWD binaries', async () => {
    const winNetstat = resolveTrustedBinaryExecution('netstat', 'win32');
    assert.ok(path.win32.isAbsolute(winNetstat.executablePath));
    assert.match(winNetstat.executablePath, /\\System32\\netstat\.exe$/i);
    assert.ok(!winNetstat.cwd.includes(process.cwd()) || process.cwd().toLowerCase() === winNetstat.cwd.toLowerCase());

    const winPs = resolveTrustedBinaryExecution('powershell', 'win32');
    assert.match(winPs.executablePath, /\\WindowsPowerShell\\v1\.0\\powershell\.exe$/i);

    const unixSs = resolveTrustedBinaryExecution('ss', 'linux');
    assert.ok(unixSs.executablePath.startsWith('/'));
    assert.equal(unixSs.cwd, '/');
    assert.equal(unixSs.env.PATH, '/usr/bin:/bin:/usr/sbin:/sbin');

    // On Windows, planting uname.exe in process.cwd() must NOT be executed by execAllowedLocalBinary('uname')
    if (process.platform === 'win32' && fs.existsSync('C:\\Windows\\System32\\hostname.exe')) {
      const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-cwd-plant-'));
      const prevCwd = process.cwd();
      try {
        fs.copyFileSync('C:\\Windows\\System32\\hostname.exe', path.join(tmpCwd, 'uname.exe'));
        process.chdir(tmpCwd);
        await assert.rejects(
          () => execAllowedLocalBinary('uname', []),
          err => err && err.code === 'ENOENT'
        );
      } finally {
        process.chdir(prevCwd);
        fs.rmSync(tmpCwd, { recursive: true, force: true });
      }
    }
  });

  test('FINDING-7: OastServer enforces per-token cap, global maxInteractions cap across tokens, and tokenTtlMs expiry', async () => {
    // 1. Per-token cap and global cap across all tokens
    await withOastServer(
      { host: '127.0.0.1', port: 0, maxInteractions: 12, maxInteractionsPerToken: 4, tokenTtlMs: 30000 },
      async oast => {
        const probes = Array.from({ length: 5 }, (_, i) =>
          oast.issueProbe({ checkId: 'ssrf-surface', target: `https://t${i}.example` })
        );

        // Send 6 callbacks to probe[0] -> only 4 kept per token
        for (let i = 0; i < 6; i++) {
          const r = await localHttpRequest(probes[0].callbackUrl, { method: 'GET' });
          assert.equal(r.status, 200);
        }
        assert.equal(oast.getInteractions(probes[0].tokenId).length, 4);

        // Send 3 callbacks each to probes[1..4] (12 more) -> global stored must stay <= 12 across BOTH lists
        for (let p = 1; p < probes.length; p++) {
          for (let j = 0; j < 3; j++) {
            const r = await localHttpRequest(probes[p].callbackUrl, { method: 'GET' });
            assert.equal(r.status, 200);
          }
        }
        assert.ok(oast.getInteractions().length <= 12);
        const totalPerToken = probes.reduce((acc, p) => acc + oast.getInteractions(p.tokenId).length, 0);
        assert.ok(totalPerToken <= 12, `Expected global cap <= 12 across tokens, got ${totalPerToken}`);
      }
    );

    // 2. Token TTL expiration rejects stale callbacks with 403
    await withOastServer({ host: '127.0.0.1', port: 0, tokenTtlMs: 35 }, async oast => {
      const probe = oast.issueProbe({ checkId: 'xxe-injection', target: 'https://ttl.example' });
      assert.equal(oast.verifyToken(probe.tokenId, probe.hmacSig), true);
      await new Promise(resolve => setTimeout(resolve, 75));
      assert.equal(oast.verifyToken(probe.tokenId, probe.hmacSig), false);
      const expiredRes = await localHttpRequest(probe.callbackUrl, { method: 'GET' });
      assert.equal(expiredRes.status, 403);
      assert.equal(oast.getInteractions(probe.tokenId).length, 0);
    });
  });

  test('FINDING-8 & FINDING-9: GET /api/system/pc-audit enforces 429 concurrency lock, scaffold API blocks overwrite, and curated labs are protected', async () => {
    const tmpHistory = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-f89-srv-'));
    const tmpLabsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-f9-labs-'));
    const started = await startServer({
      port: 0,
      host: '127.0.0.1',
      inMemory: true,
      allowPrivate: true,
      historyDir: tmpHistory
    });

    try {
      // FINDING-8: parallel GET /api/system/pc-audit requests trigger 429 in-flight lock
      const parallelAudit = await Promise.all(
        Array.from({ length: 8 }, () => fetch(`${started.url}/api/system/pc-audit`))
      );
      const auditStatuses = parallelAudit.map(r => r.status);
      assert.ok(auditStatuses.includes(200), `Expected at least one 200, got ${auditStatuses}`);
      assert.ok(auditStatuses.includes(429), `Expected concurrent requests to receive 429, got ${auditStatuses}`);
      assert.ok(auditStatuses.every(s => s === 200 || s === 429));

      // Lock releases cleanly afterwards
      const afterAudit = await fetch(`${started.url}/api/system/pc-audit`);
      assert.equal(afterAudit.status, 200);

      // FINDING-9: HTTP scaffold API ignores overwrite:true and cannot overwrite curated labs
      const apiOverwriteRes = await fetch(`${started.url}/api/cves/labs/scaffold`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cveId: 'CVE-2025-29927', overwrite: true })
      });
      assert.equal(apiOverwriteRes.status, 409);

      // Direct scaffoldCveLab also refuses to overwrite curated CVE lab IDs even with overwrite:true
      const srcCuratedDir = path.join(REPO_ROOT, 'cve-labs', 'CVE-2025-29927');
      const dstCuratedDir = path.join(tmpLabsDir, 'CVE-2025-29927');
      fs.mkdirSync(dstCuratedDir, { recursive: true });
      fs.copyFileSync(path.join(srcCuratedDir, 'server.mjs'), path.join(dstCuratedDir, 'server.mjs'));
      const originalServerBytes = fs.readFileSync(path.join(dstCuratedDir, 'server.mjs'), 'utf8');

      assert.throws(
        () => scaffoldCveLab('CVE-2025-29927', { overwrite: true, labsDir: tmpLabsDir }),
        err => err instanceof CveLabError && err.statusCode === 409
      );
      assert.equal(fs.readFileSync(path.join(dstCuratedDir, 'server.mjs'), 'utf8'), originalServerBytes);

      // Field validation and length capping on custom scaffolded labs
      const capped = scaffoldCveLab('CVE-2024-99991', {
        labsDir: tmpLabsDir,
        title: 'T'.repeat(500),
        ecosystem: 'eco' + 'x'.repeat(80),
        profile: 'prof' + 'y'.repeat(80),
        cwe: 'cwe-79'
      });
      assert.equal(capped.manifest.title.length, 160);
      assert.equal(capped.manifest.ecosystem.length, 40);
      assert.equal(capped.manifest.profile.length, 40);
      assert.equal(capped.manifest.cwe, 'CWE-79');

      assert.throws(
        () => scaffoldCveLab('CVE-2024-99992', { labsDir: tmpLabsDir, cwe: 'INVALID-CWE' }),
        err => err instanceof CveLabError && err.statusCode === 400
      );
    } finally {
      started.server.closeAllConnections?.();
      await new Promise(resolve => started.server.close(resolve));
      fs.rmSync(tmpHistory, { recursive: true, force: true });
      fs.rmSync(tmpLabsDir, { recursive: true, force: true });
    }
  });
});
