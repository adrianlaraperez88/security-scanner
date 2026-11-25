import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchMap, mockFetchError } from '../helpers/mock-fetch.js';
import runOsSecurity, { meta, tags } from '../../checks/os-security.js';

const BASE = 'https://example.com';

test('os-security: exports expected tags and all 22 CVE IDs in meta', () => {
  assert.equal(meta.id, 'os-security');
  assert.equal(meta.title, 'Universal Operating System, Edge Appliance & Market CVE Security Audit');
  assert.equal(meta.category, 'Known Vulnerabilities');
  for (const expectedTag of ['all', 'os', 'windows', 'linux', 'macos', 'bsd', 'device', 'iot', 'server']) {
    assert.ok(tags.includes(expectedTag), `Missing tag ${expectedTag}`);
  }
  assert.equal(meta.cveIds.length, 22);
  const expectedCves = [
    'CVE-2024-6387',
    'CVE-2025-26465',
    'CVE-2025-26466',
    'CVE-2024-7589',
    'CVE-2024-47176',
    'CVE-2024-38063',
    'CVE-2024-38077',
    'CVE-2022-21907',
    'CVE-2020-0796',
    'CVE-2025-24252',
    'CVE-2024-3400',
    'CVE-2024-0012',
    'CVE-2024-21762',
    'CVE-2024-55591',
    'CVE-2024-21887',
    'CVE-2025-0282',
    'CVE-2023-4966',
    'CVE-2023-20198',
    'CVE-2023-30799',
    'CVE-2024-27130',
    'CVE-2024-37032',
    'CVE-2023-48022'
  ];
  assert.deepEqual(meta.cveIds, expectedCves);
});

test('os-security: returns SAFE on generic HTML/404 pages, modern IIS 10.0, and patched OS/daemons without probing /api/version', async () => {
  let fetchCount = 0;
  const genericRes = await runOsSecurity(BASE, async () => {
    fetchCount += 1;
    return {
      status: 200,
      headers: { server: 'nginx', 'content-type': 'text/html' },
      text: '<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Home</h1></body></html>'
    };
  });
  assert.equal(genericRes.status, 'SAFE');
  assert.equal(genericRes.severity, 'NONE');
  assert.equal(fetchCount, 1, 'Must only make 1 root request on normal web targets');
  assert.ok(genericRes.osInfo);

  // Generic 404 page
  const notFoundRes = await runOsSecurity(BASE, mockFetch({
    status: 404,
    headers: { 'content-type': 'text/html' },
    text: '<html><body>404 Not Found</body></html>'
  }));
  assert.equal(notFoundRes.status, 'SAFE');

  // Modern IIS 10.0 without EOL or vulnerable build
  const modernIis = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'Microsoft-IIS/10.0' },
    text: '<html><body>Modern Windows Server</body></html>'
  }));
  assert.equal(modernIis.status, 'SAFE');
  assert.equal(modernIis.osInfo.family, 'windows');
  assert.equal(modernIis.osInfo.isEol, false);

  // Patched OpenSSH 9.9p2 on Ubuntu 24.04
  const patchedSsh = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { 'X-SSH-Banner': 'SSH-2.0-OpenSSH_9.9p2 Ubuntu-4ubuntu0.1' },
    text: 'OK'
  }));
  assert.equal(patchedSsh.status, 'SAFE');
});

test('os-security: returns ERROR on unreachable target or SSRF governance block, but evaluates cachedDeviceScan when HTTP port is closed', async () => {
  const errRes = await runOsSecurity(BASE, mockFetchError('connect ECONNREFUSED'));
  assert.equal(errRes.status, 'ERROR');

  const govRes = await runOsSecurity(BASE, async () => {
    const err = new Error('Request blocked by SSRF policy');
    err.code = 'SSRF_POLICY_BLOCKED';
    throw err;
  });
  assert.equal(govRes.status, 'ERROR');
  assert.match(govRes.reason, /SSRF policy/);

  // When HTTP root fetch fails (ECONNREFUSED) but cachedDeviceScan has port 22 SSH banner
  const deviceOnlyRes = await runOsSecurity('http://192.168.1.50', mockFetchError('connect ECONNREFUSED'), {
    cachedDeviceScan: {
      noActiveHttpService: true,
      openPorts: [22],
      openServices: [{ port: 22, service: 'ssh', banner: 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2' }]
    }
  });
  assert.equal(deviceOnlyRes.status, 'VULNERABLE');
  assert.equal(deviceOnlyRes.severity, 'CRITICAL');
  assert.ok(deviceOnlyRes.cveIds.includes('CVE-2024-6387'));

  // When cachedDeviceScan has basePortClosed: true and no activeHttpOrigin/activeHttpsOrigin, HTTP root port is skipped (fetchCount === 0)
  let fetchCount = 0;
  const closedBasePortRes = await runOsSecurity(
    'http://192.168.1.60',
    async () => {
      fetchCount++;
      throw new Error('connect ECONNREFUSED');
    },
    {
      cachedDeviceScan: {
        deviceProfile: {
          detected: true,
          basePortClosed: true,
          activeHttpOrigin: null,
          activeHttpsOrigin: null,
          openPorts: [554]
        },
        openPorts: [554]
      }
    }
  );
  assert.equal(fetchCount, 0, 'Closed HTTP root port must not be fetched when basePortClosedWithoutHttp is true');
  assert.equal(closedBasePortRes.status, 'SAFE');
});

test('os-security: Check 1 detects End-of-Life (EOL) Windows, Linux, macOS, and FreeBSD operating systems', async () => {
  // Windows Server 2012 R2 (Microsoft-IIS/8.5) -> EOL + CVE-2022-21907
  const winEol = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'Microsoft-IIS/8.5' },
    text: '<html>IIS 8.5</html>'
  }));
  assert.equal(winEol.status, 'VULNERABLE');
  assert.ok(winEol.osInfo.isEol);
  assert.ok(winEol.findings.some(f => f.cwe === 'CWE-1104' && f.detail.includes('Windows Server 2012 R2')));
  assert.ok(winEol.evidenceQuotes.includes('Server: Microsoft-IIS/8.5'));

  // Ubuntu 18.04 LTS EOL
  const ubuntuEol = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'Apache/2.4.29 (Ubuntu)' },
    text: '<html>Ubuntu 18.04</html>'
  }));
  assert.equal(ubuntuEol.status, 'VULNERABLE');
  assert.equal(ubuntuEol.severity, 'HIGH');
  assert.equal(ubuntuEol.cwe, 'CWE-1104');
  assert.ok(ubuntuEol.detail.includes('Ubuntu 18.04 LTS has reached End-of-Standard-Support'));
  assert.ok(ubuntuEol.evidenceQuotes.includes('Server: Apache/2.4.29 (Ubuntu)'));

  // CentOS 7 EOL
  const centosEol = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'Apache/2.4.6 (CentOS) el7' },
    text: '<html>CentOS 7</html>'
  }));
  assert.equal(centosEol.status, 'VULNERABLE');
  assert.equal(centosEol.cwe, 'CWE-1104');

  // macOS Darwin/20.6.0 (Big Sur) EOL
  const macEol = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'Darwin/20.6.0' },
    text: '<html>macOS</html>'
  }));
  assert.equal(macEol.status, 'VULNERABLE');
  assert.equal(macEol.cwe, 'CWE-1104');
  assert.ok(macEol.detail.includes('Big Sur'));

  // FreeBSD 12.4 EOL
  const fbsdEol = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'nginx/1.22.0 (FreeBSD 12.4)' },
    text: '<html>FreeBSD</html>'
  }));
  assert.equal(fbsdEol.status, 'VULNERABLE');
  assert.equal(fbsdEol.cwe, 'CWE-1104');
  assert.ok(fbsdEol.detail.includes('FreeBSD 12'));
});

test('os-security: Check 2 audits OpenSSH CVEs (CVE-2024-6387, CVE-2024-7589, CVE-2025-26465, CVE-2025-26466) with distro backport awareness', async () => {
  // 1. Unpatched Ubuntu 22.04 OpenSSH 8.9p1 (3ubuntu0.6) -> vulnerable to CVE-2024-6387 and CVE-2025-26465
  const unpatchedU22 = await runOsSecurity(BASE, mockFetch({ status: 200, text: 'OK' }), {
    sshBanner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6'
  });
  assert.equal(unpatchedU22.status, 'VULNERABLE');
  assert.equal(unpatchedU22.severity, 'CRITICAL');
  assert.ok(unpatchedU22.cveIds.includes('CVE-2024-6387'));
  assert.ok(unpatchedU22.cveIds.includes('CVE-2025-26465'));
  assert.ok(!unpatchedU22.cveIds.includes('CVE-2025-26466')); // 8.9p1 < 9.5p1

  // 2. Backport-patched Ubuntu 22.04 OpenSSH 8.9p1 (3ubuntu0.10) -> NOT vulnerable to CVE-2024-6387
  const patchedU22 = await runOsSecurity(BASE, mockFetch({ status: 200, text: 'OK' }), {
    sshBanner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10'
  });
  assert.ok(!patchedU22.cveIds.includes('CVE-2024-6387'), 'Ubuntu 3ubuntu0.10 backport must not trigger CVE-2024-6387');

  // 3. FreeBSD OpenSSH 9.6p1 unpatched -> CVE-2024-6387, CVE-2024-7589, CVE-2025-26465, CVE-2025-26466
  const fbsdSsh = await runOsSecurity(BASE, mockFetch({ status: 200, text: 'OK' }), {
    sshBanner: 'SSH-2.0-OpenSSH_9.6p1 FreeBSD-20230719'
  });
  assert.equal(fbsdSsh.status, 'VULNERABLE');
  assert.equal(fbsdSsh.severity, 'CRITICAL');
  assert.ok(fbsdSsh.cveIds.includes('CVE-2024-6387'));
  assert.ok(fbsdSsh.cveIds.includes('CVE-2024-7589'));
  assert.ok(fbsdSsh.cveIds.includes('CVE-2025-26465'));
  assert.ok(fbsdSsh.cveIds.includes('CVE-2025-26466'));
});

test('os-security: Check 3 detects Linux/Unix CUPS (CVE-2024-47176) and Apple AirPlay AirBorne (CVE-2025-24252)', async () => {
  // Vulnerable CUPS/2.4.7 header
  const cupsVuln = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'CUPS/2.4.7 IPP/2.1' },
    text: '<html>CUPS</html>'
  }));
  assert.equal(cupsVuln.status, 'VULNERABLE');
  assert.equal(cupsVuln.severity, 'HIGH');
  assert.ok(cupsVuln.cveIds.includes('CVE-2024-47176'));
  assert.ok(cupsVuln.evidenceQuotes.includes('Server: CUPS/2.4.7 IPP/2.1'));

  // Exposed port 631 without version -> SUSPICIOUS
  const cupsPortOnly = await runOsSecurity(BASE, mockFetch({ status: 200, text: 'OK' }), {
    cachedDeviceScan: { openPorts: [631] }
  });
  assert.equal(cupsPortOnly.status, 'SUSPICIOUS');
  assert.ok(cupsPortOnly.cveIds.includes('CVE-2024-47176'));

  // Vulnerable Apple AirTunes/366.0 -> CVE-2025-24252
  const airPlayVuln = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'AirTunes/366.0' },
    text: 'AirPlay Receiver'
  }));
  assert.equal(airPlayVuln.status, 'VULNERABLE');
  assert.equal(airPlayVuln.severity, 'CRITICAL');
  assert.ok(airPlayVuln.cveIds.includes('CVE-2025-24252'));
  assert.ok(airPlayVuln.evidenceQuotes.includes('Server: AirTunes/366.0'));
});

test('os-security: Check 4 detects Windows HTTP.sys (CVE-2022-21907), TCP/IP IPv6 (CVE-2024-38063), RDP MadLicense (CVE-2024-38077), and SMBGhost (CVE-2020-0796)', async () => {
  // Disclosed vulnerable Windows build with SMB 445 and RDP 3389 open
  const winVuln = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: {
      Server: 'Microsoft-IIS/10.0',
      'X-Windows-Build': '10.0.18362.500'
    },
    text: 'Windows Server'
  }), {
    cachedDeviceScan: {
      openPorts: [445, 3389]
    }
  });
  assert.equal(winVuln.status, 'VULNERABLE');
  assert.equal(winVuln.severity, 'CRITICAL');
  assert.ok(winVuln.cveIds.includes('CVE-2022-21907'));
  assert.ok(winVuln.cveIds.includes('CVE-2024-38063'));
  assert.ok(winVuln.cveIds.includes('CVE-2020-0796'));
  assert.ok(winVuln.cveIds.includes('CVE-2024-38077'));

  // Exposed SMB 445 & RDP 3389 without build version -> SUSPICIOUS
  const winPortsOnly = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'Microsoft-HTTPAPI/2.0' },
    text: 'OK'
  }), {
    cachedDeviceScan: {
      openPorts: [445, 3389]
    }
  });
  assert.equal(winPortsOnly.status, 'SUSPICIOUS');
  assert.ok(winPortsOnly.cveIds.includes('CVE-2024-38063'));
  assert.ok(winPortsOnly.cveIds.includes('CVE-2020-0796'));
  assert.ok(winPortsOnly.cveIds.includes('CVE-2024-38077'));
});

test('os-security: Check 5 detects PAN-OS, FortiOS, Ivanti, Citrix NetScaler, Cisco IOS XE, MikroTik RouterOS, and QNAP QTS CVEs', async () => {
  // 1. Palo Alto PAN-OS GlobalProtect 11.1.1 -> CVE-2024-3400 & CVE-2024-0012
  const panRes = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'PAN-OS/11.1.1' },
    text: '<form action="/global-protect/login.esp">GlobalProtect Portal PAN-OS 11.1.1</form>'
  }));
  assert.equal(panRes.status, 'VULNERABLE');
  assert.equal(panRes.severity, 'CRITICAL');
  assert.ok(panRes.cveIds.includes('CVE-2024-3400'));
  assert.ok(panRes.cveIds.includes('CVE-2024-0012'));

  // 2. Fortinet FortiOS 7.2.6 -> CVE-2024-21762 & CVE-2024-55591
  const fortiRes = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'xxxxxxxx-xxxxx', 'Set-Cookie': 'SVPNCOOKIE=1' },
    text: '<form action="/remote/login">FortiOS v7.2.6</form>'
  }));
  assert.equal(fortiRes.status, 'VULNERABLE');
  assert.ok(fortiRes.cveIds.includes('CVE-2024-21762'));
  assert.ok(fortiRes.cveIds.includes('CVE-2024-55591'));

  // 3. Ivanti Connect Secure 22.7R2.3 -> CVE-2024-21887 & CVE-2025-0282
  const ivantiRes = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { 'Set-Cookie': 'DSID=abc12345' },
    text: '<a href="/dana-na/auth/url_default/welcome.cgi">Ivanti Connect Secure 22.7R2.3</a>'
  }));
  assert.equal(ivantiRes.status, 'VULNERABLE');
  assert.ok(ivantiRes.cveIds.includes('CVE-2024-21887'));
  assert.ok(ivantiRes.cveIds.includes('CVE-2025-0282'));

  // 4. Citrix NetScaler 14.1-8.42 -> CVE-2023-4966
  const citrixRes = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { 'Set-Cookie': 'NSC_AAAC=12345678' },
    text: '<div id="LogonPoint"><a href="/logon/LogonPoint/index.html">Citrix ADC NS14.1-8.42</a></div>'
  }));
  assert.equal(citrixRes.status, 'VULNERABLE');
  assert.ok(citrixRes.cveIds.includes('CVE-2023-4966'));

  // 5. Cisco IOS XE 17.9.3 -> CVE-2023-20198
  const ciscoRes = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'cisco-IOS' },
    text: '<html><a href="/webui/">Cisco IOS XE 17.9.3</a></html>'
  }));
  assert.equal(ciscoRes.status, 'VULNERABLE');
  assert.ok(ciscoRes.cveIds.includes('CVE-2023-20198'));

  // 6. MikroTik RouterOS 6.49.7 -> CVE-2023-30799
  const mikrotikRes = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'MikroTik' },
    text: '<title>RouterOS v6.49.7 - WebFig</title>'
  }));
  assert.equal(mikrotikRes.status, 'VULNERABLE');
  assert.ok(mikrotikRes.cveIds.includes('CVE-2023-30799'));

  // 7. QNAP QTS 5.1.6.2722 -> CVE-2024-27130
  const qnapRes = await runOsSecurity(BASE, mockFetch({
    status: 200,
    headers: { Server: 'http server 1.0' },
    text: '<script src="/cgi-bin/authLogin.cgi"></script><title>QNAP QTS 5.1.6.2722</title>'
  }));
  assert.equal(qnapRes.status, 'VULNERABLE');
  assert.ok(qnapRes.cveIds.includes('CVE-2024-27130'));
});

test('os-security: Check 6 detects Ollama Probllama (CVE-2024-37032) and Anyscale Ray ShadowRay (CVE-2023-48022) via /api/version', async () => {
  // 1. Ollama < 0.1.34 via /api/version
  const ollamaVuln = await runOsSecurity('http://127.0.0.1:11434', mockFetchMap({
    '/api/version': {
      status: 200,
      headers: { 'content-type': 'application/json' },
      text: '{"version":"0.1.33"}'
    },
    '/': {
      status: 200,
      headers: { 'content-type': 'text/plain' },
      text: 'Ollama is running'
    }
  }));
  assert.equal(ollamaVuln.status, 'VULNERABLE');
  assert.equal(ollamaVuln.severity, 'CRITICAL');
  assert.equal(ollamaVuln.cvssScore, 9.1);
  assert.ok(ollamaVuln.cveIds.includes('CVE-2024-37032'));
  assert.equal(ollamaVuln.path, '/api/version');
  assert.ok(ollamaVuln.evidenceQuotes.some(q => q.includes('"version":"0.1.33"')));

  // Patched Ollama >= 0.1.34 returns SAFE
  const ollamaPatched = await runOsSecurity('http://127.0.0.1:11434', mockFetchMap({
    '/api/version': {
      status: 200,
      headers: { 'content-type': 'application/json' },
      text: '{"version":"0.3.12"}'
    },
    '/': {
      status: 200,
      headers: { 'content-type': 'text/plain' },
      text: 'Ollama is running'
    }
  }));
  assert.equal(ollamaPatched.status, 'SAFE');

  // 2. Anyscale Ray < 2.8.1 via /api/version
  const rayVuln = await runOsSecurity('http://127.0.0.1:8265', mockFetchMap({
    '/api/version': {
      status: 200,
      headers: { 'content-type': 'application/json' },
      text: '{"ray_version":"2.7.1","version":"2.7.1"}'
    },
    '/': {
      status: 200,
      headers: { 'content-type': 'text/html' },
      text: '<html><head><title>Ray Dashboard</title></head></html>'
    }
  }));
  assert.equal(rayVuln.status, 'VULNERABLE');
  assert.equal(rayVuln.severity, 'CRITICAL');
  assert.equal(rayVuln.cvssScore, 9.8);
  assert.ok(rayVuln.cveIds.includes('CVE-2023-48022'));
  assert.equal(rayVuln.path, '/api/version');
});
