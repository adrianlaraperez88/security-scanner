import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  OS_FAMILIES,
  parseOpenSshBanner,
  detectOperatingSystemFromSignals
} from '../../core/os-scanner.js';
import { fingerprint } from '../../core/fingerprint.js';

test('OS_FAMILIES: exports all 7 universal OS families', () => {
  assert.deepEqual(Object.keys(OS_FAMILIES), [
    'windows',
    'linux',
    'macos',
    'bsd',
    'mobile_tv_os',
    'network_appliance_os',
    'container_ai_os'
  ]);
  assert.equal(OS_FAMILIES.windows, 'Windows Server & Workstation');
  assert.equal(OS_FAMILIES.linux, 'Linux Distribution');
  assert.equal(OS_FAMILIES.macos, 'macOS / Apple Darwin / iOS / tvOS');
  assert.equal(OS_FAMILIES.bsd, 'BSD & Firewall OS (FreeBSD / OpenBSD / pfSense / OPNsense)');
  assert.equal(OS_FAMILIES.mobile_tv_os, 'Smart TV, Mobile & Embedded OS (Android / Tizen / webOS / Roku)');
  assert.equal(OS_FAMILIES.network_appliance_os, 'Network, Firewall, VPN & NAS Appliance OS');
  assert.equal(OS_FAMILIES.container_ai_os, 'Container, Cloud & AI Runtime OS Surface');
});

test('parseOpenSshBanner: parses OpenSSH versions and evaluates CVE-2024-6387 distro backports accurately', () => {
  assert.equal(parseOpenSshBanner(null), null);
  assert.equal(parseOpenSshBanner(''), null);
  assert.equal(parseOpenSshBanner('Apache/2.4.58 (Ubuntu)'), null);

  // Ubuntu 22.04 patched (3ubuntu0.10+) vs unpatched (3ubuntu0.6)
  const u22Patched = parseOpenSshBanner('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10');
  assert.equal(u22Patched.version, '8.9p1');
  assert.equal(u22Patched.baseVersion, '8.9');
  assert.equal(u22Patched.patchNum, 1);
  assert.equal(u22Patched.osFamily, 'linux');
  assert.equal(u22Patched.distro, 'Ubuntu');
  assert.equal(u22Patched.distroRelease, '22.04');
  assert.equal(u22Patched.isBackportPatchedFor6387, true);
  assert.equal(u22Patched.isFreeBsd, false);

  const u22PkgPatched = parseOpenSshBanner('OpenSSH_8.9p1 1:8.9p1-3ubuntu0.10');
  assert.equal(u22PkgPatched.isBackportPatchedFor6387, true);

  const u22Unpatched = parseOpenSshBanner('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6');
  assert.equal(u22Unpatched.version, '8.9p1');
  assert.equal(u22Unpatched.distro, 'Ubuntu');
  assert.equal(u22Unpatched.distroRelease, '22.04');
  assert.equal(u22Unpatched.isBackportPatchedFor6387, false);

  // Debian 12 patched (2+deb12u3+) vs unpatched (2+deb12u2)
  const deb12Patched = parseOpenSshBanner('SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3');
  assert.equal(deb12Patched.version, '9.2p1');
  assert.equal(deb12Patched.baseVersion, '9.2');
  assert.equal(deb12Patched.osFamily, 'linux');
  assert.equal(deb12Patched.distro, 'Debian');
  assert.equal(deb12Patched.distroRelease, '12');
  assert.equal(deb12Patched.isBackportPatchedFor6387, true);

  const deb12PkgPatched = parseOpenSshBanner('SSH-2.0-OpenSSH_9.2p1 1:9.2p1-2+deb12u4');
  assert.equal(deb12PkgPatched.isBackportPatchedFor6387, true);

  const deb12Unpatched = parseOpenSshBanner('SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2');
  assert.equal(deb12Unpatched.isBackportPatchedFor6387, false);

  // Ubuntu 24.04 patched (3ubuntu13.3+) vs unpatched (3ubuntu13.2)
  const u24Patched = parseOpenSshBanner('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3');
  assert.equal(u24Patched.version, '9.6p1');
  assert.equal(u24Patched.distro, 'Ubuntu');
  assert.equal(u24Patched.distroRelease, '24.04');
  assert.equal(u24Patched.isBackportPatchedFor6387, true);

  const u24Unpatched = parseOpenSshBanner('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.2');
  assert.equal(u24Unpatched.isBackportPatchedFor6387, false);

  // FreeBSD OpenSSH banner
  const fbsd = parseOpenSshBanner('SSH-2.0-OpenSSH_9.3p2 FreeBSD-20230719');
  assert.equal(fbsd.version, '9.3p2');
  assert.equal(fbsd.patchNum, 2);
  assert.equal(fbsd.osFamily, 'bsd');
  assert.equal(fbsd.distro, 'FreeBSD');
  assert.equal(fbsd.isFreeBsd, true);
  assert.equal(fbsd.isBackportPatchedFor6387, false);

  // Windows OpenSSH banner
  const winSsh = parseOpenSshBanner('SSH-2.0-OpenSSH_for_Windows_8.1');
  assert.equal(winSsh.version, '8.1');
  assert.equal(winSsh.patchNum, 0);
  assert.equal(winSsh.osFamily, 'windows');
  assert.equal(winSsh.distro, 'Windows');
});

test('detectOperatingSystemFromSignals: identifies Windows IIS versions, EOL status, and Windows OS ports', () => {
  const iisCases = [
    { header: 'Microsoft-IIS/6.0', osName: 'Windows Server 2003', isEol: true, eolDate: '2015-07-14' },
    { header: 'Microsoft-IIS/7.0', osName: 'Windows Server 2008', isEol: true, eolDate: '2020-01-14' },
    { header: 'Microsoft-IIS/7.5', osName: 'Windows Server 2008 R2 / Windows 7', isEol: true, eolDate: '2020-01-14' },
    { header: 'Microsoft-IIS/8.0', osName: 'Windows Server 2012', isEol: true, eolDate: '2023-10-10' },
    { header: 'Microsoft-IIS/8.5', osName: 'Windows Server 2012 R2', isEol: true, eolDate: '2023-10-10' },
    { header: 'Microsoft-IIS/10.0', osName: 'Windows Server 2016/2019/2022/2025 or Windows 10/11', isEol: false, eolDate: null }
  ];

  for (const tc of iisCases) {
    const res = detectOperatingSystemFromSignals({ headers: { Server: tc.header } });
    assert.equal(res.detected, true);
    assert.equal(res.family, 'windows');
    assert.equal(res.osName, tc.osName);
    assert.equal(res.isEol, tc.isEol);
    if (tc.eolDate) {
      assert.ok(res.eolReason.includes(tc.eolDate), `Expected ${res.eolReason} to include ${tc.eolDate}`);
    } else {
      assert.equal(res.eolReason, null);
    }
  }

  const winPorts = detectOperatingSystemFromSignals({
    headers: { Server: 'Microsoft-HTTPAPI/2.0' },
    openPorts: [135, 139, 445, 3389, 5985, 5986]
  });
  assert.equal(winPorts.family, 'windows');
  assert.equal(winPorts.exposedOsServices.length, 6);
  assert.ok(winPorts.exposedOsServices.some(s => s.port === 445 && s.service === 'smb'));
  assert.ok(winPorts.exposedOsServices.some(s => s.port === 3389 && s.service === 'rdp'));
});

test('detectOperatingSystemFromSignals: identifies Linux distributions, EOL releases, and Linux OS ports', () => {
  // Ubuntu 18.04 EOL vs 22.04 / 24.04 supported
  const u18 = detectOperatingSystemFromSignals({
    headers: { Server: 'Apache/2.4.29 (Ubuntu)', 'X-Powered-By': 'PHP/7.2.24-1ubuntu0.18.04' }
  });
  assert.equal(u18.family, 'linux');
  assert.equal(u18.osName, 'Ubuntu Linux');
  assert.equal(u18.version, '18.04');
  assert.equal(u18.isEol, true);

  const u22 = detectOperatingSystemFromSignals({
    sshBanner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10'
  });
  assert.equal(u22.family, 'linux');
  assert.equal(u22.osName, 'Ubuntu Linux');
  assert.equal(u22.version, '22.04');
  assert.equal(u22.isEol, false);
  assert.equal(u22.sshInfo.isBackportPatchedFor6387, true);

  const u24 = detectOperatingSystemFromSignals({
    headers: { Server: 'nginx/1.24.0 (Ubuntu) Ubuntu-4ubuntu0.1' }
  });
  assert.equal(u24.family, 'linux');
  assert.equal(u24.osName, 'Ubuntu Linux');
  assert.equal(u24.version, '24.04');
  assert.equal(u24.isEol, false);

  // Debian 9/10 EOL vs Debian 11/12 supported
  const deb9 = detectOperatingSystemFromSignals({
    sshBanner: 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7'
  });
  assert.equal(deb9.family, 'linux');
  assert.equal(deb9.osName, 'Debian Linux');
  assert.equal(deb9.version, '9');
  assert.equal(deb9.isEol, true);

  const deb10 = detectOperatingSystemFromSignals({
    headers: { 'X-Powered-By': 'PHP/7.3.31-1~deb10u1 (+deb10)' }
  });
  assert.equal(deb10.osName, 'Debian Linux');
  assert.equal(deb10.version, '10');
  assert.equal(deb10.isEol, true);

  const deb12 = detectOperatingSystemFromSignals({
    sshBanner: 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3'
  });
  assert.equal(deb12.osName, 'Debian Linux');
  assert.equal(deb12.version, '12');
  assert.equal(deb12.isEol, false);

  // CentOS 7 / el7 EOL, RHEL, AlmaLinux, Rocky, Alpine, SUSE, Arch
  const centos7 = detectOperatingSystemFromSignals({
    headers: { Server: 'Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips el7' }
  });
  assert.equal(centos7.family, 'linux');
  assert.equal(centos7.osName, 'CentOS Linux');
  assert.equal(centos7.isEol, true);

  assert.equal(detectOperatingSystemFromSignals({ headers: { Server: 'Apache/2.4.57 (Red Hat Enterprise Linux)' } }).osName, 'Red Hat Enterprise Linux');
  assert.equal(detectOperatingSystemFromSignals({ headers: { Server: 'Apache/2.4.57 (AlmaLinux)' } }).osName, 'AlmaLinux');
  assert.equal(detectOperatingSystemFromSignals({ headers: { Server: 'Apache/2.4.57 (Rocky Linux)' } }).osName, 'Rocky Linux');
  assert.equal(detectOperatingSystemFromSignals({ headers: { Server: 'nginx/1.24.0 (Alpine)' } }).osName, 'Alpine Linux');
  assert.equal(detectOperatingSystemFromSignals({ headers: { Server: 'Apache/2.4.51 (SUSE)' } }).osName, 'SUSE Linux');
  assert.equal(detectOperatingSystemFromSignals({ headers: { Server: 'Apache/2.4.58 (Arch)' } }).osName, 'Arch Linux');

  // Linux ports (631 CUPS, 9090 Cockpit, 2375 Docker)
  const linuxPorts = detectOperatingSystemFromSignals({ openPorts: [631, 9090, 2375] });
  assert.equal(linuxPorts.family, 'linux');
  assert.ok(linuxPorts.exposedOsServices.some(s => s.port === 631 && s.service === 'cups-ipp'));
  assert.ok(linuxPorts.exposedOsServices.some(s => s.port === 9090 && s.service === 'cockpit'));
});

test('detectOperatingSystemFromSignals: identifies macOS / Apple Darwin and BSD / Firewall OS families', () => {
  // macOS Darwin EOL (18..21) vs supported (23+)
  for (const ver of ['18.7.0', '19.6.0', '20.6.0', '21.6.0']) {
    const macEol = detectOperatingSystemFromSignals({
      headers: { Server: `Apache/2.4.34 (Unix) Darwin/${ver}` }
    });
    assert.equal(macEol.family, 'macos');
    assert.equal(macEol.osName, 'macOS / Apple Darwin');
    assert.equal(macEol.isEol, true);
  }

  const macSupported = detectOperatingSystemFromSignals({
    headers: { Server: 'Darwin/23.4.0' },
    openPorts: [548, 5000, 7000]
  });
  assert.equal(macSupported.family, 'macos');
  assert.equal(macSupported.isEol, false);
  assert.ok(macSupported.exposedOsServices.some(s => s.port === 548 && s.service === 'afp'));
  assert.ok(macSupported.exposedOsServices.some(s => s.port === 7000 && s.service === 'airplay'));

  // BSD & Firewall OS
  const fbsd12 = detectOperatingSystemFromSignals({ headers: { Server: 'Apache/2.4.54 (FreeBSD 12.4)' } });
  assert.equal(fbsd12.family, 'bsd');
  assert.equal(fbsd12.osName, 'FreeBSD');
  assert.equal(fbsd12.isEol, true);

  const fbsd14 = detectOperatingSystemFromSignals({ headers: { Server: 'nginx/1.24.0 (FreeBSD 14.0)' } });
  assert.equal(fbsd14.family, 'bsd');
  assert.equal(fbsd14.osName, 'FreeBSD');
  assert.equal(fbsd14.isEol, false);

  assert.equal(detectOperatingSystemFromSignals({ headers: { Server: 'OpenBSD httpd' } }).osName, 'OpenBSD');
  assert.equal(detectOperatingSystemFromSignals({ headers: { Server: 'bozohttpd (NetBSD)' } }).osName, 'NetBSD');
  assert.equal(detectOperatingSystemFromSignals({ html: '<title>pfSense - Login</title>' }).osName, 'pfSense');
  assert.equal(detectOperatingSystemFromSignals({ html: '<title>Login | OPNsense</title>' }).osName, 'OPNsense');
});

test('detectOperatingSystemFromSignals: identifies Network Appliance, Mobile/Smart TV, and Container/AI Runtime OS families', () => {
  // Network Appliances
  assert.equal(
    detectOperatingSystemFromSignals({
      headers: { Server: 'xxxxxxxx-xxxxx', 'Set-Cookie': 'SVPNCOOKIE=123' },
      html: '<form action="/remote/login">'
    }).osName,
    'Fortinet FortiOS'
  );
  assert.equal(
    detectOperatingSystemFromSignals({ html: '<form action="/global-protect/login.esp">GlobalProtect</form>' }).osName,
    'Palo Alto PAN-OS'
  );
  assert.equal(
    detectOperatingSystemFromSignals({
      headers: { 'Set-Cookie': 'DSID=abc' },
      html: '<a href="/dana-na/auth/url_default/welcome.cgi">Ivanti Connect Secure</a>'
    }).osName,
    'Ivanti Connect Secure'
  );
  assert.equal(
    detectOperatingSystemFromSignals({
      headers: { 'Set-Cookie': 'NSC_AAAC=xyz' },
      html: '<div id="LogonPoint"><a href="/logon/LogonPoint/index.html">Citrix Gateway</a></div>'
    }).osName,
    'Citrix NetScaler ADC'
  );
  assert.equal(
    detectOperatingSystemFromSignals({ headers: { Server: 'cisco-IOS' }, html: '/webui/' }).osName,
    'Cisco IOS XE'
  );
  assert.equal(
    detectOperatingSystemFromSignals({ html: '<title>RouterOS router configuration page - WebFig</title>' }).osName,
    'MikroTik RouterOS'
  );
  assert.equal(
    detectOperatingSystemFromSignals({ html: 'webapi/query.cgi?api=SYNO.API.Info Synology' }).osName,
    'Synology DSM'
  );
  assert.equal(
    detectOperatingSystemFromSignals({ html: '<script src="/cgi-bin/authLogin.cgi"></script><title>QNAP QTS</title>' }).osName,
    'QNAP QTS'
  );
  assert.equal(
    detectOperatingSystemFromSignals({ html: '<a href="/cgi-bin/luci">LuCI - Lua Configuration Interface (OpenWrt)</a>' }).osName,
    'OpenWrt'
  );
  assert.equal(
    detectOperatingSystemFromSignals({ html: '<title>UniFi OS - UniFi Network</title>' }).osName,
    'Ubiquiti UniFi'
  );

  // Mobile & Smart TV OS
  const tizen = detectOperatingSystemFromSignals({ openPorts: [8001, 8002], html: '{"OS":"Tizen"}' });
  assert.equal(tizen.family, 'mobile_tv_os');
  assert.equal(tizen.osName, 'Samsung Tizen OS');

  const webos = detectOperatingSystemFromSignals({ openPorts: [3000, 3001], headers: { Server: 'WebOS/6.0' } });
  assert.equal(webos.family, 'mobile_tv_os');
  assert.equal(webos.osName, 'LG webOS');

  const android = detectOperatingSystemFromSignals({ openPorts: [5555, 8008], html: '{"cast_build_revision":"1.68"}' });
  assert.equal(android.family, 'mobile_tv_os');
  assert.equal(android.osName, 'Android / Android TV');

  const roku = detectOperatingSystemFromSignals({ openPorts: [8060], html: '<vendor-name>Roku</vendor-name>' });
  assert.equal(roku.family, 'mobile_tv_os');
  assert.equal(roku.osName, 'Roku OS');

  // Container & AI Runtime OS Surfaces
  const ollama = detectOperatingSystemFromSignals({ openPorts: [11434], html: 'Ollama is running' });
  assert.equal(ollama.family, 'container_ai_os');
  assert.equal(ollama.osName, 'Ollama AI Runtime');

  const ray = detectOperatingSystemFromSignals({ openPorts: [8265], html: '<title>Ray Dashboard</title>' });
  assert.equal(ray.family, 'container_ai_os');
  assert.equal(ray.osName, 'Ray Cluster Runtime');

  const docker = detectOperatingSystemFromSignals({ headers: { Server: 'Docker/24.0.7 (linux)' }, openPorts: [2375] });
  assert.equal(docker.family, 'container_ai_os');
  assert.equal(docker.osName, 'Docker Engine');
  assert.equal(docker.version, '24.0.7');

  const k8s = detectOperatingSystemFromSignals({ openPorts: [6443, 10250] });
  assert.equal(k8s.family, 'container_ai_os');
  assert.equal(k8s.osName, 'Kubernetes Cluster Runtime');

  // Generic HTML / 404 returns detected: false
  const generic = detectOperatingSystemFromSignals({
    headers: { Server: 'nginx', 'Content-Type': 'text/html' },
    html: '<html><body><h1>404 Not Found</h1><p>Open the windows and let a ray of sunshine in.</p></body></html>'
  });
  assert.equal(generic.detected, false);
  assert.equal(generic.family, null);
  assert.equal(generic.confidence, 'none');

  // Null / primitive inputs return safe detected: false object without throwing
  const nullRes = detectOperatingSystemFromSignals(null);
  assert.equal(nullRes.detected, false);
  assert.equal(nullRes.family, null);
  assert.equal(nullRes.confidence, 'none');
  assert.deepEqual(nullRes.exposedOsServices, []);
});

test('fingerprint: attaches osInfo for HTTP and device-only targets while preserving backward compatibility', async () => {
  const iisFp = await fingerprint('https://win.example.com', async () => ({
    status: 200,
    headers: {
      server: 'Microsoft-IIS/8.5',
      'x-powered-by': 'ASP.NET'
    },
    text: '<html><body>ASP.NET App</body></html>'
  }), { deepProbe: false, apiDiscovery: false });

  assert.equal(iisFp.primary, 'aspnet');
  assert.ok(iisFp.osInfo);
  assert.equal(iisFp.osInfo.detected, true);
  assert.equal(iisFp.osInfo.family, 'windows');
  assert.equal(iisFp.osInfo.osName, 'Windows Server 2012 R2');
  assert.equal(iisFp.osInfo.isEol, true);
});
