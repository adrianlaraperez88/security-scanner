/**
 * Local & Host PC Deep Security Auditor (`core/pc-local-auditor.js`).
 *
 * Audits local host security posture with zero shell execution (`execFile`, `shell: false`)
 * and a strict frozen binary allowlist (`ALLOWED_LOCAL_BINARIES`):
 *  1. Wildcard High-Risk Listening Ports (SMB, RDP, WinRM, Docker TCP, ADB, Redis, Ollama, Telnet, VNC)
 *  2. Host Firewall Posture (Windows AdvFirewall/NetFirewallProfile, Linux UFW, macOS Application Firewall)
 *  3. Endpoint Protection / Real-Time Malware Defense (Windows Defender, Linux AppArmor/SELinux/ClamAV, macOS)
 *  4. Unquoted Windows Service Paths (`CWE-428`) outside `System32` / `SysWOW64`
 */

import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { classifyFindingConfidence } from './fp-engine.js';

const MAX_OUTPUT_CHARS = 262144;
const MAX_LINE_CHARS = 2048;
const EXEC_TIMEOUT_MS = 4000;
const EXEC_MAX_BUFFER = 512 * 1024;
const OWASP_A05 = 'A05:2021-Security Misconfiguration';

/**
 * Frozen allowlist of permitted local inspection binaries.
 * Commands outside this set are rejected prior to process creation.
 */
const ALLOWED_BINARY_LIST = [
  'netstat',
  'powershell',
  'pwsh',
  'ss',
  'lsof',
  'ufw',
  'dpkg-query',
  'rpm',
  'apk',
  'uname'
];

const INTERNAL_ALLOWED_BINARIES = new Set(ALLOWED_BINARY_LIST);

const EXPORTED_ALLOWED_SET = new Set(ALLOWED_BINARY_LIST);
for (const mutator of ['add', 'delete', 'clear']) {
  Object.defineProperty(EXPORTED_ALLOWED_SET, mutator, {
    value() {
      throw new TypeError('ALLOWED_LOCAL_BINARIES is immutable');
    },
    enumerable: false,
    writable: false,
    configurable: false
  });
}

export const ALLOWED_LOCAL_BINARIES = Object.freeze(EXPORTED_ALLOWED_SET);

const PORT_DEFINITIONS = {
  23: Object.freeze({
    port: 23,
    service: 'Telnet',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    cwe: 'CWE-319',
    description: 'Unencrypted Telnet remote login exposed on all network interfaces'
  }),
  445: Object.freeze({
    port: 445,
    service: 'SMB',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    cwe: 'CWE-284',
    description: 'SMB file/RPC sharing exposed on wildcard network interface'
  }),
  2375: Object.freeze({
    port: 2375,
    service: 'Docker Daemon TCP',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    cwe: 'CWE-306',
    description: 'Unauthenticated Docker Engine TCP API exposed on wildcard interface'
  }),
  3389: Object.freeze({
    port: 3389,
    service: 'RDP',
    severity: 'HIGH',
    cvssScore: 8.6,
    cwe: 'CWE-284',
    description: 'Remote Desktop Protocol (RDP) exposed on wildcard interface'
  }),
  5555: Object.freeze({
    port: 5555,
    service: 'Android ADB',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    cwe: 'CWE-306',
    description: 'Android Debug Bridge (ADB) daemon exposed on wildcard interface'
  }),
  5900: Object.freeze({
    port: 5900,
    service: 'VNC',
    severity: 'HIGH',
    cvssScore: 8.6,
    cwe: 'CWE-284',
    description: 'VNC remote desktop server exposed on wildcard interface'
  }),
  5985: Object.freeze({
    port: 5985,
    service: 'WinRM HTTP',
    severity: 'HIGH',
    cvssScore: 8.2,
    cwe: 'CWE-284',
    description: 'Windows Remote Management (WinRM HTTP) exposed on wildcard interface'
  }),
  6379: Object.freeze({
    port: 6379,
    service: 'Redis',
    severity: 'CRITICAL',
    cvssScore: 9.4,
    cwe: 'CWE-306',
    description: 'Redis in-memory datastore exposed on wildcard interface'
  }),
  11434: Object.freeze({
    port: 11434,
    service: 'Ollama LLM API',
    severity: 'HIGH',
    cvssScore: 8.2,
    cwe: 'CWE-306',
    description: 'Ollama local LLM API exposed on wildcard interface without authentication'
  })
};

Object.defineProperties(PORT_DEFINITIONS, {
  get: {
    value(port) {
      const key = Number(port);
      return Number.isInteger(key) && Object.prototype.hasOwnProperty.call(PORT_DEFINITIONS, key)
        ? PORT_DEFINITIONS[key]
        : undefined;
    },
    enumerable: false,
    writable: false,
    configurable: false
  },
  has: {
    value(port) {
      const key = Number(port);
      return Number.isInteger(key) && Object.prototype.hasOwnProperty.call(PORT_DEFINITIONS, key);
    },
    enumerable: false,
    writable: false,
    configurable: false
  }
});

/**
 * Frozen catalog of high-risk TCP services when bound to `0.0.0.0`, `::`, or `*`.
 * Supports both plain object indexing (`HIGH_RISK_WILDCARD_PORTS[445]`) and `.get(445)` / `.has(445)`.
 */
export const HIGH_RISK_WILDCARD_PORTS = Object.freeze(PORT_DEFINITIONS);

/**
 * Validates that a binary name is strictly in `ALLOWED_LOCAL_BINARIES` with no path separators.
 *
 * @param {string} binary
 * @param {string[]} [args=[]]
 */
export function assertAllowedLocalBinary(binary, args = []) {
  if (typeof binary !== 'string' || !binary.trim()) {
    const err = new Error('Local audit binary must be a non-empty string');
    err.code = 'DISALLOWED_LOCAL_BINARY';
    throw err;
  }
  const normalized = binary.trim();
  if (
    normalized.includes('/') ||
    normalized.includes('\\') ||
    normalized.includes('..') ||
    normalized.includes('\0') ||
    !INTERNAL_ALLOWED_BINARIES.has(normalized)
  ) {
    const err = new Error(`Command "${normalized}" is not permitted by ALLOWED_LOCAL_BINARIES`);
    err.code = 'DISALLOWED_LOCAL_BINARY';
    throw err;
  }
  if (!Array.isArray(args)) {
    const err = new Error('Command arguments must be an array of strings');
    err.code = 'INVALID_COMMAND_ARGS';
    throw err;
  }
  for (const arg of args) {
    if (typeof arg !== 'string' || arg.includes('\0') || arg.length > 4096) {
      const err = new Error('Invalid or unsafe command argument');
      err.code = 'INVALID_COMMAND_ARGS';
      throw err;
    }
  }
  return normalized;
}

const TRUSTED_UNIX_BINARY_DIRS = Object.freeze(['/usr/bin', '/bin', '/usr/sbin', '/sbin']);

/**
 * Resolves an allowlisted binary name to an absolute trusted OS path so `execFile`
 * never searches the current working directory (`CWE-427`).
 *
 * @param {string} binary
 * @param {string} [platform=process.platform]
 * @returns {{ executablePath: string, cwd: string, env: NodeJS.ProcessEnv }}
 */
export function resolveTrustedBinaryExecution(binary, platform = process.platform) {
  const safeBinary = assertAllowedLocalBinary(binary);

  if (platform === 'win32') {
    const sysRoot = process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows';
    const system32 = path.join(sysRoot, 'System32');
    const winPsDir = path.join(system32, 'WindowsPowerShell', 'v1.0');
    let executablePath;
    if (safeBinary === 'netstat') {
      executablePath = path.join(system32, 'netstat.exe');
    } else if (safeBinary === 'powershell') {
      executablePath = path.join(winPsDir, 'powershell.exe');
    } else if (safeBinary === 'pwsh') {
      executablePath = path.join(process.env.ProgramFiles || 'C:\\Program Files', 'PowerShell', '7', 'pwsh.exe');
    } else {
      executablePath = path.join(system32, `${safeBinary}.exe`);
    }
    return {
      executablePath,
      cwd: sysRoot,
      env: {
        ...process.env,
        PATH: `${system32};${winPsDir};${sysRoot}`
      }
    };
  }

  let executablePath = path.posix.join('/usr/bin', safeBinary);
  for (const dir of TRUSTED_UNIX_BINARY_DIRS) {
    const candidate = path.posix.join(dir, safeBinary);
    try {
      const st = fs.statSync(candidate);
      if (st.isFile()) {
        fs.accessSync(candidate, fs.constants.X_OK);
        executablePath = candidate;
        break;
      }
    } catch {
      // continue checking next trusted directory
    }
  }

  return {
    executablePath,
    cwd: '/',
    env: {
      ...process.env,
      PATH: '/usr/bin:/bin:/usr/sbin:/sbin'
    }
  };
}

/**
 * Executes an allowlisted local binary with `execFile` (`shell: false`, `windowsHide: true`).
 *
 * @param {string} binary
 * @param {string[]} [args=[]]
 * @param {{ commandRunner?: (binary: string, args: string[]) => Promise<string|{stdout?: string}>|string|{stdout?: string} }} [options={}]
 * @returns {Promise<string>}
 */
export async function execAllowedLocalBinary(binary, args = [], options = {}) {
  const safeBinary = assertAllowedLocalBinary(binary, args);

  if (typeof options?.commandRunner === 'function') {
    const out = await options.commandRunner(safeBinary, [...args]);
    if (typeof out === 'string') return out.slice(0, MAX_OUTPUT_CHARS);
    if (out && typeof out === 'object' && typeof out.stdout === 'string') {
      return out.stdout.slice(0, MAX_OUTPUT_CHARS);
    }
    return '';
  }

  const { executablePath, cwd, env } = resolveTrustedBinaryExecution(safeBinary, process.platform);

  return new Promise((resolve, reject) => {
    execFile(
      executablePath,
      args,
      {
        shell: false,
        windowsHide: true,
        cwd,
        env,
        timeout: EXEC_TIMEOUT_MS,
        maxBuffer: EXEC_MAX_BUFFER,
        encoding: 'utf8'
      },
      (err, stdout) => {
        if (err) {
          if (typeof stdout === 'string' && stdout.trim().length > 0) {
            resolve(stdout.slice(0, MAX_OUTPUT_CHARS));
            return;
          }
          reject(err);
          return;
        }
        resolve(String(stdout ?? '').slice(0, MAX_OUTPUT_CHARS));
      }
    );
  });
}

function isWildcardAddress(address) {
  if (typeof address !== 'string') return false;
  const clean = address.trim().toLowerCase();
  return (
    clean === '0.0.0.0' ||
    clean === '::' ||
    clean === '*' ||
    clean === '[::]' ||
    clean === '::ffff:0.0.0.0' ||
    clean === '0.0.0.0.0'
  );
}

function parseEndpointAddressPort(rawEndpoint) {
  if (typeof rawEndpoint !== 'string') return null;
  const token = rawEndpoint.trim();
  if (!token || token.length > 256) return null;

  // Bracketed IPv6: [::]:3389 or [::1]:8080 or [fe80::1%lo0]:445
  if (token.startsWith('[')) {
    const closeIdx = token.indexOf(']');
    if (closeIdx === -1) return null;
    const rawHost = token.slice(1, closeIdx);
    const rest = token.slice(closeIdx + 1);
    if (!rest.startsWith(':')) return null;
    const portNum = Number(rest.slice(1));
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) return null;
    const hostNoZone = rawHost.split('%')[0] || rawHost;
    return { address: hostNoZone, port: portNum };
  }

  // Unbracketed :::port (Linux netstat tcp6)
  if (token.startsWith(':::')) {
    const portNum = Number(token.slice(3));
    if (Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535) {
      return { address: '::', port: portNum };
    }
  }

  // macOS netstat dot notation e.g. *.445 or 127.0.0.1.6379 when no colon is present
  const lastColon = token.lastIndexOf(':');
  if (lastColon !== -1) {
    const rawHost = token.slice(0, lastColon);
    const portStr = token.slice(lastColon + 1);
    const portNum = Number(portStr);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) return null;
    const hostNoZone = rawHost.includes('%') ? rawHost.split('%')[0] : rawHost;
    return { address: hostNoZone || '*', port: portNum };
  }

  const lastDot = token.lastIndexOf('.');
  if (lastDot > 0) {
    const rawHost = token.slice(0, lastDot);
    const portNum = Number(token.slice(lastDot + 1));
    if (
      Number.isInteger(portNum) &&
      portNum >= 1 &&
      portNum <= 65535 &&
      (rawHost === '*' || rawHost.split('.').length === 4)
    ) {
      return { address: rawHost, port: portNum };
    }
  }

  return null;
}

function parseSsUsersProcess(line) {
  const idx = line.indexOf('users:((');
  if (idx === -1) return { pid: null, processName: null };
  const tail = line.slice(idx, idx + 256);
  const nameMatch = /"([^"\r\n]{1,128})"/.exec(tail);
  const pidMatch = /\bpid=(\d{1,10})\b/.exec(tail);
  return {
    pid: pidMatch ? Number(pidMatch[1]) : null,
    processName: nameMatch ? nameMatch[1] : null
  };
}

/**
 * Parses listening TCP sockets from Windows `netstat -ano`, Linux `ss -tulnp` / `netstat -tulnp`,
 * and macOS/Unix `lsof -iTCP -sTCP:LISTEN -P -n`.
 *
 * @param {string} rawOutput
 * @param {string} [platform=process.platform]
 * @returns {Array<{
 *   protocol: string,
 *   address: string,
 *   port: number,
 *   pid: number|null,
 *   processName: string|null,
 *   isWildcardBind: boolean,
 *   riskInfo: object|null
 * }>}
 */
export function parseListeningSockets(rawOutput, platform = process.platform) {
  if (typeof rawOutput !== 'string' || !rawOutput.trim()) return [];
  const bounded = rawOutput.slice(0, MAX_OUTPUT_CHARS);
  const lines = bounded.split(/\r?\n/);
  const results = [];
  const seen = new Set();

  for (const rawLine of lines) {
    const line = rawLine.slice(0, MAX_LINE_CHARS).trim();
    if (!line) continue;

    // Skip headers
    if (
      /^(?:Active Connections|Proto\b|Netid\b|State\b|COMMAND\s+PID\b)/i.test(line)
    ) {
      continue;
    }

    const tokens = line.split(/\s+/);
    if (tokens.length < 4) continue;

    let protocol = null;
    let endpoint = null;
    let pid = null;
    let processName = null;

    const firstLower = tokens[0].toLowerCase();

    // 1. lsof format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME [(LISTEN)]
    if (
      (line.endsWith('(LISTEN)') || tokens.includes('(LISTEN)')) &&
      tokens.length >= 9 &&
      /^\d+$/.test(tokens[1])
    ) {
      processName = tokens[0];
      pid = Number(tokens[1]);
      const listenIdx = tokens.indexOf('(LISTEN)');
      const addrToken = listenIdx > 0 ? tokens[listenIdx - 1] : tokens[tokens.length - 1];
      const nodeProto = listenIdx > 1 ? tokens[listenIdx - 2].toUpperCase() : 'TCP';
      protocol = nodeProto.startsWith('UDP') ? 'UDP' : 'TCP';
      endpoint = parseEndpointAddressPort(addrToken);
    } else if (
      // 2. Linux ss -tulnp: tcp LISTEN 0 128 0.0.0.0:6379 0.0.0.0:* [users:(("redis-server",pid=1120,fd=6))]
      (firstLower === 'tcp' || firstLower === 'tcp6') &&
      tokens[1].toUpperCase() === 'LISTEN' &&
      tokens.length >= 5
    ) {
      protocol = 'TCP';
      endpoint = parseEndpointAddressPort(tokens[4]);
      const proc = parseSsUsersProcess(line);
      pid = proc.pid;
      processName = proc.processName;
    } else if (
      // 3. Windows netstat -ano: TCP 0.0.0.0:445 0.0.0.0:0 LISTENING 4
      (firstLower === 'tcp' || firstLower === 'tcpv6') &&
      tokens[3] &&
      tokens[3].toUpperCase() === 'LISTENING'
    ) {
      protocol = 'TCP';
      endpoint = parseEndpointAddressPort(tokens[1]);
      if (tokens[4] && /^\d+$/.test(tokens[4])) {
        pid = Number(tokens[4]);
      }
    } else if (
      // 4. Linux netstat -tulnp: tcp 0 0 0.0.0.0:6379 0.0.0.0:* LISTEN 1120/redis-server
      (firstLower === 'tcp' || firstLower === 'tcp6') &&
      tokens[5] &&
      tokens[5].toUpperCase() === 'LISTEN'
    ) {
      protocol = 'TCP';
      endpoint = parseEndpointAddressPort(tokens[3]);
      if (tokens[6] && tokens[6] !== '-') {
        const slashIdx = tokens[6].indexOf('/');
        if (slashIdx !== -1) {
          const maybePid = Number(tokens[6].slice(0, slashIdx));
          pid = Number.isInteger(maybePid) ? maybePid : null;
          processName = tokens[6].slice(slashIdx + 1) || null;
        } else if (/^\d+$/.test(tokens[6])) {
          pid = Number(tokens[6]);
        }
      }
    } else if (
      // 5. macOS netstat -anv -p tcp: tcp4 0 0 *.445 *.* LISTEN ...
      platform === 'darwin' &&
      /^tcp[46]?$/i.test(firstLower) &&
      tokens[5] &&
      tokens[5].toUpperCase() === 'LISTEN'
    ) {
      protocol = 'TCP';
      endpoint = parseEndpointAddressPort(tokens[3]);
    }

    if (!protocol || !endpoint) continue;

    const isWildcardBind = isWildcardAddress(endpoint.address);
    const riskEntry = isWildcardBind ? (HIGH_RISK_WILDCARD_PORTS.get(endpoint.port) || null) : null;
    const dedupKey = `${protocol}:${endpoint.address}:${endpoint.port}:${pid ?? ''}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    results.push({
      protocol,
      address: endpoint.address,
      port: endpoint.port,
      pid,
      processName,
      isWildcardBind,
      riskInfo: riskEntry ? { ...riskEntry } : null
    });
  }

  return results;
}

function normalizeBooleanField(val) {
  if (typeof val === 'boolean') return val;
  if (typeof val === 'number') return val !== 0;
  if (typeof val === 'string') {
    const lower = val.trim().toLowerCase();
    if (lower === 'true' || lower === 'on' || lower === '1' || lower === 'enabled' || lower === 'active') {
      return true;
    }
    if (lower === 'false' || lower === 'off' || lower === '0' || lower === 'disabled' || lower === 'inactive') {
      return false;
    }
  }
  return null;
}

/**
 * Parses host firewall posture across Windows (`netsh advfirewall show allprofiles` or PowerShell JSON/text),
 * Linux (`ufw status`), and macOS (`socketfilterfw --getglobalstate`).
 *
 * @param {string} rawOutput
 * @param {string} [platform=process.platform]
 * @returns {{ enabled: boolean, disabledProfiles: string[], rawSummary: string }}
 */
export function parseFirewallStatus(rawOutput, platform = process.platform) {
  if (typeof rawOutput !== 'string' || !rawOutput.trim()) {
    return {
      enabled: false,
      disabledProfiles: [],
      rawSummary: 'Firewall status telemetry unavailable'
    };
  }

  const text = rawOutput.slice(0, MAX_OUTPUT_CHARS).trim();

  // 1. JSON output (PowerShell Get-NetFirewallProfile | ConvertTo-Json)
  if (text.startsWith('[') || text.startsWith('{')) {
    try {
      const parsed = JSON.parse(text);
      const items = Array.isArray(parsed) ? parsed : [parsed];
      const validProfiles = items.filter(it => it && typeof it === 'object' && ('Name' in it || 'name' in it));
      if (validProfiles.length > 0) {
        const disabledProfiles = [];
        const parts = [];
        for (const prof of validProfiles) {
          const name = String(prof.Name ?? prof.name ?? 'Profile').trim();
          const state = normalizeBooleanField(prof.Enabled ?? prof.enabled ?? prof.State ?? prof.state);
          if (state === false) {
            disabledProfiles.push(name);
            parts.push(`${name}=OFF`);
          } else if (state === true) {
            parts.push(`${name}=ON`);
          }
        }
        return {
          enabled: parts.length > 0 && disabledProfiles.length === 0,
          disabledProfiles,
          rawSummary: parts.join(', ') || text.slice(0, 160)
        };
      }
    } catch {
      // Fall through to text parsers
    }
  }

  // 2. Linux UFW (`Status: active` / `Status: inactive`)
  const ufwMatch = /\bStatus\s*:\s*(active|inactive)\b/i.exec(text);
  if (ufwMatch) {
    const isActive = ufwMatch[1].toLowerCase() === 'active';
    return {
      enabled: isActive,
      disabledProfiles: isActive ? [] : ['ufw'],
      rawSummary: ufwMatch[0].trim()
    };
  }

  // 3. macOS socketfilterfw (`Firewall is enabled. (State = 1)` / `Firewall is disabled. (State = 0)`)
  const macFwMatch = /\bFirewall\s+is\s+(enabled|disabled)\b[^\r\n]{0,64}/i.exec(text);
  if (macFwMatch) {
    const isEnabled = macFwMatch[1].toLowerCase() === 'enabled';
    return {
      enabled: isEnabled,
      disabledProfiles: isEnabled ? [] : ['global'],
      rawSummary: macFwMatch[0].trim()
    };
  }

  // 4. Windows netsh advfirewall (`Domain Profile Settings: ... State ON/OFF`)
  const lines = text.split(/\r?\n/);
  let currentProfile = null;
  const profileStates = new Map();

  for (const rawLine of lines) {
    const line = rawLine.slice(0, MAX_LINE_CHARS).trim();
    if (!line) continue;

    const headerMatch = /^(Domain|Private|Public)\s+Profile\s+Settings/i.exec(line);
    if (headerMatch) {
      const pName = headerMatch[1][0].toUpperCase() + headerMatch[1].slice(1).toLowerCase();
      currentProfile = pName;
      continue;
    }

    const stateMatch = /^State\s+(ON|OFF)\b/i.exec(line);
    if (stateMatch && currentProfile) {
      profileStates.set(currentProfile, stateMatch[1].toUpperCase() === 'ON');
      continue;
    }

    // PowerShell Format-List: Name : Domain / Enabled : True
    const psNameMatch = /^Name\s*:\s*(Domain|Private|Public)\b/i.exec(line);
    if (psNameMatch) {
      currentProfile = psNameMatch[1][0].toUpperCase() + psNameMatch[1].slice(1).toLowerCase();
      continue;
    }
    const psEnabledMatch = /^Enabled\s*:\s*(True|False|ON|OFF|1|0)\b/i.exec(line);
    if (psEnabledMatch && currentProfile) {
      profileStates.set(currentProfile, normalizeBooleanField(psEnabledMatch[1]) === true);
      continue;
    }

    // PowerShell Format-Table: Domain True
    const tableMatch = /^(Domain|Private|Public)\s+(True|False|ON|OFF)\b/i.exec(line);
    if (tableMatch) {
      const pName = tableMatch[1][0].toUpperCase() + tableMatch[1].slice(1).toLowerCase();
      profileStates.set(pName, normalizeBooleanField(tableMatch[2]) === true);
    }
  }

  if (profileStates.size > 0) {
    const disabledProfiles = [];
    const summaryParts = [];
    for (const [prof, isOn] of profileStates.entries()) {
      if (!isOn) disabledProfiles.push(prof);
      summaryParts.push(`${prof}=${isOn ? 'ON' : 'OFF'}`);
    }
    return {
      enabled: disabledProfiles.length === 0,
      disabledProfiles,
      rawSummary: summaryParts.join(', ')
    };
  }

  // Fallback for generic platform indicators
  if (platform === 'linux' && /\bACCEPT\b/.test(text) && /\bChain\s+INPUT\b/i.test(text)) {
    const hasDropOrReject = /\b(?:DROP|REJECT)\b/.test(text);
    return {
      enabled: hasDropOrReject,
      disabledProfiles: hasDropOrReject ? [] : ['iptables'],
      rawSummary: text.split(/\r?\n/)[0].slice(0, 120)
    };
  }

  return {
    enabled: false,
    disabledProfiles: [],
    rawSummary: text.split(/\r?\n/)[0].slice(0, 160)
  };
}

/**
 * Parses endpoint protection / anti-malware real-time status from Windows Defender JSON/text
 * or Linux/macOS MAC/AV telemetry.
 *
 * @param {string} rawOutput
 * @param {string} [platform=process.platform]
 * @returns {{
 *   realTimeProtectionEnabled: boolean | null,
 *   antivirusEnabled: boolean | null,
 *   detail: string
 * }}
 */
export function parseEndpointProtectionStatus(rawOutput, platform = process.platform) {
  if (typeof rawOutput !== 'string' || !rawOutput.trim()) {
    return {
      realTimeProtectionEnabled: null,
      antivirusEnabled: null,
      detail: 'Endpoint protection telemetry unavailable'
    };
  }

  const text = rawOutput.slice(0, MAX_OUTPUT_CHARS).trim();

  // 1. JSON format (Get-MpComputerStatus | ConvertTo-Json)
  if (text.startsWith('{') || text.startsWith('[')) {
    try {
      const parsed = JSON.parse(text);
      const obj = Array.isArray(parsed) ? parsed[0] : parsed;
      if (obj && typeof obj === 'object') {
        const rtp = normalizeBooleanField(
          obj.RealTimeProtectionEnabled ?? obj.realTimeProtectionEnabled
        );
        const av = normalizeBooleanField(
          obj.AntivirusEnabled ?? obj.antivirusEnabled ?? obj.AMServiceEnabled
        );
        if (rtp !== null || av !== null) {
          return {
            realTimeProtectionEnabled: rtp,
            antivirusEnabled: av,
            detail: `AntivirusEnabled=${av ?? 'unknown'}, RealTimeProtectionEnabled=${rtp ?? 'unknown'}`
          };
        }
      }
    } catch {
      // Fall through to key-value parser
    }
  }

  // 2. Windows Defender key-value text
  const rtpMatch = /\bRealTimeProtectionEnabled\s*[:=]\s*(True|False|1|0|ON|OFF)\b/i.exec(text);
  const avMatch = /\bAntivirusEnabled\s*[:=]\s*(True|False|1|0|ON|OFF)\b/i.exec(text);
  if (rtpMatch || avMatch) {
    const rtp = rtpMatch ? normalizeBooleanField(rtpMatch[1]) : null;
    const av = avMatch ? normalizeBooleanField(avMatch[1]) : null;
    return {
      realTimeProtectionEnabled: rtp,
      antivirusEnabled: av,
      detail: text.replace(/\s+/g, ' ').slice(0, 160)
    };
  }

  // 3. Linux AppArmor / SELinux / ClamAV or macOS SIP / XProtect
  const lower = text.toLowerCase();
  if (
    lower.includes('system integrity protection status: enabled') ||
    lower.includes('apparmor=install ok installed') ||
    lower.includes('apparmor module is loaded') ||
    lower.includes('selinux status: enabled') ||
    lower.includes('clamav-daemon=install ok installed') ||
    (platform === 'darwin' && lower.startsWith('darwin '))
  ) {
    const hasClam = lower.includes('clamav-daemon=install ok installed') || lower.includes('clamav');
    const isDarwinKernel = platform === 'darwin' && lower.startsWith('darwin ');
    if (isDarwinKernel && !lower.includes('integrity') && !lower.includes('xprotect')) {
      return {
        realTimeProtectionEnabled: true,
        antivirusEnabled: true,
        detail: `macOS XProtect/Gatekeeper baseline (${text.split(/\r?\n/)[0].slice(0, 100)})`
      };
    }
    return {
      realTimeProtectionEnabled: true,
      antivirusEnabled: hasClam ? true : true,
      detail: text.replace(/\s+/g, ' ').slice(0, 160)
    };
  }

  if (
    lower.includes('system integrity protection status: disabled') ||
    lower.includes('selinux status: disabled') ||
    lower.includes('apparmor: inactive')
  ) {
    return {
      realTimeProtectionEnabled: false,
      antivirusEnabled: false,
      detail: text.replace(/\s+/g, ' ').slice(0, 160)
    };
  }

  return {
    realTimeProtectionEnabled: null,
    antivirusEnabled: null,
    detail: text.replace(/\s+/g, ' ').slice(0, 160)
  };
}

function isProtectedSystemDirectory(exePath) {
  return /^[a-z]:\\windows\\(?:system32|syswow64)(?:\\|$)/i.test(exePath.trim());
}

function inspectServicePathForUnquotedSpaces(rawPathName) {
  if (typeof rawPathName !== 'string') return null;
  const trimmed = rawPathName.trim();
  if (!trimmed || trimmed.length > 1024) return null;

  // Quoted binary paths are not vulnerable to CWE-428
  if (trimmed.startsWith('"')) return null;

  const lower = trimmed.toLowerCase();
  const exeIdx = lower.indexOf('.exe');
  if (exeIdx === -1) return null;

  const afterExe = trimmed[exeIdx + 4];
  if (afterExe !== undefined && !/\s/.test(afterExe) && afterExe !== '/' && afterExe !== '-') {
    return null;
  }

  const exePath = trimmed.slice(0, exeIdx + 4).trim();
  if (!/^[a-z]:\\/i.test(exePath)) return null;
  if (!exePath.includes(' ')) return null;
  if (isProtectedSystemDirectory(exePath)) return null;

  return exePath;
}

/**
 * Parses Windows service definitions (PowerShell JSON, PowerShell Format-List, or WMIC list/table)
 * and returns services vulnerable to `CWE-428: Unquoted Search Path or Element`.
 *
 * @param {string} rawOutput
 * @returns {Array<{ serviceName: string, pathName: string, startMode: string, quote: string }>}
 */
export function parseUnquotedWindowsServices(rawOutput) {
  if (typeof rawOutput !== 'string' || !rawOutput.trim()) return [];
  const text = rawOutput.slice(0, MAX_OUTPUT_CHARS).trim();
  const candidates = [];

  // 1. PowerShell ConvertTo-Json array or single object
  if (text.startsWith('[') || text.startsWith('{')) {
    try {
      const parsed = JSON.parse(text);
      const list = Array.isArray(parsed) ? parsed : [parsed];
      for (const item of list) {
        if (!item || typeof item !== 'object') continue;
        const serviceName = String(item.Name ?? item.ServiceName ?? item.name ?? '').trim();
        const pathName = String(item.PathName ?? item.BinaryPathName ?? item.pathName ?? '').trim();
        const startMode = String(item.StartMode ?? item.StartType ?? item.startMode ?? 'Unknown').trim();
        if (serviceName && pathName) {
          candidates.push({ serviceName, pathName, startMode });
        }
      }
    } catch {
      // Fall through to line parsers
    }
  }

  // 2. Line-oriented formats (PowerShell Format-List, WMIC /format:list, or WMIC tabular)
  if (candidates.length === 0) {
    const lines = text.split(/\r?\n/);
    let current = {};

    const flushCurrent = () => {
      if (current.serviceName && current.pathName) {
        candidates.push({
          serviceName: current.serviceName,
          pathName: current.pathName,
          startMode: current.startMode || 'Unknown'
        });
      }
      current = {};
    };

    for (const rawLine of lines) {
      const line = rawLine.slice(0, MAX_LINE_CHARS).trim();
      if (!line) {
        flushCurrent();
        continue;
      }
      if (/^(?:Name\s+PathName|--+)/i.test(line)) continue;

      const kvMatch = /^(Name|ServiceName|PathName|BinaryPathName|StartMode|StartType)\s*[:=]\s*(.*)$/i.exec(line);
      if (kvMatch) {
        const key = kvMatch[1].toLowerCase();
        const val = kvMatch[2].trim();
        if (key === 'name' || key === 'servicename') {
          if (current.serviceName) flushCurrent();
          current.serviceName = val;
        } else if (key === 'pathname' || key === 'binarypathname') {
          current.pathName = val;
        } else if (key === 'startmode' || key === 'starttype') {
          current.startMode = val || 'Unknown';
        }
        continue;
      }

      // Tabular WMIC / PowerShell line: <ServiceName> <C:\Program Files\...\svc.exe [args]> [Auto|Manual|Disabled]
      const driveMatch = /^(\S+)\s+((?:"[^"]+"|[A-Za-z]:\\)[^\r\n]*)$/.exec(line);
      if (driveMatch) {
        const svcName = driveMatch[1].trim();
        let rest = driveMatch[2].trim();
        let startMode = 'Unknown';
        const modeTail = /\s{2,}(Auto|Automatic|Manual|Disabled)\s*$/i.exec(rest);
        if (modeTail) {
          startMode = modeTail[1];
          rest = rest.slice(0, modeTail.index).trim();
        }
        candidates.push({ serviceName: svcName, pathName: rest, startMode });
      }
    }
    flushCurrent();
  }

  const vulnerable = [];
  const seen = new Set();

  for (const svc of candidates) {
    if (!inspectServicePathForUnquotedSpaces(svc.pathName)) continue;
    const key = `${svc.serviceName.toLowerCase()}::${svc.pathName.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);

    vulnerable.push({
      serviceName: svc.serviceName,
      pathName: svc.pathName,
      startMode: svc.startMode || 'Unknown',
      quote: `${svc.serviceName}: ${svc.pathName}`.slice(0, 200)
    });
  }

  return vulnerable;
}

function finalizeAuditFinding(rawFinding) {
  const quotes = Array.isArray(rawFinding.evidenceQuotes)
    ? rawFinding.evidenceQuotes.filter(q => typeof q === 'string' && q.trim().length >= 8)
    : [];
  const status = rawFinding.status;
  const poeLevel = status === 'VULNERABLE' ? (quotes.length > 0 ? 3 : 2) : (status === 'SUSPICIOUS' ? 2 : 1);
  const draft = {
    checkId: 'pc-local-audit',
    name: rawFinding.name,
    status,
    severity: rawFinding.severity,
    cwe: rawFinding.cwe,
    owasp: rawFinding.owasp || OWASP_A05,
    cvssScore: rawFinding.cvssScore,
    detail: rawFinding.detail,
    fix: rawFinding.fix,
    evidenceQuotes: quotes,
    poeLevel
  };
  const { confidenceTier, confidenceScore } = classifyFindingConfidence(draft, {
    passiveVersionMatch: false
  });
  return {
    ...draft,
    confidenceTier,
    confidenceScore
  };
}

async function tryCommandsSequentially(candidates, runnerOpts) {
  for (const [binary, args] of candidates) {
    try {
      const out = await execAllowedLocalBinary(binary, args, runnerOpts);
      if (typeof out === 'string' && out.trim().length > 0) {
        return out;
      }
    } catch (err) {
      if (err && err.code === 'DISALLOWED_LOCAL_BINARY') {
        throw err;
      }
    }
  }
  return '';
}

async function collectDefaultHostTelemetry(platform, runnerOpts) {
  if (platform === 'win32') {
    const fwCmd = 'Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress';
    const mpCmd =
      'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AMServiceEnabled | ConvertTo-Json -Compress';
    const svcCmd = 'Get-CimInstance Win32_Service | Select-Object Name,PathName,StartMode | ConvertTo-Json -Compress';

    const [socketsRaw, firewallRaw, endpointRaw, servicesRaw] = await Promise.all([
      tryCommandsSequentially([['netstat', ['-ano']]], runnerOpts),
      tryCommandsSequentially(
        [
          ['powershell', ['-NoProfile', '-NonInteractive', '-Command', fwCmd]],
          ['pwsh', ['-NoProfile', '-NonInteractive', '-Command', fwCmd]]
        ],
        runnerOpts
      ),
      tryCommandsSequentially(
        [
          ['powershell', ['-NoProfile', '-NonInteractive', '-Command', mpCmd]],
          ['pwsh', ['-NoProfile', '-NonInteractive', '-Command', mpCmd]]
        ],
        runnerOpts
      ),
      tryCommandsSequentially(
        [
          ['powershell', ['-NoProfile', '-NonInteractive', '-Command', svcCmd]],
          ['pwsh', ['-NoProfile', '-NonInteractive', '-Command', svcCmd]]
        ],
        runnerOpts
      )
    ]);

    return { socketsRaw, firewallRaw, endpointRaw, servicesRaw };
  }

  if (platform === 'linux') {
    const [socketsRaw, firewallRaw, endpointRaw] = await Promise.all([
      tryCommandsSequentially(
        [
          ['ss', ['-tulnp']],
          ['netstat', ['-tulnp']],
          ['lsof', ['-iTCP', '-sTCP:LISTEN', '-P', '-n']]
        ],
        runnerOpts
      ),
      tryCommandsSequentially([['ufw', ['status']]], runnerOpts),
      tryCommandsSequentially(
        [
          ['dpkg-query', ['-W', '-f=${Package}=${Status}\\n', 'apparmor', 'clamav-daemon']],
          ['rpm', ['-q', 'selinux-policy', 'clamav']],
          ['apk', ['info']]
        ],
        runnerOpts
      )
    ]);

    return { socketsRaw, firewallRaw, endpointRaw, servicesRaw: '' };
  }

  const [socketsRaw, endpointRaw] = await Promise.all([
    tryCommandsSequentially(
      [
        ['lsof', ['-iTCP', '-sTCP:LISTEN', '-P', '-n']],
        ['netstat', ['-anv', '-p', 'tcp']]
      ],
      runnerOpts
    ),
    tryCommandsSequentially([['uname', ['-a']]], runnerOpts)
  ]);

  return { socketsRaw, firewallRaw: '', endpointRaw, servicesRaw: '' };
}

/**
 * Runs the 4-domain local/host PC deep security audit.
 *
 * @param {{
 *   platform?: string,
 *   hostname?: string,
 *   telemetry?: {
 *     socketsRaw?: string,
 *     firewallRaw?: string,
 *     endpointRaw?: string,
 *     servicesRaw?: string,
 *     listeningSockets?: Array<object>,
 *     firewall?: object,
 *     endpointProtection?: object,
 *     unquotedServices?: Array<object>
 *   },
 *   commandRunner?: (binary: string, args: string[]) => Promise<string|{stdout?: string}>|string|{stdout?: string}
 * }} [options={}]
 */
export async function runLocalPcAudit(options = {}) {
  const platform = options.platform || process.platform;
  const hostname = options.hostname || os.hostname();
  const runnerOpts = options.commandRunner ? { commandRunner: options.commandRunner } : {};

  let rawTelemetry = {
    socketsRaw: '',
    firewallRaw: '',
    endpointRaw: '',
    servicesRaw: ''
  };

  if (options.telemetry && typeof options.telemetry === 'object') {
    rawTelemetry = {
      socketsRaw: String(options.telemetry.socketsRaw ?? ''),
      firewallRaw: String(options.telemetry.firewallRaw ?? ''),
      endpointRaw: String(options.telemetry.endpointRaw ?? ''),
      servicesRaw: String(options.telemetry.servicesRaw ?? '')
    };
  } else {
    rawTelemetry = await collectDefaultHostTelemetry(platform, runnerOpts);
  }

  const listeningSockets = Array.isArray(options.telemetry?.listeningSockets)
    ? options.telemetry.listeningSockets
    : parseListeningSockets(rawTelemetry.socketsRaw, platform);

  const firewall =
    options.telemetry?.firewall && typeof options.telemetry.firewall === 'object'
      ? options.telemetry.firewall
      : parseFirewallStatus(rawTelemetry.firewallRaw, platform);

  const endpointProtection =
    options.telemetry?.endpointProtection && typeof options.telemetry.endpointProtection === 'object'
      ? options.telemetry.endpointProtection
      : parseEndpointProtectionStatus(rawTelemetry.endpointRaw, platform);

  const unquotedServices = Array.isArray(options.telemetry?.unquotedServices)
    ? options.telemetry.unquotedServices
    : parseUnquotedWindowsServices(rawTelemetry.servicesRaw);

  const findings = [];

  // 1. Check 1: Wildcard High-Risk Listening Ports
  const riskyWildcardSockets = listeningSockets.filter(s => s && s.isWildcardBind && s.riskInfo);
  if (riskyWildcardSockets.length > 0) {
    const hasCritical = riskyWildcardSockets.some(s => s.riskInfo.severity === 'CRITICAL');
    const maxCvss = riskyWildcardSockets.reduce(
      (best, s) => (Number(s.riskInfo.cvssScore) > best ? Number(s.riskInfo.cvssScore) : best),
      7.5
    );
    const quotes = riskyWildcardSockets.slice(0, 6).map(
      s =>
        `${s.protocol} ${s.address}:${s.port} LISTENING (${s.riskInfo.service}${s.pid !== null ? `, pid=${s.pid}` : ''})`
    );
    findings.push(
      finalizeAuditFinding({
        name: 'Wildcard High-Risk Listening Ports',
        status: 'VULNERABLE',
        severity: hasCritical ? 'CRITICAL' : 'HIGH',
        cwe: riskyWildcardSockets[0].riskInfo.cwe || 'CWE-284',
        owasp: OWASP_A05,
        cvssScore: maxCvss,
        detail: `Command execution of local socket audit detected ${riskyWildcardSockets.length} high-risk service(s) bound to wildcard interfaces: ${riskyWildcardSockets.map(s => `${s.riskInfo.service} (${s.address}:${s.port})`).join(', ')}`,
        fix: 'Bind local daemons (Redis, Ollama, Docker TCP, SMB, RDP, ADB, WinRM, VNC) strictly to 127.0.0.1 / ::1 or restrict inbound access via host firewall rules.',
        evidenceQuotes: quotes
      })
    );
  } else {
    findings.push(
      finalizeAuditFinding({
        name: 'Wildcard High-Risk Listening Ports',
        status: 'SAFE',
        severity: 'NONE',
        cwe: 'CWE-284',
        owasp: OWASP_A05,
        cvssScore: 0,
        detail: 'No high-risk services are bound to wildcard (0.0.0.0 / :: / *) listening sockets',
        fix: 'Continue binding sensitive administrative and database services exclusively to loopback.',
        evidenceQuotes: []
      })
    );
  }

  // 2. Check 2: Host Firewall Posture
  const fwDisabled = Array.isArray(firewall.disabledProfiles) ? firewall.disabledProfiles : [];
  if (fwDisabled.length > 0) {
    const fwQuote =
      typeof firewall.rawSummary === 'string' && firewall.rawSummary.trim().length >= 8
        ? firewall.rawSummary.trim().slice(0, 160)
        : `Firewall disabled on profiles: ${fwDisabled.join(', ')}`;
    findings.push(
      finalizeAuditFinding({
        name: 'Host Firewall Posture',
        status: 'VULNERABLE',
        severity: 'HIGH',
        cwe: 'CWE-284',
        owasp: OWASP_A05,
        cvssScore: 7.8,
        detail: `Command execution of host firewall audit confirmed disabled firewall profile(s): ${fwDisabled.join(', ')}`,
        fix: 'Enable the host firewall across all profiles (Windows Defender Firewall Domain/Private/Public, Linux ufw enable, or macOS Application Firewall).',
        evidenceQuotes: [fwQuote]
      })
    );
  } else if (firewall.enabled === true) {
    findings.push(
      finalizeAuditFinding({
        name: 'Host Firewall Posture',
        status: 'SAFE',
        severity: 'NONE',
        cwe: 'CWE-284',
        owasp: OWASP_A05,
        cvssScore: 0,
        detail: `Host firewall is active (${firewall.rawSummary || 'all inspected profiles enabled'})`,
        fix: 'Maintain default-deny inbound firewall rules across all network profiles.',
        evidenceQuotes: []
      })
    );
  } else {
    findings.push(
      finalizeAuditFinding({
        name: 'Host Firewall Posture',
        status: 'SUSPICIOUS',
        severity: 'LOW',
        cwe: 'CWE-284',
        owasp: OWASP_A05,
        cvssScore: 3.5,
        detail: `Host firewall state could not be verified without version or privileged policy output (${firewall.rawSummary || 'telemetry unavailable'})`,
        fix: 'Verify host firewall status with administrative privileges and ensure inbound filtering is active.',
        evidenceQuotes: []
      })
    );
  }

  // 3. Check 3: Endpoint Protection / Defender Real-Time Status
  if (
    endpointProtection.realTimeProtectionEnabled === false ||
    endpointProtection.antivirusEnabled === false
  ) {
    const epQuote =
      typeof endpointProtection.detail === 'string' && endpointProtection.detail.trim().length >= 8
        ? endpointProtection.detail.trim().slice(0, 160)
        : 'RealTimeProtectionEnabled=false';
    findings.push(
      finalizeAuditFinding({
        name: 'Endpoint Protection & Real-Time Malware Defense',
        status: 'VULNERABLE',
        severity: 'HIGH',
        cwe: 'CWE-693',
        owasp: OWASP_A05,
        cvssScore: 7.5,
        detail: `Command execution of endpoint protection check confirmed disabled defense (${endpointProtection.detail})`,
        fix: 'Re-enable Microsoft Defender Real-Time Protection and Antivirus (Set-MpPreference -DisableRealtimeMonitoring $false) or active EDR/MAC enforcement.',
        evidenceQuotes: [epQuote]
      })
    );
  } else if (
    endpointProtection.realTimeProtectionEnabled === true ||
    endpointProtection.antivirusEnabled === true
  ) {
    findings.push(
      finalizeAuditFinding({
        name: 'Endpoint Protection & Real-Time Malware Defense',
        status: 'SAFE',
        severity: 'NONE',
        cwe: 'CWE-693',
        owasp: OWASP_A05,
        cvssScore: 0,
        detail: `Endpoint protection active (${endpointProtection.detail})`,
        fix: 'Keep anti-malware signatures and real-time behavioral monitoring enabled.',
        evidenceQuotes: []
      })
    );
  } else {
    findings.push(
      finalizeAuditFinding({
        name: 'Endpoint Protection & Real-Time Malware Defense',
        status: 'SUSPICIOUS',
        severity: 'LOW',
        cwe: 'CWE-693',
        owasp: OWASP_A05,
        cvssScore: 3.1,
        detail: `Endpoint protection telemetry inconclusive without version or agent confirmation (${endpointProtection.detail})`,
        fix: 'Ensure endpoint protection / MAC (Defender, AppArmor, SELinux, XProtect) is active and reporting.',
        evidenceQuotes: []
      })
    );
  }

  // 4. Check 4: Unquoted Windows Service Paths (CWE-428)
  if (unquotedServices.length > 0) {
    const hasAuto = unquotedServices.some(s => /auto/i.test(String(s.startMode || '')));
    findings.push(
      finalizeAuditFinding({
        name: 'Unquoted Windows Service Paths (CWE-428)',
        status: 'VULNERABLE',
        severity: hasAuto ? 'HIGH' : 'MEDIUM',
        cwe: 'CWE-428',
        owasp: OWASP_A05,
        cvssScore: hasAuto ? 7.8 : 6.7,
        detail: `Command execution of service path audit found ${unquotedServices.length} unquoted Windows service binary path(s) with spaces: ${unquotedServices.map(s => s.serviceName).join(', ')}`,
        fix: 'Wrap the executable path of each affected Windows service ImagePath registry value in double quotes (e.g. "C:\\Program Files\\Vendor\\service.exe" --arg).',
        evidenceQuotes: unquotedServices.slice(0, 5).map(s => s.quote)
      })
    );
  } else {
    findings.push(
      finalizeAuditFinding({
        name: 'Unquoted Windows Service Paths (CWE-428)',
        status: 'SAFE',
        severity: 'NONE',
        cwe: 'CWE-428',
        owasp: OWASP_A05,
        cvssScore: 0,
        detail:
          platform === 'win32' || rawTelemetry.servicesRaw.trim().length > 0
            ? 'No unquoted Windows service binary paths containing spaces were detected'
            : `Unquoted Windows service path check not applicable on ${platform}`,
        fix: 'Ensure all custom Windows service binary paths containing spaces are enclosed in double quotes.',
        evidenceQuotes: []
      })
    );
  }

  const vulnerableCount = findings.filter(f => f.status === 'VULNERABLE').length;
  const suspiciousCount = findings.filter(f => f.status === 'SUSPICIOUS').length;
  const safeCount = findings.filter(f => f.status === 'SAFE').length;
  const overallStatus =
    vulnerableCount > 0 ? 'VULNERABLE' : (suspiciousCount > 0 ? 'SUSPICIOUS' : 'SAFE');

  const rawRisk = findings.reduce((acc, f) => {
    if (f.status === 'VULNERABLE') {
      if (f.severity === 'CRITICAL') return acc + 40;
      if (f.severity === 'HIGH') return acc + 28;
      return acc + 18;
    }
    if (f.status === 'SUSPICIOUS') return acc + 8;
    return acc;
  }, 0);
  const riskScore = Math.min(100, rawRisk);

  return {
    generatedAt: new Date().toISOString(),
    platform,
    hostname,
    summary: {
      totalChecks: 4,
      vulnerableCount,
      suspiciousCount,
      safeCount,
      overallStatus,
      riskScore
    },
    listeningSockets,
    firewall,
    endpointProtection,
    unquotedServices,
    findings
  };
}

function padCell(value, width) {
  const str = String(value ?? '');
  return str.length >= width ? str.slice(0, width) : str + ' '.repeat(width - str.length);
}

/**
 * Formats a `runLocalPcAudit` report into a clean human-readable CLI table summary.
 *
 * @param {object} report
 * @returns {string}
 */
export function formatLocalPcAuditText(report) {
  if (!report || typeof report !== 'object') {
    return 'Local PC Security Audit: No report data available.';
  }

  const summary = report.summary || {};
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const lines = [];

  lines.push('================================================================================');
  lines.push('  SECSCAN LOCAL & HOST PC DEEP SECURITY AUDIT');
  lines.push('================================================================================');
  lines.push(
    `  Host: ${report.hostname || 'unknown'}  |  Platform: ${report.platform || 'unknown'}  |  Status: ${summary.overallStatus || 'UNKNOWN'}  |  Risk Score: ${summary.riskScore ?? 0}/100`
  );
  lines.push(
    `  Checks: ${summary.totalChecks ?? findings.length} total (${summary.vulnerableCount ?? 0} vulnerable, ${summary.suspiciousCount ?? 0} suspicious, ${summary.safeCount ?? 0} safe)`
  );
  lines.push('--------------------------------------------------------------------------------');
  lines.push(
    `  ${padCell('CHECK', 42)} | ${padCell('STATUS', 10)} | ${padCell('SEVERITY', 8)} | DETAIL`
  );
  lines.push('--------------------------------------------------------------------------------');

  for (const f of findings) {
    lines.push(
      `  ${padCell(f.name, 42)} | ${padCell(f.status, 10)} | ${padCell(f.severity, 8)} | ${f.detail}`
    );
  }

  lines.push('================================================================================');
  return lines.join('\n');
}
