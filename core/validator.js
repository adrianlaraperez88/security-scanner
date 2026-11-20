import { URL } from 'node:url';
import net from 'node:net';
import dnsPromises from 'node:dns/promises';

/**
 * Checks whether the hostname is an obfuscated, single-segment, hex, or octal IP notation.
 */
function isNumericOrObfuscatedHost(rawHost) {
  const host = String(rawHost || '').trim().replace(/\.+$/, '');
  if (!host) return false;
  // If IPv6 in square brackets, handled in IPv6 checks
  if (host.startsWith('[') && host.endsWith(']')) return false;

  // Single-segment integer: e.g. 2130706433 or 0 or 12345678
  if (/^\d+$/.test(host)) return true;

  // Single-segment hex: e.g. 0x7f000001
  if (/^0x[0-9a-f]+$/i.test(host)) return true;

  // Dotted notation containing hex or octal segments or shorthand notation:
  // e.g. 0177.0.0.1 or 0x7f.0.0.1 or 127.1 or 127.0.1
  const parts = host.split('.');
  if (parts.length >= 2 && parts.length <= 4) {
    if (parts.length >= 2 && parts.length <= 3 && parts.every(p => /^\d+$/.test(p))) {
      return true;
    }
    const isAllNumOrHex = parts.every(p => /^(0x[0-9a-f]+|\d+)$/i.test(p));
    if (isAllNumOrHex) {
      const hasHex = parts.some(p => /^0x[0-9a-f]+$/i.test(p));
      const hasOctal = parts.some(p => /^0\d+$/.test(p));
      if (hasHex || hasOctal) return true;
    }
  }

  return false;
}

/**
 * Expands an IPv6 address into an array of 8 16-bit integers (0..65535), or null if invalid.
 *
 * @param {string} rawIp
 * @returns {number[] | null}
 */
export function expandIPv6(rawIp) {
  if (typeof rawIp !== 'string') return null;
  let ip = rawIp.trim().replace(/^\[|\]$/g, '');
  // Strip IPv6 zone index if present (e.g., fe80::1%eth0)
  const zoneIdx = ip.indexOf('%');
  if (zoneIdx !== -1) {
    ip = ip.slice(0, zoneIdx);
  }
  ip = ip.toLowerCase();
  if (!ip.includes(':')) return null;

  // Handle embedded IPv4 in the final segment (e.g., ::ffff:127.0.0.1 or 64:ff9b::192.168.1.1)
  const lastColon = ip.lastIndexOf(':');
  const tail = ip.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4Match = tail.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!v4Match) return null;
    const [o1, o2, o3, o4] = v4Match.slice(1).map(Number);
    if ([o1, o2, o3, o4].some(o => o > 255)) return null;
    const hi = ((o1 << 8) | o2).toString(16);
    const lo = ((o3 << 8) | o4).toString(16);
    ip = `${ip.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const doubleColonParts = ip.split('::');
  if (doubleColonParts.length > 2) return null;

  let left = [];
  let right = [];
  if (doubleColonParts.length === 2) {
    left = doubleColonParts[0] ? doubleColonParts[0].split(':') : [];
    right = doubleColonParts[1] ? doubleColonParts[1].split(':') : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    const words = [
      ...left,
      ...Array(missing).fill('0'),
      ...right
    ];
    if (words.length !== 8) return null;
    return parseHexWords(words);
  }

  const words = ip.split(':');
  if (words.length !== 8) return null;
  return parseHexWords(words);
}

function parseHexWords(words) {
  const result = [];
  for (const w of words) {
    if (!/^[0-9a-f]{1,4}$/i.test(w)) return null;
    result.push(parseInt(w, 16));
  }
  return result;
}

/**
 * Checks if four IPv4 octets fall into cloud metadata or always-forbidden ranges
 * (0.0.0.0/8 unspecified, 169.254.0.0/16 link-local / cloud metadata,
 * 100.100.100.200 Alibaba metadata, 224.0.0.0/4+ multicast/reserved).
 */
function isMetadataOrForbiddenIPv4Octets(o1, o2, o3, o4) {
  if ([o1, o2, o3, o4].some(o => !Number.isInteger(o) || o < 0 || o > 255)) {
    return true;
  }
  return (
    o1 === 0 || // 0.0.0.0/8 unspecified ("this" network)
    (o1 === 169 && o2 === 254) || // 169.254.0.0/16 link-local & cloud metadata (169.254.169.254)
    (o1 === 100 && o2 === 100 && o3 === 100 && o4 === 200) || // Alibaba Cloud metadata
    o1 >= 224 // 224.0.0.0/4 multicast & 240.0.0.0/4 reserved/broadcast
  );
}

/**
 * Checks if four IPv4 octets fall into loopback, unspecified, link-local / cloud metadata,
 * RFC1918 private, CGNAT, or multicast/reserved ranges.
 */
function isPrivateOrReservedIPv4Octets(o1, o2, o3, o4) {
  if ([o1, o2, o3, o4].some(o => !Number.isInteger(o) || o < 0 || o > 255)) {
    return true;
  }
  return (
    isMetadataOrForbiddenIPv4Octets(o1, o2, o3, o4) ||
    o1 === 127 || // 127.0.0.0/8 loopback
    o1 === 10 || // 10.0.0.0/8 RFC1918 private
    (o1 === 172 && o2 >= 16 && o2 <= 31) || // 172.16.0.0/12 RFC1918 private
    (o1 === 192 && o2 === 168) || // 192.168.0.0/16 RFC1918 private
    (o1 === 100 && o2 >= 64 && o2 <= 127) || // 100.64.0.0/10 Carrier-Grade NAT (CGNAT)
    (o1 === 192 && o2 === 0 && o3 === 0) || // 192.0.0.0/24 IETF protocol assignments
    (o1 === 198 && (o2 === 18 || o2 === 19)) // 198.18.0.0/15 benchmarking
  );
}

function isAwsIpv6MetadataWords(words) {
  return (
    words[0] === 0xfd00 &&
    words[1] === 0x0ec2 &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0 &&
    words[6] === 0 &&
    words[7] === 0x0254
  );
}

/**
 * Returns true if a hostname is a forbidden cloud metadata hostname or metadata IP literal
 * that must ALWAYS be blocked even when `allowPrivate: true`.
 *
 * @param {string} hostname
 * @returns {boolean}
 */
export function isForbiddenMetadataHost(hostname) {
  if (typeof hostname !== 'string' || !hostname.trim()) return false;
  let clean = hostname.trim().toLowerCase();
  if (clean.startsWith('[')) {
    const closeIdx = clean.indexOf(']');
    if (closeIdx !== -1) {
      clean = clean.slice(1, closeIdx);
    }
  } else if (!clean.includes(':') || clean.split(':').length === 2) {
    clean = clean.replace(/:\d*$/, '');
  }
  clean = clean.replace(/\.+$/, '');
  if (!clean) return false;

  if (
    clean === 'metadata' ||
    clean === 'metadata.google.internal' ||
    clean.endsWith('.metadata.google.internal') ||
    clean === 'metadata.goog' ||
    clean.endsWith('.metadata.goog') ||
    clean === 'instance-data' ||
    clean.endsWith('.instance-data') ||
    clean === 'instance-data.ec2.internal' ||
    clean === '169.254.169.254' ||
    clean === '100.100.100.200'
  ) {
    return true;
  }

  if (clean.includes(':')) {
    const words = expandIPv6(clean);
    if (words) {
      if (isAwsIpv6MetadataWords(words)) return true;
      const [w0, w1, w2, w3, w4, w5, w6, w7] = words;
      if (
        w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 &&
        ((w4 === 0 && (w5 === 0 || w5 === 0xffff)) || (w4 === 0xffff && w5 === 0)) &&
        !(w4 === 0 && w5 === 0 && w6 === 0 && w7 === 1)
      ) {
        const o1 = (w6 >> 8) & 0xff;
        const o2 = w6 & 0xff;
        const o3 = (w7 >> 8) & 0xff;
        const o4 = w7 & 0xff;
        if ((o1 === 169 && o2 === 254) || (o1 === 100 && o2 === 100 && o3 === 100 && o4 === 200)) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Returns true if an IP is a cloud metadata IP or always-forbidden range that must ALWAYS be
 * blocked even when `allowPrivate: true`:
 * - 169.254.0.0/16 (cloud metadata / IPv4 link-local)
 * - 100.100.100.200 (Alibaba metadata)
 * - 0.0.0.0/8 (unspecified IPv4) & 224.0.0.0/4+ (multicast/reserved/broadcast)
 * - :: (unspecified IPv6), fe80::/10 (IPv6 link-local), ff00::/8 (IPv6 multicast)
 * - fd00:ec2::254 (AWS IPv6 metadata)
 * - IPv4-mapped/compatible/translated embeddings of the above, plus NAT64/6to4/Teredo tunnels
 *
 * Authorized private ranges (RFC1918 10/8, 172.16/12, 192.168/16, loopback 127/8 & ::1,
 * CGNAT 100.64/10 except 100.100.100.200, and IPv6 ULA fc00::/7 except fd00:ec2::254) return false.
 *
 * @param {string} ip
 * @returns {boolean}
 */
export function isMetadataOrForbiddenIP(ip) {
  if (typeof ip !== 'string' || !ip.trim()) return true;
  const clean = ip.trim().replace(/^\[|\]$/g, '').toLowerCase();

  const ipv4Match = clean.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [o1, o2, o3, o4] = ipv4Match.slice(1).map(Number);
    return isMetadataOrForbiddenIPv4Octets(o1, o2, o3, o4);
  }

  if (clean.includes(':')) {
    const words = expandIPv6(clean);
    if (!words) return true; // Malformed IPv6 fails closed

    const [w0, w1, w2, w3, w4, w5, w6, w7] = words;

    // Unspecified :: (all zeros)
    if (words.every(w => w === 0)) return true;

    // Loopback ::1 is permitted when allowPrivate: true
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0 && w6 === 0 && w7 === 1) {
      return false;
    }

    // IPv4-compatible (::/96), IPv4-mapped (::ffff:0:0/96), or IPv4-translated (::ffff:0:0:0/96)
    if (
      w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 &&
      ((w4 === 0 && (w5 === 0 || w5 === 0xffff)) || (w4 === 0xffff && w5 === 0))
    ) {
      const o1 = (w6 >> 8) & 0xff;
      const o2 = w6 & 0xff;
      const o3 = (w7 >> 8) & 0xff;
      const o4 = w7 & 0xff;
      return isMetadataOrForbiddenIPv4Octets(o1, o2, o3, o4);
    }

    // IPv4-translated / NAT64 (64:ff9b::), 6to4 (2002::/16), Teredo (2001:0000::/32)
    if ((w0 === 0x0064 && w1 === 0xff9b) || w0 === 0x2002 || (w0 === 0x2001 && w1 === 0x0000)) {
      return true;
    }

    // AWS EC2 IPv6 metadata (fd00:ec2::254)
    if (isAwsIpv6MetadataWords(words)) {
      return true;
    }

    // Link-local fe80::/10 (fe80..febf)
    if ((w0 & 0xffc0) === 0xfe80) {
      return true;
    }

    // Multicast ff00::/8
    if ((w0 & 0xff00) === 0xff00) {
      return true;
    }

    return false;
  }

  // If neither valid IPv4 nor IPv6, fail closed
  return true;
}

/**
 * Returns true if an IP is loopback (127.0.0.0/8, ::1), unspecified (0.0.0.0, ::),
 * link-local / cloud metadata (169.254.0.0/16, fe80::/10, fd00:ec2::254),
 * RFC1918 private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
 * CGNAT (100.64.0.0/10), multicast (224.0.0.0/4, ff00::/8),
 * or IPv6 unique-local (fc00::/7).
 *
 * @param {string} ip
 * @returns {boolean}
 */
export function voidsExemption(ip) {
  if (typeof ip !== 'string' || !ip.trim()) return true;
  const clean = ip.trim().replace(/^\[|\]$/g, '').toLowerCase();

  // Check IPv4
  const ipv4Match = clean.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [o1, o2, o3, o4] = ipv4Match.slice(1).map(Number);
    return isPrivateOrReservedIPv4Octets(o1, o2, o3, o4);
  }

  // Check IPv6
  if (clean.includes(':')) {
    const words = expandIPv6(clean);
    if (!words) return true; // Malformed IPv6 fails closed

    const [w0, w1, w2, w3, w4, w5, w6, w7] = words;

    // Unspecified :: (all zeros)
    if (words.every(w => w === 0)) return true;

    // Loopback ::1
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0 && w6 === 0 && w7 === 1) {
      return true;
    }

    // IPv4-compatible (::/96) or IPv4-mapped (::ffff:0:0/96)
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && (w5 === 0 || w5 === 0xffff)) {
      const o1 = (w6 >> 8) & 0xff;
      const o2 = w6 & 0xff;
      const o3 = (w7 >> 8) & 0xff;
      const o4 = w7 & 0xff;
      return isPrivateOrReservedIPv4Octets(o1, o2, o3, o4);
    }

    // IPv4-translated / NAT64 (64:ff9b::/96 or 64:ff9b:1::/48)
    if (w0 === 0x0064 && w1 === 0xff9b) {
      return true;
    }

    // 6to4 (2002::/16) — inspect embedded IPv4 in w1, w2 or block
    if (w0 === 0x2002) {
      return true;
    }

    // Teredo (2001:0000::/32), Benchmarking (2001:0002::/32), Documentation (2001:0db8::/32)
    if (w0 === 0x2001 && (w1 === 0x0000 || w1 === 0x0002 || w1 === 0x0db8)) {
      return true;
    }

    // Unique-local fc00::/7 (fc00::/8 and fd00::/8, including AWS EC2 metadata fd00:ec2::254)
    if ((w0 & 0xfe00) === 0xfc00) {
      return true;
    }

    // Link-local fe80::/10 (fe80..febf)
    if ((w0 & 0xffc0) === 0xfe80) {
      return true;
    }

    // Multicast ff00::/8
    if ((w0 & 0xff00) === 0xff00) {
      return true;
    }

    return false;
  }

  // If neither valid IPv4 nor IPv6, fail closed
  return true;
}

/**
 * Alias for voidsExemption checking if an IP literal is private, loopback, link-local, or reserved.
 *
 * @param {string} ip
 * @returns {boolean}
 */
export function isPrivateOrReservedIP(ip) {
  return voidsExemption(ip);
}

/**
 * Validates a single target URL and enforces strict SSRF protections.
 *
 * @param {string} rawUrl
 * @param {{ allowPrivate?: boolean }} [options]
 * @returns {{ valid: boolean, normalized?: string, hostname?: string, error?: string }}
 */
export function validateTargetUrl(rawUrl, { allowPrivate = false } = {}) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return { valid: false, error: 'Target URL must be a non-empty string' };
  }

  const permitPrivate = Boolean(allowPrivate);
  const trimmed = rawUrl.trim();

  // Reject backslash before ? or # (authority confusion bypasses)
  const preQueryHash = trimmed.split(/[?#]/)[0];
  if (preQueryHash.includes('\\')) {
    return {
      valid: false,
      error: 'Backslash characters in URL authority or path are blocked'
    };
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, error: `Invalid URL format: "${rawUrl}"` };
  }

  // 1. Protocol check: only http: and https: allowed
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      error: `Protocol "${parsed.protocol}" is not supported; only http: and https: are permitted`
    };
  }

  // 2. Credentials check: block URLs containing username or password
  if (parsed.username || parsed.password) {
    return {
      valid: false,
      error: 'URLs containing credentials (username or password) are not allowed'
    };
  }

  // Extract raw hostname for obfuscation detection
  const rawHostMatch = trimmed.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '').split(/[/?#]/)[0];
  const rawHost = rawHostMatch.includes('@') ? rawHostMatch.split('@').pop() : rawHostMatch;
  const rawHostNoPort = (rawHost || '').replace(/:\d*$/, '').replace(/^\[|\]$/g, '').replace(/\.+$/, '');

  if (isNumericOrObfuscatedHost(rawHostNoPort)) {
    return {
      valid: false,
      error: `Obfuscated, hex, octal, or integer IP representations are blocked: "${rawHostNoPort}"`
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    return { valid: false, error: 'Target URL must have a valid hostname' };
  }

  const cleanDomain = hostname.replace(/\.+$/, '');
  const cleanHost = cleanDomain.replace(/^\[|\]$/g, '');

  // 2b. Always block cloud metadata hostnames/IPs even when allowPrivate: true
  if (isForbiddenMetadataHost(cleanDomain)) {
    return {
      valid: false,
      error: `Cloud metadata or forbidden hostname is blocked: "${hostname}"`
    };
  }

  // 3. Block loopback and local/internal domain names unless allowPrivate is enabled
  if (
    !permitPrivate &&
    (cleanDomain === 'localhost' ||
      cleanDomain.endsWith('.localhost') ||
      cleanDomain === 'local' ||
      cleanDomain.endsWith('.local') ||
      cleanDomain === 'internal' ||
      cleanDomain.endsWith('.internal'))
  ) {
    return {
      valid: false,
      error: `Internal or loopback hostname is blocked: "${hostname}"`
    };
  }

  // 4. IPv6 checks: always block metadata/unspecified/link-local/multicast/tunneling;
  //    block loopback/ULA/private ranges unless allowPrivate is enabled
  if (cleanHost.includes(':')) {
    if (isMetadataOrForbiddenIP(cleanHost)) {
      return {
        valid: false,
        error: `Cloud metadata or forbidden IPv6 address is blocked: "${hostname}"`
      };
    }
    if (
      !permitPrivate &&
      (cleanHost === '::1' ||
        cleanHost === '::' ||
        cleanHost === '0::1' ||
        cleanHost === '0::0' ||
        cleanHost.startsWith('::') || // ::/96 deprecated IPv4-compatible, loopback, unspecified
        cleanHost.startsWith('::ffff:') ||
        cleanHost.includes(':ffff:') ||
        cleanHost.startsWith('64:ff9b:') || // NAT64 (RFC 6052 / RFC 8215)
        cleanHost.startsWith('2002:') || // 6to4 (RFC 3056)
        cleanHost.startsWith('2001:0:') || // Teredo (RFC 4380)
        cleanHost.startsWith('2001::') || // Teredo
        cleanHost.startsWith('2001:db8:') || // documentation (RFC 3849)
        cleanHost.startsWith('2001:2:') || // benchmarking (RFC 5180)
        cleanHost.startsWith('fc') || // unique-local (fc00::/7)
        cleanHost.startsWith('fd') || // unique-local (fd00::/8)
        cleanHost.startsWith('fe8') || // link-local (fe80::/10)
        cleanHost.startsWith('fe9') ||
        cleanHost.startsWith('fea') ||
        cleanHost.startsWith('feb') ||
        cleanHost.startsWith('ff') || // multicast (ff00::/8)
        voidsExemption(cleanHost))
    ) {
      return {
        valid: false,
        error: `Private, loopback, or internal IPv6 address is blocked: "${hostname}"`
      };
    }
  }

  // 5. IPv4 checks: always block 0.0.0.0/8, 169.254.0.0/16, 100.100.100.200, 224.0.0.0/4+;
  //    block RFC1918 / loopback / CGNAT unless allowPrivate is enabled
  const ipv4Match = cleanHost.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [o1, o2, o3, o4] = ipv4Match.slice(1).map(Number);
    if ([o1, o2, o3, o4].some(o => o > 255)) {
      return { valid: false, error: `Invalid IPv4 address: "${hostname}"` };
    }
    if (isMetadataOrForbiddenIP(cleanHost)) {
      return {
        valid: false,
        error: `Cloud metadata or forbidden IPv4 address is blocked: "${hostname}"`
      };
    }
    if (
      !permitPrivate &&
      (o1 === 0 || // 0.0.0.0/8
        o1 === 127 || // 127.0.0.0/8 loopback
        o1 === 10 || // 10.0.0.0/8 private
        (o1 === 172 && o2 >= 16 && o2 <= 31) || // 172.16.0.0/12 private
        (o1 === 192 && o2 === 168) || // 192.168.0.0/16 private
        (o1 === 169 && o2 === 254) || // 169.254.0.0/16 link-local & cloud metadata
        (o1 === 100 && o2 >= 64 && o2 <= 127) || // 100.64.0.0/10 Carrier-Grade NAT (CGNAT)
        isPrivateOrReservedIPv4Octets(o1, o2, o3, o4))
    ) {
      return {
        valid: false,
        error: `Private, loopback, or metadata IPv4 address is blocked: "${hostname}"`
      };
    }
  }

  // Strip trailing slashes on normalized URL
  const normalized = parsed.toString().replace(/\/+$/, '');

  return {
    valid: true,
    normalized,
    hostname: parsed.hostname
  };
}

/**
 * Validates an array of target URLs.
 *
 * @param {string[]} targets
 * @param {{ allowPrivate?: boolean }} [options]
 * @returns {{ valid: boolean, targets: string[], errors: string[] }}
 */
export function validateTargets(targets, { allowPrivate = false } = {}) {
  if (!Array.isArray(targets) || targets.length === 0) {
    return {
      valid: false,
      targets: [],
      errors: ['No target URLs provided']
    };
  }

  const validTargets = [];
  const errors = [];

  for (const t of targets) {
    const res = validateTargetUrl(t, { allowPrivate });
    if (!res.valid) {
      errors.push(res.error);
    } else {
      validTargets.push(res.normalized);
    }
  }

  return {
    valid: errors.length === 0,
    targets: validTargets,
    errors
  };
}

/**
 * Normalizes the output of dns.promises.lookup or custom unit test resolvers into a string[] of IPs.
 */
function normalizeResolvedIps(rawResult) {
  if (!rawResult) return [];
  const list = Array.isArray(rawResult) ? rawResult : [rawResult];
  const ips = [];
  for (const item of list) {
    if (typeof item === 'string' && item.trim()) {
      ips.push(item.trim().replace(/^\[|\]$/g, ''));
    } else if (item && typeof item === 'object' && typeof item.address === 'string') {
      ips.push(item.address.trim().replace(/^\[|\]$/g, ''));
    }
  }
  return Array.from(new Set(ips));
}

/**
 * Resolves a target URL's hostname via DNS and validates that none of the resolved IPs
 * fall into private, loopback, link-local, metadata, or reserved ranges, while optionally
 * pinning resolved IPs in targetPinStore to prevent mid-scan DNS rebinding.
 *
 * @param {string} rawUrl
 * @param {{ resolver?: Function | object, allowPrivate?: boolean, targetPinStore?: object }} [options]
 * @returns {Promise<{ valid: boolean, url?: string, normalized?: string, hostname?: string, resolvedIps?: string[], reason?: string, error?: string, code?: string }>}
 */
export async function resolveAndValidateTarget(
  rawUrl,
  { resolver, allowPrivate = false, targetPinStore } = {}
) {
  const permitPrivate = Boolean(allowPrivate);
  const baseValidation = validateTargetUrl(rawUrl, { allowPrivate: permitPrivate });

  if (!baseValidation.valid) {
    const isPrivateOrMetadataErr = /Private, loopback, or|Internal or loopback|Cloud metadata or forbidden/i.test(
      baseValidation.error || ''
    );
    return {
      valid: false,
      reason: baseValidation.error,
      error: baseValidation.error,
      code: isPrivateOrMetadataErr ? 'DNS_REBIND_OR_PRIVATE_IP' : 'INVALID_TARGET_URL'
    };
  }

  const normalizedUrl = baseValidation.normalized;
  const hostname = baseValidation.hostname.toLowerCase();
  const cleanHost = hostname.replace(/\.+$/, '').replace(/^\[|\]$/g, '');

  // Check if hostname is already an IPv4 or IPv6 literal
  const ipVersion = net.isIP(cleanHost);
  let resolvedIps = [];

  if (ipVersion !== 0) {
    resolvedIps = [cleanHost];
  } else {
    try {
      let rawLookup;
      if (typeof resolver === 'function') {
        rawLookup = await resolver(cleanHost, { all: true });
      } else if (resolver && typeof resolver.lookup === 'function') {
        rawLookup = await resolver.lookup(cleanHost, { all: true });
      } else if (resolver && typeof resolver.resolve === 'function') {
        rawLookup = await resolver.resolve(cleanHost);
      } else {
        rawLookup = await dnsPromises.lookup(cleanHost, { all: true });
      }
      resolvedIps = normalizeResolvedIps(rawLookup);
    } catch (err) {
      const reason = `DNS resolution failed for "${cleanHost}": ${err.message || String(err)}`;
      return {
        valid: false,
        hostname: cleanHost,
        reason,
        error: reason,
        code: 'DNS_RESOLUTION_FAILED'
      };
    }
  }

  if (!resolvedIps || resolvedIps.length === 0) {
    const reason = `DNS resolution returned no IP addresses for "${cleanHost}"`;
    return {
      valid: false,
      hostname: cleanHost,
      reason,
      error: reason,
      code: 'DNS_RESOLUTION_FAILED'
    };
  }

  // Always reject metadata/forbidden IPs even when allowPrivate: true;
  // reject private/loopback/reserved IPs when !allowPrivate
  for (const ip of resolvedIps) {
    if (isMetadataOrForbiddenIP(ip)) {
      const reason = `Target "${cleanHost}" resolved to forbidden metadata or reserved IP address "${ip}" (SSRF protection)`;
      return {
        valid: false,
        hostname: cleanHost,
        resolvedIps,
        reason,
        error: reason,
        code: 'DNS_REBIND_OR_PRIVATE_IP'
      };
    }
    if (!permitPrivate && voidsExemption(ip)) {
      const reason = `Target "${cleanHost}" resolved to private or reserved IP address "${ip}" (DNS rebinding / SSRF protection)`;
      return {
        valid: false,
        hostname: cleanHost,
        resolvedIps,
        reason,
        error: reason,
        code: 'DNS_REBIND_OR_PRIVATE_IP'
      };
    }
  }

  // Verify or record DNS pin if targetPinStore is provided
  if (targetPinStore && typeof targetPinStore.verifyOrPin === 'function') {
    const pinResult = targetPinStore.verifyOrPin(cleanHost, resolvedIps, { allowPrivate: permitPrivate });
    if (!pinResult || pinResult.valid === false || pinResult.allowed === false) {
      const reason = pinResult?.reason || `DNS pin verification failed for "${cleanHost}"`;
      return {
        valid: false,
        hostname: cleanHost,
        resolvedIps,
        reason,
        error: reason,
        code: pinResult?.code || 'DNS_REBIND_OR_PRIVATE_IP'
      };
    }
  }

  return {
    valid: true,
    url: normalizedUrl,
    normalized: normalizedUrl,
    hostname: cleanHost,
    resolvedIps
  };
}
