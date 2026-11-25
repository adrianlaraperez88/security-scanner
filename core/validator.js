import { URL } from 'node:url';
import net from 'node:net';
import tls from 'node:tls';
import dnsPromises from 'node:dns/promises';
import pLimit from 'p-limit';

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

    // IPv4-compatible (::/96), IPv4-mapped (::ffff:0:0/96), or IPv4-translated (::ffff:0:0:0/96)
    if (
      w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 &&
      ((w4 === 0 && (w5 === 0 || w5 === 0xffff)) || (w4 === 0xffff && w5 === 0))
    ) {
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

function stripOuterTargetDecorations(rawInput) {
  if (typeof rawInput !== 'string') return '';
  let s = rawInput.trim();
  if (!s) return '';

  let prev;
  do {
    prev = s;
    s = s.trim();
    s = s.replace(/^['"]+|['"]+$/g, '').trim();
    const schemeMatch = s.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([\s\S]*)$/);
    if (schemeMatch) {
      const [, scheme, rest] = schemeMatch;
      const tailRe = /[?#]/.test(rest) ? /\\+$/ : /[\\/]+$/;
      s = `${scheme}${rest.replace(tailRe, '')}`;
    } else {
      const tailRe = /[?#]/.test(s) ? /\\+$/ : /[\\/]+$/;
      s = s.replace(tailRe, '');
    }
  } while (s !== prev);

  return s;
}

function parseBareIpParts(rawInput) {
  const s = stripOuterTargetDecorations(rawInput);
  if (!s) return null;

  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s) || /^(?:javascript|data|vbscript|file):/i.test(s)) {
    return null;
  }
  if (/\s/.test(s)) {
    return null;
  }

  // Bare unbracketed IPv6 literal (e.g. ::1, 2001:db8::1, ::1/status)
  const sepIdx = s.search(/[/?#]/);
  const hostCandidate = sepIdx === -1 ? s : s.slice(0, sepIdx);
  const tailCandidate = sepIdx === -1 ? '' : s.slice(sepIdx);
  if (net.isIP(hostCandidate) === 6) {
    return {
      ip: hostCandidate,
      urlHost: `[${hostCandidate}]`,
      tail: tailCandidate,
      httpsUrl: `https://[${hostCandidate}]${tailCandidate}`,
      httpUrl: `http://[${hostCandidate}]${tailCandidate}`,
      isIPv6: true
    };
  }

  // Bracketed IPv6 without explicit :port (optional path/query/hash)
  const v6Match = s.match(/^\[([^\]]+)\](?::(\d+))?([/?#].*)?$/);
  if (v6Match && net.isIP(v6Match[1]) === 6) {
    if (v6Match[2]) return null;
    const ip = v6Match[1];
    const tail = v6Match[3] || '';
    return {
      ip,
      urlHost: `[${ip}]`,
      tail,
      httpsUrl: `https://[${ip}]${tail}`,
      httpUrl: `http://[${ip}]${tail}`,
      isIPv6: true
    };
  }

  // Bare IPv4 (allowing optional trailing dot) without explicit :port (optional path/query/hash)
  const v4Match = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})\.?(?::(\d+))?([/?#].*)?$/);
  if (v4Match && net.isIP(v4Match[1]) === 4) {
    if (v4Match[2]) return null;
    const ip = v4Match[1];
    const tail = v4Match[3] || '';
    return {
      ip,
      urlHost: ip,
      tail,
      httpsUrl: `https://${ip}${tail}`,
      httpUrl: `http://${ip}${tail}`,
      isIPv6: false
    };
  }

  return null;
}

/**
 * Returns true ONLY if `rawInput` (after stripping outer quotes and trailing slashes/backslashes)
 * is a literal IPv4 or IPv6 address with NO explicit scheme (`http://`, `https://`, etc.)
 * and NO explicit `:port`, optionally carrying a path/query/hash tail.
 *
 * @param {unknown} rawInput
 * @returns {boolean}
 */
export function isBareIpTarget(rawInput) {
  return parseBareIpParts(rawInput) !== null;
}

/**
 * Normalizes raw user target input (CLI, Web UI, API) into a clean http(s) URL string:
 * - Returns '' for null, undefined, non-string, or empty/quote-only inputs
 * - Iteratively strips outer whitespace, matching/unmatched outer quotes (' or "),
 *   and trailing backslashes/slashes on the target tail (never internal backslashes)
 * - Preserves explicit schemes (http://, https://, file://, javascript:, etc.)
 * - Infers http:// for bare IPv4, bare/bracketed IPv6 (bracketing bare IPv6), and localhost
 *   (using https:// when explicit port is :443 or :8443)
 * - Infers https:// for bare domains (or http:// when explicit port is :80)
 *
 * @param {unknown} rawInput
 * @returns {string}
 */
export function normalizeTargetInput(rawInput) {
  const s = stripOuterTargetDecorations(rawInput);
  if (!s) return '';

  // Preserve any explicit scheme (including non-HTTP schemes so validateTargetUrl rejects them)
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s) || /^(?:javascript|data|vbscript|file):/i.test(s)) {
    return s;
  }

  // Do not synthesize a scheme around whitespace-broken strings
  if (/\s/.test(s)) {
    return s;
  }

  // Bare unbracketed IPv6 literal (e.g. ::1, 2001:db8::1, ::1/status) -> http://[ipv6]...
  const sepIdx = s.search(/[/?#]/);
  const hostCandidate = sepIdx === -1 ? s : s.slice(0, sepIdx);
  const tailCandidate = sepIdx === -1 ? '' : s.slice(sepIdx);
  if (net.isIP(hostCandidate) === 6) {
    return `http://[${hostCandidate}]${tailCandidate}`;
  }

  // Bracketed IPv6 with optional :port and path/query/hash
  const v6Match = s.match(/^\[([^\]]+)\](?::(\d+))?(?:[/?#].*)?$/);
  if (v6Match && net.isIP(v6Match[1]) === 6) {
    const port = v6Match[2] || '';
    const scheme = port === '443' || port === '8443' ? 'https://' : 'http://';
    return `${scheme}${s}`;
  }

  // Bare IPv4 (allowing optional trailing dot) with optional :port and path/query/hash
  const v4Match = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})\.?(?::(\d+))?(?:[/?#].*)?$/);
  if (v4Match && net.isIP(v4Match[1]) === 4) {
    const port = v4Match[2] || '';
    const scheme = port === '443' || port === '8443' ? 'https://' : 'http://';
    return `${scheme}${s}`;
  }

  // localhost or *.localhost with optional trailing dot, :port, and path/query/hash
  const localMatch = s.match(/^(?:[a-zA-Z0-9-]+\.)*localhost\.?(?::(\d+))?(?:[/?#].*)?$/i);
  if (localMatch) {
    const port = localMatch[1] || '';
    const scheme = port === '443' || port === '8443' ? 'https://' : 'http://';
    return `${scheme}${s}`;
  }

  // Bare domain (e.g. nas.local, example.com): https:// by default, http:// if explicit :80
  const domPortMatch = s.match(/^[^/?#:]+:(\d+)(?:[/?#]|$)/);
  const domScheme = domPortMatch && domPortMatch[1] === '80' ? 'http://' : 'https://';
  return `${domScheme}${s}`;
}

/**
 * Validates a single target URL and enforces strict SSRF protections.
 *
 * @param {string} rawUrl
 * @param {{ allowPrivate?: boolean, normalize?: boolean }} [options]
 * @returns {{ valid: boolean, normalized?: string, hostname?: string, error?: string }}
 */
export function validateTargetUrl(rawUrl, { allowPrivate = false, normalize = false } = {}) {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
    return { valid: false, error: 'Target URL must be a non-empty string' };
  }

  const candidate = normalize ? normalizeTargetInput(rawUrl) : rawUrl;
  if (typeof candidate !== 'string' || !candidate.trim()) {
    return { valid: false, error: 'Target URL must be a non-empty string' };
  }

  const permitPrivate = Boolean(allowPrivate);
  const trimmed = candidate.trim();

  // Reject ASCII control characters (including \t, \r, \n, \x00, \x7f) before new URL()
  // so WHATWG URL parsing cannot strip them to smuggle obfuscated IPs or inject CRLF/NUL.
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) {
    return {
      valid: false,
      error: 'Control characters in target URL are blocked'
    };
  }

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
 * @param {{ allowPrivate?: boolean, normalize?: boolean }} [options]
 * @returns {{ valid: boolean, targets: string[], errors: string[] }}
 */
export function validateTargets(targets, { allowPrivate = false, normalize = true } = {}) {
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
    const res = validateTargetUrl(t, { allowPrivate, normalize });
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
 * Canonicalizes a single IP string:
 * - trims whitespace and brackets `[` `]`
 * - strips IPv6 zone index (`%eth0`)
 * - unmaps IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1` or `::ffff:c000:0201` -> `192.0.2.1`)
 * - lowercases IPv6 hex digits
 * Returns `''` if the input is not a valid IPv4 or IPv6 literal.
 *
 * @param {string} rawIp
 * @returns {string}
 */
export function canonicalizeIpAddress(rawIp) {
  if (typeof rawIp !== 'string' || !rawIp.trim()) return '';
  let ip = rawIp.trim().replace(/^\[|\]$/g, '');
  const zoneIdx = ip.indexOf('%');
  if (zoneIdx !== -1) {
    ip = ip.slice(0, zoneIdx);
  }
  ip = ip.toLowerCase();

  // Standard IPv4
  const ipv4Match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const octets = ipv4Match.slice(1).map(Number);
    if (octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)) return '';
    return octets.join('.');
  }

  // IPv6 (including IPv4-mapped IPv6 ::ffff:a.b.c.d or ::ffff:xxxx:yyyy)
  if (ip.includes(':')) {
    const words = expandIPv6(ip);
    if (!words) return '';
    const [w0, w1, w2, w3, w4, w5, w6, w7] = words;
    // Unmap IPv4-mapped IPv6 (::ffff:0:0/96)
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0xffff) {
      const o1 = (w6 >> 8) & 0xff;
      const o2 = w6 & 0xff;
      const o3 = (w7 >> 8) & 0xff;
      const o4 = w7 & 0xff;
      return `${o1}.${o2}.${o3}.${o4}`;
    }
    return net.isIP(ip) === 6 ? ip : '';
  }

  return '';
}

/**
 * Normalizes and canonicalizes the output of dns.promises.lookup or custom resolvers
 * into a sorted, deduplicated array of canonical IP strings (mirroring SecScan `canonicalIPs`
 * in `intercept/target_resolve.go`).
 *
 * @param {unknown} rawResult
 * @returns {string[]}
 */
export function canonicalizeResolvedIps(rawResult) {
  if (!rawResult) return [];
  const list = Array.isArray(rawResult) ? rawResult : [rawResult];
  const ips = [];
  for (const item of list) {
    let candidate = '';
    if (typeof item === 'string' && item.trim()) {
      candidate = item.trim();
    } else if (item && typeof item === 'object' && typeof item.address === 'string') {
      candidate = item.address.trim();
    }
    if (!candidate) continue;
    const canonical = canonicalizeIpAddress(candidate) || candidate.replace(/^\[|\]$/g, '');
    if (canonical) {
      ips.push(canonical);
    }
  }
  const unique = Array.from(new Set(ips));
  unique.sort();
  return unique;
}

function normalizeResolvedIps(rawResult) {
  return canonicalizeResolvedIps(rawResult);
}

/**
 * Parses an explicit Source-IP / Origin-IP override specification (`--source-ip`, `sourceIp`, `sourceIpMap`).
 * Supports:
 * - Single IP literal: `"203.0.113.50"` or `"[2001:db8::1]"` -> `{ defaultIps: ["203.0.113.50"], hostMap: Map }`
 * - Comma-separated host mappings: `"example.com=203.0.113.50,api.example.com=203.0.113.51|203.0.113.52"`
 * - Object map: `{ "example.com": "203.0.113.50", "*": ["203.0.113.50"] }`
 *
 * @param {string | string[] | Record<string, string | string[]> | null | undefined} sourceIpInput
 * @returns {{ defaultIps: string[], hostMap: Map<string, string[]>, invalidEntries: string[] }}
 */
export function parseSourceIpMap(sourceIpInput) {
  const defaultIps = [];
  const hostMap = new Map();
  const invalidEntries = [];

  if (!sourceIpInput) {
    return { defaultIps, hostMap, invalidEntries };
  }

  const addHostIps = (rawHost, rawIps) => {
    const cleanHost = String(rawHost || '')
      .trim()
      .toLowerCase()
      .replace(/\.+$/, '')
      .replace(/^\[|\]$/g, '');
    const tokens = Array.isArray(rawIps)
      ? rawIps
      : String(rawIps || '')
          .split(/[|;\s]+/)
          .map(s => s.trim())
          .filter(Boolean);
    const validIps = [];
    for (const tok of tokens) {
      const canon = canonicalizeIpAddress(tok);
      if (canon) {
        validIps.push(canon);
      } else {
        invalidEntries.push(tok);
      }
    }
    if (validIps.length === 0) return;
    if (!cleanHost || cleanHost === '*' || cleanHost === 'default') {
      for (const ip of validIps) {
        if (!defaultIps.includes(ip)) defaultIps.push(ip);
      }
    } else {
      const existing = hostMap.get(cleanHost) || [];
      for (const ip of validIps) {
        if (!existing.includes(ip)) existing.push(ip);
      }
      hostMap.set(cleanHost, existing);
    }
  };

  if (typeof sourceIpInput === 'object' && !Array.isArray(sourceIpInput)) {
    for (const [k, v] of Object.entries(sourceIpInput)) {
      addHostIps(k, v);
    }
    return { defaultIps, hostMap, invalidEntries };
  }

  const rawEntries = Array.isArray(sourceIpInput)
    ? sourceIpInput.flatMap(item => String(item || '').split(','))
    : String(sourceIpInput).split(',');

  for (const rawEntry of rawEntries) {
    const entry = rawEntry.trim();
    if (!entry) continue;
    const eqIdx = entry.indexOf('=');
    if (eqIdx !== -1) {
      const hostPart = entry.slice(0, eqIdx).trim();
      const ipPart = entry.slice(eqIdx + 1).trim();
      addHostIps(hostPart, ipPart);
    } else {
      addHostIps('*', entry);
    }
  }

  return { defaultIps, hostMap, invalidEntries };
}

/**
 * Resolves any explicit Source-IP override configured for `hostname`.
 *
 * @param {string} hostname
 * @param {{ sourceIp?: unknown, sourceIpMap?: unknown }} [options]
 * @returns {string[]}
 */
export function resolveConfiguredSourceIps(hostname, { sourceIp = null, sourceIpMap = null } = {}) {
  const cleanHost = String(hostname || '')
    .trim()
    .toLowerCase()
    .replace(/\.+$/, '')
    .replace(/^\[|\]$/g, '');

  const combined = [];
  for (const spec of [sourceIp, sourceIpMap]) {
    if (!spec) continue;
    const parsed = parseSourceIpMap(spec);
    if (cleanHost && parsed.hostMap.has(cleanHost)) {
      for (const ip of parsed.hostMap.get(cleanHost)) {
        if (!combined.includes(ip)) combined.push(ip);
      }
      continue;
    }
    // Check wildcard suffix match in hostMap (e.g. *.example.com)
    let matchedWildcard = false;
    for (const [pattern, ips] of parsed.hostMap.entries()) {
      if (pattern.startsWith('*.')) {
        const suffix = pattern.slice(2);
        if (cleanHost === suffix || cleanHost.endsWith(`.${suffix}`)) {
          for (const ip of ips) {
            if (!combined.includes(ip)) combined.push(ip);
          }
          matchedWildcard = true;
        }
      }
    }
    if (!matchedWildcard && parsed.defaultIps.length > 0) {
      for (const ip of parsed.defaultIps) {
        if (!combined.includes(ip)) combined.push(ip);
      }
    }
  }
  return combined;
}

/**
 * SecScan DNS ResolveCache (`intercept/target_resolve.go`):
 * - Positive answers are cached per host for `ttlMs` (default 10s).
 * - Concurrent lookups for the same host coalesce into a single in-flight lookup (`flights`).
 * - `fresh: true` bypasses the cached entry and refreshes the cache with the new lookup result.
 * - Failed or empty lookups are never cached.
 * - Each lookup is bounded by `timeoutMs` (default 3s).
 */
export class ResolveCache {
  constructor({
    resolver = null,
    ttlMs = 10000,
    timeoutMs = 3000,
    now = () => Date.now()
  } = {}) {
    this.resolver = resolver;
    this.ttlMs = Number.isFinite(Number(ttlMs)) && Number(ttlMs) >= 0 ? Number(ttlMs) : 10000;
    this.timeoutMs = Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0 ? Number(timeoutMs) : 3000;
    this.now = typeof now === 'function' ? now : () => Date.now();
    this.entries = new Map();
    this.flights = new Map();
  }

  /**
   * Replaces the underlying resolver and clears cached entries.
   */
  use(resolver) {
    this.resolver = resolver;
    this.entries.clear();
  }

  clear() {
    this.entries.clear();
    this.flights.clear();
  }

  async _invokeResolver(cleanHost, customResolver = null) {
    const activeResolver = customResolver || this.resolver;
    let timer = null;
    const timeoutPromise = new Promise((_, reject) => {
      timer = setTimeout(() => {
        reject(new Error(`lookup timed out after ${this.timeoutMs}ms`));
      }, this.timeoutMs);
      if (typeof timer?.unref === 'function') timer.unref();
    });

    const lookupPromise = (async () => {
      if (typeof activeResolver === 'function') {
        return await activeResolver(cleanHost, { all: true });
      }
      if (activeResolver && typeof activeResolver.lookup === 'function') {
        return await activeResolver.lookup(cleanHost, { all: true });
      }
      if (activeResolver && typeof activeResolver.resolve === 'function') {
        return await activeResolver.resolve(cleanHost);
      }
      return await dnsPromises.lookup(cleanHost, { all: true });
    })();

    try {
      const raw = await Promise.race([lookupPromise, timeoutPromise]);
      const ips = canonicalizeResolvedIps(raw);
      if (ips.length === 0) {
        throw new Error('the lookup returned no address');
      }
      return ips;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /**
   * Resolves `host` into canonical sorted IPs, coalescing concurrent lookups.
   *
   * @param {string} host
   * @param {{ fresh?: boolean, resolver?: Function | object | null }} [options]
   * @returns {Promise<{ ips: string[], at: number, cached: boolean }>}
   */
  async lookup(host, { fresh = false, resolver = null } = {}) {
    const cleanHost = String(host || '')
      .trim()
      .toLowerCase()
      .replace(/\.+$/, '')
      .replace(/^\[|\]$/g, '');

    if (!cleanHost) {
      throw new Error('Hostname must be non-empty');
    }

    const literalCanon = canonicalizeIpAddress(cleanHost);
    if (literalCanon) {
      return { ips: [literalCanon], at: this.now(), cached: false };
    }

    const nowTs = this.now();
    if (!fresh && !resolver) {
      const entry = this.entries.get(cleanHost);
      if (entry && nowTs - entry.at < this.ttlMs) {
        return { ips: [...entry.ips], at: entry.at, cached: true };
      }
    }

    const flightKey = `${cleanHost}`;
    const existingFlight = this.flights.get(flightKey);
    if (existingFlight) {
      const res = await existingFlight;
      return { ips: [...res.ips], at: res.at, cached: false };
    }

    const flightPromise = (async () => {
      const ips = await this._invokeResolver(cleanHost, resolver);
      const record = { ips, at: this.now() };
      if (!resolver) {
        this.entries.set(cleanHost, record);
      }
      return record;
    })();

    this.flights.set(flightKey, flightPromise);
    try {
      const res = await flightPromise;
      return { ips: [...res.ips], at: res.at, cached: false };
    } finally {
      this.flights.delete(flightKey);
    }
  }
}

export const defaultResolveCache = new ResolveCache();

/**
 * Resolves a target URL's hostname via DNS (or explicit Source-IP override) and validates that none
 * of the resolved IPs fall into private, loopback, link-local, metadata, or reserved ranges, while
 * optionally pinning resolved IPs in targetPinStore to prevent mid-scan DNS rebinding.
 *
 * @param {string} rawUrl
 * @param {{
 *   resolver?: Function | object,
 *   resolveCache?: ResolveCache | null,
 *   fresh?: boolean,
 *   allowPrivate?: boolean,
 *   targetPinStore?: object,
 *   sourceIp?: unknown,
 *   sourceIpMap?: unknown
 * }} [options]
 * @returns {Promise<{ valid: boolean, url?: string, normalized?: string, hostname?: string, resolvedIps?: string[], primaryIp?: string, sourceIp?: string | null, sourceIpUsed?: boolean, reason?: string, error?: string, code?: string }>}
 */
export async function resolveAndValidateTarget(
  rawUrl,
  {
    resolver,
    resolveCache = null,
    fresh = false,
    allowPrivate = false,
    targetPinStore,
    sourceIp = null,
    sourceIpMap = null
  } = {}
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

  // Check if explicit Source-IP / Origin-IP override is configured for this host
  if (sourceIp || sourceIpMap) {
    const parsedA = sourceIp ? parseSourceIpMap(sourceIp) : { invalidEntries: [] };
    const parsedB = sourceIpMap ? parseSourceIpMap(sourceIpMap) : { invalidEntries: [] };
    const badEntries = [...parsedA.invalidEntries, ...parsedB.invalidEntries];
    if (badEntries.length > 0) {
      const reason = `Invalid source IP address "${badEntries[0]}" configured for "${cleanHost}"`;
      return {
        valid: false,
        hostname: cleanHost,
        reason,
        error: reason,
        code: 'INVALID_SOURCE_IP'
      };
    }
  }

  const configuredSourceIps = resolveConfiguredSourceIps(cleanHost, { sourceIp, sourceIpMap });
  const ipVersion = net.isIP(cleanHost);
  let resolvedIps = [];
  let sourceIpUsed = false;

  if (configuredSourceIps.length > 0) {
    resolvedIps = configuredSourceIps;
    sourceIpUsed = true;
  } else if (ipVersion !== 0) {
    resolvedIps = canonicalizeResolvedIps([cleanHost]);
  } else {
    try {
      if (resolveCache && typeof resolveCache.lookup === 'function') {
        const cachedRes = await resolveCache.lookup(cleanHost, { fresh, resolver });
        resolvedIps = cachedRes.ips;
      } else {
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
      }
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
    resolvedIps,
    primaryIp: resolvedIps[0] || null,
    sourceIp: sourceIpUsed ? (resolvedIps[0] || null) : null,
    sourceIpUsed
  };
}

const TLS_REACHABLE_ERROR_CODES = new Set([
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_HAS_EXPIRED',
  'CERT_NOT_YET_VALID',
  'CERT_REVOKED',
  'CERT_UNTRUSTED',
  'CERT_REJECTED',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'HOSTNAME_MISMATCH',
  'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE',
  'ERR_SSL_TLSV1_ALERT_INTERNAL_ERROR',
  'ERR_SSL_TLSV1_UNRECOGNIZED_NAME'
]);

const TLS_NON_TLS_ERROR_CODES = new Set([
  'ERR_SSL_WRONG_VERSION_NUMBER',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'UND_ERR_CONNECT_TIMEOUT'
]);

const TLS_REACHABLE_MSG_RE = /certificate|altname|Hostname\/IP does not match|self[- ]signed|unable to verify|cert_has_expired|ERR_TLS_CERT_ALTNAME_INVALID|handshake failure|SSL alert number 40|ssl\/tls alert|sslv3 alert|tlsv1 alert|unrecognized name/i;
const TLS_NON_TLS_MSG_RE = /wrong version number|ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|timed?\s*out|aborted/i;
const TLS_SNI_ALERT_CODES = new Set([
  'ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE',
  'ERR_SSL_TLSV1_ALERT_UNRECOGNIZED_NAME',
  'ERR_SSL_TLS_ALERT_HANDSHAKE_FAILURE'
]);
const TLS_SNI_ALERT_MSG_RE = /SSL alert number 40|ssl\/tls alert handshake failure|sslv3 alert handshake failure|tlsv1 alert unrecognized name|ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE|ERR_SSL_TLSV1_ALERT_UNRECOGNIZED_NAME|handshake failure|unrecognized name/i;

function isTlsReachableError(err) {
  if (!err || typeof err !== 'object') return false;
  const seen = new Set();
  const queue = [err];
  let idx = 0;
  let sawTlsIndicator = false;

  while (idx < queue.length && idx < 32) {
    const node = queue[idx++];
    if (!node || typeof node !== 'object' || seen.has(node)) continue;
    seen.add(node);

    const code = String(node.code || '');
    const msg = String(node.message || '');
    if (TLS_NON_TLS_ERROR_CODES.has(code) || TLS_NON_TLS_MSG_RE.test(msg)) {
      return false;
    }
    if (
      TLS_REACHABLE_ERROR_CODES.has(code) ||
      code.startsWith('ERR_TLS_') ||
      code.startsWith('ERR_SSL_') ||
      TLS_REACHABLE_MSG_RE.test(msg)
    ) {
      sawTlsIndicator = true;
    }

    if (node.cause && typeof node.cause === 'object' && !seen.has(node.cause)) {
      queue.push(node.cause);
    }
    if (Array.isArray(node.errors)) {
      for (const sub of node.errors) {
        if (sub && typeof sub === 'object' && !seen.has(sub)) {
          queue.push(sub);
        }
      }
    }
  }

  return sawTlsIndicator;
}

function isSniHandshakeRejectedError(err) {
  if (!err || typeof err !== 'object') return false;
  const seen = new Set();
  const queue = [err];
  let idx = 0;
  let sawSniAlert = false;

  while (idx < queue.length && idx < 32) {
    const node = queue[idx++];
    if (!node || typeof node !== 'object' || seen.has(node)) continue;
    seen.add(node);

    const code = String(node.code || '');
    const msg = String(node.message || '');
    if (TLS_NON_TLS_ERROR_CODES.has(code) || TLS_NON_TLS_MSG_RE.test(msg)) {
      return false;
    }
    if (
      TLS_SNI_ALERT_CODES.has(code) ||
      TLS_SNI_ALERT_MSG_RE.test(msg) ||
      (code === 'EPROTO' && TLS_SNI_ALERT_MSG_RE.test(msg))
    ) {
      sawSniAlert = true;
    }

    if (node.cause && typeof node.cause === 'object' && !seen.has(node.cause)) {
      queue.push(node.cause);
    }
    if (Array.isArray(node.errors)) {
      for (const sub of node.errors) {
        if (sub && typeof sub === 'object' && !seen.has(sub)) {
          queue.push(sub);
        }
      }
    }
  }

  return sawSniAlert;
}

function probeTlsSocket(host, port, timeoutMs) {
  return new Promise(resolve => {
    let settled = false;
    let socket = null;
    let timer = null;
    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      if (socket) {
        try { socket.setTimeout(0); } catch {}
        try { socket.destroy(); } catch {}
      }
      resolve(outcome);
    };

    try {
      socket = tls.connect(
        {
          host,
          port,
          rejectUnauthorized: false
        },
        () => finish({ reachable: true, httpStatusOk: true, sniHandshakeRejected: false })
      );
      timer = setTimeout(() => finish({ reachable: false, httpStatusOk: false, sniHandshakeRejected: false }), timeoutMs);
      timer.unref?.();
      socket.setTimeout(timeoutMs, () => finish({ reachable: false, httpStatusOk: false, sniHandshakeRejected: false }));
      socket.on('error', (err) => {
        const reachable = isTlsReachableError(err);
        const sniHandshakeRejected = reachable && isSniHandshakeRejectedError(err);
        finish({
          reachable,
          httpStatusOk: reachable && !sniHandshakeRejected,
          sniHandshakeRejected
        });
      });
    } catch (err) {
      const reachable = isTlsReachableError(err);
      const sniHandshakeRejected = reachable && isSniHandshakeRejectedError(err);
      finish({
        reachable,
        httpStatusOk: reachable && !sniHandshakeRejected,
        sniHandshakeRejected
      });
    }
  });
}

function isTcpProbeOpen(res) {
  return res === true || Boolean(res && res.open === true);
}

/**
 * Resolves bare IP targets (scheme-less, port-less literal IPv4/IPv6) by validating
 * SSRF & Asset Gate policies first and then probing HTTPS (443) and HTTP (80) reachability
 * in parallel.
 *
 * Non-bare-IP targets are normalized synchronously via `normalizeTargetInput()` without probing.
 *
 * @param {string[]} rawTargets
 * @param {{
 *   allowPrivate?: boolean,
 *   scopeRules?: Array<object> | null,
 *   guard?: object | Array<object> | Function | null,
 *   fetcher?: Function | null,
 *   tcpProbe?: Function | null,
 *   timeoutMs?: number,
 *   timeout?: number,
 *   sourceIp?: unknown,
 *   sourceIpMap?: unknown,
 *   dnsResolver?: Function | object | null,
 *   resolver?: Function | object | null,
 *   resolveCache?: ResolveCache | null
 * }} [options]
 * @returns {Promise<{
 *   targets: string[],
 *   probeSummary: Map<string, { httpsReachable: boolean, httpReachable: boolean, resolvedTargets: string[], blocked?: boolean }>
 * }>}
 */
export async function resolveBareIpTargets(rawTargets, options = {}) {
  options = options && typeof options === 'object' ? options : {};
  const probeSummary = new Map();
  if (!Array.isArray(rawTargets) || rawTargets.length === 0) {
    return { targets: [], probeSummary };
  }

  const allowPrivate = Boolean(options.allowPrivate);
  const scopeRules = Array.isArray(options.scopeRules) ? options.scopeRules : null;
  const guard = options.guard ?? null;
  const sourceIp = options.sourceIp ?? null;
  const sourceIpMap = options.sourceIpMap ?? null;
  const dnsResolver = options.dnsResolver ?? options.resolver ?? null;
  const resolveCache = options.resolveCache ?? null;

  const rawTimeout = Number(options.timeoutMs ?? options.timeout);
  const probeTimeout = Number.isFinite(rawTimeout) && rawTimeout > 0
    ? Math.min(rawTimeout, 3500)
    : 3500;

  const parsedConcurrency = Number(options.concurrency);
  const entryConcurrency = Number.isFinite(parsedConcurrency) && parsedConcurrency > 0
    ? Math.min(8, Math.max(1, Math.floor(parsedConcurrency)))
    : 6;
  const entryLimit = pLimit(entryConcurrency);

  const customTcpProbe = typeof options.tcpProbe === 'function' ? options.tcpProbe : null;
  const rawFetcher = typeof options.fetcher === 'function' ? options.fetcher : null;
  const hasCustomFetcher = Boolean(
    rawFetcher &&
    !rawFetcher.isDefaultFetch &&
    !(rawFetcher.governance && !rawFetcher.hasCustomFetcher)
  );

  let fetchModPromise = null;
  const getFetchMod = () => {
    if (!fetchModPromise) fetchModPromise = import('./fetch.js');
    return fetchModPromise;
  };

  let deviceModPromise = null;
  const getDeviceMod = () => {
    if (!deviceModPromise) deviceModPromise = import('./device-scanner.js');
    return deviceModPromise;
  };

  const evaluateCandidateGovernance = async (bare) => {
    const httpsCheck = validateTargetUrl(bare.httpsUrl, { allowPrivate });
    const httpCheck = validateTargetUrl(bare.httpUrl, { allowPrivate });
    if (!httpsCheck.valid || !httpCheck.valid) {
      return { allowed: false, httpsAllowed: false, httpAllowed: false, probeHost: bare.ip };
    }

    const dnsRes = await resolveAndValidateTarget(bare.httpUrl, {
      resolver: dnsResolver,
      resolveCache,
      allowPrivate,
      sourceIp,
      sourceIpMap
    });
    if (!dnsRes.valid) {
      return { allowed: false, httpsAllowed: false, httpAllowed: false, probeHost: bare.ip };
    }

    const resolvedIps = Array.isArray(dnsRes.resolvedIps) && dnsRes.resolvedIps.length > 0
      ? dnsRes.resolvedIps
      : [bare.ip];
    const probeHost = dnsRes.primaryIp || resolvedIps[0] || bare.ip;

    const { runAssetGateCheck } = await getFetchMod();
    const checkGate = (candidateUrl) => {
      const preGate = runAssetGateCheck(candidateUrl, { guard, scopeRules, alwaysBuiltin: true });
      if (preGate && preGate.allowed === false) return false;
      const postGate = runAssetGateCheck(
        { url: candidateUrl, hostname: bare.ip, resolvedIps },
        { guard, scopeRules, alwaysBuiltin: true }
      );
      if (postGate && postGate.allowed === false) return false;
      return true;
    };

    const httpsAllowed = checkGate(bare.httpsUrl);
    const httpAllowed = checkGate(bare.httpUrl);
    return {
      allowed: httpsAllowed || httpAllowed,
      httpsAllowed,
      httpAllowed,
      probeHost
    };
  };

  const probeHttpSchemeViaFetcher = async (candidateUrl, isHttps, fetcherImpl) => {
    const { fetchWithRetry } = await getFetchMod();
    try {
      const res = await fetchWithRetry(candidateUrl, {
        retries: 0,
        failFast: true,
        followRedirects: false,
        timeout: probeTimeout,
        maxBytes: 4096,
        allowPrivate,
        guard,
        scopeRules,
        dnsResolver,
        resolveCache,
        sourceIp,
        sourceIpMap,
        ...(fetcherImpl ? { fetcher: fetcherImpl } : {})
      });
      const httpStatusOk = Number(res?.status) >= 100;
      return {
        reachable: httpStatusOk,
        httpStatusOk,
        sniHandshakeRejected: false
      };
    } catch (err) {
      if (err?.isGovernanceBlock) {
        return { reachable: false, httpStatusOk: false, sniHandshakeRejected: false };
      }
      if (isHttps && isTlsReachableError(err)) {
        const sniHandshakeRejected = isSniHandshakeRejectedError(err);
        return {
          reachable: true,
          httpStatusOk: !sniHandshakeRejected,
          sniHandshakeRejected
        };
      }
      return { reachable: false, httpStatusOk: false, sniHandshakeRejected: false };
    }
  };

  const probePairCache = new Map();

  const probeScheme = async (isHttps, port, candidateUrl, probeHost) => {
    if (customTcpProbe) {
      let tcpRes;
      try {
        tcpRes = await customTcpProbe(probeHost, port, { timeoutMs: probeTimeout });
      } catch {
        return { reachable: false, httpStatusOk: false, sniHandshakeRejected: false };
      }
      if (!isTcpProbeOpen(tcpRes)) {
        return { reachable: false, httpStatusOk: false, sniHandshakeRejected: false };
      }
      if (hasCustomFetcher) {
        return await probeHttpSchemeViaFetcher(candidateUrl, isHttps, rawFetcher);
      }
      return { reachable: true, httpStatusOk: true, sniHandshakeRejected: false };
    }

    if (hasCustomFetcher) {
      return await probeHttpSchemeViaFetcher(candidateUrl, isHttps, rawFetcher);
    }

    // Live run: fast TCP precheck + HTTP/HTTPS verification (with TLS handshake fallback for 443)
    const { probeSingleTcpPort } = await getDeviceMod();
    const tcpTimeout = Math.min(probeTimeout, 2000);
    const tcpRes = await probeSingleTcpPort(probeHost, port, {
      timeoutMs: tcpTimeout,
      bannerTimeoutMs: 40
    });
    if (!isTcpProbeOpen(tcpRes)) {
      return { reachable: false, httpStatusOk: false, sniHandshakeRejected: false };
    }

    const httpOutcome = await probeHttpSchemeViaFetcher(candidateUrl, isHttps, null);
    if (httpOutcome.reachable) return httpOutcome;

    if (isHttps) {
      return await probeTlsSocket(probeHost, port, Math.min(probeTimeout, 2000));
    }
    return { reachable: false, httpStatusOk: false, sniHandshakeRejected: false };
  };

  const resolveSingleEntry = async (raw) => {
    if (!isBareIpTarget(raw)) {
      if (typeof raw !== 'string') return [raw];
      const norm = normalizeTargetInput(raw);
      return [norm || raw.trim()];
    }

    const bare = parseBareIpParts(raw);
    const fallbackUrl = normalizeTargetInput(raw) || bare.httpUrl;
    const summaryKey = String(raw);

    // Run SSRF & Asset Gate governance per target entry (supporting path-aware scopeRules)
    const gov = await evaluateCandidateGovernance(bare);
    if (!gov.allowed) {
      const blockedTargets = [fallbackUrl];
      probeSummary.set(summaryKey, {
        httpsReachable: false,
        httpReachable: false,
        httpsSniRequired: false,
        resolvedTargets: [...blockedTargets],
        blocked: true
      });
      return blockedTargets;
    }

    // Key probe cache on bare IP origin (without path/query/hash tail) and deduplicate
    // concurrent in-flight origin scheme probes via shared promises.
    const originCacheKey = bare.urlHost.toLowerCase();
    let originCache = probePairCache.get(originCacheKey);
    if (!originCache) {
      originCache = { httpsPromise: null, httpPromise: null };
      probePairCache.set(originCacheKey, originCache);
    }

    if (gov.httpsAllowed && !originCache.httpsPromise) {
      originCache.httpsPromise = probeScheme(true, 443, bare.httpsUrl, gov.probeHost);
    }
    if (gov.httpAllowed && !originCache.httpPromise) {
      originCache.httpPromise = probeScheme(false, 80, bare.httpUrl, gov.probeHost);
    }

    const [rawHttpsProbe, rawHttpProbe] = await Promise.all([
      gov.httpsAllowed
        ? originCache.httpsPromise
        : Promise.resolve({ reachable: false, httpStatusOk: false, sniHandshakeRejected: false }),
      gov.httpAllowed
        ? originCache.httpPromise
        : Promise.resolve({ reachable: false, httpStatusOk: false, sniHandshakeRejected: false })
    ]);

    const httpsReachable = Boolean(gov.httpsAllowed && rawHttpsProbe?.reachable);
    const httpsSniRequired = Boolean(httpsReachable && rawHttpsProbe?.sniHandshakeRejected);
    const httpReachable = Boolean(gov.httpAllowed && rawHttpProbe?.reachable);

    let resolvedTargets;
    if (httpsReachable && httpReachable) {
      resolvedTargets = [bare.httpsUrl, bare.httpUrl];
    } else if (httpsReachable) {
      resolvedTargets = [bare.httpsUrl];
    } else if (httpReachable) {
      resolvedTargets = [bare.httpUrl];
    } else if (gov.httpsAllowed && !gov.httpAllowed) {
      resolvedTargets = [bare.httpsUrl];
    } else {
      resolvedTargets = [fallbackUrl];
    }

    probeSummary.set(summaryKey, {
      httpsReachable,
      httpReachable,
      httpsSniRequired,
      resolvedTargets: [...resolvedTargets]
    });
    return resolvedTargets;
  };

  const expandedGroups = await Promise.all(
    rawTargets.map(raw => entryLimit(() => resolveSingleEntry(raw)))
  );
  const seen = new Set();
  const dedupedTargets = [];
  for (const group of expandedGroups) {
    for (const targetUrl of group) {
      if (typeof targetUrl === 'string') {
        const key = targetUrl.replace(/\/+$/, '');
        if (seen.has(key)) continue;
        seen.add(key);
        dedupedTargets.push(targetUrl);
      } else if (!seen.has(targetUrl)) {
        seen.add(targetUrl);
        dedupedTargets.push(targetUrl);
      }
    }
  }

  return { targets: dedupedTargets, probeSummary };
}
