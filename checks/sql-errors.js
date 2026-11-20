import { URL } from 'node:url';
import {
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['all'];

const GOVERNANCE_ERROR_CODES = new Set([
  'SSRF_POLICY_BLOCKED',
  'TARGET_RULE_BLOCKED',
  'TARGET_OUT_OF_SCOPE',
  'DNS_REBIND_OR_PRIVATE_IP'
]);

function isGovernanceBlockError(err) {
  if (!err) return false;
  if (err.isGovernanceBlock === true) return true;
  if (GOVERNANCE_ERROR_CODES.has(err.code)) return true;
  const msg = typeof err.message === 'string' ? err.message : '';
  return (
    msg.startsWith('Redirect blocked by SSRF policy') ||
    msg.startsWith('Request blocked by SSRF policy') ||
    msg.startsWith('[SECSCAN platform control')
  );
}

/**
 * SQL error disclosure check.
 *
 * Appends a single quote to common query parameters and scans the response
 * for database-specific error messages (filtering out patterns already present
 * on the unmodified baseline response).
 */
const TEST_PROBES = [
  { param: 'id',     value: "'",  label: "?id='" },
  { param: 'q',      value: "'",  label: "?q='" },
  { param: 'search', value: "'",  label: "?search='" },
  { param: 'query',  value: "'",  label: "?query='" },
  { param: 'user',   value: "'",  label: "?user='" },
  { param: 'name',   value: "'",  label: "?name='" },
  { param: 'filter', value: "'",  label: "?filter='" },
  { param: 'page',   value: "1'", label: "?page=1'" },
];

const SQL_ERROR_PATTERNS = [
  // MySQL
  'you have an error in your sql syntax',
  'mysql_fetch_array()',
  'mysql_num_rows()',
  'supplied argument is not a valid mysql',
  'warning: mysql',
  // PostgreSQL
  'pg_query()',
  'pg::syntaxerror',
  'psql error',
  // MSSQL
  'microsoft ole db provider for sql server',
  'odbc sql server driver',
  'sqlserver error',
  'unclosed quotation mark',
  // Oracle
  'ora-01756',
  'ora-00907',
  'quoted string not properly terminated',
  // SQLite
  'sqlite_error',
  'sqlite3.operationalerror',
  // Generic DB-specific
  'sqlstate',
  'sql syntax',
  'unterminated string literal',
];

export default async function run(target, fetchWithRetry) {
  let baseUrl;
  try {
    baseUrl = new URL(String(target ?? '').trim());
  } catch {
    return { name: 'sql error disclosure', status: 'ERROR', severity: 'NONE', reason: 'Invalid URL' };
  }

  let networkSuccess = false;
  let lastError = null;
  const baselinePatterns = new Set();

  // Baseline fetch to avoid false positives from pre-existing page text
  try {
    const baseRes = await fetchWithRetry(baseUrl.href);
    if (baseRes?.isGovernanceBlock) {
      return {
        name: 'sql error disclosure',
        status: 'ERROR',
        severity: 'NONE',
        reason: baseRes.reason || baseRes.error || 'Blocked by governance policy'
      };
    }
    networkSuccess = true;
    const baseBody = (typeof baseRes?.text === 'string' ? baseRes.text : '').toLowerCase();
    for (const p of SQL_ERROR_PATTERNS) {
      if (baseBody.includes(p)) {
        baselinePatterns.add(p);
      }
    }
  } catch (err) {
    if (isGovernanceBlockError(err)) {
      return { name: 'sql error disclosure', status: 'ERROR', severity: 'NONE', reason: err.message };
    }
    lastError = err;
  }

  for (const probe of TEST_PROBES) {
    const probeUrl = new URL(baseUrl.href);
    probeUrl.searchParams.set(probe.param, probe.value);

    try {
      const res = await fetchWithRetry(probeUrl.href);
      if (res?.isGovernanceBlock) {
        return {
          name: 'sql error disclosure',
          status: 'ERROR',
          severity: 'NONE',
          reason: res.reason || res.error || 'Blocked by governance policy'
        };
      }

      networkSuccess = true;
      if (
        res?.status === 404 ||
        res?.status === 405 ||
        isRedirectedToDifferentPath(res, probeUrl.href) ||
        isFrameworkRouteErrorResponse(res, res?.text)
      ) {
        continue;
      }
      const body = (typeof res?.text === 'string' ? res.text : '').toLowerCase();

      const matched = SQL_ERROR_PATTERNS.filter(p => !baselinePatterns.has(p) && body.includes(p));

      if (matched.length > 0) {
        const hit = matched[0];
        const { confirmed, res: confirmRes } = await confirmReproducible(
          probeUrl.href,
          fetchWithRetry,
          {},
          (r) => r?.status !== 404 && typeof r?.text === 'string' && r.text.toLowerCase().includes(hit) && !baselinePatterns.has(hit)
        );
        if (!confirmed) continue;

        const finalRes = confirmRes || res;
        const path = `${probeUrl.pathname || '/'}${probeUrl.search}`;
        const snippet = extractVerbatimSnippet(finalRes?.text || res?.text || '', hit) || `SQL error via ${probe.label}: ${hit}`;
        return {
          name          : 'sql error disclosure',
          status        : 'VULNERABLE',
          severity      : 'HIGH',
          path,
          url           : probeUrl.href,
          detail        : `SQL error leaked via ${probe.label}: ${hit}`,
          fix           : "Disable detailed database error messages in production. Implement parameterized queries or use an ORM to prevent SQL injection at the identified vulnerable parameter.",
          payload       : probe.label,
          files         : [{
            path,
            url          : probeUrl.href,
            method       : 'GET',
            status       : finalRes?.status ?? 500,
            matchedSignal: hit,
            reproducible : true,
            preview      : snippet
          }],
          reproVerified : true,
          poeLevel      : snippet.length >= 8 ? 3 : 2,
          ...(snippet.length >= 8 ? { evidenceQuotes: [snippet] } : {}),
          ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
        };
      }
    } catch (err) {
      if (isGovernanceBlockError(err)) {
        return { name: 'sql error disclosure', status: 'ERROR', severity: 'NONE', reason: err.message };
      }
      lastError = err;
    }
  }

  if (!networkSuccess) {
    return {
      name: 'sql error disclosure',
      status: 'ERROR',
      severity: 'NONE',
      reason: lastError?.message || 'Target unreachable'
    };
  }

  return { name: 'sql error disclosure', status: 'SAFE', severity: 'NONE' };
}
