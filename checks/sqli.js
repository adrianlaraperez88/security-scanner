import { Fuzzer } from '../core/fuzzer.js';

export const tags = ['all'];

export default async function run(target, fetchWithRetry, options = {}) {
  const fuzzer = new Fuzzer(fetchWithRetry);

  let errorResult;
  let timeResult;
  try {
    // 1. Error-based probe (Single quote)
    errorResult = await fuzzer.fuzzDetailed(target, "'", 'SQLI_ERROR', options);
    if (errorResult.governanceError) {
      return {
        name: 'sql injection',
        status: 'ERROR',
        severity: 'NONE',
        reason: errorResult.governanceError.message || 'Blocked by governance policy'
      };
    }

    // 2. Time-based blind probe (Sleep) using baseline-adjusted latency
    timeResult = await fuzzer.fuzzDetailed(target, "') OR SLEEP(5) --", 'SQLI_TIME', options);
    if (timeResult.governanceError) {
      return {
        name: 'sql injection',
        status: 'ERROR',
        severity: 'NONE',
        reason: timeResult.governanceError.message || 'Blocked by governance policy'
      };
    }
  } catch (err) {
    return {
      name: 'sql injection',
      status: 'ERROR',
      severity: 'NONE',
      reason: err?.message || 'Invalid target URL'
    };
  }

  const allFindings = [...errorResult.findings, ...timeResult.findings];
  const totalAttempted = errorResult.attempted + timeResult.attempted;
  const anyNetworkSuccess =
    (errorResult.attempted > 0 && errorResult.networkSuccess) ||
    (timeResult.attempted > 0 && timeResult.networkSuccess);

  if (allFindings.length === 0) {
    if (totalAttempted > 0 && !anyNetworkSuccess) {
      const err = timeResult.lastError || errorResult.lastError;
      return {
        name: 'sql injection',
        status: 'ERROR',
        severity: 'NONE',
        reason: err?.message || 'Target unreachable'
      };
    }
    return { name: 'sql injection', status: 'SAFE', severity: 'NONE' };
  }

  // Deduplicate by parameter
  const uniqueParams = [...new Set(allFindings.map(f => f.parameter))];

  return {
    name    : 'sql injection',
    status  : 'VULNERABLE',
    severity: 'CRITICAL',
    detail  : `${uniqueParams.length} parameter(s) vulnerable (Error/Time-based)`,
    findings: allFindings.map(f => ({ parameter: f.parameter, type: f.type, url: f.url })),
    fix     : 'Use prepared statements and parameterized queries for all database interactions. Never concatenate user input directly into SQL strings. Implement a strong Web Application Firewall (WAF) and use an ORM with built-in protection.'
  };
}
