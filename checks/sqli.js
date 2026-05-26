import { Fuzzer } from '../core/fuzzer.js';

export const tags = ['all'];

export default async function run(target, fetchWithRetry) {
  const fuzzer = new Fuzzer(fetchWithRetry);
  
  // 1. Error-based probe (Single quote)
  const errorFindings = await fuzzer.fuzz(target, "'", 'SQLI_ERROR');
  
  // 2. Time-based blind probe (Sleep)
  // We use a 5-second sleep. Fuzzer detects vulnerable if > 4.5s
  const timeFindings = await fuzzer.fuzz(target, "') OR SLEEP(5) --", 'SQLI_TIME');

  const allFindings = [...errorFindings, ...timeFindings];

  if (allFindings.length === 0) {
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
