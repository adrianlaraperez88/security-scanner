import { URL } from 'url';

/**
 * The Fuzzer engine for Scanner 2.0.
 * Injects payloads into URL parameters and analyzes responses for signatures.
 */
export class Fuzzer {
  constructor(fetchWithRetry) {
    this.fetch = fetchWithRetry;
  }

  /**
   * Identifies query parameters in a URL and generates test cases.
   */
  async fuzz(targetUrl, payload, signatureType = 'REFLECTED') {
    const url = new URL(targetUrl);
    const params = Array.from(url.searchParams.keys());
    const findings = [];

    if (params.length === 0) return [];

    for (const param of params) {
      const testUrl = new URL(targetUrl);
      const originalValue = testUrl.searchParams.get(param);
      
      // Inject payload
      testUrl.searchParams.set(param, payload);

      const startTime = Date.now();
      try {
        const res = await this.fetch(testUrl.href);
        const duration = Date.now() - startTime;

        if (this.isVulnerable(res, payload, signatureType, duration)) {
          findings.push({
            parameter: param,
            payload: payload,
            type: signatureType,
            url: testUrl.href
          });
        }
      } catch (e) {
        // Skip on network errors
      }
    }

    return findings;
  }

  /**
   * Internal logic to decide if a response matches a vulnerability signature.
   */
  isVulnerable(res, payload, type, duration) {
    const body = res.text || '';

    switch (type) {
      case 'XSS_REFLECTED':
        // Check if payload is reflected exactly (not HTML encoded)
        return body.includes(payload);

      case 'SQLI_ERROR':
        // Look for common DB error strings
        const sqlErrors = [
          'sql syntax', 'mysql_fetch', 'ora-00933', 'postgresql query failed',
          'sqlite3::exception', 'dynamic sql generation', 'unclosed quotation mark'
        ];
        const lowBody = body.toLowerCase();
        return sqlErrors.some(err => lowBody.includes(err));

      case 'SQLI_TIME':
        // If response took significantly longer than expected (e.g. > 4.5s for a 5s sleep)
        return duration >= 4500;

      default:
        return false;
    }
  }
}
