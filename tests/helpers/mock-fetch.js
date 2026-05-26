/**
 * Mock fetch helpers for unit tests.
 * These replace fetchWithRetry in check tests with controlled responses.
 */

/** Always returns the same response for any URL/options */
export function mockFetch(response) {
  return async () => ({ headers: {}, ...response });
}

/** Returns different responses based on URL substring match */
export function mockFetchMap(map) {
  return async (url) => {
    for (const [pattern, response] of Object.entries(map)) {
      if (url.includes(pattern)) {
        return { headers: {}, ...response };
      }
    }
    // Default: 404
    return { status: 404, headers: {}, text: 'Not Found' };
  };
}

/** Always throws (simulates network failure) */
export function mockFetchError(message = 'fetch failed') {
  return async () => { throw new Error(message); };
}

/** Returns different responses per call (cycle through array) */
export function mockFetchSequence(responses) {
  let i = 0;
  return async () => {
    const r = responses[i % responses.length];
    i++;
    return { headers: {}, ...r };
  };
}
