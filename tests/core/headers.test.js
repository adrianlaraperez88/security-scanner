import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  MAX_CUSTOM_HEADERS,
  MAX_CUSTOM_HEADER_BYTES,
  parseCustomHeaderLine,
  validateCustomHeaders,
  validateCustomHeadersResult,
} from '../../core/headers.js';

test('CANDIDATE-5: core/headers validates RFC 7230 tokens and rejects CR/LF/NUL, non-scalars, and prototype keys', () => {
  assert.deepEqual(validateCustomHeaders(null), {});
  assert.deepEqual(validateCustomHeaders({ 'X-Api-Key': 'abc-123', 'X-Env': 'staging' }), {
    'X-Api-Key': 'abc-123',
    'X-Env': 'staging',
  });

  for (const badHeaders of [
    ['X-Arr: 1'],
    'not-an-object',
    { 'X[Bad]': '1' },
    { 'Bad Header': '1' },
    { 'X-Ctl': 'ok\r\nInjected: 1' },
    { 'X-Nul': 'ok\0bad' },
    { 'X-Obj': { nested: true } },
    JSON.parse('{"__proto__":"evil"}'),
    { constructor: 'evil' },
    { prototype: 'evil' },
  ]) {
    const res = validateCustomHeadersResult(badHeaders);
    assert.equal(res.valid, false, `Expected invalid for ${JSON.stringify(badHeaders)}`);
    assert.throws(() => validateCustomHeaders(badHeaders));
  }
});

test('CANDIDATE-5: core/headers blocks hop-by-hop, framing, and Host headers regardless of case', () => {
  const forbidden = [
    'Host',
    'host',
    'Content-Length',
    'Transfer-Encoding',
    'Connection',
    'Keep-Alive',
    'Upgrade',
    'Expect',
    'TE',
    'Trailer',
    'Proxy-Connection',
  ];
  for (const name of forbidden) {
    const res = validateCustomHeadersResult({ [name]: 'val' });
    assert.equal(res.valid, false, `Expected forbidden header ${name} to be rejected`);
    const parsed = parseCustomHeaderLine(`${name}: val`);
    assert.equal(parsed.valid, false, `Expected parseCustomHeaderLine to reject ${name}`);
  }
});

test('CANDIDATE-5: core/headers enforces <= 32 headers and <= 8192 serialized bytes', () => {
  const thirtyTwo = {};
  for (let i = 0; i < MAX_CUSTOM_HEADERS; i++) {
    thirtyTwo[`X-Header-${i}`] = 'ok';
  }
  assert.equal(validateCustomHeadersResult(thirtyTwo).valid, true);

  const thirtyThree = { ...thirtyTwo, 'X-Header-32': 'too-many' };
  assert.equal(validateCustomHeadersResult(thirtyThree).valid, false);

  const bigValue = 'a'.repeat(MAX_CUSTOM_HEADER_BYTES);
  assert.equal(validateCustomHeadersResult({ 'X-Big': bigValue }).valid, false);
});
