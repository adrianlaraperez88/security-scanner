import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mockFetch, mockFetchError } from '../helpers/mock-fetch.js';
import run, { tags } from '../../checks/php-version.js';

const BASE = 'https://php.example.com';

test('php-version: exports expected tags', () => {
  assert.deepEqual(tags, ['php', 'laravel', 'wordpress', 'drupal', 'magento', 'symfony', 'codeigniter', 'joomla']);
});

test('php-version: handles PHP/8.6.0 (and 8.3.37/8.4.28/8.5.13) as supported branch SUSPICIOUS LOW info leak', async () => {
  for (const version of ['8.6.0', '8.5.13', '8.4.28', '8.3.37']) {
    const res = await run(BASE, mockFetch({
      status: 200,
      headers: { 'x-powered-by': `PHP/${version}` },
      trafficId: `tx-${version}`
    }));

    assert.equal(res.name, 'php version (eol)');
    assert.equal(res.status, 'SUSPICIOUS', `Expected SUSPICIOUS for PHP/${version}`);
    assert.equal(res.severity, 'LOW');
    assert.equal(res.version, version);
    assert.equal(res.poeLevel, 2);
    assert.match(res.detail, /supported branch/i);
    assert.match(res.detail, /8\.6\.0/);
    assert.deepEqual(res.evidenceQuotes, [`X-Powered-By: PHP/${version}`]);
  }
});

test('php-version: warns on PHP 8.2.36 upcoming EOL Dec 2026 (MEDIUM, SUSPICIOUS)', async () => {
  const res = await run(BASE, mockFetch({
    status: 200,
    headers: { 'x-powered-by': 'PHP/8.2.36' },
    trafficId: 'tx-82'
  }));

  assert.equal(res.status, 'SUSPICIOUS');
  assert.equal(res.severity, 'MEDIUM');
  assert.equal(res.version, '8.2.36');
  assert.equal(res.eolDate, 'Dec 2026');
  assert.equal(res.poeLevel, 2);
  assert.match(res.detail, /Dec 2026/);
  assert.match(res.detail, /8\.2\.36/);
  assert.match(res.fix, /31 Dec 2026/);
});

test('php-version: flags EOL PHP 8.1 (HIGH), 8.0 (CRITICAL), and 7.x (CRITICAL) as VULNERABLE', async () => {
  const res81 = await run(BASE, mockFetch({
    status: 200,
    headers: { 'x-powered-by': 'PHP/8.1.34' }
  }));
  assert.equal(res81.status, 'VULNERABLE');
  assert.equal(res81.severity, 'HIGH');
  assert.equal(res81.eolDate, 'Dec 2025');
  assert.equal(res81.poeLevel, 3);

  const res80 = await run(BASE, mockFetch({
    status: 200,
    headers: { 'x-powered-by': 'PHP/8.0.30' }
  }));
  assert.equal(res80.status, 'VULNERABLE');
  assert.equal(res80.severity, 'CRITICAL');
  assert.equal(res80.eolDate, 'Nov 2023');

  const res74 = await run(BASE, mockFetch({
    status: 200,
    headers: { server: 'Apache/2.4 PHP/7.4.33' }
  }));
  assert.equal(res74.status, 'VULNERABLE');
  assert.equal(res74.severity, 'CRITICAL');
});

test('php-version: SAFE when PHP version is not disclosed and ERROR on fetch failure', async () => {
  const safeRes = await run(BASE, mockFetch({
    status: 200,
    headers: { server: 'nginx' }
  }));
  assert.equal(safeRes.status, 'SAFE');
  assert.equal(safeRes.severity, 'NONE');

  const errRes = await run(BASE, mockFetchError('ECONNREFUSED'));
  assert.equal(errRes.status, 'ERROR');
  assert.match(errRes.reason, /ECONNREFUSED/);
});
