import { test } from 'node:test';
import assert    from 'node:assert/strict';
import { calculateRisk } from '../../core/severity.js';

test('calculateRisk: empty results → LOW score 0', () => {
  const r = calculateRisk([]);
  assert.equal(r.score, 0);
  assert.equal(r.level, 'LOW');
});

test('calculateRisk: single CRITICAL finding → score 20, HIGH level', () => {
  const r = calculateRisk([{ severity: 'CRITICAL' }]);
  assert.equal(r.score, 20);
  assert.equal(r.level, 'HIGH');   // 20 = HIGH (CRITICAL requires >= 40)
});

test('calculateRisk: two CRITICAL findings → CRITICAL level', () => {
  const r = calculateRisk([{ severity: 'CRITICAL' }, { severity: 'CRITICAL' }]);
  assert.equal(r.score, 40);
  assert.equal(r.level, 'CRITICAL');
});

test('calculateRisk: mixed findings → correct score', () => {
  const results = [
    { severity: 'HIGH'   },  // 10
    { severity: 'MEDIUM' },  // 5
    { severity: 'LOW'    },  // 1
    { severity: 'NONE'   },  // 0
  ];
  const r = calculateRisk(results);
  assert.equal(r.score, 16);
  assert.equal(r.level, 'MEDIUM');
});

test('calculateRisk: score >= 40 → CRITICAL level', () => {
  const results = Array.from({ length: 3 }, () => ({ severity: 'CRITICAL' }));
  const r = calculateRisk(results);
  assert.ok(r.score >= 40);
  assert.equal(r.level, 'CRITICAL');
});

test('calculateRisk: unknown severity treated as 0', () => {
  const r = calculateRisk([{ severity: 'UNKNOWN' }]);
  assert.equal(r.score, 0);
});
