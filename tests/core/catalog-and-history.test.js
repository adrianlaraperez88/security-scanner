import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getCheckInfo, PRESETS, scaffoldCheck } from '../../core/catalog.js';
import { mergeConfig } from '../../core/config.js';
import { listHistory, loadHistoryById } from '../../core/history.js';
import { calculateRisk } from '../../core/severity.js';

test('catalog: getCheckInfo resolves known v2.1 checks, aliases, and fallback metadata', () => {
  const nextInfo = getCheckInfo('nextjs-checks');
  assert.equal(nextInfo.id, 'nextjs-checks');
  assert.ok(nextInfo.title.includes('Next.js'));
  assert.ok(nextInfo.plainExplanation.length > 10);
  assert.ok(nextInfo.whyItMatters.length > 10);
  assert.ok(nextInfo.defaultFix.length > 10);

  const aiAliasInfo = getCheckInfo('ai & llm exposure');
  assert.equal(aiAliasInfo.id, 'ai-llm-exposure');

  const sriInfo = getCheckInfo('supply chain & sri');
  assert.equal(sriInfo.id, 'sri-supply-chain');

  const springInfo = getCheckInfo('spring boot security');
  assert.equal(springInfo.id, 'spring-checks');

  const customInfo = getCheckInfo('custom-zero-day-check');
  assert.equal(customInfo.id, 'custom-zero-day-check');
  assert.equal(customInfo.title, 'Custom Zero Day Check');
  assert.equal(customInfo.category, 'General Security');
});

test('catalog: PRESETS contains guided presets for regular users', () => {
  assert.ok(Array.isArray(PRESETS));
  const ids = PRESETS.map(p => p.id);
  assert.ok(ids.includes('quick'));
  assert.ok(ids.includes('full'));
  assert.ok(ids.includes('modern'));
  assert.ok(ids.includes('cms'));
  assert.ok(ids.includes('api'));

  const modern = PRESETS.find(p => p.id === 'modern');
  assert.ok(modern.checks.includes('nextjs-checks'));
  assert.ok(modern.checks.includes('ai-llm-exposure'));
  assert.ok(modern.checks.includes('sri-supply-chain'));
});

test('catalog: scaffoldCheck with dryRun: true returns generated templates without writing files', () => {
  const res = scaffoldCheck('sample-dryrun-check', {
    dryRun: true,
    title: 'Sample Dryrun Check',
    category: 'API Security',
    tags: ['api', 'all']
  });

  assert.equal(res.created, false);
  assert.equal(res.dryRun, true);
  assert.equal(res.checkFilename, 'sample-dryrun-check.js');
  assert.equal(res.testFilename, 'sample-dryrun-check.test.js');
  assert.ok(res.checkCode.includes('export default async function run'));
  assert.ok(res.testCode.includes("import run from '../../checks/sample-dryrun-check.js'"));
});

test('config: mergeConfig preserves maxDepth, port, and ui options', () => {
  const defaults = mergeConfig({}, {});
  assert.equal(defaults.maxDepth, 3);
  assert.equal(defaults.port, 4321);
  assert.equal(defaults.ui, false);

  const fromConfig = mergeConfig({}, { maxDepth: 5, port: 8080 });
  assert.equal(fromConfig.maxDepth, 5);
  assert.equal(fromConfig.port, 8080);

  const fromCli = mergeConfig({ maxDepth: 2, port: 9000, ui: true }, { maxDepth: 5, port: 8080 });
  assert.equal(fromCli.maxDepth, 2);
  assert.equal(fromCli.port, 9000);
  assert.equal(fromCli.ui, true);
});

test('history: listHistory returns array and loadHistoryById blocks path traversal', () => {
  const historyList = listHistory();
  assert.ok(Array.isArray(historyList));

  // Path traversal & invalid ID attempts must return null
  assert.equal(loadHistoryById('../../package.json'), null);
  assert.equal(loadHistoryById('../scan.js'), null);
  assert.equal(loadHistoryById('..\\package.json'), null);
  assert.equal(loadHistoryById('/etc/passwd'), null);
  assert.equal(loadHistoryById('sub/file.json'), null);
  assert.equal(loadHistoryById('not-a-json-file.txt'), null);
  assert.equal(loadHistoryById(null), null);
});

test('severity: calculateRisk returns letter grades and ignores ERROR/SAFE statuses', () => {
  const clean = calculateRisk([
    { status: 'SAFE', severity: 'NONE' },
    { status: 'ERROR', severity: 'LOW' },
    { status: 'ERROR', severity: 'HIGH' }
  ]);
  assert.equal(clean.score, 0);
  assert.equal(clean.grade, 'A+');
  assert.ok(clean.summary.length > 0);

  const gradeC = calculateRisk([{ status: 'VULNERABLE', severity: 'HIGH' }]);
  assert.equal(gradeC.score, 10);
  assert.equal(gradeC.grade, 'C');

  const gradeF = calculateRisk([
    { status: 'VULNERABLE', severity: 'CRITICAL' },
    { status: 'VULNERABLE', severity: 'CRITICAL' }
  ]);
  assert.equal(gradeF.score, 40);
  assert.equal(gradeF.grade, 'F');
});
