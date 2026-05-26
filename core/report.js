import fs from 'fs';
import { generateHtmlReport } from './html-report.js';

export function generateReport(results, risk = null) {
  const vulns      = results.filter(r => r.status === 'VULNERABLE');
  const suspicious = results.filter(r => r.status === 'SUSPICIOUS');
  const errors     = results.filter(r => r.status === 'ERROR');

  return {
    generatedAt : new Date().toISOString(),
    summary     : {
      ...(risk || {}),
      totalChecks : results.length,
      vulnerable  : vulns.length,
      suspicious  : suspicious.length,
      errors      : errors.length
    },
    findings: results
  };
}

export function saveReport(report, stem = 'report') {
  const file = stem.endsWith('.json') ? stem : `${stem}.json`;
  fs.writeFileSync(file, JSON.stringify(report, null, 2));
  return file;
}

export function saveHtmlReport(results, risk, stem = 'report') {
  const file = stem.endsWith('.html') ? stem : `${stem}.html`;
  fs.writeFileSync(file, generateHtmlReport(results, risk));
  return file;
}