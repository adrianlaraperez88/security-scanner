const weights = {
  NONE: 0,
  LOW: 1,
  MEDIUM: 5,
  HIGH: 10,
  CRITICAL: 20
};

export function calculateRisk(results = []) {
  let score = 0;
  const seenChecks = new Set();

  for (const r of results) {
    if (r.status === 'SAFE' || r.status === 'ERROR') {
      continue;
    }

    const checkKey = r.checkId || r.name;
    if (checkKey) {
      const dedupKey = `${String(checkKey).toLowerCase()}::${r.status || ''}::${r.severity || ''}`;
      if (seenChecks.has(dedupKey)) {
        continue;
      }
      seenChecks.add(dedupKey);
    }

    score += weights[r.severity] || 0;
  }

  let level = 'LOW';
  if (score >= 40) level = 'CRITICAL';
  else if (score >= 20) level = 'HIGH';
  else if (score >= 8) level = 'MEDIUM';

  let grade = 'A+';
  let summary = '';

  if (score === 0) {
    grade = 'A+';
    summary = 'Outstanding security posture. No vulnerabilities or suspicious findings were identified.';
  } else if (score <= 4) {
    grade = 'A';
    summary = 'Strong security posture. Only minor low-risk advisories were detected; overall defense is solid.';
  } else if (score <= 7) {
    grade = 'B';
    summary = 'Good security posture with minor issues. A few low or moderate issues should be reviewed.';
  } else if (score <= 19) {
    grade = 'C';
    summary = 'Moderate risk detected. Notable security gaps require remediation before production use.';
  } else if (score <= 39) {
    grade = 'D';
    summary = 'High security risk. Significant vulnerabilities were detected that expose the system to attack.';
  } else {
    grade = 'F';
    summary = 'Critical security danger. Immediate action required to address high-severity vulnerabilities.';
  }

  return { score, level, grade, summary };
}
