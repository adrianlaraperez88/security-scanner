const weights = {
  NONE: 0,
  LOW: 1,
  MEDIUM: 5,
  HIGH: 10,
  CRITICAL: 20
};

export function calculateRisk(results) {
  let score = 0;

  for (const r of results) {
    score += weights[r.severity] || 0;
  }

  let level = "LOW";

  if (score >= 40) level = "CRITICAL";
  else if (score >= 20) level = "HIGH";
  else if (score >= 8) level = "MEDIUM";

  return { score, level };
}