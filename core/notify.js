/**
 * Webhook / Slack notification sender.
 * Sends a POST to the configured webhook URL after a scan completes.
 * Payload is Slack-compatible (works with Slack Incoming Webhooks out of the box)
 * and also works as a generic JSON webhook.
 */

// ── Slack-style block builder ─────────────────────────────────────────────────
function buildSlackPayload(results, risk, targets) {
  const vulns      = results.filter(r => r.status === 'VULNERABLE');
  const suspicious = results.filter(r => r.status === 'SUSPICIOUS');
  const riskEmoji  = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' }[risk.level] ?? '⚪';

  const header = `${riskEmoji} *Security Scan — ${risk.level} Risk (${risk.score} pts)*`;
  const targetLine = `*Targets:* ${targets.join(', ')}`;

  let body = '';

  if (vulns.length) {
    body += `\n*🚨 Vulnerable (${vulns.length}):*\n`;
    body += vulns.map(v => `  • \`${v.name}\` [${v.severity}]${v.path ? ' → ' + v.path : ''}`).join('\n');
  }

  if (suspicious.length) {
    body += `\n*⚠️ Suspicious (${suspicious.length}):*\n`;
    body += suspicious.map(s => `  • \`${s.name}\` [${s.severity}]${s.detail ? ' → ' + s.detail : ''}`).join('\n');
  }

  if (!vulns.length && !suspicious.length) {
    body = '\n✅ All checks passed — no findings detected.';
  }

  return {
    text: `${header}\n${targetLine}${body}`,
    // Slack blocks format (for rich formatting)
    blocks: [
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `${header}\n${targetLine}` }
      },
      ...(body ? [{
        type: 'section',
        text: { type: 'mrkdwn', text: body }
      }] : []),
      {
        type: 'context',
        elements: [{
          type: 'mrkdwn',
          text: `Security Scanner v1.2 · ${new Date().toISOString()}`
        }]
      }
    ]
  };
}

// ── Generic JSON payload ───────────────────────────────────────────────────────
function buildGenericPayload(results, risk, targets) {
  return {
    scanner   : 'security-scanner/1.2',
    timestamp : new Date().toISOString(),
    targets,
    risk,
    summary   : {
      vulnerable : results.filter(r => r.status === 'VULNERABLE').length,
      suspicious : results.filter(r => r.status === 'SUSPICIOUS').length,
      total      : results.length,
    },
    findings: results.filter(r => r.status === 'VULNERABLE' || r.status === 'SUSPICIOUS')
  };
}

// ── Sender ─────────────────────────────────────────────────────────────────────
export async function sendWebhook(webhookUrl, results, risk, targets) {
  if (!webhookUrl) return;

  // Use Slack payload format (also works as generic JSON for most webhook services)
  const payload = buildSlackPayload(results, risk, targets);

  try {
    const controller = new AbortController();
    const timer      = setTimeout(() => controller.abort(), 10000);

    const res = await fetch(webhookUrl, {
      method  : 'POST',
      headers : { 'Content-Type': 'application/json' },
      body    : JSON.stringify(payload),
      signal  : controller.signal,
    });

    clearTimeout(timer);

    if (!res.ok) {
      console.warn(`⚠️  Webhook returned ${res.status}: ${await res.text()}`);
    } else {
      console.log(`📣  Notification sent → ${webhookUrl}`);
    }

  } catch (e) {
    console.warn(`⚠️  Webhook failed: ${e.message}`);
  }
}
