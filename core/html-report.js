// ── Sorting helpers ───────────────────────────────────────────────────────────
const STATUS_ORDER   = { VULNERABLE: 0, SUSPICIOUS: 1, ERROR: 2, SAFE: 3 };
const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4 };

const SEV_COLORS = {
  CRITICAL: { bg: '#ff4444', fg: '#fff' },
  HIGH    : { bg: '#e05f00', fg: '#fff' },
  MEDIUM  : { bg: '#d29922', fg: '#0d1117' },
  LOW     : { bg: '#1f6feb', fg: '#fff' },
  NONE    : { bg: '#30363d', fg: '#8b949e' },
};

const STATUS_META = {
  VULNERABLE: { icon: '🚨', color: '#ff4444', label: 'VULNERABLE' },
  SUSPICIOUS: { icon: '⚠️',  color: '#d29922', label: 'SUSPICIOUS' },
  SAFE       : { icon: '✅', color: '#3fb950', label: 'SAFE'       },
  ERROR      : { icon: '❓', color: '#6e7681', label: 'ERROR'      },
};

const RISK_COLORS = {
  CRITICAL: '#ff4444',
  HIGH    : '#e05f00',
  MEDIUM  : '#d29922',
  LOW     : '#3fb950',
};

function esc(str) {
  return String(str ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function getDetail(r) {
  if (r.path)              return r.path;
  if (r.detail)            return r.detail;
  if (r.missing?.length)   return 'Missing: ' + r.missing.slice(0, 4).join(', ') + (r.missing.length > 4 ? '…' : '');
  if (r.files?.length)     return r.files.map(f => f.path).join(', ');
  if (r.findings?.length)  return r.findings.map(f => f.issue ?? f.method ?? '').filter(Boolean).join(' · ');
  if (r.issues?.length)    return r.issues.map(i => i.issue ?? '').join(' · ');
  if (r.panels?.length)    return r.panels.map(p => p.path).join(', ');
  if (r.paths?.length)     return r.paths.join(', ');
  if (r.reason)            return r.reason;
  return '';
}

function sevBadge(sev) {
  const c = SEV_COLORS[sev] ?? SEV_COLORS.NONE;
  return `<span class="badge" style="background:${c.bg};color:${c.fg}">${esc(sev)}</span>`;
}

function statusCell(status) {
  const m = STATUS_META[status] ?? STATUS_META.ERROR;
  return `<span style="color:${m.color};font-weight:600">${m.icon} ${m.label}</span>`;
}

function buildRows(results) {
  const sorted = [...results].sort((a, b) => {
    const sd = (STATUS_ORDER[a.status] ?? 4) - (STATUS_ORDER[b.status] ?? 4);
    if (sd !== 0) return sd;
    return (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5);
  });

  return sorted.map(r => {
    const rowBg = r.status === 'VULNERABLE' ? 'rgba(255,68,68,0.07)'
                : r.status === 'SUSPICIOUS' ? 'rgba(210,153,34,0.06)'
                : r.status === 'ERROR'      ? 'rgba(110,118,129,0.05)'
                : '';

    let hostname = r.target;
    try { hostname = new URL(r.target).hostname; } catch {}

    return `
    <tr style="background:${rowBg}">
      <td class="td-status">${statusCell(r.status)}</td>
      <td class="td-sev">${sevBadge(r.severity)}</td>
      <td class="td-name"><code>${esc(r.name)}</code></td>
      <td class="td-host"><code class="muted">${esc(hostname)}</code></td>
      <td class="td-detail">
        <div class="td-muted">${esc(getDetail(r))}</div>
        ${r.fix ? `
        <div class="fix-box">
          <div class="fix-lbl">Recommendation</div>
          ${esc(r.fix)}
        </div>` : ''}
      </td>
    </tr>`;
  }).join('');
}

function buildTargetSummary(results) {
  const byTarget = {};
  results.forEach(r => {
    const h = (() => { try { return new URL(r.target).hostname; } catch { return r.target; } })();
    if (!byTarget[h]) byTarget[h] = { vuln: 0, susp: 0, safe: 0, err: 0, total: 0 };
    byTarget[h].total++;
    if (r.status === 'VULNERABLE') byTarget[h].vuln++;
    else if (r.status === 'SUSPICIOUS') byTarget[h].susp++;
    else if (r.status === 'ERROR') byTarget[h].err++;
    else byTarget[h].safe++;
  });

  return Object.entries(byTarget).map(([host, s]) => `
    <div class="target-card">
      <div class="target-host">${esc(host)}</div>
      <div class="target-stats">
        <span style="color:#ff4444">${s.vuln} vuln</span>
        <span style="color:#d29922">${s.susp} susp</span>
        <span style="color:#3fb950">${s.safe} safe</span>
        ${s.err ? `<span style="color:#6e7681">${s.err} err</span>` : ''}
      </div>
    </div>`).join('');
}

export function generateHtmlReport(results, risk) {
  const date        = new Date().toLocaleString('en-US', { dateStyle: 'long', timeStyle: 'short' });
  const vulns       = results.filter(r => r.status === 'VULNERABLE').length;
  const suspicious  = results.filter(r => r.status === 'SUSPICIOUS').length;
  const safe        = results.filter(r => r.status === 'SAFE').length;
  const errors      = results.filter(r => r.status === 'ERROR').length;
  const riskColor   = RISK_COLORS[risk?.level] ?? '#6e7681';
  const scorePct    = Math.min(100, Math.round(((risk?.score ?? 0) / 60) * 100));
  const maxScore    = 60;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Scan Report · ${date}</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  :root{
    --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;
    --border:#30363d;--text:#c9d1d9;--text2:#e6edf3;--muted:#6e7681;
    --blue:#58a6ff;--risk:${riskColor};
  }
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
       background:var(--bg);color:var(--text);min-height:100vh;padding:2rem 1rem}
  .container{max-width:1200px;margin:0 auto}

  /* Header */
  .header{display:flex;justify-content:space-between;align-items:flex-start;
          padding-bottom:1.5rem;border-bottom:1px solid var(--border);margin-bottom:2rem;flex-wrap:wrap;gap:1rem}
  .header-left h1{font-size:1.3rem;font-weight:700;color:var(--text2)}
  .header-left h1 .accent{color:var(--blue)}
  .header-left .meta{font-size:0.78rem;color:var(--muted);margin-top:0.25rem}
  .risk-pill{padding:0.3rem 1rem;border-radius:20px;font-weight:800;font-size:0.9rem;
             background:${riskColor}22;color:${riskColor};border:1px solid ${riskColor}55;
             align-self:center;letter-spacing:0.05em}

  /* Stat cards */
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:0.75rem;margin-bottom:2rem}
  .card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;
        padding:1.1rem 1rem;text-align:center}
  .card .val{font-size:2rem;font-weight:800;line-height:1.1}
  .card .lbl{font-size:0.7rem;color:var(--muted);text-transform:uppercase;
             letter-spacing:0.09em;margin-top:0.2rem}

  /* Risk gauge */
  .gauge-section{margin-bottom:2rem}
  .section-title{font-size:0.72rem;text-transform:uppercase;letter-spacing:0.1em;
                 color:var(--muted);font-weight:600;margin-bottom:0.8rem;
                 padding-bottom:0.4rem;border-bottom:1px solid var(--border)}
  .gauge-track{height:10px;background:var(--bg3);border-radius:5px;overflow:hidden}
  .gauge-fill{height:100%;width:${scorePct}%;background:linear-gradient(90deg,#3fb950,#d29922,#e05f00,#ff4444);
              border-radius:5px;transition:width .6s ease}
  .gauge-labels{display:flex;justify-content:space-between;font-size:10px;color:var(--muted);
                margin-top:4px;padding:0 2px}

  /* Target summary */
  .targets-grid{display:flex;flex-wrap:wrap;gap:0.6rem;margin-bottom:2rem}
  .target-card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;
               padding:0.7rem 1rem}
  .target-host{font-family:monospace;font-size:0.82rem;color:var(--blue);margin-bottom:0.3rem}
  .target-stats{display:flex;gap:0.8rem;font-size:0.75rem;font-weight:600}

  /* Table */
  .table-wrap{overflow-x:auto;border-radius:10px;border:1px solid var(--border)}
  table{width:100%;border-collapse:collapse;background:var(--bg2)}
  thead tr{background:var(--bg3)}
  th{padding:9px 14px;text-align:left;font-size:10px;text-transform:uppercase;
     letter-spacing:0.08em;color:var(--muted);font-weight:600;white-space:nowrap}
  td{padding:12px 14px;border-top:1px solid var(--border);vertical-align:top}
  tr:hover td{background:rgba(88,166,255,0.04)}
  .td-name code{font-size:12px;color:var(--text2)}
  .td-host code{font-size:11px}
  .td-detail{font-size:11px;max-width:300px}
  .td-muted{color:var(--muted)}
  .fix-box{margin-top:8px;padding:8px 12px;background:var(--bg3);border-radius:6px;
           border-left:3px solid var(--blue);font-size:11px;color:var(--text)}
  .fix-lbl{font-size:9px;text-transform:uppercase;letter-spacing:0.05em;color:var(--blue);
           font-weight:800;margin-bottom:3px}
  .badge{padding:1px 7px;border-radius:4px;font-size:10px;font-weight:700;
         letter-spacing:0.06em;white-space:nowrap}
  .muted{color:var(--muted)}

  /* Footer */
  .footer{margin-top:2.5rem;font-size:0.72rem;color:var(--muted);text-align:center;
          padding-top:1.5rem;border-top:1px solid var(--border)}

  @media print{
    body{background:#fff;color:#000;padding:1rem}
    .card,.target-card,.table-wrap{border-color:#ccc}
    table,thead tr{background:#f6f8fa}
    :root{--bg2:#f6f8fa;--bg3:#eaeef2;--text2:#24292f;--text:#57606a;--muted:#57606a;--border:#d0d7de;--blue:#0969da}
    .fix-box{background:#fff;border:1px solid #ddd;border-left:3px solid #0969da}
  }
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <h1>🔍 Security Scan Report · <span class="accent">${esc(date)}</span></h1>
      <div class="meta">Security Scanner v1.2 · ${results.length} checks executed</div>
    </div>
    <div class="risk-pill">${esc(risk?.level ?? 'UNKNOWN')} RISK</div>
  </div>

  <!-- Stat cards -->
  <div class="cards">
    <div class="card"><div class="val" style="color:var(--risk)">${esc(risk?.level ?? '—')}</div><div class="lbl">Risk Level</div></div>
    <div class="card"><div class="val" style="color:var(--risk)">${risk?.score ?? 0}<span style="font-size:1rem;font-weight:400;color:var(--muted)">/${maxScore}</span></div><div class="lbl">Risk Score</div></div>
    <div class="card"><div class="val" style="color:${vulns > 0 ? '#ff4444' : '#3fb950'}">${vulns}</div><div class="lbl">Vulnerable</div></div>
    <div class="card"><div class="val" style="color:${suspicious > 0 ? '#d29922' : '#3fb950'}">${suspicious}</div><div class="lbl">Suspicious</div></div>
    <div class="card"><div class="val" style="color:#3fb950">${safe}</div><div class="lbl">Safe</div></div>
    <div class="card"><div class="val" style="color:var(--muted)">${errors}</div><div class="lbl">Errors</div></div>
  </div>

  <!-- Gauge -->
  <div class="gauge-section">
    <div class="section-title">Risk Score — ${risk?.score ?? 0} / ${maxScore}</div>
    <div class="gauge-track"><div class="gauge-fill"></div></div>
    <div class="gauge-labels"><span>LOW</span><span>MEDIUM</span><span>HIGH</span><span>CRITICAL</span></div>
  </div>

  <!-- Target summary -->
  <div class="section-title">Targets</div>
  <div class="targets-grid">${buildTargetSummary(results)}</div>

  <!-- Findings table -->
  <div class="section-title" style="margin-bottom:0.8rem">Findings</div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Status</th>
          <th>Severity</th>
          <th>Check</th>
          <th>Target</th>
          <th>Findings & Remediation</th>
        </tr>
      </thead>
      <tbody>${buildRows(results)}</tbody>
    </table>
  </div>

  <div class="footer">Security Scanner v1.2 · Generated ${esc(date)}</div>
</div>
</body>
</html>`;
}
