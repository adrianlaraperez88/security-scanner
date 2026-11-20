import { getCheckInfo } from './catalog.js';
import { buildReproductionContext } from './reproduction.js';
import { redactSecretsInText, redactEndpointQuery } from './ai-advisor.js';

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

const GRADE_COLORS = {
  'A+': '#3fb950',
  'A' : '#3fb950',
  'B' : '#58a6ff',
  'C' : '#d29922',
  'D' : '#e05f00',
  'F' : '#ff4444',
};

export function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const esc = escapeHtml;

/**
 * Collects unique normalized CVE IDs for a finding without leaking unrelated fallback CVEs.
 *
 * @param {object} [finding={}]
 * @param {object|null} [meta=null]
 * @returns {string[]}
 */
export function extractFindingCveIds(finding = {}, meta = null) {
  const f = finding && typeof finding === 'object' ? finding : {};
  const ids = new Set();
  const add = val => {
    if (Array.isArray(val)) {
      for (const item of val) {
        if (typeof item === 'string' && item.trim()) ids.add(item.trim().toUpperCase());
      }
    } else if (typeof val === 'string' && val.trim()) {
      for (const part of val.split(',')) {
        const clean = part.trim();
        if (clean) ids.add(clean.toUpperCase());
      }
    }
  };

  if (Array.isArray(f.cveIds)) {
    add(f.cveIds);
  } else if (f.cve) {
    add(f.cve);
  } else if (meta && Array.isArray(meta.cveIds)) {
    add(meta.cveIds);
  }

  if (f.cve) add(f.cve);
  if (Array.isArray(f.findings)) {
    for (const sub of f.findings) {
      if (sub && typeof sub === 'object') {
        if (sub.cve) add(sub.cve);
        if (Array.isArray(sub.cveIds)) add(sub.cveIds);
      }
    }
  }

  return Array.from(ids);
}

function getDetail(r) {
  if (r.path)              return r.path;
  if (r.detail)            return r.detail;
  if (r.missing?.length)   return 'Missing: ' + r.missing.slice(0, 4).join(', ') + (r.missing.length > 4 ? '…' : '');
  if (r.files?.length)     return r.files.map(f => f.path).join(', ');
  if (r.findings?.length)  return r.findings.map(f => f.issue ?? f.reason ?? f.detail ?? f.method ?? f.name ?? '').filter(Boolean).join(' · ');
  if (r.issues?.length)    return r.issues.map(i => i.issue ?? '').join(' · ');
  if (r.panels?.length)    return r.panels.map(p => p.path).join(', ');
  if (r.paths?.length)     return r.paths.join(', ');
  if (r.reason)            return r.reason;
  return '';
}

function sevBadge(sev) {
  const c = (Object.hasOwn(SEV_COLORS, sev) ? SEV_COLORS[sev] : null) ?? SEV_COLORS.NONE;
  return `<span class="badge" style="background:${c.bg};color:${c.fg}">${esc(sev)}</span>`;
}

function statusCell(status) {
  const m = (Object.hasOwn(STATUS_META, status) ? STATUS_META[status] : null) ?? STATUS_META.ERROR;
  return `<span style="color:${m.color};font-weight:600">${m.icon} ${m.label}</span>`;
}

export function groupFindings(results = []) {
  if (!Array.isArray(results)) return [];

  const groups = new Map();

  for (const r of results) {
    if (!r || typeof r !== 'object') continue;

    const checkKey = String(r.checkId || r.name || 'unknown').toLowerCase().trim();
    const status = r.status || 'ERROR';
    const severity = r.severity || 'NONE';
    const groupKey = `${checkKey}::${status}::${severity}`;

    const pageUrl = r.target || '';

    if (!groups.has(groupKey)) {
      const pages = pageUrl ? [pageUrl] : [];
      groups.set(groupKey, {
        ...r,
        pages,
        pageCount: pages.length
      });
    } else {
      const existing = groups.get(groupKey);
      if (pageUrl && !existing.pages.includes(pageUrl)) {
        existing.pages.push(pageUrl);
        existing.pageCount = existing.pages.length;
      }
      if (!existing.detail && r.detail) existing.detail = r.detail;
      if (!existing.path && r.path) existing.path = r.path;
      if (!existing.reason && r.reason) existing.reason = r.reason;
      if (!existing.fix && r.fix) existing.fix = r.fix;
      if (!existing.cwe && r.cwe) existing.cwe = r.cwe;
      if (!existing.owasp && r.owasp) existing.owasp = r.owasp;
      if (existing.cvssScore === undefined && r.cvssScore !== undefined) existing.cvssScore = r.cvssScore;
      if (Array.isArray(r.cveIds) && r.cveIds.length > 0) {
        const merged = new Set(Array.isArray(existing.cveIds) ? existing.cveIds : []);
        for (const id of r.cveIds) {
          if (typeof id === 'string' && id.trim()) merged.add(id.trim());
        }
        existing.cveIds = Array.from(merged);
      }
      if (existing.poeLevel === undefined && r.poeLevel !== undefined) existing.poeLevel = r.poeLevel;
      if (!existing.verificationStatus && r.verificationStatus) existing.verificationStatus = r.verificationStatus;
      if (!existing.reproduction && r.reproduction) existing.reproduction = r.reproduction;
      if (r.reproVerified === true) existing.reproVerified = true;
      if (Array.isArray(r.files) && r.files.length > 0) {
        const seenFiles = new Set((existing.files || []).map(f => f?.path || f?.url));
        const mergedFiles = [...(Array.isArray(existing.files) ? existing.files : [])];
        for (const f of r.files) {
          const key = f?.path || f?.url;
          if (key && !seenFiles.has(key)) {
            seenFiles.add(key);
            mergedFiles.push(f);
          }
        }
        existing.files = mergedFiles;
      }
      if (Array.isArray(r.evidenceQuotes) && r.evidenceQuotes.length > 0) {
        const mergedQuotes = new Set([...(Array.isArray(existing.evidenceQuotes) ? existing.evidenceQuotes : []), ...r.evidenceQuotes]);
        existing.evidenceQuotes = Array.from(mergedQuotes).slice(0, 6);
      }
      if (!existing.apiCommunication && r.apiCommunication) existing.apiCommunication = r.apiCommunication;
    }
  }

  return Array.from(groups.values());
}

export function sanitizeApiCommunication(apiComm) {
  if (!apiComm || typeof apiComm !== 'object' || Array.isArray(apiComm)) return null;
  const cleanList = (arr, max = 50, { redactQuery = false } = {}) =>
    Array.isArray(arr)
      ? Array.from(
          new Set(
            arr
              .filter(v => typeof v === 'string' && v.trim())
              .map(v => {
                const pre = v.trim().slice(0, 1024);
                return redactQuery ? redactEndpointQuery(pre) : redactSecretsInText(pre);
              })
              .filter(Boolean)
          )
        ).slice(0, max)
      : [];
  const cleanConfigFiles = (arr, max = 20) =>
    Array.isArray(arr)
      ? Array.from(
          new Set(
            arr
              .map(v => (typeof v === 'string' ? v : (v && typeof v === 'object' ? v.path : '')))
              .filter(v => typeof v === 'string' && v.trim())
              .map(v => redactEndpointQuery(v.trim().slice(0, 512)))
              .filter(Boolean)
          )
        ).slice(0, max)
      : [];
  const issues = [];
  const seenIssues = new Set();
  if (Array.isArray(apiComm.issues)) {
    for (const iss of apiComm.issues) {
      if (!iss || typeof iss !== 'object') continue;
      const type = redactSecretsInText(String(iss.type || 'api_issue').trim().slice(0, 128));
      const severity = redactSecretsInText(String(iss.severity || 'MEDIUM').trim().slice(0, 32).toUpperCase());
      const detail = redactSecretsInText(redactEndpointQuery(String(iss.detail || iss.reason || '').trim().slice(0, 1024)));
      const endpoint = iss.endpoint
        ? redactEndpointQuery(String(iss.endpoint).trim().slice(0, 512))
        : undefined;
      const key = `${type}|${severity}|${endpoint || ''}|${detail}`;
      if (seenIssues.has(key)) continue;
      seenIssues.add(key);
      issues.push({
        type,
        severity,
        detail,
        ...(endpoint ? { endpoint } : {})
      });
      if (issues.length >= 30) break;
    }
  }
  const usesApi = Boolean(apiComm.usesApi);
  return {
    usesApi,
    architecture: redactSecretsInText(String(apiComm.architecture || (usesApi ? 'spa_api_driven' : 'traditional_web')).slice(0, 128)),
    frameworks: cleanList(apiComm.frameworks, 20),
    clients: cleanList(apiComm.clients, 20),
    protocols: cleanList(apiComm.protocols, 20),
    sameOriginEndpoints: cleanList(apiComm.sameOriginEndpoints, 50, { redactQuery: true }),
    externalApiOrigins: cleanList(apiComm.externalApiOrigins, 50, { redactQuery: true }),
    configFiles: cleanConfigFiles(apiComm.configFiles, 20),
    cspConnectSrc: cleanList(apiComm.cspConnectSrc, 30, { redactQuery: true }),
    issues,
    bundlesInspected: Math.max(0, Number(apiComm.bundlesInspected) || 0),
    summary: redactSecretsInText(String(apiComm.summary || '').slice(0, 2048))
  };
}

export function sanitizeTextWithEndpoints(str) {
  return redactSecretsInText(
    String(str || '').replace(/(?:https?:\/\/[^\s"'<>)]+|\/[^\s"'<>)]+)\?[^\s"'<>)]+/g, m => redactEndpointQuery(m))
  );
}

export function sanitizeFindingRecord(item) {
  if (!item || typeof item !== 'object') return item;
  const copy = { ...item };
  if (typeof copy.name === 'string') copy.name = sanitizeTextWithEndpoints(copy.name);
  if (typeof copy.title === 'string') copy.title = sanitizeTextWithEndpoints(copy.title);
  if (typeof copy.endpoint === 'string') copy.endpoint = redactEndpointQuery(copy.endpoint);
  if (typeof copy.path === 'string') copy.path = redactEndpointQuery(copy.path);
  if (typeof copy.target === 'string') copy.target = redactEndpointQuery(copy.target);
  if (Array.isArray(copy.pages)) {
    copy.pages = copy.pages.map(p => typeof p === 'string' ? redactEndpointQuery(p) : p);
  }
  if (typeof copy.detail === 'string') copy.detail = sanitizeTextWithEndpoints(copy.detail);
  if (typeof copy.reason === 'string') copy.reason = sanitizeTextWithEndpoints(copy.reason);
  if (Array.isArray(copy.evidenceQuotes)) {
    copy.evidenceQuotes = copy.evidenceQuotes.map(q => typeof q === 'string' ? sanitizeTextWithEndpoints(q) : q);
  }
  if (Array.isArray(copy.files)) {
    copy.files = copy.files.map(f => {
      if (!f || typeof f !== 'object') return f;
      return {
        ...f,
        ...(typeof f.path === 'string' ? { path: redactEndpointQuery(f.path) } : {}),
        ...(typeof f.url === 'string' ? { url: redactEndpointQuery(f.url) } : {}),
        ...(typeof f.reason === 'string' ? { reason: sanitizeTextWithEndpoints(f.reason) } : {}),
        ...(typeof f.matchedSignal === 'string' ? { matchedSignal: sanitizeTextWithEndpoints(f.matchedSignal) } : {}),
        ...(typeof f.preview === 'string' ? { preview: sanitizeTextWithEndpoints(f.preview) } : {})
      };
    });
  }
  if (copy.apiCommunication && typeof copy.apiCommunication === 'object') {
    copy.apiCommunication = sanitizeApiCommunication(copy.apiCommunication);
  }
  if (Array.isArray(copy.findings)) {
    copy.findings = copy.findings.map(sub => sanitizeFindingRecord(sub));
  }
  return copy;
}

export function mergeApiCommunication(stacks = null, results = [], explicitApiComm = null) {
  const candidates = [];
  const pushCandidate = (c) => {
    if (c && typeof c === 'object' && !Array.isArray(c)) {
      if (
        c.usesApi !== undefined ||
        Array.isArray(c.sameOriginEndpoints) ||
        Array.isArray(c.externalApiOrigins) ||
        Array.isArray(c.clients) ||
        Array.isArray(c.protocols)
      ) {
        candidates.push(c);
      }
    }
  };

  pushCandidate(explicitApiComm);

  if (Array.isArray(stacks)) {
    for (const s of stacks) {
      if (s && typeof s === 'object') {
        pushCandidate(s.apiCommunication);
      }
    }
  } else if (stacks && typeof stacks === 'object') {
    if (stacks.apiCommunication && typeof stacks.apiCommunication === 'object') {
      pushCandidate(stacks.apiCommunication);
    } else {
      for (const fp of Object.values(stacks)) {
        if (fp && typeof fp === 'object') {
          pushCandidate(fp.apiCommunication);
        }
      }
    }
  }

  if (Array.isArray(results)) {
    for (const r of results) {
      if (r && typeof r === 'object' && r.apiCommunication) {
        pushCandidate(r.apiCommunication);
      }
    }
  }

  if (candidates.length === 0) return null;

  const usesApi = candidates.some(c => Boolean(c.usesApi));
  const archCandidate =
    candidates.find(c => c.usesApi && c.architecture && c.architecture !== 'traditional_web') ||
    candidates.find(c => c.architecture && c.architecture !== 'traditional_web') ||
    candidates[0];
  const architecture = archCandidate?.architecture || (usesApi ? 'spa_api_driven' : 'traditional_web');
  const summaryCandidate =
    candidates.find(c => c.usesApi && typeof c.summary === 'string' && c.summary.trim()) ||
    candidates.find(c => typeof c.summary === 'string' && c.summary.trim());

  return sanitizeApiCommunication({
    usesApi,
    architecture,
    frameworks: candidates.flatMap(c => (Array.isArray(c.frameworks) ? c.frameworks : [])),
    clients: candidates.flatMap(c => (Array.isArray(c.clients) ? c.clients : [])),
    protocols: candidates.flatMap(c => (Array.isArray(c.protocols) ? c.protocols : [])),
    sameOriginEndpoints: candidates.flatMap(c => (Array.isArray(c.sameOriginEndpoints) ? c.sameOriginEndpoints : [])),
    externalApiOrigins: candidates.flatMap(c => (Array.isArray(c.externalApiOrigins) ? c.externalApiOrigins : [])),
    configFiles: candidates.flatMap(c => (Array.isArray(c.configFiles) ? c.configFiles : [])),
    cspConnectSrc: candidates.flatMap(c => (Array.isArray(c.cspConnectSrc) ? c.cspConnectSrc : [])),
    issues: candidates.flatMap(c => (Array.isArray(c.issues) ? c.issues : [])),
    bundlesInspected: Math.max(0, ...candidates.map(c => Number(c.bundlesInspected) || 0)),
    summary: summaryCandidate?.summary || ''
  });
}

function renderPagesList(pages = []) {
  if (!Array.isArray(pages) || pages.length === 0) {
    return '<code class="muted">—</code>';
  }

  const MAX_VISIBLE = 8;
  const visible = pages.slice(0, MAX_VISIBLE);
  const remaining = pages.length - visible.length;

  const listItems = visible
    .map(p => `<li style="margin:2px 0;word-break:break-all"><code class="muted">${esc(p)}</code></li>`)
    .join('');

  const extraItems = remaining > 0
    ? `<details style="margin-top:4px;font-size:11px;color:var(--blue);cursor:pointer">
         <summary>+ ${remaining} more page${remaining > 1 ? 's' : ''}</summary>
         <ul style="margin:4px 0 0 16px;padding:0;list-style:disc">
           ${pages.slice(MAX_VISIBLE).map(p => `<li style="margin:2px 0;word-break:break-all"><code class="muted">${esc(p)}</code></li>`).join('')}
         </ul>
       </details>`
    : '';

  return `
    <div style="font-size:11px;font-weight:700;color:var(--text2);margin-bottom:4px">
      Pages (${pages.length}):
    </div>
    <ul style="margin:0 0 0 16px;padding:0;list-style:disc">
      ${listItems}
    </ul>
    ${extraItems}
  `;
}

function buildRows(groupedResults) {
  const sorted = [...groupedResults].sort((a, b) => {
    const aStatus = Object.hasOwn(STATUS_ORDER, a.status) ? STATUS_ORDER[a.status] : 4;
    const bStatus = Object.hasOwn(STATUS_ORDER, b.status) ? STATUS_ORDER[b.status] : 4;
    const sd = aStatus - bStatus;
    if (sd !== 0) return sd;
    const aSev = Object.hasOwn(SEVERITY_ORDER, a.severity) ? SEVERITY_ORDER[a.severity] : 5;
    const bSev = Object.hasOwn(SEVERITY_ORDER, b.severity) ? SEVERITY_ORDER[b.severity] : 5;
    return aSev - bSev;
  });

  return sorted.map(r => {
    const rowBg = r.status === 'VULNERABLE' ? 'rgba(255,68,68,0.07)'
                : r.status === 'SUSPICIOUS' ? 'rgba(210,153,34,0.06)'
                : r.status === 'ERROR'      ? 'rgba(110,118,129,0.05)'
                : '';

    const pages = Array.isArray(r.pages) && r.pages.length > 0
      ? r.pages
      : (r.target ? [r.target] : []);

    const meta = r.meta || getCheckInfo(r.checkId || r.name);
    const title = meta?.title || r.name;
    const category = meta?.category || 'General';
    const cwe = r.cwe || meta?.cwe || '';
    const owasp = r.owasp || meta?.owasp || '';
    const cvssScore = r.cvssScore ?? meta?.cvssScore;
    const cveIds = extractFindingCveIds(r, meta);
    const rawPoe = r.poeLevel ?? r.poe_level ?? r.quality?.poeLevel;
    const verStatus = r.verificationStatus || r.verification_status || r.quality?.verificationStatus || '';
    const plainExplanation = meta?.plainExplanation || '';
    const whyItMatters = meta?.whyItMatters || '';
    const fixText = r.fix || (r.status !== 'SAFE' ? meta?.defaultFix : null);
    const detail = getDetail(r);
    const hasFilesList = Array.isArray(r.files) && r.files.length > 0;
    const evidenceItems = hasFilesList
      ? r.files
      : (Array.isArray(r.findings) ? r.findings : []);
    const evidenceLabel = hasFilesList ? 'Matched Files' : 'Matched Paths / Evidence';
    const filesHtml = evidenceItems.length > 0
      ? `<div class="meaning-box" style="margin-top:6px">
           <span class="meaning-lbl">${evidenceLabel} (${evidenceItems.length}):</span>
           <ul style="margin:4px 0 0 16px;padding:0">
             ${evidenceItems.slice(0, 8).map(f => `<li><code>${esc(f.path || f.url || f.name || '')}</code>${f.status ? ` (HTTP ${esc(f.status)})` : ''}${f.matchedSignal ? ` — ${esc(f.matchedSignal)}` : (f.detail || f.issue || f.reason ? ` — ${esc(f.detail || f.issue || f.reason)}` : '')}${f.preview ? ` · <code>${esc(f.preview)}</code>` : ''}</li>`).join('')}
           </ul>
         </div>`
      : '';
    const quotesHtml = Array.isArray(r.evidenceQuotes) && r.evidenceQuotes.length > 0
      ? `<div class="why-box" style="margin-top:5px">
           <span class="meaning-lbl">Evidence Proof:</span>
           <code>${esc(r.evidenceQuotes.slice(0, 3).join(' | '))}</code>
         </div>`
      : '';
    const repro = r.status !== 'SAFE' ? (r.reproduction || buildReproductionContext(r)) : null;
    const reproStatusText = repro
      ? (repro.reproducible || r.reproVerified ? 'Confirmed Reproducible' : 'Recorded Trigger Trace')
      : '';
    const reproHtml = repro ? `
        <div class="repro-box">
          <div class="repro-lbl">How to Reproduce &amp; Verify Fix · <span class="badge" style="background:${repro.reproducible || r.reproVerified ? 'rgba(63,185,80,0.2)' : 'rgba(210,153,34,0.2)'};color:${repro.reproducible || r.reproVerified ? '#3fb950' : '#d29922'}">${esc(reproStatusText)}</span></div>
          ${repro.observedSignal ? `<div style="font-size:11px;margin-bottom:4px"><strong>Observed:</strong> <code>${esc(repro.observedSignal)}</code></div>` : ''}
          ${Array.isArray(repro.steps) && repro.steps.length ? `<ol class="repro-steps">${repro.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}
          ${repro.curl ? `<pre class="repro-cmd"><code>${esc(repro.curl)}</code></pre>` : ''}
        </div>` : '';

    return `
    <tr style="background:${rowBg}">
      <td class="td-status">${statusCell(r.status)}</td>
      <td class="td-sev">${sevBadge(r.severity)}</td>
      <td class="td-name">
        <div class="check-title">${esc(title)}</div>
        <div class="check-badges">
          <code>${esc(r.name)}</code>
          <span class="cat-badge">${esc(category)}</span>
          ${cwe ? `<span class="cat-badge cwe-badge">${esc(cwe)}</span>` : ''}
          ${owasp ? `<span class="cat-badge owasp-badge">${esc(owasp)}</span>` : ''}
          ${Number.isFinite(Number(cvssScore)) ? `<span class="cat-badge cvss-badge">CVSS ${esc(cvssScore)}</span>` : ''}
          ${cveIds.map(id => `<span class="cat-badge cve-badge">${esc(id)}</span>`).join('')}
          ${rawPoe !== undefined && rawPoe !== null ? `<span class="cat-badge poe-badge">PoE L${esc(rawPoe)}</span>` : ''}
          ${verStatus ? `<span class="cat-badge ver-badge">${esc(verStatus)}</span>` : ''}
          ${r.reproVerified ? '<span class="cat-badge" style="color:#3fb950;border-color:rgba(63,185,80,0.4)">Reproducible</span>' : ''}
        </div>
      </td>
      <td class="td-host">${renderPagesList(pages)}</td>
      <td class="td-detail">
        ${detail ? `<div class="td-muted" style="margin-bottom:6px">${esc(detail)}</div>` : ''}
        ${filesHtml}
        ${quotesHtml}
        ${plainExplanation ? `
        <div class="meaning-box">
          <span class="meaning-lbl">What this means:</span>
          <span>${esc(plainExplanation)}</span>
        </div>` : ''}
        ${whyItMatters ? `
        <div class="why-box">
          <span class="why-lbl">Why it matters:</span>
          <span>${esc(whyItMatters)}</span>
        </div>` : ''}
        ${reproHtml}
        ${fixText ? `
        <div class="fix-box">
          <div class="fix-lbl">Recommendation</div>
          ${esc(fixText)}
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

function buildStackSummary(stacks) {
  if (!stacks || typeof stacks !== 'object') return '';

  let entries = [];
  if (Array.isArray(stacks)) {
    entries = stacks.map((fp, idx) => {
      const url = fp?.target || fp?.url || `Target #${idx + 1}`;
      return [url, fp];
    });
  } else {
    entries = Object.keys(stacks).map(k => [k, stacks[k]]);
  }

  if (entries.length === 0) return '';

  const cards = entries.map(([targetUrl, fp]) => {
    if (!fp || typeof fp !== 'object') return '';

    const validStackItems = Array.isArray(fp.stack)
      ? fp.stack.filter(s => s && typeof s === 'object' && s.tech)
      : [];
    const summary = fp.summary || (validStackItems.length
      ? validStackItems.map(s => `${s.tech}(${Number(s.score) || 0})`).join(', ')
      : 'Unknown stack');

    const validTags = Array.isArray(fp.detectedTags)
      ? fp.detectedTags.filter(Boolean)
      : [];
    const tags = validTags.length > 0
      ? validTags.map(t => `<span class="cat-badge">${esc(t)}</span>`).join(' ')
      : '<span class="muted" style="font-size:11px">None detected</span>';

    const recProfile = fp.recommendedProfile || 'smart';
    const activeCount = Number(fp.activeChecksCount) || 0;
    const skippedCount = Number(fp.skippedChecksCount) || 0;
    const confidence = Number(fp.confidence) || 0;

    return `
    <div class="target-card" style="flex:1;min-width:280px">
      <div class="target-host">${esc(targetUrl)}</div>
      <div style="font-size:12px;margin:6px 0;color:var(--text2)">
        <strong>Stack:</strong> ${esc(summary)}
        ${confidence > 0 ? `<span class="muted" style="font-size:11px">(${confidence}% confidence)</span>` : ''}
      </div>
      <div style="font-size:11px;margin-bottom:6px;display:flex;align-items:center;gap:6px;flex-wrap:wrap">
        <span class="muted">Ecosystem Tags:</span>
        ${tags}
      </div>
      <div style="font-size:11px;margin-bottom:6px">
        <span class="muted">Recommended Profile:</span>
        <strong style="color:var(--blue)">${esc(recProfile)}</strong>
      </div>
      <div class="target-stats" style="margin-top:8px">
        <span style="color:#3fb950">${activeCount} relevant checks executed</span>
        ${skippedCount > 0 ? `<span style="color:var(--muted)">${skippedCount} skipped</span>` : ''}
      </div>
    </div>`;
  }).filter(Boolean);

  if (cards.length === 0) return '';

  return `
  <!-- Detected Technology Stack & Audit Strategy -->
  <div class="section-title">🧠 Detected Technology Stack & Audit Strategy</div>
  <div class="targets-grid">${cards.join('')}</div>`;
}

function buildApiCommunicationSummary(apiComm) {
  if (!apiComm || typeof apiComm !== 'object') return '';
  const safe = sanitizeApiCommunication(apiComm);
  if (!safe) return '';

  const statusLabel = safe.usesApi ? 'YES — SPA / Client-Side API' : 'No Client-Side API Detected';
  const statusColor = safe.usesApi ? '#3fb950' : 'var(--muted)';
  const clientBadges = safe.clients.length > 0
    ? safe.clients.map(c => `<span class="cat-badge">${esc(c)}</span>`).join(' ')
    : '<span class="muted" style="font-size:11px">None detected</span>';
  const protocolBadges = safe.protocols.length > 0
    ? safe.protocols.map(p => `<span class="cat-badge">${esc(p)}</span>`).join(' ')
    : '<span class="muted" style="font-size:11px">None detected</span>';
  const sameOriginHtml = safe.sameOriginEndpoints.length > 0
    ? safe.sameOriginEndpoints.map(ep => `<code class="muted" style="margin-right:6px">${esc(ep)}</code>`).join(' ')
    : '<span class="muted" style="font-size:11px">None discovered</span>';
  const externalOriginsHtml = safe.externalApiOrigins.length > 0
    ? safe.externalApiOrigins.map(o => `<code style="color:var(--blue);margin-right:6px">${esc(o)}</code>`).join(' ')
    : '<span class="muted" style="font-size:11px">None discovered</span>';
  const configFilesHtml = safe.configFiles.length > 0
    ? `<div style="font-size:11px;margin-top:6px">
         <span class="muted">Runtime Config Files:</span>
         ${safe.configFiles.map(cf => `<code class="muted" style="margin-left:4px">${esc(cf)}</code>`).join(' ')}
       </div>`
    : '';
  const issuesHtml = safe.issues.length > 0
    ? `<div style="font-size:11px;margin-top:8px">
         <div style="color:#d29922;font-weight:700;margin-bottom:4px">Detected API Configuration Issues (${safe.issues.length}):</div>
         <ul style="margin:0 0 0 16px;padding:0">
           ${safe.issues.map(iss => `<li style="margin:2px 0"><strong>[${esc(iss.severity)}] ${esc(iss.type)}:</strong> ${esc(iss.detail)}${iss.endpoint ? ` (<code>${esc(iss.endpoint)}</code>)` : ''}</li>`).join('')}
         </ul>
       </div>`
    : '';

  return `
  <!-- API Communication Summary -->
  <div class="section-title">🔌 API Communication &amp; Discovered Endpoints</div>
  <div class="targets-grid" style="margin-bottom:1.8rem">
    <div class="target-card" style="flex:1;min-width:280px">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">
        <strong style="color:${statusColor};font-size:12px">${esc(statusLabel)}</strong>
        <span class="cat-badge">${esc(safe.architecture)}</span>
      </div>
      ${safe.summary ? `<div style="font-size:12px;margin:6px 0;color:var(--text2)">${esc(safe.summary)}</div>` : ''}
      <div style="font-size:11px;margin-bottom:6px;display:flex;align-items:center;gap:6px;flex-wrap:wrap">
        <span class="muted">API Clients:</span>
        ${clientBadges}
      </div>
      <div style="font-size:11px;margin-bottom:6px;display:flex;align-items:center;gap:6px;flex-wrap:wrap">
        <span class="muted">Protocols:</span>
        ${protocolBadges}
      </div>
      <div style="font-size:11px;margin-bottom:6px">
        <span class="muted">Same-Origin Routes (${safe.sameOriginEndpoints.length}):</span>
        ${sameOriginHtml}
      </div>
      <div style="font-size:11px;margin-bottom:4px">
        <span class="muted">External API Origins (${safe.externalApiOrigins.length}):</span>
        ${externalOriginsHtml}
      </div>
      ${configFilesHtml}
      ${issuesHtml}
    </div>
  </div>`;
}

function buildCveCoverageSummary(cveCoverage) {
  if (!cveCoverage || typeof cveCoverage !== 'object') return '';
  const summary = cveCoverage.summary && typeof cveCoverage.summary === 'object'
    ? cveCoverage.summary
    : cveCoverage;
  const total = Number(summary.totalAdvisories);
  if (!Number.isFinite(total)) return '';

  const covered = Number(summary.coveredCount ?? 0);
  const partial = Number(summary.partialCount ?? 0);
  const missing = Number(summary.missingCount ?? 0);
  const kevTotal = Number(summary.kevTotal ?? 0);
  const kevCovered = Number(summary.kevCovered ?? 0);
  const kevMissing = Number(summary.kevMissing ?? 0);
  const coveragePct = Number(summary.coveragePercent ?? 100);
  const tags = Array.isArray(cveCoverage.techTags)
    ? cveCoverage.techTags
    : (Array.isArray(cveCoverage.filter?.techTags) ? cveCoverage.filter.techTags : []);

  return `
  <!-- CVE Coverage Summary -->
  <div class="section-title">🛡️ CVE Coverage Audit Summary${tags.length ? ` (${esc(tags.join(', '))})` : ''}</div>
  <div class="cards" style="margin-bottom:1.8rem">
    <div class="card"><div class="val" style="color:var(--blue)">${esc(coveragePct)}%</div><div class="lbl">CVE Coverage</div></div>
    <div class="card"><div class="val" style="color:var(--text2)">${esc(total)}</div><div class="lbl">Advisories</div></div>
    <div class="card"><div class="val" style="color:#3fb950">${esc(covered)}</div><div class="lbl">Covered</div></div>
    <div class="card"><div class="val" style="color:#d29922">${esc(partial)}</div><div class="lbl">Partial</div></div>
    <div class="card"><div class="val" style="color:${missing > 0 ? '#ff4444' : '#3fb950'}">${esc(missing)}</div><div class="lbl">Missing</div></div>
    <div class="card"><div class="val" style="color:${kevMissing > 0 ? '#ff4444' : '#3fb950'}">${esc(kevCovered)}/${esc(kevTotal)}</div><div class="lbl">KEV Covered</div></div>
  </div>`;
}

export function generateHtmlReport(results, risk, stacks = null, options = null) {
  const sanitizedResults = Array.isArray(results) ? results.map(sanitizeFindingRecord) : [];
  const date        = new Date().toLocaleString('en-US', { dateStyle: 'long', timeStyle: 'short' });
  const grouped     = groupFindings(sanitizedResults);
  const vulns       = grouped.filter(r => r.status === 'VULNERABLE').length;
  const suspicious  = grouped.filter(r => r.status === 'SUSPICIOUS').length;
  const safe        = grouped.filter(r => r.status === 'SAFE').length;
  const errors      = grouped.filter(r => r.status === 'ERROR').length;
  const riskColor   = (Object.hasOwn(RISK_COLORS, risk?.level) ? RISK_COLORS[risk.level] : null) ?? '#6e7681';
  const grade       = risk?.grade ?? 'A+';
  const gradeColor  = (Object.hasOwn(GRADE_COLORS, grade) ? GRADE_COLORS[grade] : null) ?? '#3fb950';
  const scorePct    = Math.min(100, Math.max(0, Math.round(((Number(risk?.score) || 0) / 60) * 100)));
  const maxScore    = 60;
  const cveCoverage = options && typeof options === 'object'
    ? (options.cveCoverage ?? (options.totalAdvisories !== undefined || options.summary ? options : null))
    : null;
  const explicitApiComm = options && typeof options === 'object'
    ? (options.apiCommunication || null)
    : null;
  const apiCommunication = mergeApiCommunication(stacks, results, explicitApiComm);

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
          padding-bottom:1.5rem;border-bottom:1px solid var(--border);margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem}
  .header-left h1{font-size:1.3rem;font-weight:700;color:var(--text2)}
  .header-left h1 .accent{color:var(--blue)}
  .header-left .meta{font-size:0.78rem;color:var(--muted);margin-top:0.25rem}
  .grade-pill{padding:0.35rem 1.1rem;border-radius:20px;font-weight:800;font-size:0.95rem;
              letter-spacing:0.05em;align-self:center}
  .risk-pill{padding:0.35rem 1.1rem;border-radius:20px;font-weight:800;font-size:0.95rem;
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
  .check-title{font-weight:600;color:var(--text2);margin-bottom:4px;font-size:13px}
  .check-badges{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
  .cat-badge{font-size:9px;font-weight:600;padding:1px 6px;border-radius:4px;
             background:var(--bg3);color:var(--muted);border:1px solid var(--border);text-transform:uppercase;letter-spacing:0.04em}
  .cve-badge{background:rgba(255,68,68,0.14);color:#ff7b72;border-color:rgba(255,68,68,0.4)}
  .cvss-badge{background:rgba(88,166,255,0.14);color:var(--blue);border-color:rgba(88,166,255,0.4)}
  .td-host code{font-size:11px}
  .td-detail{font-size:11px;max-width:360px}
  .td-muted{color:var(--muted)}
  .meaning-box{margin-top:6px;font-size:11px;line-height:1.45;color:var(--text)}
  .meaning-lbl{color:var(--blue);font-weight:700;display:inline-block;margin-right:4px}
  .why-box{margin-top:5px;font-size:11px;line-height:1.45;color:var(--text)}
  .why-lbl{color:#d29922;font-weight:700;display:inline-block;margin-right:4px}
  .fix-box{margin-top:8px;padding:8px 12px;background:var(--bg3);border-radius:6px;
           border-left:3px solid var(--blue);font-size:11px;color:var(--text)}
  .fix-lbl{font-size:9px;text-transform:uppercase;letter-spacing:0.05em;color:var(--blue);
           font-weight:800;margin-bottom:3px}
  .repro-box{margin-top:8px;padding:8px 12px;background:rgba(210,153,34,0.08);border-radius:6px;
             border-left:3px solid #d29922;font-size:11px;color:var(--text)}
  .repro-lbl{font-size:9px;text-transform:uppercase;letter-spacing:0.05em;color:#d29922;
             font-weight:800;margin-bottom:4px}
  .repro-steps{margin:4px 0 6px 16px;padding:0;line-height:1.45}
  .repro-cmd{margin:4px 0 0;padding:6px 8px;background:var(--bg);border:1px solid var(--border);
             border-radius:4px;overflow-x:auto;font-size:10px;white-space:pre-wrap;word-break:break-all}
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
      <div class="meta">Security Scanner v2.2 · ${results.length} checks executed</div>
    </div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <div class="grade-pill" style="background:${gradeColor}22;color:${gradeColor};border:1px solid ${gradeColor}55">
        GRADE ${esc(grade)}
      </div>
      <div class="risk-pill">${esc(risk?.level ?? 'UNKNOWN')} RISK</div>
    </div>
  </div>

  ${risk?.summary ? `
  <div style="background:var(--bg2);border:1px solid var(--border);border-left:4px solid ${gradeColor};border-radius:8px;padding:0.9rem 1.2rem;margin-bottom:1.8rem">
    <div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:0.09em;color:var(--muted);font-weight:700;margin-bottom:4px">Security Posture Assessment</div>
    <div style="color:var(--text2);font-size:0.92rem;line-height:1.5">${esc(risk.summary)}</div>
  </div>` : ''}

  <!-- Stat cards -->
  <div class="cards">
    <div class="card"><div class="val" style="color:${gradeColor}">${esc(grade)}</div><div class="lbl">Security Grade</div></div>
    <div class="card"><div class="val" style="color:var(--risk)">${esc(risk?.level ?? '—')}</div><div class="lbl">Risk Level</div></div>
    <div class="card"><div class="val" style="color:var(--risk)">${esc(risk?.score ?? 0)}<span style="font-size:1rem;font-weight:400;color:var(--muted)">/${maxScore}</span></div><div class="lbl">Risk Score</div></div>
    <div class="card"><div class="val" style="color:${vulns > 0 ? '#ff4444' : '#3fb950'}">${vulns}</div><div class="lbl">Vulnerable</div></div>
    <div class="card"><div class="val" style="color:${suspicious > 0 ? '#d29922' : '#3fb950'}">${suspicious}</div><div class="lbl">Suspicious</div></div>
    <div class="card"><div class="val" style="color:#3fb950">${safe}</div><div class="lbl">Safe</div></div>
    <div class="card"><div class="val" style="color:var(--muted)">${errors}</div><div class="lbl">Errors</div></div>
  </div>

  <!-- Gauge -->
  <div class="gauge-section">
    <div class="section-title">Risk Score — ${esc(risk?.score ?? 0)} / ${maxScore}</div>
    <div class="gauge-track"><div class="gauge-fill"></div></div>
    <div class="gauge-labels"><span>LOW</span><span>MEDIUM</span><span>HIGH</span><span>CRITICAL</span></div>
  </div>

  <!-- Target summary -->
  <div class="section-title">Targets</div>
  <div class="targets-grid">${buildTargetSummary(grouped)}</div>

  ${buildStackSummary(stacks)}

  ${buildApiCommunicationSummary(apiCommunication)}

  ${buildCveCoverageSummary(cveCoverage)}

  <!-- Findings table -->
  <div class="section-title" style="margin-bottom:0.8rem">Findings (Grouped by Vulnerability)</div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Status</th>
          <th>Severity</th>
          <th>Check</th>
          <th>Affected Pages</th>
          <th>Findings & Remediation</th>
        </tr>
      </thead>
      <tbody>${buildRows(grouped)}</tbody>
    </table>
  </div>

  <div class="footer">Security Scanner v2.2 · Generated ${esc(date)}</div>
</div>
</body>
</html>`;
}
