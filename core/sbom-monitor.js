import {
  evaluateTechnologyVersion,
  RUNTIME_SCA_CATALOG,
  resolveTechCatalogKey
} from './runtime-sca.js';
import { KNOWN_CVE_ADVISORIES } from './cve-catalog.js';

const ADVISORY_BY_CVE_ID = new Map(
  KNOWN_CVE_ADVISORIES.map(adv => [String(adv.cveId || '').toUpperCase(), adv])
);

function extractTargetsFromRecord(record) {
  if (!record || typeof record !== 'object') return [];
  if (Array.isArray(record.targets) && record.targets.length > 0) {
    const clean = record.targets
      .filter(t => typeof t === 'string' && t.trim())
      .map(t => t.trim());
    if (clean.length > 0) return clean;
  }
  if (typeof record.target === 'string' && record.target.trim()) {
    return [record.target.trim()];
  }
  if (record.stacks && typeof record.stacks === 'object' && !Array.isArray(record.stacks)) {
    const stackKeys = Object.keys(record.stacks).filter(
      k => k !== 'runtimeSca' && k !== 'findings' && k.trim()
    );
    if (stackKeys.length > 0) return stackKeys;
  }
  return ['unknown'];
}

function collectScaFindingsForTarget(record, targetUrl, isSingleTargetRecord) {
  const findings = [];
  const pushFindingsList = (list) => {
    if (!Array.isArray(list)) return;
    for (const item of list) {
      if (item && typeof item === 'object') {
        findings.push(item);
      }
    }
  };

  const pushScaContainer = (sca) => {
    if (!sca || typeof sca !== 'object') return;
    if (Array.isArray(sca.findings)) {
      pushFindingsList(sca.findings);
    } else if (Array.isArray(sca.technologies)) {
      pushFindingsList(sca.technologies);
    } else if (Array.isArray(sca.components)) {
      pushFindingsList(sca.components);
    }
  };

  // 1. Target-specific stack entry in record.stacks
  if (record.stacks && typeof record.stacks === 'object') {
    if (Array.isArray(record.stacks)) {
      for (const s of record.stacks) {
        if (!s || typeof s !== 'object') continue;
        if (!s.target || s.target === targetUrl || isSingleTargetRecord) {
          pushScaContainer(s.runtimeSca || s);
        }
      }
    } else {
      const targetStack = record.stacks[targetUrl];
      if (targetStack && typeof targetStack === 'object') {
        pushScaContainer(targetStack.runtimeSca || targetStack);
        if (Array.isArray(targetStack.stack)) {
          pushFindingsList(targetStack.stack);
        }
      } else if (isSingleTargetRecord) {
        pushScaContainer(record.stacks.runtimeSca);
        for (const fp of Object.values(record.stacks)) {
          if (fp && typeof fp === 'object') {
            pushScaContainer(fp.runtimeSca);
            if (Array.isArray(fp.stack)) {
              pushFindingsList(fp.stack);
            }
          }
        }
      }
    }
  }

  // 2. Top-level record.runtimeSca
  if (record.runtimeSca && typeof record.runtimeSca === 'object') {
    if (isSingleTargetRecord || findings.length === 0) {
      pushScaContainer(record.runtimeSca);
    }
  }

  // 3. Check results (e.g. runtime-sca check result)
  if (Array.isArray(record.results)) {
    for (const res of record.results) {
      if (!res || typeof res !== 'object') continue;
      if (res.target && res.target !== targetUrl && !isSingleTargetRecord) continue;
      if (res.runtimeSca && typeof res.runtimeSca === 'object') {
        pushScaContainer(res.runtimeSca);
      }
      if (Array.isArray(res.scaFindings)) {
        pushFindingsList(res.scaFindings);
      }
    }
  }

  return findings;
}

/**
 * Re-evaluates stored Software Bill of Materials (SBOM) & Runtime SCA components
 * from scan history records in-memory against the current `RUNTIME_SCA_CATALOG`
 * and `KNOWN_CVE_ADVISORIES` with zero network traffic (`zeroTouchMode: true`).
 *
 * @param {Array<object>} [historyRecords=[]]
 */
export function buildSbomAndCveDriftReport(historyRecords = []) {
  const records = Array.isArray(historyRecords) ? historyRecords : [];

  // Deduplicate by target URL, keeping the most recent scan record per target
  const latestRecordByTarget = new Map();

  for (let i = 0; i < records.length; i++) {
    const rec = records[i];
    if (!rec || typeof rec !== 'object') continue;

    const targets = extractTargetsFromRecord(rec);
    const parsedTime = rec.timestamp ? Date.parse(rec.timestamp) : NaN;
    const timestampMs = Number.isFinite(parsedTime) ? parsedTime : -1;

    for (const rawTarget of targets) {
      const target = String(rawTarget || '').trim();
      if (!target) continue;

      const existing = latestRecordByTarget.get(target);
      if (!existing) {
        latestRecordByTarget.set(target, {
          record: rec,
          timestamp: rec.timestamp || null,
          timestampMs,
          isSingleTargetRecord: targets.length === 1
        });
      } else if (timestampMs > existing.timestampMs) {
        latestRecordByTarget.set(target, {
          record: rec,
          timestamp: rec.timestamp || null,
          timestampMs,
          isSingleTargetRecord: targets.length === 1
        });
      }
    }
  }

  const targetsList = [];
  const driftAlerts = [];
  let vulnerableTargetsCount = 0;
  let totalComponents = 0;
  let outOfDateComponentsCount = 0;
  let vulnerableComponentsCount = 0;

  for (const [target, entry] of latestRecordByTarget.entries()) {
    const rawFindings = collectScaFindingsForTarget(
      entry.record,
      target,
      entry.isSingleTargetRecord
    );

    const byTech = new Map();
    for (const item of rawFindings) {
      const candidateKeys = [item.id, item.key, item.techId, item.tech, item.name].filter(
        k => typeof k === 'string' && k.trim()
      );
      let canonicalTech = null;
      for (const rawKey of candidateKeys) {
        const clean = rawKey.trim().toLowerCase();
        canonicalTech =
          resolveTechCatalogKey(rawKey) ||
          (Object.hasOwn(RUNTIME_SCA_CATALOG, clean) ? clean : null) ||
          (clean.includes('yii') ? 'yii' : null);
        if (canonicalTech) break;
      }
      if (!canonicalTech) continue;

      const rawVersions = [];
      if (Array.isArray(item.identifiedVersions)) {
        rawVersions.push(...item.identifiedVersions);
      }
      if (typeof item.identifiedVersion === 'string' && item.identifiedVersion.trim()) {
        rawVersions.push(item.identifiedVersion.trim());
      }
      if (typeof item.version === 'string' && item.version.trim()) {
        rawVersions.push(item.version.trim());
      }
      if (rawVersions.length === 0) continue;

      if (!byTech.has(canonicalTech)) {
        byTech.set(canonicalTech, {
          versions: new Set(),
          sources: new Set()
        });
      }
      const bucket = byTech.get(canonicalTech);
      for (const v of rawVersions) {
        if (typeof v === 'string' && v.trim()) {
          bucket.versions.add(v.trim());
        }
      }
      if (Array.isArray(item.sources)) {
        for (const s of item.sources) {
          if (typeof s === 'string' && s.trim()) {
            bucket.sources.add(s.trim());
          }
        }
      }
    }

    const components = [];
    let targetVulnerableCount = 0;
    let targetOutOfDateCount = 0;
    let targetHighestCvss = 0.0;

    for (const [techKey, bucket] of byTech.entries()) {
      const evaluated = evaluateTechnologyVersion(
        techKey,
        Array.from(bucket.versions),
        { sources: Array.from(bucket.sources) }
      );
      if (!evaluated) continue;

      const matchedAdvisories = [];
      let hasKev = false;
      for (const cveId of evaluated.cveIds || []) {
        const upperId = String(cveId || '').toUpperCase();
        const catalogAdv = ADVISORY_BY_CVE_ID.get(upperId);
        if (catalogAdv) {
          if (catalogAdv.kev) hasKev = true;
          matchedAdvisories.push({
            cveId: catalogAdv.cveId,
            title: catalogAdv.title,
            severity: catalogAdv.severity,
            cvssScore: catalogAdv.cvssScore,
            kev: Boolean(catalogAdv.kev),
            cwe: catalogAdv.cwe,
            owasp: catalogAdv.owasp
          });
        }
      }

      const latestVersion = evaluated.overallLatestVersion !== 'N/A'
        ? evaluated.overallLatestVersion
        : evaluated.latestBranchVersion;

      const enrichedComponent = {
        ...evaluated,
        techId: evaluated.id,
        techName: evaluated.name,
        latestVersion,
        kev: hasKev,
        advisories: matchedAdvisories
      };

      components.push(enrichedComponent);
      totalComponents += 1;

      if (evaluated.isOutOfDate) {
        outOfDateComponentsCount += 1;
        targetOutOfDateCount += 1;
      }
      if (evaluated.isVulnerable) {
        vulnerableComponentsCount += 1;
        targetVulnerableCount += 1;
      }
      if (evaluated.highestCvss > targetHighestCvss) {
        targetHighestCvss = evaluated.highestCvss;
      }

      if (evaluated.isVulnerable || evaluated.isOutOfDate) {
        driftAlerts.push({
          target,
          techId: evaluated.id,
          techName: evaluated.name,
          identifiedVersion: evaluated.identifiedVersion,
          latestBranchVersion: evaluated.latestBranchVersion,
          latestVersion,
          highestCvss: evaluated.highestCvss,
          cveIds: [...(evaluated.cveIds || [])],
          kev: hasKev,
          isVulnerable: evaluated.isVulnerable,
          isOutOfDate: evaluated.isOutOfDate,
          isEol: evaluated.isEol,
          recommendedAction: evaluated.recommendedAction
        });
      }
    }

    components.sort((a, b) => (b.highestCvss - a.highestCvss) || a.name.localeCompare(b.name));

    if (targetVulnerableCount > 0) {
      vulnerableTargetsCount += 1;
    }

    targetsList.push({
      target,
      lastScannedAt: entry.timestamp || null,
      componentsCount: components.length,
      outOfDateCount: targetOutOfDateCount,
      vulnerableCount: targetVulnerableCount,
      highestCvss: targetHighestCvss,
      components
    });
  }

  driftAlerts.sort((a, b) => (b.highestCvss - a.highestCvss) || a.target.localeCompare(b.target));

  return {
    generatedAt: new Date().toISOString(),
    zeroTouchMode: true,
    totalTargets: targetsList.length,
    vulnerableTargetsCount,
    totalComponents,
    outOfDateComponentsCount,
    vulnerableComponentsCount,
    driftAlerts,
    targets: targetsList
  };
}
