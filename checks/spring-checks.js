import {
  getHeader,
  isHtmlOrScript,
  isRedirectedToDifferentPath,
  isFrameworkRouteErrorResponse,
  parseJsonObject,
  extractVerbatimSnippet,
  confirmReproducible
} from '../core/check-verify.js';

export const tags = ['spring', 'java'];

const CHECKS = [
  {
    path: '/actuator/env',
    name: 'exposed spring boot actuator env',
    severity: 'CRITICAL',
    status: 'VULNERABLE',
    reason: 'Spring Boot Actuator /actuator/env endpoint is publicly accessible, exposing environment variables and configuration properties.',
    validate: (res) => {
      const json = !isHtmlOrScript(res, res?.text) ? parseJsonObject(res?.text) : null;
      return Boolean(json && !Array.isArray(json) && (Array.isArray(json.propertySources) || Array.isArray(json.activeProfiles)));
    },
    signalDesc: 'Actuator /env JSON propertySources/activeProfiles'
  },
  {
    path: '/actuator/mappings',
    name: 'exposed spring boot actuator mappings',
    severity: 'HIGH',
    status: 'VULNERABLE',
    reason: 'Spring Boot Actuator /actuator/mappings endpoint is publicly accessible, revealing internal route mapping details.',
    validate: (res) => {
      const json = !isHtmlOrScript(res, res?.text) ? parseJsonObject(res?.text) : null;
      const text = typeof res?.text === 'string' ? res.text : '';
      return Boolean(json && (text.includes('"dispatcherServlets"') || json.contexts));
    },
    signalDesc: 'Actuator /mappings JSON contexts/dispatcherServlets'
  },
  {
    path: '/actuator/health',
    name: 'exposed spring boot actuator health',
    severity: 'LOW',
    status: 'SUSPICIOUS',
    reason: 'Spring Boot Actuator /actuator/health endpoint is publicly accessible without authentication.',
    validate: (res) => {
      const json = !isHtmlOrScript(res, res?.text) ? parseJsonObject(res?.text) : null;
      return Boolean(json && !Array.isArray(json) && typeof json.status === 'string');
    },
    signalDesc: 'Actuator /health JSON status'
  },
  {
    path: '/v3/api-docs',
    name: 'exposed spring openapi docs',
    severity: 'MEDIUM',
    status: 'SUSPICIOUS',
    reason: 'OpenAPI v3 API documentation (/v3/api-docs) is publicly accessible without authentication.',
    validate: (res) => {
      const json = !isHtmlOrScript(res, res?.text) ? parseJsonObject(res?.text) : null;
      return Boolean(json && !Array.isArray(json) && json.openapi && json.paths);
    },
    signalDesc: 'Spring OpenAPI v3 JSON'
  }
];

function isHeapdumpResponse(res) {
  if (res?.status !== 200) return false;
  const text = typeof res.text === 'string' ? res.text : '';
  if (isHtmlOrScript(res, text)) return false;
  const ct = getHeader(res?.headers, 'content-type').toLowerCase();
  const len = Number(getHeader(res?.headers, 'content-length'));
  return ct.includes('octet-stream') || text.startsWith('JAVA PROFILE') || text.length > 100 || len > 100;
}

export default async function run(target, fetchWithRetry) {
  const base = target.replace(/\/+$/, '');
  const found = [];
  let networkSuccess = false;

  try {
    const heapUrl = `${base}/actuator/heapdump`;
    const heapRes = await fetchWithRetry(heapUrl);
    networkSuccess = true;

    if (isHeapdumpResponse(heapRes)) {
      const { confirmed, res: cRes } = await confirmReproducible(
        heapUrl,
        fetchWithRetry,
        {},
        isHeapdumpResponse
      );
      if (confirmed) {
        const finalRes = cRes || heapRes;
        const ct = getHeader(finalRes?.headers, 'content-type') || 'application/octet-stream';
        const quote = `HTTP 200 /actuator/heapdump (${ct})`;
        found.push({
          name         : 'exposed spring boot actuator heapdump',
          path         : '/actuator/heapdump',
          url          : heapUrl,
          method       : 'GET',
          status       : 200,
          statusTag    : 'VULNERABLE',
          severity     : 'CRITICAL',
          matchedSignal: ct,
          reproducible : true,
          preview      : quote,
          reason       : 'Spring Boot Actuator /actuator/heapdump endpoint is publicly accessible, allowing download of full JVM memory dump containing sensitive application memory.',
          ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
        });
      }
    }
  } catch { /* heapdump request failed */ }

  for (const check of CHECKS) {
    try {
      const url = `${base}${check.path}`;
      const res = await fetchWithRetry(url, { followRedirects: false });
      networkSuccess = true;

      if (
        res?.status !== 200 ||
        isRedirectedToDifferentPath(res, url) ||
        isFrameworkRouteErrorResponse(res, res?.text) ||
        !check.validate(res)
      ) {
        continue;
      }

      const { confirmed, res: cRes } = await confirmReproducible(
        url,
        fetchWithRetry,
        { followRedirects: false },
        (r) => r?.status === 200 && !isRedirectedToDifferentPath(r, url) && check.validate(r)
      );
      if (!confirmed) continue;

      const finalRes = cRes || res;
      const preview = extractVerbatimSnippet(finalRes.text || res.text || '', /propertySources|activeProfiles|dispatcherServlets|"status"|"openapi"/i)
        || check.signalDesc;
      found.push({
        name         : check.name,
        path         : check.path,
        url,
        method       : 'GET',
        status       : 200,
        statusTag    : check.status,
        severity     : check.severity,
        matchedSignal: check.signalDesc,
        reproducible : true,
        preview,
        reason       : check.reason,
        ...(finalRes?.trafficId !== undefined ? { trafficId: finalRes.trafficId } : {})
      });
    } catch { /* probe failed */ }
  }

  if (!networkSuccess) {
    return { name: 'spring boot security', status: 'ERROR', severity: 'NONE', reason: 'Target unreachable' };
  }

  if (found.length === 0) {
    return { name: 'spring boot security', status: 'SAFE', severity: 'NONE' };
  }

  const maxSev = found.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
               : found.some(f => f.severity === 'HIGH')     ? 'HIGH'
               : found.some(f => f.severity === 'MEDIUM')   ? 'MEDIUM'
               : 'LOW';
  const primary = found[0];
  const evidenceQuotes = found.map(f => f.preview).filter(q => typeof q === 'string' && q.length >= 8).slice(0, 5);

  return {
    name          : 'spring boot security',
    status        : found.some(f => f.statusTag === 'VULNERABLE') ? 'VULNERABLE' : 'SUSPICIOUS',
    severity      : maxSev,
    path          : primary.path,
    detail        : `Confirmed ${found.length} Spring Boot endpoint(s): ${found.map(f => f.path).join(', ')}`,
    findings      : found.map(f => ({ name: f.name, severity: f.severity, path: f.path, url: f.url, status: f.status, matchedSignal: f.matchedSignal, preview: f.preview, reason: f.reason })),
    files         : found,
    reproVerified : true,
    poeLevel      : evidenceQuotes.length > 0 ? 3 : 2,
    ...(evidenceQuotes.length > 0 ? { evidenceQuotes } : {}),
    ...(primary.trafficId !== undefined ? { trafficId: primary.trafficId } : {}),
    fix           : 'Restrict access to Spring Boot Actuator endpoints by configuring "management.endpoints.web.exposure.include=health,info" in application.properties/yml and securing Actuator endpoints with Spring Security.'
  };
}
