export const tags = ['all', 'java', 'spring', 'tomcat', 'php', 'python', 'aspnet', 'api'];

export const meta = {
  id: 'xxe-injection',
  title: 'XML External Entity (XXE) & Unsafe XML/SOAP Entity Expansion',
  category: 'Injection & Input',
  plainExplanation:
    'Safely tests XML-accepting endpoints with a benign internal DTD entity declaration (<!ENTITY secscanxxe "secscan_xxe_eval_9412">) to verify whether custom DOCTYPE entities are expanded or whether raw XML parser exceptions are disclosed.',
  whyItMatters:
    'XML parsers that permit DOCTYPE declarations and entity resolution allow attackers to read arbitrary local files (file:///etc/passwd), probe internal networks via SSRF, or trigger denial-of-service via entity expansion.',
  defaultFix:
    'Disable DOCTYPE declarations (disallow-doctype-decl = true) and external general/parameter entities in your XML parser (DocumentBuilderFactory, SAXParserFactory, libxml_disable_entity_loader, defusedxml).',
  cwe: 'CWE-611',
  owasp: 'A05:2021-Security Misconfiguration',
  cvssScore: 8.6,
  cveIds: [],
  references: [
    'https://cwe.mitre.org/data/definitions/611.html',
    'https://portswigger.net/web-security/xxe'
  ]
};

const GOVERNANCE_ERROR_CODES = new Set([
  'SSRF_POLICY_BLOCKED',
  'TARGET_RULE_BLOCKED',
  'TARGET_OUT_OF_SCOPE',
  'DNS_REBIND_OR_PRIVATE_IP'
]);

function isGovernanceBlock(err) {
  if (!err) return false;
  if (err.isGovernanceBlock === true || GOVERNANCE_ERROR_CODES.has(err.code)) return true;
  const msg = String(err.message || '');
  return (
    msg.startsWith('Redirect blocked by SSRF policy') ||
    msg.startsWith('Request blocked by SSRF policy') ||
    msg.startsWith('[SECSCAN platform control')
  );
}

const XXE_CANARY = 'secscan_xxe_eval_9412';
const SAFE_XXE_BODY = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE secscan [<!ENTITY secscanxxe "${XXE_CANARY}">]>
<request><probe>&secscanxxe;</probe></request>`;

function extractResponseQuote(res) {
  const cleanBody = String(res?.text || '')
    .slice(0, 4096)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim();
  if (cleanBody.length >= 8) {
    return cleanBody.slice(0, 120);
  }
  const hdrs = res?.headers;
  if (hdrs && typeof hdrs === 'object') {
    const entries = typeof hdrs.entries === 'function' ? Array.from(hdrs.entries()) : Object.entries(hdrs);
    for (const [k, v] of entries) {
      const line = `${k}: ${Array.isArray(v) ? v.join(', ') : String(v ?? '')}`
        .replace(/[\r\n\t]+/g, ' ')
        .trim();
      if (line.length >= 8) return line.slice(0, 120);
    }
  }
  return null;
}

export async function run(targetInput, fetchWithRetry, options = {}) {
  const target = Array.isArray(targetInput) ? targetInput[0] : targetInput;
  if (!target || typeof target !== 'string') {
    return {
      name: meta.title,
      checkId: meta.id,
      target: String(target || ''),
      status: 'SAFE',
      detail: 'No valid target URL provided.'
    };
  }

  let res;
  try {
    res = await fetchWithRetry(target, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/xml',
        Accept: 'application/xml, text/xml, application/json, text/plain'
      },
      body: SAFE_XXE_BODY,
      followRedirects: false
    });
  } catch (err) {
    if (isGovernanceBlock(err)) throw err;
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'ERROR',
      detail: `Target request failed: ${err.message}`
    };
  }

  if (!res || res.status === 404 || res.status === 405 || res.status === 410 || res.status === 415) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      status: 'SAFE',
      detail: 'No XML entity expansion or unsafe XML parser exposure detected.'
    };
  }

  const body = String(res.text || '');

  // 1. Confirmed XML entity expansion: body contains expanded canary but does NOT merely echo "<!ENTITY"
  if (res.status === 200 && body.includes(XXE_CANARY) && !body.includes('<!ENTITY secscanxxe')) {
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      url: target,
      status: 'VULNERABLE',
      severity: 'HIGH',
      findings: [
        {
          url: target,
          status: res.status,
          expandedEntity: XXE_CANARY,
          matchedSignal: XXE_CANARY,
          issue: `XML parser at ${target} processed DOCTYPE declaration and expanded custom entity &secscanxxe; into "${XXE_CANARY}".`
        }
      ],
      evidenceQuotes: [XXE_CANARY],
      poeLevel: 3,
      ...(res.trafficId ? { trafficId: res.trafficId } : {}),
      detail: `XML parser expanded custom DOCTYPE entity &secscanxxe; into "${XXE_CANARY}" (CWE-611).`
    };
  }

  if (options?.oastServer && options.oastServer.running === true) {
    const probe = options.oastServer.issueProbe({
      checkId: meta.id,
      target,
      parameter: 'xml_dtd_system'
    });
    const oastXmlBody = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE secscan [<!ENTITY secscanoast SYSTEM "${probe.callbackUrl}">]><request><probe>&secscanoast;</probe></request>`;

    let oastRes = null;
    try {
      oastRes = await fetchWithRetry(target, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/xml',
          Accept: 'application/xml, text/xml, application/json, text/plain'
        },
        body: oastXmlBody,
        followRedirects: false
      });
    } catch (err) {
      if (isGovernanceBlock(err)) throw err;
    }

    const interaction = await options.oastServer.waitForInteraction(
      probe.tokenId,
      options.oastWaitMs ?? 500
    );
    if (interaction) {
      const oastQuote = `OAST callback verified token=${probe.tokenId} (${interaction.method} ${interaction.path})`;
      const responseQuote = extractResponseQuote(oastRes);
      const evidenceQuotes = responseQuote ? [oastQuote, responseQuote] : [oastQuote];
      return {
        name: meta.title,
        checkId: meta.id,
        target,
        url: target,
        status: 'VULNERABLE',
        severity: 'CRITICAL',
        findings: [
          {
            url: target,
            probeUrl: probe.callbackUrl,
            tokenId: probe.tokenId,
            status: oastRes?.status ?? 0,
            matchedSignal: oastQuote,
            oastVerified: true,
            issue: `XML parser at ${target} resolved external SYSTEM entity &secscanoast; and triggered a verified OAST callback to token "${probe.tokenId}" (${interaction.method} ${interaction.path}).`
          }
        ],
        evidenceQuotes,
        poeLevel: 3,
        reproVerified: true,
        oastVerified: true,
        ...(oastRes?.trafficId ? { trafficId: oastRes.trafficId } : {}),
        detail: `XML parser resolved external SYSTEM entity and triggered a cryptographically verified OAST callback (token=${probe.tokenId}).`
      };
    }
  }

  // 2. Verbose XML parser exception disclosure
  const parserErrMatch = body.match(
    /(org\.xml\.sax\.SAXParseException|javax\.xml\.stream\.XMLStreamException|simplexml_load_string\(\):|DOMDocument::loadXML\(\):|lxml\.etree\.XMLSyntaxError|System\.Xml\.XmlException)/i
  );
  if (parserErrMatch) {
    const quote = parserErrMatch[0];
    return {
      name: meta.title,
      checkId: meta.id,
      target,
      url: target,
      status: 'SUSPICIOUS',
      severity: 'MEDIUM',
      findings: [
        {
          url: target,
          status: res.status,
          parserSignature: quote,
          matchedSignal: quote,
          issue: `Endpoint accepts XML input and discloses raw XML parser exception signature: "${quote}".`
        }
      ],
      evidenceQuotes: [quote],
      poeLevel: 3,
      ...(res.trafficId ? { trafficId: res.trafficId } : {}),
      detail: `Endpoint disclosed raw XML parser exception ("${quote}").`
    };
  }

  return {
    name: meta.title,
    checkId: meta.id,
    target,
    status: 'SAFE',
    detail: 'No XML entity expansion or unsafe XML parser exposure detected.'
  };
}

export default run;
