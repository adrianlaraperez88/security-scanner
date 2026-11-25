/**
 * Invicti Proof-Based Scanning™ (0-100% Certainty & Structured Proof Artifacts)
 * and Multi-Framework Enterprise Compliance Mapping Engine:
 *  - OWASP Top 10 (2021)
 *  - OWASP API Security Top 10 (2023)
 *  - PCI-DSS v4.0
 *  - ISO/IEC 27001:2022
 *  - NIST SP 800-53 Rev. 5
 *  - SOC 2 Trust Services Criteria
 *  - HIPAA Security Rule
 */

const COMPLIANCE_BY_CWE = {
  // Injection (SQLi, Command Injection, Code Injection, SSTI, CRLF, XXE)
  'CWE-89': {
    owaspApi2023: 'API8:2023-Security Misconfiguration',
    pciDss4: 'PCI-DSS v4.0 Req 6.2.4 (Injection & SQLi Prevention)',
    iso27001: 'ISO/IEC 27001:2022 A.8.28 (Secure Coding)',
    nist80053: 'NIST SP 800-53 Rev.5 SI-10 (Information Input Validation)',
    soc2: 'SOC 2 CC6.1 & CC7.1 (Input Validation & Vulnerability Management)',
    hipaa: 'HIPAA §164.312(a)(1) & §164.312(c)(1) (Integrity Controls)'
  },
  'CWE-78': {
    owaspApi2023: 'API8:2023-Security Misconfiguration',
    pciDss4: 'PCI-DSS v4.0 Req 6.2.4 (OS Command Injection Prevention)',
    iso27001: 'ISO/IEC 27001:2022 A.8.28 (Secure Coding)',
    nist80053: 'NIST SP 800-53 Rev.5 SI-10 (Information Input Validation)',
    soc2: 'SOC 2 CC6.1 (Logical Access & Input Controls)',
    hipaa: 'HIPAA §164.312(a)(1) (Access Control)'
  },
  'CWE-94': {
    owaspApi2023: 'API8:2023-Security Misconfiguration',
    pciDss4: 'PCI-DSS v4.0 Req 6.2.4 & 6.3.3 (Code Injection & Patching)',
    iso27001: 'ISO/IEC 27001:2022 A.8.28 & A.8.8 (Technical Vulnerabilities)',
    nist80053: 'NIST SP 800-53 Rev.5 SI-10 & SI-2 (Flaw Remediation)',
    soc2: 'SOC 2 CC7.1 (System Operations & Vulnerability Detection)',
    hipaa: 'HIPAA §164.308(a)(1)(ii)(A) (Risk Analysis)'
  },
  'CWE-1336': {
    owaspApi2023: 'API8:2023-Security Misconfiguration',
    pciDss4: 'PCI-DSS v4.0 Req 6.2.4 (Template Injection Prevention)',
    iso27001: 'ISO/IEC 27001:2022 A.8.28 (Secure Coding)',
    nist80053: 'NIST SP 800-53 Rev.5 SI-10 (Information Input Validation)',
    soc2: 'SOC 2 CC6.1 (Logical Access Controls)',
    hipaa: 'HIPAA §164.312(c)(1) (Integrity)'
  },
  'CWE-79': {
    owaspApi2023: 'API8:2023-Security Misconfiguration',
    pciDss4: 'PCI-DSS v4.0 Req 6.2.4 (Cross-Site Scripting Prevention)',
    iso27001: 'ISO/IEC 27001:2022 A.8.28 (Secure Coding)',
    nist80053: 'NIST SP 800-53 Rev.5 SI-10 (Information Input Validation)',
    soc2: 'SOC 2 CC6.1 (Logical Access & Output Encoding)',
    hipaa: 'HIPAA §164.312(c)(1) (Integrity)'
  },
  'CWE-113': {
    owaspApi2023: 'API8:2023-Security Misconfiguration',
    pciDss4: 'PCI-DSS v4.0 Req 6.2.4 (HTTP Header / CRLF Injection Prevention)',
    iso27001: 'ISO/IEC 27001:2022 A.8.28 (Secure Coding)',
    nist80053: 'NIST SP 800-53 Rev.5 SI-10 (Information Input Validation)',
    soc2: 'SOC 2 CC6.6 (Boundary Protection)',
    hipaa: 'HIPAA §164.312(e)(1) (Transmission Security)'
  },
  'CWE-611': {
    owaspApi2023: 'API8:2023-Security Misconfiguration',
    pciDss4: 'PCI-DSS v4.0 Req 6.2.4 (XML External Entity / XXE Prevention)',
    iso27001: 'ISO/IEC 27001:2022 A.8.28 (Secure Coding)',
    nist80053: 'NIST SP 800-53 Rev.5 SI-10 (Information Input Validation)',
    soc2: 'SOC 2 CC6.6 (System Boundary Protection)',
    hipaa: 'HIPAA §164.312(a)(1) (Access Control)'
  },
  // Broken Access Control / BOLA / IDOR / Auth
  'CWE-639': {
    owaspApi2023: 'API1:2023-Broken Object Level Authorization',
    pciDss4: 'PCI-DSS v4.0 Req 7.2.1 & 6.2.4 (Access Control & IDOR Prevention)',
    iso27001: 'ISO/IEC 27001:2022 A.8.3 (Information Access Restriction)',
    nist80053: 'NIST SP 800-53 Rev.5 AC-3 (Access Enforcement)',
    soc2: 'SOC 2 CC6.1 & CC6.3 (Role-Based Access Control)',
    hipaa: 'HIPAA §164.312(a)(1) (Unique User Access Control)'
  },
  'CWE-915': {
    owaspApi2023: 'API3:2023-Broken Object Property Level Authorization',
    pciDss4: 'PCI-DSS v4.0 Req 6.2.4 (Mass Assignment & Object Binding)',
    iso27001: 'ISO/IEC 27001:2022 A.8.3 & A.8.28 (Access Restriction)',
    nist80053: 'NIST SP 800-53 Rev.5 AC-3 & SI-10 (Access Enforcement)',
    soc2: 'SOC 2 CC6.1 (Logical Access Security)',
    hipaa: 'HIPAA §164.312(a)(1) (Access Control)'
  },
  'CWE-284': {
    owaspApi2023: 'API5:2023-Broken Function Level Authorization',
    pciDss4: 'PCI-DSS v4.0 Req 7.2.1 (Access Control Model)',
    iso27001: 'ISO/IEC 27001:2022 A.8.3 (Information Access Restriction)',
    nist80053: 'NIST SP 800-53 Rev.5 AC-3 (Access Enforcement)',
    soc2: 'SOC 2 CC6.1 (Logical Access Security)',
    hipaa: 'HIPAA §164.312(a)(1) (Access Control)'
  },
  'CWE-287': {
    owaspApi2023: 'API2:2023-Broken Authentication',
    pciDss4: 'PCI-DSS v4.0 Req 8.3.1 (Strong User Authentication)',
    iso27001: 'ISO/IEC 27001:2022 A.8.5 (Secure Authentication)',
    nist80053: 'NIST SP 800-53 Rev.5 IA-2 (Identification and Authentication)',
    soc2: 'SOC 2 CC6.1 (Authentication Controls)',
    hipaa: 'HIPAA §164.312(d) (Person or Entity Authentication)'
  },
  'CWE-347': {
    owaspApi2023: 'API2:2023-Broken Authentication',
    pciDss4: 'PCI-DSS v4.0 Req 8.3.1 & 4.2.1 (Cryptographic Signature Verification)',
    iso27001: 'ISO/IEC 27001:2022 A.8.24 (Use of Cryptography)',
    nist80053: 'NIST SP 800-53 Rev.5 IA-5 & SC-13 (Cryptographic Protection)',
    soc2: 'SOC 2 CC6.1 (Authentication & Token Integrity)',
    hipaa: 'HIPAA §164.312(d) (Authentication)'
  },
  // SSRF / Network / Desync
  'CWE-918': {
    owaspApi2023: 'API7:2023-Server Side Request Forgery',
    pciDss4: 'PCI-DSS v4.0 Req 6.2.4 & 1.3.2 (Outbound Traffic & SSRF Prevention)',
    iso27001: 'ISO/IEC 27001:2022 A.8.20 & A.8.22 (Network Segregation)',
    nist80053: 'NIST SP 800-53 Rev.5 SC-7 (Boundary Protection)',
    soc2: 'SOC 2 CC6.6 (Network Boundary Protection)',
    hipaa: 'HIPAA §164.312(e)(1) (Transmission Security)'
  },
  'CWE-444': {
    owaspApi2023: 'API8:2023-Security Misconfiguration',
    pciDss4: 'PCI-DSS v4.0 Req 6.4.1 & 6.2.4 (HTTP Framing & Proxy Security)',
    iso27001: 'ISO/IEC 27001:2022 A.8.20 (Networks Security)',
    nist80053: 'NIST SP 800-53 Rev.5 SC-7 & SI-10 (Protocol Validation)',
    soc2: 'SOC 2 CC6.6 (System Boundary Protection)',
    hipaa: 'HIPAA §164.312(e)(1) (Transmission Security)'
  },
  // Rate Limit / Resource Consumption
  'CWE-770': {
    owaspApi2023: 'API4:2023-Unrestricted Resource Consumption',
    pciDss4: 'PCI-DSS v4.0 Req 6.4.1 (DoS & Automated Abuse Mitigation)',
    iso27001: 'ISO/IEC 27001:2022 A.8.6 (Capacity Management)',
    nist80053: 'NIST SP 800-53 Rev.5 SC-5 (Denial-of-Service Protection)',
    soc2: 'SOC 2 A1.1 (Availability & Capacity Management)',
    hipaa: 'HIPAA §164.308(a)(7)(i) (Contingency & Availability)'
  },
  // TLS / Crypto
  'CWE-295': {
    owaspApi2023: 'API8:2023-Security Misconfiguration',
    pciDss4: 'PCI-DSS v4.0 Req 4.2.1 (Strong Cryptography & Valid TLS Certificates)',
    iso27001: 'ISO/IEC 27001:2022 A.8.24 (Use of Cryptography)',
    nist80053: 'NIST SP 800-53 Rev.5 SC-8 & SC-17 (PKI Certificates)',
    soc2: 'SOC 2 CC6.7 (Data in Transit Encryption)',
    hipaa: 'HIPAA §164.312(e)(1) (Transmission Security)'
  },
  'CWE-319': {
    owaspApi2023: 'API8:2023-Security Misconfiguration',
    pciDss4: 'PCI-DSS v4.0 Req 4.2.1 (Encrypted Transmission Over Open Networks)',
    iso27001: 'ISO/IEC 27001:2022 A.8.24 (Use of Cryptography)',
    nist80053: 'NIST SP 800-53 Rev.5 SC-8 (Transmission Confidentiality and Integrity)',
    soc2: 'SOC 2 CC6.7 (Encryption in Transit)',
    hipaa: 'HIPAA §164.312(e)(2)(ii) (Encryption)'
  }
};

const DEFAULT_COMPLIANCE = {
  owaspApi2023: 'API8:2023-Security Misconfiguration',
  pciDss4: 'PCI-DSS v4.0 Req 6.3.1 & 6.2.4 (Security Vulnerability Identification & Hardening)',
  iso27001: 'ISO/IEC 27001:2022 A.8.8 & A.8.9 (Management of Technical Vulnerabilities & Configuration)',
  nist80053: 'NIST SP 800-53 Rev.5 CM-6 & RA-5 (Configuration Settings & Vulnerability Monitoring)',
  soc2: 'SOC 2 CC7.1 (System Configuration & Vulnerability Detection)',
  hipaa: 'HIPAA §164.308(a)(1)(ii)(A) (Security Management & Risk Analysis)'
};

/**
 * Maps a CWE identifier and checkId to 6 enterprise compliance frameworks.
 *
 * @param {string} cwe
 * @param {string} [checkId='']
 * @returns {{
 *   cwe: string,
 *   owaspApi2023: string,
 *   pciDss4: string,
 *   iso27001: string,
 *   nist80053: string,
 *   soc2: string,
 *   hipaa: string
 * }}
 */
export function mapCweToCompliance(cwe, checkId = '') {
  const normCwe = String(cwe || 'CWE-16').trim().toUpperCase();
  const idLower = String(checkId || '').trim().toLowerCase();

  let entry = Object.hasOwn(COMPLIANCE_BY_CWE, normCwe)
    ? COMPLIANCE_BY_CWE[normCwe]
    : null;

  if (!entry) {
    if (idLower.includes('cve-') || normCwe === 'CWE-1104' || normCwe === 'CWE-416' || normCwe === 'CWE-787' || normCwe === 'CWE-190') {
      entry = {
        owaspApi2023: 'API8:2023-Security Misconfiguration',
        pciDss4: 'PCI-DSS v4.0 Req 6.3.3 (Patching Critical Security Vulnerabilities)',
        iso27001: 'ISO/IEC 27001:2022 A.8.8 (Management of Technical Vulnerabilities)',
        nist80053: 'NIST SP 800-53 Rev.5 SI-2 (Flaw Remediation)',
        soc2: 'SOC 2 CC7.1 (Vulnerability & Patch Management)',
        hipaa: 'HIPAA §164.308(a)(5)(ii)(B) (Protection from Malicious Software & Patching)'
      };
    } else if (idLower.includes('api-endpoints') || idLower.includes('api-communication')) {
      entry = {
        owaspApi2023: 'API9:2023-Improper Inventory Management',
        pciDss4: 'PCI-DSS v4.0 Req 6.4.1 & 12.5.1 (API & Asset Inventory Protection)',
        iso27001: 'ISO/IEC 27001:2022 A.5.9 (Inventory of Information and Associated Assets)',
        nist80053: 'NIST SP 800-53 Rev.5 CM-8 (System Component Inventory)',
        soc2: 'SOC 2 CC6.1 & CC6.6 (API Boundary & Inventory)',
        hipaa: 'HIPAA §164.312(a)(1) (Access Control)'
      };
    } else {
      entry = DEFAULT_COMPLIANCE;
    }
  }

  return {
    cwe: normCwe,
    ...entry
  };
}

/**
 * Invicti Proof-Based Scanning™ Confidence & Proof Artifact Builder.
 * Computes a deterministic 0-100% `certainty` score and structured `proofArtifact`
 * from S1 receipt verification, `poeLevel`, `evidenceQuotes`, and reproduction traces.
 *
 * @param {object} finding
 * @returns {{
 *   certainty: number,
 *   certaintyLabel: string,
 *   isConfirmedProof: boolean,
 *   proofType: string,
 *   extractedProof: string | null,
 *   verificationCommand: string | null
 * }}
 */
export function buildProofBasedArtifact(finding = {}) {
  const status = String(finding.status || 'SAFE').toUpperCase();
  if (status === 'SAFE' || status === 'ERROR') {
    return {
      certainty: 0,
      certaintyLabel: 'Not Vulnerable (0%)',
      isConfirmedProof: false,
      proofType: 'none',
      extractedProof: null,
      verificationCommand: null
    };
  }

  const quotes = Array.isArray(finding.evidenceQuotes)
    ? finding.evidenceQuotes.filter(q => typeof q === 'string' && q.trim().length >= 8)
    : [];
  const poeLevel = Number(finding.poeLevel ?? finding.poe_level ?? 0);
  const s1Verified =
    finding.verificationStatus === 'verified' ||
    finding.verified === true ||
    finding.reproVerified === true;
  const checkId = String(finding.checkId || finding.name || '').toLowerCase();

  let proofType = 'http_response_receipt';
  if (checkId === 'ssti-check') proofType = 'arithmetic_template_evaluation';
  else if (checkId === 'xxe-injection') proofType = 'xml_entity_expansion_proof';
  else if (checkId === 'crlf-header-injection') proofType = 'injected_response_header_proof';
  else if (checkId === 'cache-poisoning') proofType = 'cache_persistence_differential';
  else if (checkId === 'subdomain-takeover') proofType = 'dangling_cname_provider_signature';
  else if (checkId.startsWith('cve-') || (Array.isArray(finding.cveIds) && finding.cveIds.length > 0)) {
    proofType = 'version_and_protocol_receipt';
  } else if (checkId === 'env' || checkId === 'git' || checkId === 'ai-llm-exposure') {
    proofType = 'sensitive_artifact_extraction';
  }

  let certainty = 60;
  let certaintyLabel = 'Tentative (60% Certainty)';
  let isConfirmedProof = false;

  if (status === 'VULNERABLE' && (s1Verified || (poeLevel >= 3 && quotes.length > 0))) {
    certainty = 100;
    certaintyLabel = 'Confirmed — Proof-Based Verified (100% Certainty)';
    isConfirmedProof = true;
  } else if (status === 'VULNERABLE' && (poeLevel >= 2 || quotes.length > 0)) {
    certainty = 90;
    certaintyLabel = 'High Confidence (90% Certainty)';
    isConfirmedProof = false;
  } else if (status === 'VULNERABLE') {
    certainty = 80;
    certaintyLabel = 'Firm Confidence (80% Certainty)';
  } else if (status === 'SUSPICIOUS' && quotes.length > 0) {
    certainty = 75;
    certaintyLabel = 'Medium-High Confidence (75% Certainty)';
  }

  return {
    certainty,
    certaintyLabel,
    isConfirmedProof,
    proofType,
    extractedProof: quotes[0] || finding.reproduction?.observedSignal || null,
    verificationCommand: finding.reproduction?.curl || null
  };
}

/**
 * Aggregates scan findings into an executive multi-framework compliance matrix summary.
 *
 * @param {Array<object>} [findings=[]]
 */
export function buildComplianceSummary(findings = []) {
  const activeFindings = (Array.isArray(findings) ? findings : []).filter(
    f => f && (f.status === 'VULNERABLE' || f.status === 'SUSPICIOUS')
  );

  const frameworks = {
    pciDss4: new Map(),
    owaspApi2023: new Map(),
    iso27001: new Map(),
    nist80053: new Map(),
    soc2: new Map(),
    hipaa: new Map()
  };

  let confirmedProofCount = 0;
  for (const f of activeFindings) {
    const comp = f.compliance || mapCweToCompliance(f.cwe, f.checkId || f.name);
    const proof = f.proofArtifact || buildProofBasedArtifact(f);
    if (proof.isConfirmedProof) confirmedProofCount++;

    for (const key of Object.keys(frameworks)) {
      const control = comp[key];
      if (!control) continue;
      const map = frameworks[key];
      const existing = map.get(control) || { control, count: 0, checks: [] };
      existing.count += 1;
      const checkLabel = f.checkId || f.name || 'finding';
      if (!existing.checks.includes(checkLabel)) {
        existing.checks.push(checkLabel);
      }
      map.set(control, existing);
    }
  }

  return {
    totalActiveFindings: activeFindings.length,
    confirmedProofCount,
    overallCompliant: activeFindings.filter(f => f.status === 'VULNERABLE').length === 0,
    frameworks: {
      pciDss4: Array.from(frameworks.pciDss4.values()),
      owaspApi2023: Array.from(frameworks.owaspApi2023.values()),
      iso27001: Array.from(frameworks.iso27001.values()),
      nist80053: Array.from(frameworks.nist80053.values()),
      soc2: Array.from(frameworks.soc2.values()),
      hipaa: Array.from(frameworks.hipaa.values())
    }
  };
}
