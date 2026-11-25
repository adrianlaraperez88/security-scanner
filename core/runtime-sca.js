import {
  redactSecretsInText,
  redactEndpointQuery
} from './ai-advisor.js';

export const DEFAULT_MAX_SCA_BUNDLE_BYTES = 262_144; // 256 KiB
export const DEFAULT_MAX_SCA_HTML_BYTES = 2_097_152; // 2 MiB

/**
 * Branch-aware Runtime Software Composition Analysis (SCA) catalog covering
 * client-side libraries, frontend frameworks, backend runtimes, CMS platforms,
 * and web servers with branch-level and overall latest version baselines,
 * CVSS scores, End-of-Life (EOL) metadata, and known CVE ranges.
 */
export const RUNTIME_SCA_CATALOG = {
  'moment.js': {
    id: 'moment.js',
    name: 'Moment.js',
    category: 'frontend',
    icon: '🕒',
    eol: true,
    EOL: true,
    latestBranchVersion: 'N/A',
    branches: null,
    overallLatestVersion: '2.31.0',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '2.29.4',
        cve: 'CVE-2022-31129',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Inefficient Regular Expression Complexity (ReDoS) in Moment.js rfc2822 parser (< 2.29.4)'
      },
      {
        below: '2.29.2',
        cve: 'CVE-2022-24785',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Path Traversal in Moment.js locale loading (< 2.29.2)'
      }
    ]
  },

  lodash: {
    id: 'lodash',
    name: 'Lodash',
    category: 'frontend',
    icon: '📦',
    eol: false,
    EOL: false,
    latestBranchVersion: 'N/A',
    branches: null,
    overallLatestVersion: '4.18.1',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '4.17.21',
        cve: 'CVE-2021-23337',
        cvss: 7.2,
        severity: 'HIGH',
        summary: 'Command Injection via template function in Lodash (< 4.17.21)'
      },
      {
        below: '4.17.21',
        cve: 'CVE-2020-8203',
        cvss: 7.4,
        severity: 'HIGH',
        summary: 'Prototype Pollution in Lodash zipObjectDeep (< 4.17.21)'
      }
    ]
  },

  jquery: {
    id: 'jquery',
    name: 'jQuery',
    category: 'frontend',
    icon: '💲',
    eol: false,
    EOL: false,
    branches: {
      '1': { latest: '1.12.4', cvss: 6.1, eol: true },
      '2': { latest: '2.2.4', cvss: 6.1, eol: true },
      '3': { latest: '3.7.1', cvss: 0.0 },
      '4': { latest: '4.0.0', cvss: 0.0 }
    },
    overallLatestVersion: '4.0.0',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '3.5.0',
        cve: 'CVE-2020-11022',
        cvss: 6.1,
        severity: 'MEDIUM',
        summary: 'Cross-Site Scripting (XSS) in jQuery.htmlPrefilter (< 3.5.0)'
      },
      {
        below: '3.5.0',
        cve: 'CVE-2020-11023',
        cvss: 6.1,
        severity: 'MEDIUM',
        summary: 'Cross-Site Scripting (XSS) in jQuery <option> elements (< 3.5.0)'
      },
      {
        below: '3.4.0',
        cve: 'CVE-2019-11358',
        cvss: 6.1,
        severity: 'MEDIUM',
        summary: 'Prototype Pollution in jQuery.extend (< 3.4.0)'
      }
    ]
  },

  bootstrap: {
    id: 'bootstrap',
    name: 'Bootstrap',
    category: 'frontend',
    icon: '🅱️',
    eol: false,
    EOL: false,
    branches: {
      '3': { latest: '3.4.1', cvss: 6.1, eol: true },
      '4': { latest: '4.6.2', cvss: 0.0, eol: true },
      '5': { latest: '5.3.9', cvss: 0.0 }
    },
    overallLatestVersion: '5.3.9',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '3.4.1',
        cve: 'CVE-2019-8331',
        cvss: 6.1,
        severity: 'MEDIUM',
        summary: 'Cross-Site Scripting (XSS) in Bootstrap tooltip/popover data-template (< 3.4.1)'
      },
      {
        below: '4.3.1',
        cve: 'CVE-2019-8331',
        cvss: 6.1,
        severity: 'MEDIUM',
        summary: 'Cross-Site Scripting (XSS) in Bootstrap tooltip/popover data-template (< 4.3.1)'
      }
    ]
  },

  angularjs: {
    id: 'angularjs',
    name: 'AngularJS',
    category: 'frontend',
    icon: '🅰️',
    eol: true,
    EOL: true,
    branches: {
      '1': { latest: '1.8.3', cvss: 7.5, eol: true }
    },
    overallLatestVersion: '1.8.3',
    overallLatestCvss: 7.5,
    vulnerabilities: [
      {
        atMost: '1.8.3',
        cve: 'CVE-2022-25869',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Stored Cross-Site Scripting (XSS) in AngularJS (<= 1.8.3, End-of-Life)'
      },
      {
        atMost: '1.8.3',
        cve: 'CVE-2023-26116',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Regular Expression Denial of Service (ReDoS) in AngularJS angular.copy (<= 1.8.3, End-of-Life)'
      },
      {
        atMost: '1.8.3',
        cve: 'CVE-2024-21490',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Regular Expression Denial of Service (ReDoS) in AngularJS ng-srcset (<= 1.8.3, End-of-Life)'
      }
    ]
  },

  angular: {
    id: 'angular',
    name: 'Angular',
    category: 'frontend',
    icon: '🅰️',
    eol: false,
    EOL: false,
    branches: {
      '15': { latest: '15.2.10', cvss: 0.0, eol: true },
      '16': { latest: '16.2.12', cvss: 0.0, eol: true },
      '17': { latest: '17.3.12', cvss: 0.0, eol: true },
      '18': { latest: '18.2.13', cvss: 0.0 },
      '19': { latest: '19.2.9', cvss: 0.0 },
      '20': { latest: '20.3.35', cvss: 0.0 },
      '21': { latest: '21.2.4', cvss: 0.0 },
      '22': { latest: '22.2.6', cvss: 0.0 }
    },
    overallLatestVersion: '22.2.6',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '16.2.12',
        cve: 'CVE-2023-26117',
        cvss: 6.1,
        severity: 'MEDIUM',
        summary: 'Regular Expression Denial of Service (ReDoS) in Angular (< 16.2.12)'
      },
      {
        min: '20.0.0',
        atMost: '20.3.34',
        cve: 'CVE-2026-22801',
        cvss: 6.1,
        severity: 'MEDIUM',
        summary: 'Angular 20.x branch vulnerability (20.0.0 - 20.3.34)'
      }
    ]
  },

  react: {
    id: 'react',
    name: 'React',
    category: 'frontend',
    icon: '⚛️',
    eol: false,
    EOL: false,
    branches: {
      '17': { latest: '17.0.2', cvss: 0.0, eol: true },
      '18': { latest: '18.3.1', cvss: 0.0 },
      '19': { latest: '19.1.0', cvss: 0.0 }
    },
    overallLatestVersion: '19.1.0',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '18.2.0',
        cve: null,
        cvss: 5.3,
        severity: 'MEDIUM',
        summary: 'Outdated React runtime (< 18.2.0) lacking modern SSR and DOM security patches'
      }
    ]
  },

  vue: {
    id: 'vue',
    name: 'Vue.js',
    category: 'frontend',
    icon: '🟩',
    eol: false,
    EOL: false,
    branches: {
      '2': { latest: '2.7.16', cvss: 5.3, eol: true },
      '3': { latest: '3.5.13', cvss: 0.0 }
    },
    overallLatestVersion: '3.5.13',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '2.7.16',
        cve: 'CVE-2024-6783',
        cvss: 5.3,
        severity: 'MEDIUM',
        summary: 'Regular Expression Denial of Service (ReDoS) in Vue.js 2 parseHTML (< 2.7.16)'
      }
    ]
  },

  nextjs: {
    id: 'nextjs',
    name: 'Next.js',
    category: 'frameworks',
    icon: '▲',
    eol: false,
    EOL: false,
    branches: {
      '13': { latest: '13.5.9', cvss: 0.0, eol: true },
      '14': { latest: '14.2.25', cvss: 0.0 },
      '15': { latest: '15.2.3', cvss: 0.0 }
    },
    overallLatestVersion: '15.2.3',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '14.2.25',
        cve: 'CVE-2025-29927',
        cvss: 9.1,
        severity: 'CRITICAL',
        summary: 'Next.js Middleware Authorization Bypass via x-middleware-subrequest (< 14.2.25)'
      },
      {
        below: '14.1.1',
        cve: 'CVE-2024-34351',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Next.js Server Actions Host Header SSRF (< 14.1.1)'
      }
    ]
  },

  dompurify: {
    id: 'dompurify',
    name: 'DOMPurify',
    category: 'frontend',
    icon: '🧹',
    eol: false,
    EOL: false,
    branches: {
      '2': { latest: '2.5.8', cvss: 0.0 },
      '3': { latest: '3.2.4', cvss: 0.0 }
    },
    overallLatestVersion: '3.2.4',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '2.4.1',
        cve: 'CVE-2022-25887',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Mutation XSS (mXSS) bypass in DOMPurify (< 2.4.1)'
      },
      {
        below: '2.5.4',
        cve: 'CVE-2024-45801',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'DOM Clobbering / Prototype Pollution mXSS bypass in DOMPurify (< 3.1.3)'
      },
      {
        min: '3.0.0',
        below: '3.1.3',
        cve: 'CVE-2024-45801',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'DOM Clobbering / Prototype Pollution mXSS bypass in DOMPurify (< 3.1.3)'
      }
    ]
  },

  axios: {
    id: 'axios',
    name: 'Axios',
    category: 'frontend',
    icon: '📡',
    eol: false,
    EOL: false,
    branches: {
      '0': { latest: '0.28.1', cvss: 6.5 },
      '1': { latest: '1.8.2', cvss: 0.0 }
    },
    overallLatestVersion: '1.8.2',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '1.6.0',
        cve: 'CVE-2023-45857',
        cvss: 6.5,
        severity: 'MEDIUM',
        summary: 'Cross-Site Request Forgery (CSRF) token leakage across origins in Axios (< 1.6.0)'
      },
      {
        below: '1.7.4',
        cve: 'CVE-2024-39338',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Server-Side Request Forgery (SSRF) via path-relative URLs in Axios (< 1.7.4)'
      }
    ]
  },

  handlebars: {
    id: 'handlebars',
    name: 'Handlebars',
    category: 'frontend',
    icon: '🪶',
    eol: false,
    EOL: false,
    branches: {
      '4': { latest: '4.7.8', cvss: 0.0 }
    },
    overallLatestVersion: '4.7.8',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '4.7.7',
        cve: 'CVE-2021-23369',
        cvss: 9.8,
        severity: 'CRITICAL',
        summary: 'Remote Code Execution via prototype pollution in Handlebars template compilation (< 4.7.7)'
      }
    ]
  },

  laravel: {
    id: 'laravel',
    name: 'Laravel',
    category: 'frameworks',
    icon: '🔺',
    eol: false,
    EOL: false,
    branches: {
      '10': { latest: '10.48.28', cvss: 0.0 },
      '11': { latest: '11.44.1', cvss: 0.0 },
      '12': { latest: '12.1.1', cvss: 0.0 }
    },
    overallLatestVersion: '12.1.1',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '11.44.1',
        cve: 'CVE-2025-27515',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Laravel File Validation Bypass (< 11.44.1)'
      },
      {
        below: '10.48.28',
        cve: 'CVE-2024-52301',
        cvss: 8.1,
        severity: 'HIGH',
        summary: 'Laravel Environment Manipulation via query string argv (< 10.48.28)'
      }
    ]
  },

  wordpress: {
    id: 'wordpress',
    name: 'WordPress',
    category: 'frameworks',
    icon: '📝',
    eol: false,
    EOL: false,
    branches: {
      '6': { latest: '6.7.2', cvss: 0.0 }
    },
    overallLatestVersion: '6.7.2',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '6.6.2',
        cve: 'CVE-2024-6307',
        cvss: 6.1,
        severity: 'MEDIUM',
        summary: 'WordPress Core Stored Cross-Site Scripting (XSS) (< 6.6.2)'
      },
      {
        below: '6.5.5',
        cve: 'CVE-2024-4439',
        cvss: 7.2,
        severity: 'HIGH',
        summary: 'WordPress Core Avatar Block Stored XSS (< 6.5.5)'
      }
    ]
  },

  drupal: {
    id: 'drupal',
    name: 'Drupal',
    category: 'frameworks',
    icon: '💧',
    eol: false,
    EOL: false,
    branches: {
      '7': { latest: '7.103.0', cvss: 7.5, eol: true },
      '9': { latest: '9.5.11', cvss: 7.5, eol: true },
      '10': { latest: '10.4.3', cvss: 0.0 },
      '11': { latest: '11.1.3', cvss: 0.0 }
    },
    overallLatestVersion: '11.1.3',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '10.2.0',
        cve: 'CVE-2024-45440',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Drupal Core cache poisoning and error disclosure (< 10.2.0)'
      }
    ]
  },

  symfony: {
    id: 'symfony',
    name: 'Symfony',
    category: 'frameworks',
    icon: '🎼',
    eol: false,
    EOL: false,
    branches: {
      '6': { latest: '6.4.14', cvss: 0.0 },
      '7': { latest: '7.1.7', cvss: 0.0 }
    },
    overallLatestVersion: '7.1.7',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '6.4.14',
        cve: 'CVE-2024-50342',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Symfony HttpFoundation Request URL parsing flaw (< 6.4.14)'
      }
    ]
  },

  php: {
    id: 'php',
    name: 'PHP',
    category: 'runtimes',
    icon: '🐘',
    eol: false,
    EOL: false,
    branches: {
      '7': { latest: '7.4.33', cvss: 9.8, eol: true },
      '8.0': { latest: '8.0.30', cvss: 9.8, eol: true },
      '8.1': { latest: '8.1.31', cvss: 0.0 },
      '8.2': { latest: '8.2.27', cvss: 0.0 },
      '8.3': { latest: '8.3.17', cvss: 0.0 },
      '8.4': { latest: '8.4.4', cvss: 0.0 }
    },
    overallLatestVersion: '8.4.4',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '8.1.29',
        cve: 'CVE-2024-4577',
        cvss: 9.8,
        severity: 'CRITICAL',
        summary: 'PHP CGI Argument Injection Remote Code Execution (< 8.1.29)'
      },
      {
        min: '8.2.0',
        below: '8.2.20',
        cve: 'CVE-2024-4577',
        cvss: 9.8,
        severity: 'CRITICAL',
        summary: 'PHP CGI Argument Injection Remote Code Execution (< 8.2.20)'
      },
      {
        min: '8.3.0',
        below: '8.3.8',
        cve: 'CVE-2024-4577',
        cvss: 9.8,
        severity: 'CRITICAL',
        summary: 'PHP CGI Argument Injection Remote Code Execution (< 8.3.8)'
      }
    ]
  },

  nginx: {
    id: 'nginx',
    name: 'Nginx',
    category: 'servers',
    icon: '🟩',
    eol: false,
    EOL: false,
    branches: {
      '1': { latest: '1.27.4', cvss: 0.0 }
    },
    overallLatestVersion: '1.27.4',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '1.26.2',
        cve: 'CVE-2024-7347',
        cvss: 5.9,
        severity: 'MEDIUM',
        summary: 'NGINX ngx_http_mp4_module buffer over-read (< 1.26.2)'
      },
      {
        below: '1.25.3',
        cve: 'CVE-2023-44487',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'HTTP/2 Rapid Reset Denial of Service in NGINX (< 1.25.3)'
      }
    ]
  },

  apache: {
    id: 'apache',
    name: 'Apache HTTP Server',
    category: 'servers',
    icon: '🪶',
    eol: false,
    EOL: false,
    branches: {
      '2': { latest: '2.4.63', cvss: 0.0 }
    },
    overallLatestVersion: '2.4.63',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '2.4.62',
        cve: 'CVE-2024-38476',
        cvss: 9.8,
        severity: 'CRITICAL',
        summary: 'Apache HTTP Server mod_proxy backend handler confusion & SSRF (< 2.4.62)'
      },
      {
        below: '2.4.59',
        cve: 'CVE-2024-27316',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Apache HTTP Server HTTP/2 CONTINUATION frames flood DoS (< 2.4.59)'
      }
    ]
  },

  express: {
    id: 'express',
    name: 'Express',
    category: 'frameworks',
    icon: '🚂',
    eol: false,
    EOL: false,
    branches: {
      '4': { latest: '4.21.2', cvss: 0.0 },
      '5': { latest: '5.0.1', cvss: 0.0 }
    },
    overallLatestVersion: '5.0.1',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '4.21.1',
        cve: 'CVE-2024-43796',
        cvss: 5.0,
        severity: 'MEDIUM',
        summary: 'Express Cross-Site Scripting (XSS) via response.redirect() (< 4.21.1)'
      },
      {
        below: '4.19.2',
        cve: 'CVE-2024-29041',
        cvss: 6.1,
        severity: 'MEDIUM',
        summary: 'Express Open Redirect in response.redirect() (< 4.19.2)'
      }
    ]
  },

  'spring-boot': {
    id: 'spring-boot',
    name: 'Spring Boot',
    category: 'frameworks',
    icon: '🍃',
    eol: false,
    EOL: false,
    branches: {
      '2': { latest: '2.7.18', cvss: 7.5, eol: true },
      '3': { latest: '3.4.5', cvss: 0.0 }
    },
    overallLatestVersion: '3.4.5',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '3.3.10',
        cve: 'CVE-2025-22235',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Spring Boot EndpointRequest Security Matcher Bypass (< 3.3.10)'
      },
      {
        below: '3.2.10',
        cve: 'CVE-2024-38816',
        cvss: 7.5,
        severity: 'HIGH',
        summary: 'Spring WebMvc/WebFlux Static Resource Path Traversal (< 3.2.10)'
      }
    ]
  },

  tomcat: {
    id: 'tomcat',
    name: 'Apache Tomcat',
    category: 'servers',
    icon: '🐱',
    eol: false,
    EOL: false,
    branches: {
      '9': { latest: '9.0.105', cvss: 0.0 },
      '10': { latest: '10.1.41', cvss: 0.0 },
      '11': { latest: '11.0.7', cvss: 0.0 }
    },
    overallLatestVersion: '11.0.7',
    overallLatestCvss: 0.0,
    vulnerabilities: [
      {
        below: '9.0.100',
        cve: 'CVE-2025-24813',
        cvss: 9.8,
        severity: 'CRITICAL',
        summary: 'Apache Tomcat Partial-PUT Deserialization Remote Code Execution (< 9.0.100)'
      },
      {
        below: '9.0.98',
        cve: 'CVE-2024-50379',
        cvss: 9.8,
        severity: 'CRITICAL',
        summary: 'Apache Tomcat TOCTOU Race Condition RCE on Case-Insensitive Filesystems (< 9.0.98)'
      }
    ]
  }
};

const TECH_KEY_ALIASES = {
  moment: 'moment.js',
  momentjs: 'moment.js',
  'moment.js': 'moment.js',
  lodash: 'lodash',
  jquery: 'jquery',
  bootstrap: 'bootstrap',
  angularjs: 'angularjs',
  'angular.js': 'angularjs',
  angular: 'angular',
  '@angular/core': 'angular',
  react: 'react',
  'react-dom': 'react',
  vue: 'vue',
  'vue.js': 'vue',
  vuejs: 'vue',
  nextjs: 'nextjs',
  'next.js': 'nextjs',
  next: 'nextjs',
  dompurify: 'dompurify',
  purify: 'dompurify',
  axios: 'axios',
  handlebars: 'handlebars',
  'handlebars.js': 'handlebars',
  laravel: 'laravel',
  wordpress: 'wordpress',
  drupal: 'drupal',
  symfony: 'symfony',
  php: 'php',
  nginx: 'nginx',
  apache: 'apache',
  httpd: 'apache',
  express: 'express',
  spring: 'spring-boot',
  springboot: 'spring-boot',
  'spring-boot': 'spring-boot',
  tomcat: 'tomcat',
  'apache-tomcat': 'tomcat'
};

export function resolveTechCatalogKey(rawKey) {
  if (typeof rawKey !== 'string') return null;
  const clean = rawKey.trim().toLowerCase();
  if (!clean) return null;
  if (Object.hasOwn(RUNTIME_SCA_CATALOG, clean)) return clean;
  if (Object.hasOwn(TECH_KEY_ALIASES, clean)) return TECH_KEY_ALIASES[clean];
  return null;
}

/**
 * Strictly parses a semantic version string (`major.minor.patch` or `major.minor`),
 * rejecting 8+ digit date timestamps (e.g. `20261125`), 4-digit year majors (e.g. `2026.11.25`),
 * IPv4 addresses (`1.2.3.4`), and hex hashes.
 *
 * @param {string} versionStr
 * @returns {{ major: number, minor: number, patch: number, raw: string, normalized: string } | null}
 */
export function parseSemver(versionStr) {
  if (typeof versionStr !== 'string') return null;
  const trimmed = versionStr.trim().replace(/^[vV](?=\d)/, '');
  if (!trimmed || trimmed.length > 48) return null;

  // Reject 5+ digit numbers (such as 8-digit date timestamps like 20261125)
  if (/\d{5,}/.test(trimmed)) return null;

  // Reject pure hex hashes or commit-like strings
  if (/^[0-9a-f]{7,}$/i.test(trimmed)) return null;

  const match = trimmed.match(/^(\d{1,3})\.(\d{1,4})(?:\.(\d{1,4}))?(?:-(?:alpha|beta|rc|pre|p|patch|build|dev|next|canary)[A-Za-z0-9.-]{0,16})?$/i);
  if (!match) return null;

  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = match[3] !== undefined ? Number(match[3]) : 0;

  if (!Number.isFinite(major) || !Number.isFinite(minor) || !Number.isFinite(patch)) {
    return null;
  }
  // Reject year-like major numbers
  if (major >= 500) return null;

  const normalized = `${major}.${minor}.${patch}`;
  return {
    major,
    minor,
    patch,
    raw: match[3] !== undefined ? `${major}.${minor}.${patch}` : normalized,
    normalized
  };
}

/**
 * Compares two semantic version strings or parsed semver objects.
 * Returns -1 if a < b, 0 if a === b, 1 if a > b.
 *
 * @param {string | { major: number, minor: number, patch: number }} a
 * @param {string | { major: number, minor: number, patch: number }} b
 * @returns {number}
 */
export function compareSemver(a, b) {
  const pa = (a && typeof a === 'object' && Number.isFinite(a.major)) ? a : parseSemver(String(a ?? ''));
  const pb = (b && typeof b === 'object' && Number.isFinite(b.major)) ? b : parseSemver(String(b ?? ''));

  if (!pa && !pb) return 0;
  if (!pa) return -1;
  if (!pb) return 1;

  if (pa.major !== pb.major) return pa.major > pb.major ? 1 : -1;
  if (pa.minor !== pb.minor) return pa.minor > pb.minor ? 1 : -1;
  if (pa.patch !== pb.patch) return pa.patch > pb.patch ? 1 : -1;
  return 0;
}

function expandVersionInputs(identifiedVersions) {
  const rawItems = Array.isArray(identifiedVersions)
    ? identifiedVersions
    : (identifiedVersions !== undefined && identifiedVersions !== null ? [identifiedVersions] : []);

  const parsedList = [];
  const seenNormalized = new Set();

  for (const item of rawItems) {
    if (typeof item !== 'string') continue;
    const trimmed = item.trim();
    if (!trimmed) continue;

    // Check if range string like "2.9.0 - 2.23.0" or "2.9.0-2.23.0"
    const rangeMatch = trimmed.match(/^v?(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\s*[-–]\s*v?(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)$/i);
    const candidates = rangeMatch ? [rangeMatch[1], rangeMatch[2]] : [trimmed];

    for (const cand of candidates) {
      const parsed = parseSemver(cand);
      if (parsed && !seenNormalized.has(parsed.normalized)) {
        seenNormalized.add(parsed.normalized);
        parsedList.push(parsed);
      }
    }
  }

  parsedList.sort(compareSemver);
  return parsedList.map(p => p.normalized);
}

/**
 * Evaluates identified versions of a technology against RUNTIME_SCA_CATALOG
 * and returns an Invicti-style branch-aware SCA row.
 *
 * @param {string} techKey
 * @param {string | string[]} identifiedVersions
 * @param {{ sources?: string[] }} [extraMeta={}]
 */
export function evaluateTechnologyVersion(techKey, identifiedVersions, extraMeta = {}) {
  let canonicalKey = resolveTechCatalogKey(techKey);
  if (!canonicalKey) return null;

  const validVersions = expandVersionInputs(identifiedVersions);
  if (validVersions.length === 0) return null;

  // Automatically distinguish AngularJS (1.x) vs modern Angular (2+)
  const firstParsed = parseSemver(validVersions[0]);
  if (canonicalKey === 'angular' && firstParsed && firstParsed.major === 1) {
    canonicalKey = 'angularjs';
  } else if (canonicalKey === 'angularjs' && firstParsed && firstParsed.major >= 2) {
    canonicalKey = 'angular';
  }

  const catalogEntry = RUNTIME_SCA_CATALOG[canonicalKey];
  if (!catalogEntry) return null;

  const minVersion = validVersions[0];
  const maxVersion = validVersions[validVersions.length - 1];
  const identifiedVersion = validVersions.length === 1
    ? validVersions[0]
    : `${minVersion} - ${maxVersion}`;

  // Resolve branch metadata using highest identified version (or major.minor then major)
  const maxParsed = parseSemver(maxVersion);
  let branchInfo = null;
  if (catalogEntry.branches && maxParsed) {
    const minorBranchKey = `${maxParsed.major}.${maxParsed.minor}`;
    const majorBranchKey = `${maxParsed.major}`;
    if (Object.hasOwn(catalogEntry.branches, minorBranchKey)) {
      branchInfo = catalogEntry.branches[minorBranchKey];
    } else if (Object.hasOwn(catalogEntry.branches, majorBranchKey)) {
      branchInfo = catalogEntry.branches[majorBranchKey];
    }
  }

  const latestBranchVersion = (catalogEntry.latestBranchVersion === 'N/A' || !branchInfo?.latest)
    ? 'N/A'
    : String(branchInfo.latest);
  const latestBranchCvss = latestBranchVersion === 'N/A'
    ? null
    : Number(branchInfo.cvss ?? 0.0);
  const latestBranchDisplay = latestBranchVersion === 'N/A'
    ? 'N/A'
    : `${latestBranchVersion} (Highest CVSS: ${latestBranchCvss.toFixed(1)})`;

  const overallLatestVersion = catalogEntry.overallLatestVersion || 'N/A';
  const overallLatestCvss = overallLatestVersion === 'N/A'
    ? null
    : Number(catalogEntry.overallLatestCvss ?? 0.0);
  const overallLatestDisplay = overallLatestVersion === 'N/A'
    ? 'N/A'
    : `${overallLatestVersion} (Highest CVSS: ${overallLatestCvss.toFixed(1)})`;

  // Evaluate vulnerability ranges against all identified versions
  const matchedVulns = [];
  const seenVulnKeys = new Set();
  const catalogVulns = Array.isArray(catalogEntry.vulnerabilities) ? catalogEntry.vulnerabilities : [];

  for (const rule of catalogVulns) {
    const matchesAny = validVersions.some(ver => {
      if (rule.min && compareSemver(ver, rule.min) < 0) return false;
      if (rule.below && compareSemver(ver, rule.below) >= 0) return false;
      if (rule.atMost && compareSemver(ver, rule.atMost) > 0) return false;
      return Boolean(rule.below || rule.atMost);
    });

    if (matchesAny) {
      const cveKey = rule.cve || rule.summary;
      if (!seenVulnKeys.has(cveKey)) {
        seenVulnKeys.add(cveKey);
        matchedVulns.push({
          cve: rule.cve || null,
          cvss: Number(rule.cvss ?? 0.0),
          severity: rule.severity || (Number(rule.cvss) >= 9.0 ? 'CRITICAL' : Number(rule.cvss) >= 7.0 ? 'HIGH' : 'MEDIUM'),
          summary: rule.summary || `${catalogEntry.name} vulnerability`
        });
      }
    }
  }

  let highestCvss = matchedVulns.reduce((max, v) => Math.max(max, Number(v.cvss) || 0), 0.0);
  if (branchInfo && Number(branchInfo.cvss) > highestCvss && compareSemver(minVersion, branchInfo.latest) <= 0) {
    highestCvss = Number(branchInfo.cvss);
  }

  const isEol = Boolean(catalogEntry.eol || catalogEntry.EOL || branchInfo?.eol);
  const belowOverall = overallLatestVersion !== 'N/A' && validVersions.some(v => compareSemver(v, overallLatestVersion) < 0);
  const belowBranch = latestBranchVersion !== 'N/A' && validVersions.some(v => compareSemver(v, latestBranchVersion) < 0);
  const eolWithVuln = isEol && ((overallLatestCvss ?? 0) > 0 || highestCvss > 0);

  const isOutOfDate = Boolean(belowOverall || belowBranch || highestCvss > 0 || eolWithVuln);
  const status = isOutOfDate ? 'Out of date' : 'Up to date';
  const isVulnerable = Boolean(highestCvss >= 4.0 || matchedVulns.length > 0);

  const identifiedVersionDisplay = `${identifiedVersion} (Highest CVSS: ${highestCvss.toFixed(1)})`;
  const cveIds = Array.from(new Set(matchedVulns.map(v => v.cve).filter(Boolean)));

  let recommendedAction = '';
  if (status === 'Out of date') {
    if (isEol && (overallLatestCvss ?? 0) > 0) {
      if (catalogEntry.id === 'angularjs') {
        const modernNgVer = RUNTIME_SCA_CATALOG.angular?.overallLatestVersion || '22.2.6';
        recommendedAction = `AngularJS 1.x is End-of-Life (Highest CVSS: ${overallLatestCvss.toFixed(1)}). Migrate to modern Angular (${modernNgVer}).`;
      } else {
        recommendedAction = `${catalogEntry.name} is End-of-Life (Highest CVSS: ${overallLatestCvss.toFixed(1)}). Migrate to a supported release.`;
      }
    } else if (overallLatestVersion !== 'N/A' && (overallLatestCvss ?? 0) === 0) {
      recommendedAction = `This target could be at high risk of attack. Recommend updating to version ${overallLatestVersion}`;
    } else if (overallLatestVersion !== 'N/A') {
      recommendedAction = `This target could be at high risk of attack. Recommend updating to version ${overallLatestVersion}`;
    } else {
      recommendedAction = 'This target could be at high risk of attack. Recommend updating to the latest patched release.';
    }
  }

  const rawSources = Array.isArray(extraMeta?.sources) ? extraMeta.sources : [];
  const sources = Array.from(new Set(rawSources.filter(s => typeof s === 'string' && s.trim()).map(s => s.trim())));

  return {
    id: catalogEntry.id,
    name: catalogEntry.name,
    category: catalogEntry.category,
    icon: catalogEntry.icon,
    status,
    isOutOfDate,
    isVulnerable,
    isEol,
    identifiedVersion,
    identifiedVersions: validVersions,
    highestCvss,
    identifiedVersionDisplay,
    latestBranchVersion,
    latestBranchCvss,
    latestBranchDisplay,
    overallLatestVersion,
    overallLatestCvss,
    overallLatestDisplay,
    cveIds,
    vulnerabilities: matchedVulns,
    recommendedAction,
    sources
  };
}

function normalizeHeadersMap(headers) {
  const out = {};
  if (!headers) return out;
  if (typeof headers.entries === 'function') {
    for (const [k, v] of headers.entries()) {
      out[String(k).toLowerCase()] = String(v);
    }
    return out;
  }
  if (typeof headers === 'object') {
    for (const [k, v] of Object.entries(headers)) {
      out[String(k).toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
    }
  }
  return out;
}

const ASSET_URL_PATTERNS = [
  {
    tech: 'jquery',
    regex: /(?:^|[\/@_-])jquery(?!-(?:ui|migrate|validation|cookie|form|easing|modal))\b(?:[^?#]*?[\/@v_-](\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)|(?:\.slim)?(?:\.min)?\.js\?(?:ver|v)=(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?))/i
  },
  {
    tech: 'moment.js',
    regex: /(?:^|[\/@_-])moment(?:\.js|-with-locales)?\b(?:[^?#]*?[\/@v_-](\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)|(?:\.min)?\.js\?(?:ver|v)=(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?))/i
  },
  {
    tech: 'lodash',
    regex: /(?:^|[\/@_-])lodash(?:\.core|\.fp)?\b(?:[^?#]*?[\/@v_-](\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)|(?:\.min)?\.js\?(?:ver|v)=(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?))/i
  },
  {
    tech: 'bootstrap',
    regex: /(?:^|[\/@_-])bootstrap(?:\.bundle)?\b(?:[^?#]*?[\/@v_-](\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)|(?:\.min)?\.(?:js|css)\?(?:ver|v)=(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?))/i
  },
  {
    tech: 'angular',
    regex: /(?:^|[\/@_-])(?:@angular\/core|angular(?:\.js|js)?)\b(?:[^?#]*?[\/@v_-](\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)|(?:\.min)?\.js\?(?:ver|v)=(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?))/i
  },
  {
    tech: 'vue',
    regex: /(?:^|[\/@_-])vue(?:\.js|\.runtime|\.global)?\b(?:[^?#]*?[\/@v_-](\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)|(?:\.prod)?(?:\.min)?\.js\?(?:ver|v)=(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?))/i
  },
  {
    tech: 'react',
    regex: /(?:^|[\/@_-])react(?:-dom)?\b(?:[^?#]*?[\/@v_-](\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)|(?:\.production\.min|\.development)?\.js\?(?:ver|v)=(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?))/i
  },
  {
    tech: 'dompurify',
    regex: /(?:^|[\/@_-])(?:dom)?purify\b(?:[^?#]*?[\/@v_-](\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)|(?:\.min)?\.js\?(?:ver|v)=(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?))/i
  },
  {
    tech: 'axios',
    regex: /(?:^|[\/@_-])axios\b(?:[^?#]*?[\/@v_-](\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)|(?:\.min)?\.js\?(?:ver|v)=(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?))/i
  },
  {
    tech: 'handlebars',
    regex: /(?:^|[\/@_-])handlebars(?:\.runtime)?\b(?:[^?#]*?[\/@v_-](\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)|(?:\.min)?\.js\?(?:ver|v)=(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?))/i
  }
];

const BUNDLE_BANNER_PATTERNS = [
  {
    tech: 'jquery',
    regex: /(?:\b(?:jQuery(?:\s+JavaScript\s+Library)?)\s+v?(\d{1,3}\.\d{1,4}\.\d{1,4})\b|jQuery\.fn\.jquery\s*=\s*["'](\d{1,3}\.\d{1,4}\.\d{1,4})["'])/gi
  },
  {
    tech: 'moment.js',
    regex: /(?:\/\/!\s*moment\.js[\s\S]{0,160}?version\s*:\s*v?(\d{1,3}\.\d{1,4}\.\d{1,4})\b|\/\*![^\r\n*]*\bmoment(?:\.js)?\s+v?(\d{1,3}\.\d{1,4}\.\d{1,4})\b|\bmoment(?:\.js)?\.version\s*=\s*["']v?(\d{1,3}\.\d{1,4}\.\d{1,4})["'])/gi
  },
  {
    tech: 'lodash',
    regex: /(?:\blodash\.VERSION\s*=\s*["']v?(\d{1,3}\.\d{1,4}\.\d{1,4})["']|\/\*![^\r\n*]*\bLodash\s+v?(\d{1,3}\.\d{1,4}\.\d{1,4})\b)/gi
  },
  {
    tech: 'bootstrap',
    regex: /(?:\*!\s*Bootstrap\s+v?(\d{1,3}\.\d{1,4}\.\d{1,4})\b|\*\s*Bootstrap\s+v(\d{1,3}\.\d{1,4}\.\d{1,4})\b)/gi
  },
  {
    tech: 'angularjs',
    regex: /\bAngularJS\s+v?(\d{1,3}\.\d{1,4}\.\d{1,4})\b/gi
  },
  {
    tech: 'angular',
    regex: /(?:@license\s+Angular\s+v?(\d{1,3}\.\d{1,4}\.\d{1,4})\b|\/\*![^\r\n*]*\bAngular\s+v?(\d{1,3}\.\d{1,4}\.\d{1,4})\b)/gi
  },
  {
    tech: 'react',
    regex: /(?:@license\s+React\s+v?(\d{1,3}\.\d{1,4}\.\d{1,4})\b|\bReact\.version\s*=\s*["'](\d{1,3}\.\d{1,4}\.\d{1,4})["'])/gi
  },
  {
    tech: 'vue',
    regex: /(?:\/\*![^\r\n*]*\bVue(?:\.js)?\s+v?(\d{1,3}\.\d{1,4}\.\d{1,4})\b|\bVue\.version\s*=\s*["'](\d{1,3}\.\d{1,4}\.\d{1,4})["'])/gi
  },
  {
    tech: 'dompurify',
    regex: /\bDOMPurify(?:\.version\s*=\s*["']|\s+v?)(\d{1,3}\.\d{1,4}\.\d{1,4})\b/gi
  },
  {
    tech: 'axios',
    regex: /(?:\/\*![^\r\n*]*\baxios\s+v?(\d{1,3}\.\d{1,4}\.\d{1,4})\b|\baxios\.VERSION\s*=\s*["'](\d{1,3}\.\d{1,4}\.\d{1,4})["'])/gi
  },
  {
    tech: 'handlebars',
    regex: /(?:\bHandlebars\.VERSION\s*=\s*["'](\d{1,3}\.\d{1,4}\.\d{1,4})["']|\/\*![^\r\n*]*\bhandlebars\s+v?(\d{1,3}\.\d{1,4}\.\d{1,4})\b)/gi
  },
  {
    tech: 'nextjs',
    regex: /(?:window\.next\s*=\s*\{\s*version\s*:\s*["'](\d{1,3}\.\d{1,4}\.\d{1,4})["']|"next"\s*:\s*\{\s*"version"\s*:\s*["'](\d{1,3}\.\d{1,4}\.\d{1,4})["'])/gi
  }
];

export function buildRuntimeScaSummary(findings = []) {
  const safeFindings = Array.isArray(findings) ? findings.filter(Boolean) : [];
  const totalIdentified = safeFindings.length;
  const outOfDateCount = safeFindings.filter(f => f.isOutOfDate || f.status === 'Out of date').length;
  const upToDateCount = safeFindings.filter(f => !f.isOutOfDate && f.status === 'Up to date').length;
  const vulnerableCount = safeFindings.filter(f => f.isVulnerable || Number(f.highestCvss) >= 4.0).length;
  const highestCvss = safeFindings.length > 0
    ? Math.max(0.0, ...safeFindings.map(f => Number(f.highestCvss) || 0.0))
    : 0.0;

  const summary = totalIdentified === 0
    ? 'No client-side or server-side runtime technology versions detected.'
    : `Identified ${totalIdentified} technology version(s): ${outOfDateCount} out of date (${vulnerableCount} with known CVEs, highest CVSS ${highestCvss.toFixed(1)}), ${upToDateCount} up to date.`;

  return {
    totalIdentified,
    outOfDateCount,
    upToDateCount,
    vulnerableCount,
    highestCvss,
    findings: safeFindings,
    summary
  };
}

/**
 * Extracts runtime technology versions from HTML tags, attributes, inline scripts,
 * JS bundle banners, and HTTP response headers.
 *
 * @param {{
 *   html?: string,
 *   headers?: Record<string, string | string[]>,
 *   pageUrl?: string,
 *   bundleTexts?: Array<string | { url?: string, path?: string, text?: string }>
 * }} [input={}]
 */
export function extractRuntimeScaFromResponse({
  html = '',
  headers = {},
  pageUrl = '',
  bundleTexts = []
} = {}) {
  const safeHtml = typeof html === 'string' ? html.slice(0, DEFAULT_MAX_SCA_HTML_BYTES) : '';
  const normHeaders = normalizeHeadersMap(headers);

  // Map<canonicalTechKey, { versions: Set<string>, sources: Set<string> }>
  const detected = new Map();

  const recordVersion = (rawTech, rawVer, sourceLabel) => {
    let techKey = resolveTechCatalogKey(rawTech);
    if (!techKey) return;

    const versions = expandVersionInputs(rawVer);
    if (versions.length === 0) return;

    for (const ver of versions) {
      const parsed = parseSemver(ver);
      if (!parsed) continue;
      let effectiveKey = techKey;
      if (effectiveKey === 'angular' && parsed.major === 1) {
        effectiveKey = 'angularjs';
      } else if (effectiveKey === 'angularjs' && parsed.major >= 2) {
        effectiveKey = 'angular';
      }

      if (!detected.has(effectiveKey)) {
        detected.set(effectiveKey, { versions: new Set(), sources: new Set() });
      }
      const entry = detected.get(effectiveKey);
      entry.versions.add(parsed.normalized);
      if (sourceLabel) entry.sources.add(sourceLabel);
    }
  };

  // 1. Extract from data-sca-versions attribute or HTML comments (e.g. data-sca-versions="moment.js:2.9.0-2.23.0")
  const dataScaRe = /\bdata-sca-versions\s*=\s*(?:"([^"]{1,512})"|'([^']{1,512})')/gi;
  let dataMatch;
  while ((dataMatch = dataScaRe.exec(safeHtml)) !== null) {
    const rawAttr = dataMatch[1] || dataMatch[2] || '';
    for (const pair of rawAttr.split(/[;,]/)) {
      const idx = pair.indexOf(':');
      if (idx === -1) continue;
      const tName = pair.slice(0, idx).trim();
      const vRange = pair.slice(idx + 1).trim();
      if (tName && vRange) {
        recordVersion(tName, vRange, 'html-attr: data-sca-versions');
      }
    }
  }

  // 2. Extract from <script src="..."> and <link href="..."> URLs
  const scriptSrcRe = /<script\b[^>]{0,1024}?\bsrc\s*=\s*(?:"([^"]{1,1024})"|'([^']{1,1024})'|([^\s"'=<>`]{1,1024}))[^>]{0,1024}>/gi;
  let sMatch;
  while ((sMatch = scriptSrcRe.exec(safeHtml)) !== null) {
    const rawSrc = (sMatch[1] || sMatch[2] || sMatch[3] || '').trim();
    if (!rawSrc) continue;
    for (const pat of ASSET_URL_PATTERNS) {
      const m = rawSrc.match(pat.regex);
      const ver = m?.[1] || m?.[2];
      if (ver) {
        recordVersion(pat.tech, ver, `script-src: ${rawSrc}`);
      }
    }
  }

  const linkHrefRe = /<link\b[^>]{0,1024}?\bhref\s*=\s*(?:"([^"]{1,1024})"|'([^']{1,1024})'|([^\s"'=<>`]{1,1024}))[^>]{0,1024}>/gi;
  let lMatch;
  while ((lMatch = linkHrefRe.exec(safeHtml)) !== null) {
    const rawHref = (lMatch[1] || lMatch[2] || lMatch[3] || '').trim();
    if (!rawHref) continue;
    for (const pat of ASSET_URL_PATTERNS) {
      const m = rawHref.match(pat.regex);
      const ver = m?.[1] || m?.[2];
      if (ver) {
        recordVersion(pat.tech, ver, `link-href: ${rawHref}`);
      }
    }
  }

  // 3. Extract from HTML attributes (ng-version) and <meta name="generator">
  const ngVerMatch = safeHtml.match(/\bng-version\s*=\s*(?:"(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)"|'(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)')/i);
  if (ngVerMatch) {
    const ver = ngVerMatch[1] || ngVerMatch[2];
    recordVersion('angular', ver, 'html-attr: ng-version');
  }

  const metaTagRe = /<meta\b([^>]{1,1024})>/gi;
  let mMatch;
  while ((mMatch = metaTagRe.exec(safeHtml)) !== null) {
    const attrs = mMatch[1] || '';
    if (!/\bname\s*=\s*["']?generator["']?\b/i.test(attrs)) continue;
    const contentMatch = attrs.match(/\bcontent\s*=\s*(?:"([^"]{1,512})"|'([^']{1,512})')/i);
    const content = (contentMatch?.[1] || contentMatch?.[2] || '').trim();
    if (!content) continue;

    const wpMatch = content.match(/\bWordPress\s+v?(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (wpMatch) recordVersion('wordpress', wpMatch[1], 'meta: generator');

    const drupalMatch = content.match(/\bDrupal\s+v?(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (drupalMatch) recordVersion('drupal', drupalMatch[1], 'meta: generator');

    const nextMatch = content.match(/\bNext\.?js\s+v?(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (nextMatch) recordVersion('nextjs', nextMatch[1], 'meta: generator');
  }

  // 4. Scan inline HTML comments/scripts and external bundleTexts for library banners
  const scanBannerText = (textContent, sourceLabel) => {
    if (typeof textContent !== 'string' || !textContent) return;
    const bounded = textContent.slice(0, DEFAULT_MAX_SCA_BUNDLE_BYTES);
    for (const pat of BUNDLE_BANNER_PATTERNS) {
      pat.regex.lastIndex = 0;
      let bm;
      while ((bm = pat.regex.exec(bounded)) !== null) {
        const ver = bm[1] || bm[2] || bm[3];
        if (ver) {
          recordVersion(pat.tech, ver, sourceLabel);
        }
      }
    }
  };

  if (safeHtml) {
    const htmlSourceLabel = pageUrl ? `bundle-banner: ${pageUrl}` : 'bundle-banner: inline-html';
    scanBannerText(safeHtml, htmlSourceLabel);
  }

  if (Array.isArray(bundleTexts)) {
    for (let i = 0; i < bundleTexts.length; i++) {
      const item = bundleTexts[i];
      if (typeof item === 'string') {
        scanBannerText(item, 'bundle-banner: /bundle.js');
      } else if (item && typeof item === 'object' && typeof item.text === 'string') {
        const srcPath = item.url || item.path || `/bundle-${i + 1}.js`;
        scanBannerText(item.text, `bundle-banner: ${srcPath}`);
      }
    }
  }

  // 5. Extract from HTTP response headers
  const serverHdr = normHeaders['server'] || '';
  if (serverHdr) {
    const nginxMatch = serverHdr.match(/\bnginx\/(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (nginxMatch) recordVersion('nginx', nginxMatch[1], 'header: Server');

    const tomcatMatch = serverHdr.match(/\b(?:Apache[- ])?Tomcat\/(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (tomcatMatch) recordVersion('tomcat', tomcatMatch[1], 'header: Server');

    if (!/tomcat|coyote/i.test(serverHdr)) {
      const apacheMatch = serverHdr.match(/\bApache\/(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
      if (apacheMatch) recordVersion('apache', apacheMatch[1], 'header: Server');
    }
  }

  const poweredHdr = normHeaders['x-powered-by'] || '';
  if (poweredHdr) {
    const phpMatch = poweredHdr.match(/\bPHP\/(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (phpMatch) recordVersion('php', phpMatch[1], 'header: X-Powered-By');

    const nextMatch = poweredHdr.match(/\bNext\.?js\s*\/?\s*v?(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (nextMatch) recordVersion('nextjs', nextMatch[1], 'header: X-Powered-By');

    const expressMatch = poweredHdr.match(/\bExpress\s*\/?\s*v?(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (expressMatch) recordVersion('express', expressMatch[1], 'header: X-Powered-By');

    const tomcatMatch = poweredHdr.match(/\b(?:Apache[- ])?Tomcat\/(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (tomcatMatch) recordVersion('tomcat', tomcatMatch[1], 'header: X-Powered-By');

    const laravelMatch = poweredHdr.match(/\bLaravel\s*\/?\s*v?(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (laravelMatch) recordVersion('laravel', laravelMatch[1], 'header: X-Powered-By');

    const symfonyMatch = poweredHdr.match(/\bSymfony\s*\/?\s*v?(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (symfonyMatch) recordVersion('symfony', symfonyMatch[1], 'header: X-Powered-By');

    const springMatch = poweredHdr.match(/\bSpring(?:\s+Boot)?\s*\/?\s*v?(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (springMatch) recordVersion('spring-boot', springMatch[1], 'header: X-Powered-By');
  }

  const generatorHdr = normHeaders['x-generator'] || '';
  if (generatorHdr) {
    const wpMatch = generatorHdr.match(/\bWordPress\s*\/?\s*v?(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (wpMatch) recordVersion('wordpress', wpMatch[1], 'header: X-Generator');

    const drupalMatch = generatorHdr.match(/\bDrupal\s*\/?\s*v?(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (drupalMatch) recordVersion('drupal', drupalMatch[1], 'header: X-Generator');

    const nextMatch = generatorHdr.match(/\bNext\.?js\s*\/?\s*v?(\d{1,3}\.\d{1,4}(?:\.\d{1,4})?)\b/i);
    if (nextMatch) recordVersion('nextjs', nextMatch[1], 'header: X-Generator');
  }

  // Evaluate each detected technology against RUNTIME_SCA_CATALOG
  const findings = [];
  for (const [techKey, info] of detected.entries()) {
    const row = evaluateTechnologyVersion(
      techKey,
      Array.from(info.versions),
      { sources: Array.from(info.sources) }
    );
    if (row) {
      findings.push(row);
    }
  }

  return buildRuntimeScaSummary(findings);
}

function safeParseUrl(raw, base) {
  try {
    return base ? new URL(raw, base) : new URL(raw);
  } catch {
    return null;
  }
}

function isHtmlFallbackResponse(res) {
  if (!res) return false;
  const headers = normalizeHeadersMap(res.headers);
  const ct = (headers['content-type'] || '').toLowerCase();
  if (ct.includes('text/html') || ct.includes('application/xhtml+xml')) return true;
  const trimmed = typeof res.text === 'string' ? res.text.trimStart().slice(0, 64).toLowerCase() : '';
  return trimmed.startsWith('<!doctype') || trimmed.startsWith('<html') || trimmed.startsWith('<head') || trimmed.startsWith('<body');
}

/**
 * Passively inspects the target root response and up to `maxBundles` same-origin
 * `.js` bundles (256 KiB cap per bundle) to detect runtime dependency versions and CVEs.
 *
 * @param {string} targetUrl
 * @param {Function} fetchWithRetry
 * @param {object} [options={}]
 */
export async function detectRuntimeScaFindings(targetUrl, fetchWithRetry, options = {}) {
  const baseObj = safeParseUrl(targetUrl);
  if (!baseObj || !['http:', 'https:'].includes(baseObj.protocol)) {
    return buildRuntimeScaSummary([]);
  }
  const baseOrigin = baseObj.origin;

  let rootRes = options?.rootResponse || null;
  if (!rootRes && typeof fetchWithRetry === 'function') {
    try {
      rootRes = await fetchWithRetry(baseObj.href, {
        sameOriginRedirects: true,
        maxBytes: DEFAULT_MAX_SCA_HTML_BYTES
      });
    } catch {
      return buildRuntimeScaSummary([]);
    }
  }

  if (!rootRes || typeof rootRes !== 'object') {
    return buildRuntimeScaSummary([]);
  }

  if (rootRes.url) {
    const finalObj = safeParseUrl(rootRes.url, baseObj.href);
    if (!finalObj || finalObj.origin !== baseOrigin) {
      return buildRuntimeScaSummary([]);
    }
  }

  const rootHeaders = normalizeHeadersMap(rootRes.headers);
  if (rootRes.status >= 300 && rootRes.status < 400 && rootHeaders.location) {
    const redirObj = safeParseUrl(rootHeaders.location, baseObj.href);
    if (!redirObj || redirObj.origin !== baseOrigin) {
      return buildRuntimeScaSummary([]);
    }
  }

  const rootHtml = typeof rootRes.text === 'string' ? rootRes.text : '';
  const maxBundles = Number.isFinite(Number(options?.maxBundles))
    ? Math.max(0, Math.floor(Number(options.maxBundles)))
    : 4;
  const seenBundleUrls = options?.seenBundleUrls instanceof Set ? options.seenBundleUrls : null;

  const bundleTexts = Array.isArray(options?.bundleTexts) ? [...options.bundleTexts] : [];

  if (maxBundles > 0 && rootHtml && typeof fetchWithRetry === 'function') {
    const candidateScripts = [];
    const localSeen = new Set();
    const scriptSrcRe = /<script\b[^>]{0,1024}?\bsrc\s*=\s*(?:"([^"]{1,1024})"|'([^']{1,1024})'|([^\s"'=<>`]{1,1024}))[^>]{0,1024}>/gi;
    let match;
    while ((match = scriptSrcRe.exec(rootHtml)) !== null) {
      const rawSrc = (match[1] || match[2] || match[3] || '').trim();
      if (!rawSrc || rawSrc.startsWith('data:') || rawSrc.startsWith('javascript:')) continue;
      const parsed = safeParseUrl(rawSrc, baseObj.href);
      if (!parsed || parsed.origin !== baseOrigin) continue;
      if (!/\.(?:m?js)(?:$|\?)/i.test(parsed.pathname)) continue;
      if (localSeen.has(parsed.href)) continue;
      localSeen.add(parsed.href);
      candidateScripts.push(parsed);
    }

    let fetchedCount = 0;
    for (const parsedScript of candidateScripts) {
      if (fetchedCount >= maxBundles) break;
      if (seenBundleUrls) {
        if (seenBundleUrls.has(parsedScript.href) || seenBundleUrls.has(parsedScript.pathname)) {
          continue;
        }
        seenBundleUrls.add(parsedScript.href);
      }

      try {
        const scriptRes = await fetchWithRetry(parsedScript.href, {
          followRedirects: false,
          redirect: 'manual',
          maxBytes: DEFAULT_MAX_SCA_BUNDLE_BYTES
        });
        if (!scriptRes || scriptRes.status !== 200 || typeof scriptRes.text !== 'string' || !scriptRes.text) {
          continue;
        }
        if (scriptRes.url) {
          const finalScriptObj = safeParseUrl(scriptRes.url, baseObj.href);
          if (!finalScriptObj || finalScriptObj.origin !== baseOrigin) continue;
        }
        if (isHtmlFallbackResponse(scriptRes)) continue;

        fetchedCount += 1;
        bundleTexts.push({
          url: parsedScript.pathname,
          text: scriptRes.text.slice(0, DEFAULT_MAX_SCA_BUNDLE_BYTES)
        });
      } catch {
        // Ignore individual bundle fetch error
      }
    }
  }

  return extractRuntimeScaFromResponse({
    html: rootHtml,
    headers: rootRes.headers || {},
    pageUrl: baseObj.pathname || '/',
    bundleTexts
  });
}

function sanitizeSourceItem(src) {
  if (typeof src !== 'string') return '';
  const trimmed = src.trim().slice(0, 512);
  if (!trimmed) return '';
  const colonIdx = trimmed.indexOf(':');
  if (colonIdx !== -1) {
    const prefix = trimmed.slice(0, colonIdx + 1);
    const val = trimmed.slice(colonIdx + 1).trim();
    return `${redactSecretsInText(prefix)} ${redactEndpointQuery(val)}`.trim();
  }
  return redactSecretsInText(redactEndpointQuery(trimmed));
}

/**
 * Sanitizes a Runtime SCA report object, redacting secrets and sensitive query parameters.
 *
 * @param {object|null} sca
 * @returns {object|null}
 */
export function sanitizeRuntimeSca(sca) {
  if (!sca || typeof sca !== 'object' || Array.isArray(sca)) return null;
  const rawFindings = Array.isArray(sca.findings)
    ? sca.findings
    : (Array.isArray(sca.technologies) ? sca.technologies : null);
  if (!rawFindings && sca.totalIdentified === undefined) return null;

  const cleanFindings = [];
  if (Array.isArray(rawFindings)) {
    for (const item of rawFindings.slice(0, 50)) {
      if (!item || typeof item !== 'object') continue;
      const id = redactSecretsInText(String(item.id || item.name || 'unknown').trim().slice(0, 64));
      const name = redactSecretsInText(String(item.name || id).trim().slice(0, 128));
      const category = redactSecretsInText(String(item.category || 'frontend').trim().slice(0, 64));
      const icon = redactSecretsInText(String(item.icon || '📦').trim().slice(0, 16));
      const isOutOfDate = Boolean(item.isOutOfDate ?? (item.status === 'Out of date'));
      const status = isOutOfDate ? 'Out of date' : 'Up to date';
      const highestCvss = Math.max(0.0, Number(item.highestCvss) || 0.0);
      const isVulnerable = Boolean(item.isVulnerable ?? (highestCvss >= 4.0));
      const isEol = Boolean(item.isEol);
      const identifiedVersions = Array.isArray(item.identifiedVersions)
        ? item.identifiedVersions.filter(v => typeof v === 'string' && v.trim()).map(v => redactSecretsInText(v.trim().slice(0, 32)))
        : (typeof item.identifiedVersion === 'string' && item.identifiedVersion.trim() ? [redactSecretsInText(item.identifiedVersion.trim().slice(0, 64))] : []);
      const identifiedVersion = redactSecretsInText(String(item.identifiedVersion || identifiedVersions.join(' - ') || '').trim().slice(0, 64));
      const identifiedVersionDisplay = redactSecretsInText(
        String(item.identifiedVersionDisplay || `${identifiedVersion} (Highest CVSS: ${highestCvss.toFixed(1)})`).trim().slice(0, 128)
      );
      const latestBranchVersion = redactSecretsInText(String(item.latestBranchVersion || 'N/A').trim().slice(0, 64));
      const latestBranchCvss = (latestBranchVersion === 'N/A' || item.latestBranchCvss === null || item.latestBranchCvss === undefined)
        ? null
        : Math.max(0.0, Number(item.latestBranchCvss) || 0.0);
      const latestBranchDisplay = latestBranchVersion === 'N/A'
        ? 'N/A'
        : redactSecretsInText(
            String(item.latestBranchDisplay || `${latestBranchVersion} (Highest CVSS: ${(latestBranchCvss ?? 0).toFixed(1)})`).trim().slice(0, 128)
          );
      const overallLatestVersion = redactSecretsInText(String(item.overallLatestVersion || 'N/A').trim().slice(0, 64));
      const overallLatestCvss = (overallLatestVersion === 'N/A' || item.overallLatestCvss === null || item.overallLatestCvss === undefined)
        ? null
        : Math.max(0.0, Number(item.overallLatestCvss) || 0.0);
      const overallLatestDisplay = overallLatestVersion === 'N/A'
        ? 'N/A'
        : redactSecretsInText(
            String(item.overallLatestDisplay || `${overallLatestVersion} (Highest CVSS: ${(overallLatestCvss ?? 0).toFixed(1)})`).trim().slice(0, 128)
          );
      const cveIds = Array.isArray(item.cveIds)
        ? Array.from(new Set(item.cveIds.filter(c => typeof c === 'string' && c.trim()).map(c => c.trim().toUpperCase())))
        : [];
      const vulnerabilities = Array.isArray(item.vulnerabilities)
        ? item.vulnerabilities
            .filter(v => v && typeof v === 'object')
            .slice(0, 20)
            .map(v => ({
              cve: v.cve ? redactSecretsInText(String(v.cve).trim().toUpperCase().slice(0, 32)) : null,
              cvss: Math.max(0.0, Number(v.cvss) || 0.0),
              severity: redactSecretsInText(String(v.severity || 'MEDIUM').trim().toUpperCase().slice(0, 16)),
              summary: redactSecretsInText(String(v.summary || '').trim().slice(0, 512))
            }))
        : [];
      const recommendedAction = redactSecretsInText(String(item.recommendedAction || '').trim().slice(0, 512));
      const sources = Array.isArray(item.sources)
        ? Array.from(new Set(item.sources.map(sanitizeSourceItem).filter(Boolean))).slice(0, 20)
        : [];

      cleanFindings.push({
        id,
        name,
        category,
        icon,
        status,
        isOutOfDate,
        isVulnerable,
        isEol,
        identifiedVersion,
        identifiedVersions,
        highestCvss,
        identifiedVersionDisplay,
        latestBranchVersion,
        latestBranchCvss,
        latestBranchDisplay,
        overallLatestVersion,
        overallLatestCvss,
        overallLatestDisplay,
        cveIds,
        vulnerabilities,
        recommendedAction,
        sources
      });
    }
  }

  const summaryObj = buildRuntimeScaSummary(cleanFindings);
  return {
    ...summaryObj,
    summary: redactSecretsInText(String(sca.summary || summaryObj.summary).slice(0, 2048))
  };
}

/**
 * Merges Runtime SCA data across target fingerprint stacks, check results, and explicit options.
 *
 * @param {object|Array|null} [stacks=null]
 * @param {Array} [results=[]]
 * @param {object|null} [explicitSca=null]
 * @returns {object|null}
 */
export function mergeRuntimeSca(stacks = null, results = [], explicitSca = null) {
  const candidates = [];
  const pushCandidate = (c) => {
    if (c && typeof c === 'object' && !Array.isArray(c)) {
      if (
        Array.isArray(c.findings) ||
        Array.isArray(c.technologies) ||
        c.totalIdentified !== undefined
      ) {
        candidates.push(c);
      }
    }
  };

  pushCandidate(explicitSca);

  if (Array.isArray(stacks)) {
    for (const s of stacks) {
      if (s && typeof s === 'object') {
        pushCandidate(s.runtimeSca);
      }
    }
  } else if (stacks && typeof stacks === 'object') {
    if (stacks.runtimeSca && typeof stacks.runtimeSca === 'object') {
      pushCandidate(stacks.runtimeSca);
    } else {
      for (const fp of Object.values(stacks)) {
        if (fp && typeof fp === 'object') {
          pushCandidate(fp.runtimeSca);
        }
      }
    }
  }

  if (Array.isArray(results)) {
    for (const r of results) {
      if (!r || typeof r !== 'object') continue;
      if (r.runtimeSca && typeof r.runtimeSca === 'object') {
        pushCandidate(r.runtimeSca);
      } else if (Array.isArray(r.scaFindings) && r.scaFindings.length > 0) {
        pushCandidate({ findings: r.scaFindings });
      }
    }
  }

  if (candidates.length === 0) return null;

  // Merge findings by technology id
  const mergedByTech = new Map();
  const customFindings = [];

  for (const cand of candidates) {
    const list = Array.isArray(cand.findings)
      ? cand.findings
      : (Array.isArray(cand.technologies) ? cand.technologies : []);
    for (const item of list) {
      if (!item || typeof item !== 'object') continue;
      const canonical = resolveTechCatalogKey(item.id || item.name);
      if (canonical) {
        if (!mergedByTech.has(canonical)) {
          mergedByTech.set(canonical, { versions: new Set(), sources: new Set() });
        }
        const entry = mergedByTech.get(canonical);
        const vers = Array.isArray(item.identifiedVersions) && item.identifiedVersions.length > 0
          ? item.identifiedVersions
          : (item.identifiedVersion ? [item.identifiedVersion] : []);
        for (const v of expandVersionInputs(vers)) entry.versions.add(v);
        if (Array.isArray(item.sources)) {
          for (const s of item.sources) {
            if (typeof s === 'string' && s.trim()) entry.sources.add(s.trim());
          }
        }
      } else {
        customFindings.push(item);
      }
    }
  }

  const mergedFindings = [];
  for (const [techKey, info] of mergedByTech.entries()) {
    const evaluated = evaluateTechnologyVersion(
      techKey,
      Array.from(info.versions),
      { sources: Array.from(info.sources) }
    );
    if (evaluated) mergedFindings.push(evaluated);
  }
  mergedFindings.push(...customFindings);

  return sanitizeRuntimeSca(buildRuntimeScaSummary(mergedFindings));
}
