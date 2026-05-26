# 🔍 Security Scanner v2.0 (Discovery Mode)

A powerful, autonomous security scanner for modern web applications. Version 2.0 introduces **Discovery Mode** — a recursive crawling engine that maps your entire application and an **Active Fuzzer** that probes parameters for SQL Injection and XSS.

Runs **47 checks** across React, Angular, Vue, Node.js, Python, Laravel, and WordPress. Produces **actionable remediation advice**, dark-mode HTML reports, and JSON output for CI/CD integration.

---

## 🚀 What's New in v2.0

- **🕷️ Autonomous Crawler**: Recursively discovers all links and pages within the target domain.
- **🧪 Active Fuzzing Engine**: Automatically identifies URL parameters and injects attack payloads.
- **💀 Advanced Checks**: Detects Reflected XSS, Error-based SQLi, and Time-based Blind SQLi.
- **🌍 Expanded Polyglot Support**: Native detection and specialized checks for React, Angular 18+, Vue, Node.js (Express), and Python (Django/Flask).
- **💡 Remediation Advice**: Every finding now includes a "How to Fix" section.

---

## Quick Start

```bash
npm install -g security-scanner

# Scan a site and all discovered pages (depth 3)
secscan https://example.com --html

# Targeted framework audit with deep discovery
secscan https://example.com --profile frontend --depth 5 --html

# Compare with last scan to find new regressions
secscan https://example.com --diff
```

---

## CLI Reference

```
secscan <url> [options]

Options:
  --depth <n>         Crawl depth for discovery          (default: 3)
  --json              Save JSON report
  --html              Save HTML report (dark-mode, self-contained)
  --output <stem>     Base name for reports              (default: report)
  --profile <name>    Scan profile (see below)           (default: full)
  --profiles          List all available profiles
  --tech <list>       Force tech tags, comma-separated   (e.g. react,node)
  --concurrency <n>   Parallel targets                   (default: 5)
  --timeout <ms>      Request timeout in ms              (default: 10000)
  --auth <token>      Authorization header (e.g. "Bearer eyJ...")
  --diff              Compare with last scan and show changes
  --no-history        Do not save this scan to history
  --webhook <url>     Send results to Slack/webhook URL after scan
```

---

## Scan Profiles

| Profile     | Description |
|-------------|-------------|
| `quick`     | Fast scan of highest-impact checks (~5s) |
| `frontend`  | **[NEW]** Modern Frontend (React, Angular, Vue) audit |
| `node`      | **[NEW]** Node.js / Express security audit |
| `python`    | **[NEW]** Python (Django/Flask) security audit |
| `api`       | REST API audit — CORS, rate limit, JWT, auth |
| `laravel`   | Full Laravel application audit |
| `wordpress` | WordPress site security audit |
| `full`      | All 47 checks — comprehensive autonomous audit (default) |

---

## Technical Features

### 🕸️ Discovery Mode
The scanner uses a concurrent breadth-first crawler to identify every accessible page on the target domain. This ensures that security checks are not just limited to the homepage but cover the entire application surface area.

### 🧪 Active Fuzzing
Unlike traditional scanners that only check static paths, the v2.0 fuzzer identifies dynamic parameters (e.g., `?id=123`) and executes:
- **XSS Probing**: Injects unique tokens and monitors for unescaped reflection.
- **SQLi Probing**: Executes error-based signatures and time-based delays (Blind SQLi).

---

## All 47 Checks

### 🔥 Active Attack Checks (Scanner 2.0)
| Check | Detects |
|---|---|
| `xss` | Reflected Cross-Site Scripting via parameters |
| `sqli` | Error-based and Time-based (Blind) SQL Injection |

### 🌍 Modern Stacks
| Check | Detects |
|---|---|
| `frontend-checks` | Source maps exposure, Dev-mode leaks, hardcoded API keys |
| `node-checks` | `package.json` exposure, `node_modules` leak, Express disclosure |
| `python-checks` | Django/Flask Debug mode, `requirements.txt`, `__pycache__` |

### General Web
| Check | Detects |
|---|---|
| `security-headers` | Missing HSTS, CSP, X-Frame-Options, Referrer-Policy |
| `ssl-tls` | Expired certs, weak TLS 1.0/1.1, insecure cipher suites |
| `cors` | Wildcard `*` or reflected origin vulnerabilities |
| `cookie-security` | Missing `Secure`, `HttpOnly`, `SameSite` flags |
| `rate-limit` | Burst test — absence of 429 rate limiting |

### Laravel / PHP / WordPress
| Check | Detects |
|---|---|
| `laravel-debug` | Ignition RCE, Telescope exposure, Debug mode |
| `php-info` | Exposed `phpinfo()` and configuration backups |
| `wp-checks` | User enumeration, xmlrpc, version disclosure |

---

## Test Suite

```bash
npm test
# 90 tests | 0 failures
```

Each of the 47 checks is backed by unit tests with mock HTTP responses covering VULNERABLE, SAFE, and ERROR cases.

---

## Project Structure

```
security-scanner/
├── checks/                      # 47 check plugins
├── core/
│   ├── crawler.js               # Autonomous discovery engine [2.0]
│   ├── fuzzer.js                # Active parameter attack engine [2.0]
│   ├── queue.js                 # Task & URL lifecycle management [2.0]
│   ├── fingerprint.js           # Tech detection (React, Vue, Angular, Django, etc.)
│   ├── html-report.js           # Dark-mode HTML generator w/ remediation
│   └── ...                      # See core/ for full framework
├── tests/                       # 90 unit tests
├── scan.js                      # Main Discovery Mode orchestrator
└── README.md
```
