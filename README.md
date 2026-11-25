# 🛡️ Security Scanner v2.7 — Autonomous Security Platform & Burp/Invicti Workbench

An autonomous web security verification platform, Burp-class interactive workbench, and CLI scanner built on **Node.js v24 ESM** with embedded **`node:sqlite` + `FTS5`** persistence.

- **84 Built-in Security Checks** across CVEs, injection, modern web, APIs, AI/LLM, supply chain, cloud, headers, CMS, and LAN/OS targets
- **73 Web/Runtime + 22 OS/Edge Curated CVE Advisories (`95` Total)** with external CVE DB confirmation & Tri-State Docker Labs
- **21 Scan Profiles** (`smart`, `quick`, `api`, `modern`, `device`, `ops`, `nginx`, `apache`, `spring`, `laravel`, `wordpress`, `full`, etc.)
- **Zero-Infrastructure** native execution or **`<1s` Docker Live Auto-Sync** (`docker compose`)

---

## 📚 Documentation Hub (Detailed Guides by Menu & Feature)

| Guide | What It Covers |
|---|---|
| **[🔐 Authentication, Visual `.lsr` Recorder, System Variables & TOTP MFA](docs/authentication-and-lsr.md)** | The 3 authentication methods, **System Variables (`{{VAR:name}}`)** & Secrets Vault (`{{SECRET:name}}`), `#lsr-recorder-backdrop` modal, **Top Failure Diagnostics Banner** (all 8 codes), interactive **Visual `Play` Preview**, 6 action types, Restrictions & Session Detection, RFC 6238 TOTP MFA, and `.secscan-history/auth-sequences.json` reuse |
| **[🖥️ 7-Tab Web UI Dashboard, Menus & Workbenches](docs/web-ui-guide.md)** | Walkthrough of the Header & `🩺 System Doctor` modal plus all 7 tabs: `New Scan`, `Scan Results & Evidence`, `Tasks & Sessions`, `Dual-Graph Explorer`, `Traffic & Replay` (Intruder, Autorize, Decoder, Comparer, HAR 1.2, CDP Extension), `Past Scans & Compare`, and `Checks & System Guardrails` |
| **[📦 Runtime SCA, 84-Check Catalog, 21 Profiles & Tri-State CVE Labs](docs/runtime-sca-and-cve-audits.md)** | Invicti-style **Runtime SCA Findings** (`Identified Version`, `Latest Branch`, `Overall Latest`, `CVSS`, `EOL`), full **21 Profiles** table, complete **84-Check Catalog** tables, `--cve-audit`, `--cve-db`, and Tri-State (`vulnerable` / `patched` / `fp_trap`) CVE Labs |
| **[🌐 Origin IP Discovery, Pinned `--source-ip`, Internal Networks & Devices](docs/network-origin-ip-and-devices.md)** | Discovering origin IPs behind CDN/WAF (`--get-real-ip`, `--scan-real-ip`), `ResolveCache` + `PinnedDialer` (`--source-ip`), authorized RFC1918 scanning (`--allow-private`) & Scope/Deny rules, `--device-category` (`Smart TV`, `IP Camera`, `PC`), and `--pc-local` host auditor |
| **[🧰 CLI Flags, `.secscanrc`, REST API, Agent Mode, LLM Pool & Docker](docs/cli-and-api-reference.md)** | Complete `secscan --help` CLI flag reference, `.secscanrc` config, full `core/server.js` REST API table, `--agent` mode, Multi-LLM Pool & Ollama setup, 7-Gate VDP Reviewer, 9-Probe Posture Check, Pre-Report FP Gate, and Docker live auto-sync |

---

## ⚡ Quick Start

### 1. Web UI Dashboard (Recommended)
```bash
npm run ui
# or: secscan --ui --port 4321
```
Open `http://127.0.0.1:4321` in your browser (bound strictly to `127.0.0.1` with Host/Origin anti-CSRF validation and CSP hardening).

### 2. CLI Scans
```bash
# Smart tech-stack-aware scan (default) with dark-mode HTML & JSON reports
secscan https://example.com --html --json

# Discover origin IP behind CDN/WAF and scan directly with --source-ip pinning
secscan example.com --scan-real-ip --cve CVE-2026-123007 --html

# Export Markdown, formula-safe CSV, and OASIS SARIF v2.1.0
secscan https://example.com --markdown report.md --csv report.csv --sarif report.sarif

# Autonomous Agent Mode with verification goal & Noise Governor
secscan https://example.com --agent --goal "Verify API auth and headers" --noise-profile quiet

# Authorized internal network or LAN device audit
secscan https://10.20.30.40 --allow-private --scope "allow:10.20.0.0/16,deny:10.20.0.5" --html
secscan 192.168.1.25 --tv

# Local host PC audit, System Doctor, CVE Coverage Audit & Tri-State CVE Labs
secscan --doctor https://example.com
npm run pc:audit
npm run cve:audit
npm run cve:lab
```

### 3. Docker Live Auto-Sync
```bash
npm run docker:up     # Build & start Web UI on http://127.0.0.1:4321 with <1s bind-mount reload
docker compose exec secscan node bin/cli.js https://example.com --html --json
```

---

## 🏗️ Architecture & 5-Stage Data Flow

```mermaid
flowchart LR
    A["1. Target Validation, ResolveCache & PinnedDialer<br/>validator.js · fetch.js · guard.js · egress.js"] --> B["2. Fingerprinting & Smart Scheduling<br/>fingerprint.js · profiles.js · crawler.js"]
    B --> C{"Scan Mode"}
    C -->|Standard Discovery| D["84 Check Plugins & Active Fuzzers<br/>checks/*.js · fuzzer.js"]
    C -->|"Agentic Mode (--agent)"| E["Planner-Worker Loop & Dual-Graph<br/>agent-engine.js · graph-store.js · llmpool.js"]
    D --> F["4. Pre-Report FP Gate, Traffic Capture & S1 Receipts<br/>fp-engine.js · check-verify.js · traffic.js · evidence.js"]
    E --> F
    F --> G["5. Grading, 7-Gate VDP Review, CVE Audit & Reports<br/>severity.js · submission-review.js · cve-audit.js · report.js"]
```

---

## ✨ Key Feature Highlights

- **Invicti Runtime SCA Findings (`core/runtime-sca.js`, `checks/runtime-sca.js`, `POST /api/sca/analyze`)**: Extracts client/server versions from headers, HTML attributes, script URLs, and same-origin JS bundle banners, comparing **Identified Version (Highest CVSS)** against **Latest Branch Version** and **Overall Latest Version** with EOL alerts.
- **Visual Login Sequence Recorder (`.lsr`), System Variables & RFC 6238 TOTP MFA (`core/auth-session.js`)**: Multi-step `.lsr` flows (`navigate`, `change_input`, `fill_otp`, `click_button`, `extract_token`, `custom_request`), global **System Variables (`{{VAR:name}}`)**, masked **Secrets Vault (`{{SECRET:name}}`)**, **Top Failure Diagnostics Banner** (`8` diagnostic codes), interactive **Visual `Play` Preview**, Restrictions, and Session Detection auto-replay.
- **Invicti Proof-Based Scanning™ & 6-Framework Compliance (`core/compliance-proof.js`)**: Deterministic `0–100%` certainty scoring, structured `proofArtifact` objects, and automatic mapping across **PCI-DSS v4.0**, **OWASP API 2023**, **ISO 27001**, **NIST 800-53**, **SOC 2**, and **HIPAA**.
- **Burp-Class Workbench (`core/intruder.js`, `core/decoder-comparer.js`, `extension/`)**: **Intruder `§marker§`** (4 attack modes), **Autorize** 3-context BOLA/IDOR matrix, 17-op **Decoder & JWT Inspector**, **Response Comparer**, **OpenAPI/Swagger Importer**, **Chrome/Edge CDP Traffic Extension**, and **HAR 1.2** export.
- **Origin IP Discovery & Pinned Source-IP (`core/real-ip-finder.js`, `core/validator.js`, `core/fetch.js`)**: Discovers origin servers behind CDN/WAF (`--get-real-ip`, `--scan-real-ip`) and dials `--source-ip` directly at the socket layer with `Host` + TLS SNI preserved and automatic `--resolve` `curl` reproduction commands.
- **Autonomous Agent Mode, Dual-Graph & Multi-LLM Pool (`core/agent-engine.js`, `core/graph-store.js`, `core/llmpool.js`)**: Planner-worker loop with 19-field Asset Query DSL, Okapi BM25 tool selection, `/btw` read-only side questions, and multi-provider failover (`gemini`, `anthropic`, `openai`, `ollama`) with offline deterministic playbooks.
- **Pre-Report FP Gate, OAST, Sandbox DOM & Host PC Auditor**: `verifyFindingBeforeReport` + Soft-404 shingle filtering (`core/fp-engine.js`), HMAC-tokenized blind OAST callbacks (`core/oast-server.js`), isolated `node:vm` DOM taint verifier (`core/dom-sandbox-verifier.js`), declarative YAML/JSON templates (`core/template-loader.js`), and local host PC security audits (`--pc-local`).

---

## 🧰 Quick Feature Reference Table

| Tool / Capability | CLI Flags | REST API Endpoints | Web UI Controls |
|---|---|---|---|
| **Runtime SCA Findings** | `--check runtime-sca` | `POST /api/sca/analyze`, `POST /api/fingerprint` | Tab 2 `#results-runtime-sca-card` + Tab 1 `#tech-detect-sca-row` |
| **Visual `.lsr` Recorder, System Variables & TOTP MFA** | `--username`, `--password`, `--login-url`, `--save-session`, `--load-session` | `GET\|POST\|PUT\|DELETE /api/auth/variables`, `GET\|POST\|DELETE /api/auth/sequences`, `POST /api/auth/inspect-page`, `POST /api/auth/otp-preview`, `POST /api/auth/record-session` | `#sys-vars-panel`, `#lsr-reuse-select`, `#btn-open-otp-config`, `#btn-new-lsr-sequence`, `#lsr-recorder-backdrop` |
| **Real / Origin IP & Source-IP Pinning** | `--get-real-ip`, `--scan-real-ip`, `--source-ip <ip>` | `POST /api/real-ip`, `POST /api/scan` (`sourceIp`) | `#get-real-ip-btn`, `#adv-get-real-ip-btn`, `#adv-source-ip` |
| **Device & Local Host PC Auditing** | `--device`, `--tv`, `--camera`, `--pc`, `--device-category`, `--pc-local` | `POST /api/scan` (`deviceCategory`), `GET /api/system/pc-audit` | `#allow-private-toggle`, `#opt-device-category` |
| **Burp Intruder / Autorize / Decoder / Comparer** | `--intruder`, `--payloads`, `--attack-mode`, `--autorize`, `--auth-low` | `POST /api/intruder/run`, `/api/autorize/run`, `/api/tools/decode`, `/api/tools/compare` | Tab 5 **Traffic & Replay** workbenches |
| **OpenAPI Importer & CDP Traffic Extension** | Auto-discovered during API scans | `POST /api/openapi/import`, `POST /api/traffic/ingest`, `GET /api/traffic/export.har` | `#btn-discover-openapi`, `extension/` popup, Tab 5 **Export HAR 1.2** |
| **Proof-Based Scanning & 6-Framework Compliance** | Included in `--json`, `--html`, `--sarif` | `GET /api/scan/:id`, `GET\|POST /api/compliance/summary` | Tab 2 certainty badges, Evidence Drawer & Compliance tags |
| **CVE Audit, External DB & Tri-State Labs** | `--cve-audit`, `--cve-db`, `--cve-lab`, `--new-cve-lab` | `GET /api/cves/coverage`, `POST /api/cves/audit`, `/confirm-db`, `/labs/run` | Tab 7 **🎯 CVE Coverage Audit** |
| **Diagnostics, VDP Review & Posture Check** | `--doctor`, `--review-report`, `--posture-check` | `GET /api/system/doctor`, `POST /api/system/diagnose-target`, `/api/reports/review`, `/api/llm/posture-check` | Header **`🩺 System Doctor`** modal |

---

## 🧪 Running the Test Suite

Run the complete Node.js test suite (`tests/checks/`, `tests/core/`, `tests/ui/`, `e2e/`):

```bash
npm test
```

Verify check discovery and catalog registration:

```bash
node bin/cli.js --list-checks
```

---

## 📁 Project Structure

```
security-scanner/
├── bin/cli.js                  # CLI entrypoint (--ui, --intruder, --autorize, --source-ip, --cve-lab, --pc-local, etc.)
├── checks/                     # 84 modular ESM security check plugins
├── core/                       # Engine modules (auth-session, runtime-sca, intruder, fp-engine, server, graph-store, etc.)
├── cve-labs/                   # 10 Tri-State Per-CVE Docker Labs + unified multi-persona gateway
├── docs/                       # Detailed topic guides linked from this README
├── e2e/                        # End-to-end test suite
├── extension/                  # Manifest V3 Chrome/Edge CDP Traffic Capture Extension
├── skills/                     # Modular agent verification methodologies (SKILL.md)
├── templates/                  # Declarative YAML/JSON CVE templates
├── tests/                      # Unit & integration tests (checks/, core/, ui/)
├── ui/                         # 7-tab Web UI Dashboard (index.html, app.js, styles.css, components/)
├── Dockerfile                  # Node 24 Alpine container image
├── docker-compose.yml          # Live auto-sync Docker Compose config (bind mounts + node --watch)
└── scan.js                     # Main Discovery Mode & Agentic Mode orchestrator
```
