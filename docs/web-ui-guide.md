# 🖥️ 7-Tab Web UI Dashboard, Menus & Interactive Workbenches Guide

Launch the localhost-hardened Web UI (`127.0.0.1:4321`, anti-CSRF Host/Origin validation, CSP hardening) via:

```bash
npm run ui
# or: secscan --ui --port 4321
```

---

## Header Bar & `🩺 System Doctor` Modal

The top header bar displays the active tab navigation, connection indicator (`#server-status-dot`), and **`🩺 System Doctor`** (`#btn-open-system-doctor`).

Opening **`🩺 System Doctor`** (`#system-doctor-backdrop`) lets you:
1. **Inspect Local Environment Readiness (`GET /api/system/doctor`)**: Checks Node.js runtime (`>= 22`), native `node:sqlite` `DatabaseSync` availability, write permissions for `.secscan-history/` and `reports/`, proxy configuration (with credentials masked), active Multi-LLM Pool profiles, and loaded check plugins (`84`).
2. **Run PC-vs-Target Diagnostics (`POST /api/system/diagnose-target`)**: Enter any target URL (`#doctor-target-input`, optionally checking **Allow Authorized Internal / Private Targets**) to distinguish local network/DNS failures, SSRF/scope policy blocks, and remote website reachability errors before launching a scan.

---

## Tab 1: `🚀 New Scan` (`#tab-new-scan`)

Designed for both guided quick scans and deep technical configurations:

- **Target URL Wizard (`#target-url`)**: Bare IPs default to `http://`; inline validation (`#url-validation-banner`) warns on blocked private/metadata targets unless `--allow-private` is enabled.
- **`🔎 Detect Tech Stack` (`#detect-stack-btn`)**: Fingerprints 27 technologies without running active exploits and renders `#tech-detect-banner` with:
  - Detected ecosystem badges (`#tech-detect-badges`) & smart check selection count (`#tech-detect-counter`).
  - **Runtime SCA Preview (`#tech-detect-sca-row`)**: Immediate preview of identified client/server libraries (`jQuery`, `Bootstrap`, `Moment.js`, `Lodash`, `AngularJS`, `Angular`, etc.), highest CVSS, and branch/overall latest versions.
  - **SPA & Backend API Communication Preview (`#tech-detect-api-row`)** + **`🤖 Ask AI About APIs`** (`#btn-analyze-detect-api`).
  - **Device Discovery Preview (`#tech-detect-device-row`)** when scanning LAN/IoT/TV/Camera/PC targets.
- **`🌐 Get Real IP` (`#get-real-ip-btn`)**: Discovers origin IPs behind Cloudflare, CloudFront, Fastly, Akamai, Imperva, or Sucuri via DNS, SPF, MX, subdomains, and origin headers (`#real-ip-banner`), with 1-click **`📌 Pin as --source-ip`** and **`🎯 Switch Target to http://<IP>`**.
- **Agentic Mode, Noise Governor & Internal/Device Controls**:
  - **`🤖 Enable Agentic Verification Mode (--agent)`** (`#opt-agent-mode`) + optional Goal (`#opt-agent-goal`).
  - **Noise Governor (`#opt-noise-profile`)**: `balanced` (default), `quiet`, `aggressive`, or `off`.
  - **`🏢 Allow Authorized Internal / Private Targets (--allow-private)`** (`#allow-private-toggle`), which reveals the **📺 Device Category** selector (`#opt-device-category`: `All Devices`, `Smart TV & Streaming Media`, `IP Camera / NVR / Surveillance`, `PC / Workstation / Local Server`).
- **1-Click Scan Presets (`#preset-cards`)**: Fast profile selection populated from `/api/meta`.
- **`⚙️ Advanced Options` Drawer (`#advanced-drawer`)**:
  - Max Crawl Depth (`1–5`), Concurrency Limit (`1–10`), Request Timeout (`5000–30000 ms`), Custom `Authorization` header (`#adv-auth`).
  - **🔐 Website Authentication & Login Sequence Recorder**: System Variables (`{{VAR:name}}`), Secrets Vault (`{{SECRET:name}}`), TOTP MFA (`#btn-open-otp-config`), `.lsr` Sequence Reuse Bar (`#lsr-reuse-select`), Visual Recorder Modal (`#btn-new-lsr-sequence`), Standard Login Macro (`#adv-auth-username`, `#adv-auth-password`, `#adv-auth-login-url`, `#adv-auth-type`, `#btn-test-record-login`), and **`📋 Discover OpenAPI / Swagger Routes`** (`#btn-discover-openapi`). See [Authentication & LSR Guide](./authentication-and-lsr.md).
  - **Tech Stack Override (`#adv-tech`)**, **Direct Source / Origin IP Pinning (`#adv-source-ip`)**, **Specific Check/CVE Filter (`#adv-checks`)**, **Custom HTTP Headers (`#custom-headers-input`)**, **`Force All Checks`** (`#opt-force-all`), and **Save to History** (`#adv-save-history`).
- **Live SSE Progress (`#scan-progress-panel`)**: Real-time phase badge, percentage bar, detected tech chips, pages discovered, live Vulnerable/Suspicious/Safe counters, and streaming activity feed.

---

## Tab 2: `📊 Scan Results & Evidence` (`#tab-scan-results`)

Inspect executive summaries, technical proofs, and export reports:

- **Overall Health Card (`#health-card`)**: **A+ to F** Security Grade, risk pill (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`), score (`0–60+`), target metadata, and archive status.
- **Detected Tech Stack & Audit Strategy (`#results-stack-card`)**: Shows executed vs. skipped framework checks.
- **📦 Runtime SCA Findings Table (`#results-runtime-sca-card`)**: Invicti-style 6-column dependency table (`Name`, `Status`, `Identified Version (Highest CVSS)`, `Latest Branch Version`, `Overall Latest Version`, `Recommended Action`) with out-of-date/EOL KPIs.
- **🔌 Discovered SPA & Backend API Communication (`#results-api-card`)**: Lists discovered REST/GraphQL/WebSocket routes, external API origins with 1-click external scan triggers, and **`🤖 Ask AI About APIs`**.
- **🎯 Target CVE Advisory Coverage Banner (`#results-cve-coverage-banner`)**: Covered/Partial/Missing KPI pills and **`Open CVE Audit`** shortcut into Tab 7.
- **🎯 Top Priority Action Plan & `🤖 AI Action Roadmap` (`#btn-generate-ai-summary`)**: Prioritized remediation roadmap tailored for `Regular Person View` (`beginner`) or `Developer View` (`pro`) via `#btn-toggle-view-mode`.
- **Per-Finding Cards & `🤖 AI Fix Solution`**: Filter by status (`All`, `Vulnerable`, `Warnings`, `Passed`), severity (`CRITICAL`–`LOW`), or text/CVE search (`#findings-search`). Each finding includes CVSS/CVE/Certainty badges (`0–100%`), 6-framework compliance tags, **`🤖 AI Fix Solution`**, and **Evidence & Retest**.
- **S1 Evidence & 1-Click Retest Drawer (`#evidence-drawer-backdrop`)**: Shows bound request/response snapshots, highlighted verbatim `evidenceQuotes` (`>= 8` chars), secret-redacted `curl` reproduction commands (with `--resolve` when Source-IP pinning is active), **Fix Patch Generator**, and **`Retest`** (`POST /api/findings/:id/retest`) yielding `reproduced`, `fixed`, or `inconclusive`.
- **Exports Bar**: Download **💾 JSON**, **📥 HTML**, **📝 Markdown**, **📊 CSV** (UTF-8 BOM + formula-safe), or **📋 SARIF** (OASIS SARIF v2.1.0).

---

## Tab 3: `🤖 Tasks & Sessions` (`#tab-tasks-sessions`)

Powered by `ui/components/session-explorer.js` for autonomous `--agent` sessions:
- **Task Launcher & LLM Chain Selector**: Launch planner-worker tasks (including `allowPrivate` support), inspect active worker loops, and configure per-task LLM failover chains (`PUT /api/tasks/:id/llm`).
- **Intent Steering & Cancellation**: Trigger additional planning rounds (`POST /api/tasks/:id/plan`), steer active intents, or cancel noisy branches (`POST /api/tasks/:id/intents/:nodeId/steer|cancel`).
- **Gap-Free Activity Timeline & Coverage Ledger**: Displays `mergeBySeq` event history and coverage ledger gaps.
- **`/btw` Read-Only Side Questions**: Ask ephemeral questions (`POST /api/tasks/:id/sidequestion`) answered from a snapshot without mutating the exploration graph or sending target probes.

---

## Tab 4: `🕸️ Dual-Graph Explorer` (`#tab-dual-graph`)

Combines two interactive SQLite-backed visualizations (`ui/components/exploration-graph.js`, `coverage-graph.js`, `asset-dsl-search.js`):
- **🧭 Exploration DAG (`#dg-exploration-view`)**: Visualizes `begin -> goal -> intent -> fact -> finding` reasoning lineage per task (`#dg-task-select`), with **cold-graph folding** (`?fold=true`) to collapse older completed rounds into digest nodes.
- **🕸️ Asset Coverage & 19-Field DSL (`#dg-coverage-view`)**:
  - Visualizes parent host chains (`endpoint/service/app -> subdomain/ip -> root_domain`) and `/24` IPv4 / `/48` IPv6 C-segments.
  - **19-Field Asset Query DSL**: Filter assets with boolean expressions (`AND`/`&&`, `OR`/`||`, parentheses, `=`, `!=`, `>`, `>=`, `<`, `<=`) across `domain`, `host`, `ip`, `port`, `service`, `protocol`, `url`, `path`, `title`, `status`, `source`, `company`, `c_segment`, `type`, `scope`, `confidence`, `verified`, `severity`, and `finding`.
  - **External Tool Ingestion (`POST /api/assets/ingest`)**: Import `nmap`, `nuclei`, `httpx`, `ffuf`, and `bbot` outputs into the Global Asset Graph.

---

## Tab 5: `📡 Traffic & Replay` (`#tab-traffic-replay`)

Full Burp-class interactive HTTP workbench (`ui/components/traffic-inspector.js`):
- **FTS5 Traffic Search & Split Inspector**: Filter captured exchanges by full-text query, host, HTTP method, or status band (`2xx`–`5xx`); inspect split request/response headers, decompressed bodies, passive scan alerts, and WebSocket/SSE stream frames.
- **RFC-9110 Replay (Repeater)**: Edit method, URL, headers, or body and replay live under SSRF and scope guardrails (`POST /api/traffic/:id/replay`).
- **🎯 Intruder `§marker§` Workbench (`POST /api/intruder/run`)**: Parameterized fuzzing across **Sniper**, **Battering Ram**, **Pitchfork**, and **Cluster Bomb** attack modes with ReDoS-safe `grepMatch` / `grepExtract` rules and status/length/latency anomaly scoring.
- **🔐 Autorize 3-Context Matrix (`POST /api/autorize/run`)**: Replays endpoints across `Primary (Admin/Owner)` vs. `Secondary (Low-Privilege)` vs. `Unauthenticated` contexts with a 404 canary to flag **BOLA / IDOR / BFLA** (`BYPASSED_LOW_PRIV`, `BYPASSED_UNAUTH`).
- **🧬 Decoder, JWT Inspector & Response Comparer (`POST /api/tools/decode`, `POST /api/tools/compare`)**: Chainable 17-operation encode/decode/hash/decompress pipeline, 5-layer Smart Auto-Decoder, JWT security checks (`alg: none`, `kid` traversal/SQLi, `jku`/`x5u` SSRF), and byte/word/line/JSON structural diffing.
- **⚙️ Rewrite Rules (HMAC Taint Guard)**: Configure request/response header, body, or query rewrite rules with sensitive-value HMAC tainting (`GET|POST|DELETE /api/traffic/rewrite-rules`).
- **Chrome/Edge CDP Extension (`extension/`) & 📦 Export HAR 1.2**: Stream live authenticated browser traffic into `POST /api/traffic/ingest`, inspect clustered URL templates (`GET /api/traffic/templates`), and export standard HAR 1.2 (`GET /api/traffic/export.har`).

---

## Tab 6: `🕓 Past Scans & Compare` (`#tab-history`)

- **Historical Scans Archive (`GET /api/history`)**: Browse saved scans with date, target host, Security Grade, vulnerable/suspicious counts, and 1-click load back into Tab 2 (`Scan Results & Evidence`).
- **Side-by-Side Regression Diff (`POST /api/diff`)**: Assign **Scan A (Baseline)** and **Scan B (Current)** to compute **🆕 New Findings (Introduced)**, **✅ Fixed Findings (Resolved)**, and **↕️ Status Changed**.

---

## Tab 7: `🛠️ Checks & System Guardrails` (`#tab-catalog`)

Switch between 4 specialized sub-views:
1. **📚 Browse Catalog (`#catalog-browse-view`)**: Filter all **84 built-in checks** by 14 category pills or search text (`#catalog-search-input`).
2. **🎯 CVE Coverage Audit (`#catalog-cve-coverage-view`)**: Powered by `ui/components/cve-coverage.js`. Displays KPI cards across curated CVE advisories, ecosystem breakdown, status (`All` / `Missing` / `Partial` / `Covered`) and `?tech=` filters, external CVE database confirmation (`OSV.dev`, `NVD 2.0`, `GitHub GHSA`, `CISA KEV` via `POST /api/cves/confirm-db`), and custom JSON advisory catalog upload (`POST /api/cves/audit`).
3. **✨ New Check Builder (`#catalog-builder-view`)**: Interactive scaffolder (`POST /api/checks/scaffold`) that validates IDs (`/^[a-z0-9-]{2,40}$/`), previews generated ESM check + unit test code, and writes `checks/<id>.js` and `tests/checks/<id>.test.js`.
4. **🛡️ System Guardrails & Multi-LLM Pool (`#catalog-guardrails-view`)**: Powered by `ui/components/system-guardrails.js`. Manage Multi-LLM Pool profiles (`gemini`, `anthropic`, `openai`, `openai-responses`, `ollama`), inspect/reset circuit breakers, configure **Target Noise Governor** (`off`, `quiet`, `balanced`, `aggressive`) with per-host telemetry, edit **Scope/Deny Asset Gate** rules, and test the **8-Question Closed-World JEV Risk Evaluator**.
