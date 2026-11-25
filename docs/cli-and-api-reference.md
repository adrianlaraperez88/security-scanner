# 🧰 CLI Flags, `.secscanrc`, REST API Reference, Agent Mode, Multi-LLM Pool & Docker

Complete command-line, configuration, REST API, AI/LLM, verification-gate, and Docker reference for **Security Scanner v2.7**.

---

## 1. Complete CLI Flags Reference (`secscan --help`)

```
Usage: secscan <url> [options]
       secscan --cve-audit [options]
       secscan --doctor [url...] [options]
       secscan --review-report <path> [--json]
       secscan --posture-check [model] [--json]
       secscan --ui [--port 4321]
       secscan --new-check <name>
       secscan --list-checks

General:
  -h, --help                Show this help message and exit
  -v, --version             Print version and exit
  --doctor                  Check runtime, storage, proxy, LLM pool, and optional target connectivity

Web Dashboard:
  --ui                      Launch interactive Web UI Dashboard
  --port <port>             Port for Web UI server          (default: 4321)

CVE Coverage Audit & Tri-State Labs:
  --cve-audit               Audit built-in scanner checks against CVE advisories
  --cve-lab [all|CVE-ID,..] Run Tri-State CVE Lab Benchmark (vulnerable, patched, fp_trap) and market comparison
  --cve-lab-mode <mode>     CVE lab execution mode: emulated (default) or docker
  --cve-db <provider|url>   Confirm vs external CVE DB: osv|nvd|ghsa|cisa-kev or custom JSON URL
  --cve-packages <list>     Filter/match package@version list (e.g. laravel/framework@11.30.0,next@14.2.1)
  --cve-catalog <file>      Load custom CVE advisory catalog or NVD/OSV/GHSA/KEV JSON export file
  --cve-feed                Sync optional online advisory feed (graceful offline fallback)
  --fail-on-missing-cves    Exit 1 if any evaluated CVE advisories are missing coverage

Maintenance & Scaffolding:
  --new-check <name>        Scaffold a new check plugin and test suite
  --new-cve-lab <CVE-ID>    Scaffold a new Tri-State CVE Docker Lab under cve-labs/<CVE-ID>
  --list-checks             List all security checks with metadata

Scan Options:
  --detect, --fingerprint   Detect tech stack and profile recommendation only (no scan)
  --force-all               Run all security checks regardless of detected tech stack
  --check, --cve <id>       Run only specific check IDs or CVE IDs (comma-separated or repeatable)
  --pc-local                Run deep local host PC security audit (ports, firewall, AV/EDR, unquoted services)
  --oast                    Start local HMAC-tokenized OAST callback server for blind SSRF/XXE verification
  --templates <path>        Run declarative YAML/JSON CVE templates from file or directory
  --json                    Save JSON report (or stdout JSON in --cve-audit / --doctor mode)
  --html                    Save HTML report (dark-mode, self-contained)
  --markdown [file]         Save Markdown report (optional output filename)
  --csv [file]              Save CSV report (optional output filename, UTF-8 BOM + formula-safe)
  --sarif [file]            Save SARIF v2.1.0 report (default: secscan-report.sarif)
  --ai-fix                  Generate AI / playbook fix solutions and audience summary
  --audience <beginner|pro> Target audience for --ai-fix guidance (default: pro)
  --output <stem>           Base name for reports            (default: report)
  --profile <name>          Scan profile (21 profiles): smart (default)|device|quick|modern|cms|api|laravel|wordpress|apache|nginx|spring|full
  --device, --tv, --camera, --pc, --iot
                            Scan Smart TVs, IP Cameras/NVRs, PCs/Workstations/Servers, Routers, Printers, NAS or IoT devices
                            (sets --profile device --allow-private; --tv/--camera/--pc set category)
  --device-category <cat>   Filter device discovery/checks: all|smart_tv|ip_camera|pc_workstation (aliases: tv, camera, pc)
  --profiles                List all 21 available profiles
  --depth <n>               Crawl depth for discovery (0..5, default: 3)
  --tech <list>             Force tech tags, comma-separated (e.g. react,node,laravel)
  --concurrency <n>         Parallel targets                 (default: 5)
  --timeout <ms>            Request timeout in ms            (default: 10000)
  --auth <token>            Authorization header value
  --auth-low <token>        Secondary low-privilege Authorization header for --autorize
  --intruder <url>          Run Burp Intruder §marker§ fuzzer against target URL
  --payloads <list>         Comma-separated payload list or file for --intruder
  --attack-mode <mode>      Intruder mode: sniper|battering_ram|pitchfork|cluster_bomb
  --autorize <url>          Run Burp Autorize 3-context BOLA/IDOR differential test
  --header "Name: Value"    Custom HTTP request header (repeatable)
  --diff                    Compare with last scan and show changes
  --no-history              Do not save this scan to history
  --webhook <url>           Send results to Slack/webhook URL
  --agent                   Run AgentEngine planner-worker verification loop
  --goal <text>             Custom verification goal for --agent mode
  --noise-profile <p>       NoiseGovernor profile: off|quiet|balanced|aggressive
  --source-ip <ip|host=ip>  Connect HTTP/HTTPS directly to Source/Origin IP with Host & TLS SNI
  --get-real-ip, --real-ip  Discover website real/origin IP (DNS, CDN, SPF, MX, subdomains, headers)
  --scan-real-ip            Discover real/origin IP first and automatically pin --source-ip for the scan
  --review-report <file>    Validate report/finding file against SecScan 7-Gate VDP eligibility rules
  --posture-check [model]   Run SecScan 9-Probe Fenceline LLM refusal-posture check
  --scope <rule>            Scope allow/deny rule (repeatable or comma-separated)
  --allow-private           Allow RFC1918 & internal hosts (cloud metadata stays blocked)

Authentication & Session Recording:
  --login-url <url>         Login form or API endpoint URL (auto-detected if omitted with --username)
  --username, --user <user> Username or email for authenticated website login
  --password, --pass <pass> Password for authenticated website login
  --login-type <type>       Login submission format: auto, form, or json (default: auto)
  --save-session <file>     Record and save the authenticated session (cookies/JWT/CSRF) to a JSON file
  --load-session <file>     Load a previously recorded session JSON file for authenticated scanning
  --record-session          Test login with --username & --password, print recorded session, and exit
```

---

## 2. `.secscanrc` Configuration File (`core/config.js`)

Create a `.secscanrc` JSON file in your project root to persist default CLI and scan options:

```json
{
  "profile": "smart",
  "concurrency": 5,
  "timeout": 10000,
  "maxDepth": 3,
  "output": "report",
  "json": true,
  "html": true,
  "sarif": false,
  "aiFix": true,
  "audience": "pro",
  "noiseProfile": "balanced",
  "allowPrivate": false,
  "scopeRules": ["deny:admin.internal.local"],
  "headers": {
    "X-Audit-Tag": "security-scanner"
  }
}
```

Supported `.secscanrc` keys include `targets`, `sourceIp`, `concurrency`, `timeout`, `profile`, `output`, `json`, `html`, `markdown`, `csv`, `sarif`, `aiFix`, `audience`, `headers`, `auth`, `webhook`, `noHistory`, `maxDepth`, `port`, `ui`, `forceAll`, `techOverride`, `agent`, `goal`, `noiseProfile`, `scopeRules`, `allowPrivate`, `cveCatalog`, `cveFeed`, and `failOnMissingCves`.

---

## 3. REST API Endpoints Table (`core/server.js`)

The local server binds strictly to `127.0.0.1` (`--port 4321`) with Host/Origin anti-CSRF validation and CSP headers.

| Method & Path | Purpose |
|---|---|
| `GET /api/meta` | Version, scan presets, 21 profiles, CVE coverage summary, and full 84-check catalog |
| `GET /api/system/doctor` | Local environment preflight, storage permissions, proxy, and LLM pool status check |
| `POST /api/system/diagnose-target` | PC-vs-target preflight triage (DNS resolution, SSRF/scope gate, ping latency) |
| `GET /api/system/pc-audit` | Run local host PC deep security auditor (`core/pc-local-auditor.js`) |
| `POST /api/sca/analyze` | Run branch-aware Runtime SCA dependency & version vulnerability detection (`{ targetUrl }` or `{ html, headers }`) |
| `GET\|POST /api/auth/variables`, `PUT\|DELETE /api/auth/variables/:name` | Manage shared **System Variables (`{{VAR:name}}`)** across `.lsr` sequences (secret categories masked on list) |
| `POST /api/auth/inspect-page` | Governed login page DOM inspector returning sanitized forms, inputs, OTP candidates, buttons, and CSRF tokens |
| `POST /api/auth/otp-preview` | Validate RFC 6238 TOTP MFA config (`SHA1`/`SHA256`/`SHA512`, `6`/`8` digits) and preview live code + remaining window |
| `GET\|POST /api/auth/sequences`, `DELETE /api/auth/sequences/:id` | List, save/validate, or delete `.lsr` Login Sequence Recorder definitions (with secrets masked on export) |
| `POST /api/auth/record-session`, `POST /api/auth/macro-test` | Execute single-step login macro or multi-step `.lsr` Login Sequence (+ System Variables & TOTP MFA), record session, and return step diagnostics |
| `GET /api/auth/sessions`, `DELETE /api/auth/sessions/:id` | List recorded authenticated sessions (secrets redacted) or delete a stored session by ID |
| `POST /api/intruder/run` | Burp Intruder `§marker§` engine (`sniper`, `battering_ram`, `pitchfork`, `cluster_bomb`, grep-match/extract & anomaly scoring) |
| `POST /api/autorize/run` | Burp Autorize 3-context (`Primary` vs. `Secondary` vs. `Unauthenticated`) BOLA/IDOR/BFLA differential matrix |
| `POST /api/tools/decode` | Burp Decoder 17-operation pipeline, Recursive Smart Auto-Decoder, and JWT Security Inspector |
| `POST /api/tools/compare` | Burp Response Comparer (similarity ratio, status/byte/word/line deltas, header diff, and JSON structural diff) |
| `GET\|POST /api/compliance/summary` | Invicti Proof-Based Scanning™ (`0–100%`) & 6-Framework Enterprise Compliance Matrix (`PCI-DSS v4.0`, `OWASP API 2023`, `ISO 27001`, `NIST 800-53`, `SOC 2`, `HIPAA`) |
| `POST /api/openapi/import` | OpenAPI 3.x / Swagger 2.0 schema importer & live discovery (`/openapi.json`, `/swagger.json`, `/v3/api-docs`) |
| `POST /api/real-ip` | Discover website Real / Origin IP behind CDN/WAF (DNS, SPF, MX, subdomain, origin headers, differential verify) |
| `POST /api/reports/review` | 7-Gate VDP vulnerability report submission reviewer (`{ reportText, authorModel, skipBattery }`) |
| `POST /api/llm/posture-check` | 9-Probe Fenceline LLM Posture Check (`{ model, provider, profileId }`) |
| `POST /api/ai/remediate` | Generate dual-audience fix solution (AI-enhanced or offline stack playbook fallback) |
| `POST /api/ai/summary` | Generate executive/developer scan summary for target audience (`beginner` \| `pro`) |
| `POST /api/ai/analyze-api` | Ask LLM or deterministic playbook about discovered SPA API communication, backend endpoints, and hardening guidance |
| `GET /api/cves/coverage` | Audit built-in check CVE coverage (supports `?tech=...`, `?feed=1`, and `?provider=osv\|nvd\|ghsa\|cisa-kev`) |
| `POST /api/cves/audit` | Evaluate custom CVE advisory JSON arrays (`{ advisories, techTags, includeFeed }`) |
| `POST /api/cves/confirm-db` | Confirm CVE coverage against external NVD 2.0 / OSV.dev / GHSA / CISA KEV payloads & `package@version` specs |
| `GET /api/cves/labs`, `POST /api/cves/labs/run`, `POST /api/cves/labs/scaffold` | List, run, and scaffold Tri-State Per-CVE Docker/Emulated Labs and compute precision/recall/FPR metrics |
| `POST /api/templates/run` | Execute declarative YAML/JSON CVE templates under SSRF & ReDoS guardrails (`core/template-loader.js`) |
| `POST /api/fingerprint` | Tech stack fingerprinting and check selection preview |
| `POST /api/scan`, `GET /api/scan/:id`, `GET /api/scan/:id/stream` | Launch scan (supports `sourceIp`, `sourceIpMap`, `loginSequence`, `deviceCategory`), inspect status, and stream live SSE events |
| `GET /api/scan/:id/export?format=json\|html\|markdown\|csv\|sarif` | Export scan, history, or task findings in any format (including OASIS SARIF v2.1.0) |
| `GET /api/history`, `GET /api/history/:id`, `POST /api/diff` | Browse past scans and compute regression diffs |
| `POST /api/report/html` | Generate standalone dark-mode HTML report |
| `POST /api/checks/scaffold` | Preview (`dryRun`) or create new check + test files (`checks/*.js` & `tests/checks/*.test.js`) |
| `GET\|POST /api/tasks`, `GET /api/tasks/:id`, `PUT /api/tasks/:id/llm` | List/create agent tasks, view graph/coverage, configure LLM chain |
| `POST /api/tasks/:id/plan`, `/sidequestion`, `/intents/:nodeId/steer\|cancel` | Plan next round, ask `/btw` side question, steer or cancel intents |
| `GET /api/graph/exploration/:taskId`, `/coverage`, `/lineage/:taskId/:findingId` | Inspect Exploration DAG (with `?fold=true`), Asset Coverage, and Finding Lineage |
| `GET /api/assets?dsl=...`, `POST /api/assets/ingest` | Query assets with 19-field Asset DSL; ingest `nmap`/`nuclei`/`httpx`/`ffuf`/`bbot` |
| `GET /api/findings/asset-tree`, `GET\|POST /api/findings/:id/evidence`, `POST .../verify\|retest` | Asset-grouped findings, S1 evidence binding/verification, and 1-Click Retests |
| `GET /api/traffic`, `/hosts`, `/templates`, `/export.har`, `/:id`, `/:id/passive`, `/:id/stream-messages`, `POST /api/traffic/:id/replay`, `/ingest`, `GET\|POST\|DELETE /api/traffic/rewrite-rules` | FTS5 traffic search, URL template clustering, HAR 1.2 export, passive scan, WebSocket/SSE stream frames, RFC-9110 replay, external/extension ingest, and HMAC rewrite rules |
| `GET /api/llm/pool`, `POST /api/llm/profiles`, `POST .../reset`, `DELETE /api/llm/profiles/:id` | Multi-LLM pool status (`gemini`, `anthropic`, `openai`, `ollama`), profile CRUD, and circuit breaker reset |
| `GET\|PUT /api/guard/settings`, `POST /api/guard/evaluate` | Noise Governor, Scope/Deny rules, Intercept rules, and JEV / risk evaluator |

---

## 4. Autonomous Agentic Mode (`--agent`)

`core/agent-engine.js` runs a planner-worker verification loop persisted in the embedded SQLite Dual-Graph Store (`core/graph-store.js`):
- **Goal Decomposition & Bounded Workers**: Breaks `--goal` into verification intents fenced by atomic leases (`claimIntentToken`, `heartbeatIntentClaim`, `settleIntentClaim`), bounded by `BudgetLedger`, and folded across rounds (`core/coldgraph.js`).
- **Okapi BM25 Tool Selection (`core/toolrag.js`) & `skills/`**: Projects the top-K relevant check/agent tools per intent while workers load `SKILL.md` methodologies (`api-recon`, `api-security`, `codeaudit`, `patch-diff`).
- **`/btw` Read-Only Side Questions (`core/sidequestion.js`)**: Answers operator questions from a deep-cloned, 4-stage compressed snapshot with `tools: []`—zero graph mutation or target probing.

```bash
secscan https://example.com --agent --goal "Verify API auth, CORS, and Next.js middleware controls" --noise-profile quiet
```

---

## 5. Multi-LLM Pool & Local Ollama Setup

Security Scanner runs **deterministic stack-aware playbooks** offline by default, and supports multi-provider LLM failover (`gemini`, `anthropic`, `openai`, `openai-responses`, `ollama`) with round-robin worker rotation (`llmRotate`), context-window pre-filtering, and quota-aware circuit breaking (`402` / exhausted `429` hard-trip; transient `60s -> 300s -> 1800s` cooldown ladder).

### Option A — Environment Auto-Discovery (Ollama)
```powershell
# PowerShell (Windows)
$env:OLLAMA_HOST = "http://127.0.0.1:11434"
$env:SECSCAN_OLLAMA_MODEL = "qwen2.5-coder:7b"   # optional, default: llama3.1
node bin/cli.js --doctor
node bin/cli.js https://your-app.com --ai-fix --audience pro
```

```bash
# Bash / macOS / Linux
export OLLAMA_HOST="http://127.0.0.1:11434"
export SECSCAN_OLLAMA_MODEL="qwen2.5-coder:7b"
secscan --doctor && secscan https://your-app.com --ai-fix --audience pro
```

### Option B — Configure via Web UI (Ollama, LM Studio, vLLM, llama.cpp)
1. Open **Tab 7 (`Checks & System Guardrails`) → `🛡️ System Guardrails & Multi-LLM Pool`**.
2. Add an `ollama (Local)` profile (blank Base URL defaults to `http://127.0.0.1:11434`) or an `openai (OpenAI-compatible)` profile (e.g., `http://127.0.0.1:1234/v1` for LM Studio / vLLM).

---

## 6. Verification Gates, Report Review & Posture Checks

### Pre-Report False-Positive Verification Gate (`core/check-verify.js`, `core/fp-engine.js`)
Every non-`SAFE` finding passes through `verifyFindingBeforeReport` inside `EnrichEngine.enrichFinding`:
- **HTTP 404/405/410 & Soft-404 Shingle Suppression (`isSoft404Response`)**: Downgrades findings whose trace returned `404`/`405`/`410` (unless passive root-header or `subdomain-takeover`/`iis-shortname`), framework Soft-404 pages, unconfirmed login redirects (`301`/`302`/`307`/`308`), and SPA HTML catch-alls on JSON/config probes.
- **Negative-Control Invariant Probing (`verifyDifferentialProbe`)**: Subtracts echo/reflection baselines so mirrored nonces or prose never trigger false positives.
- **Prerequisite-Gated Confidence Tiering (`classifyFindingConfidence`)**: Assigns `CONFIRMED_EXPLOITABLE`, `VERSION_ATTRIBUTED`, `HEURISTIC_ADVISORY`, or `INFORMATIONAL`, downgrading unversioned Next.js RSC responses, Tomcat without `PUT`, unexecuted PHPUnit `GET 200`, distro backport banners (`Ubuntu`/`Debian`/`el9`), and unpinned semver ranges (`^`, `~`, `>=`).
- **S1 Receipt Sanitization (`ensureVerbatimEvidenceQuotes`)**: Requires `poeLevel >= 3` and verbatim `>= 8`-char quotes in bound HTTP snapshots.

### 7-Gate VDP Report Reviewer (`--review-report`, `core/submission-review.js`)
Evaluates Markdown vulnerability reports against 7 mandatory gates (`remote_exploitable`, `target_eligible`, `not_out_of_scope_class`, `default_config`, `impact_demonstrated`, `poc_reproducible`, `claim_matches_proof`), blocks self-review (`model === authorModel`), and runs a 2-fixture falsification battery (`eligible-must-pass` and `out-of-scope-must-fail`):

```bash
secscan --review-report ./reports/my-finding-report.md --json
```

### 9-Probe Fenceline LLM Posture Check (`--posture-check`, `core/posture-check.js`)
Runs 4 out-of-bounds offensive probes (`REFUSE-1..4`, must refuse) and 5 authorized defensive probes (`ALLOW-1..5`, must answer without over-refusal), grading posture as `CLEAN`, `PARTIAL`, `INVALID`, or `CONTRAST`:

```bash
secscan --posture-check
```

---

## 7. Docker Live Auto-Sync (`docker compose`)

`Dockerfile` (Node 24 Alpine with native `node:sqlite`) and `docker-compose.yml` bind-mount `./checks`, `./core`, `./ui`, `./bin`, and `./scan.js` with `node --watch core/server.js`:

```bash
# Build and start Web UI & API on http://127.0.0.1:4321
npm run docker:up

# Optional Compose Watch mode (for remote Docker contexts)
npm run docker:watch

# Run CLI commands inside the running container (reports saved to ./reports)
docker compose exec secscan node bin/cli.js https://example.com --html --json
docker compose exec secscan node bin/cli.js https://example.com --source-ip 203.0.113.50 --html

# View logs / stop container
npm run docker:logs
npm run docker:down
```

Code edits in `core/` or `scan.js` reload the container server in `< 1 s`; edits in `ui/` and `checks/` take effect immediately on the next refresh or scan.
