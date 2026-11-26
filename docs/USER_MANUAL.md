# 📘 Security Scanner v2.7 — User Manual

Welcome to the **Security Scanner v2.7** User Manual. This guide covers day-to-day workflows in the Web UI and REST API, with deep coverage of **Saved Target Systems, 1-Click Configuration Cloner, and Scheduled Fix Verification (`Verify Open Issues Only`)**.

---

## 1. Quick Overview of Core Workflows

1. **Launch Web UI**: `npm run ui` (or `secscan --ui --port 4321`) and open `http://127.0.0.1:4321`.
2. **Configure Authentication (Optional)**: Use the **Top Auth Token Bar** (`#top-auth-token-bar`) or **🔐 Login & LSR Studio** (`#tab-login-lsr`) to record `.lsr` multi-step/TOTP login sequences, bind **System Variables (`{{VAR:name}}`)**, and harvest Bearer JWTs / session cookies.
3. **Save, Clone & Schedule Target Systems**: Persist your full target setup (URL, environment, profile, `.lsr` login sequence, headers, and recurring schedule) so you can re-verify fixes in seconds or clone configurations across environments.
4. **Inspect Results & Verify Fixes**: Review graded findings, discovered menus/forms & RBAC/BFLA matrix, S1 verbatim evidence receipts, and run fast delta fix verification scans.

---

## 2. Saved Target Systems, 1-Click Configuration Cloner & Scheduled Fix Verification

Instead of re-entering a target URL, scan profile, crawl depth, custom headers, and `.lsr` login sequence every time a developer deploys a patch, save the target as a **Target System** (`core/target-systems.js`).

### 2.1 Quick Target Systems Bar (`#target-systems-quick-bar`)

Located directly in **Tab 1 (`🚀 New Scan`)**:

- **Target System Selector (`#target-system-select`)**: Pick any saved system (`Name [environment] — URL (N open issues)`) to populate the scan form, or leave `-- New / Ad-Hoc Target --` for a one-off scan.
- **System Name (`#target-system-name`) & Environment (`#target-system-env`)**: Tag the target as `production`, `staging`, `development`, or `qa`.
- **`💾 Save System` (`#btn-save-target-system`)**: Saves the current form (URL, profile, crawl depth, concurrency, timeout, noise profile, `allowPrivate`, `sourceIp`, `techOverride`, `checks`, custom headers, and linked `.lsr` sequence). Updates the selected system if one is active, or creates a new Target System.
- **`📋 Clone` (`#btn-clone-target-system`)**: Duplicates the selected Target System in 1 click (preserving its profile, `.lsr` sequence, headers, and scan options) and opens the editor so you can immediately tweak the URL, name, or environment (e.g., `Production` → `Staging`).
- **`🎯 Verify Open Issues Only` (`#btn-run-target-system-fixes`)**: Runs **only** the `unfixedCheckIds` (`VULNERABLE` or `SUSPICIOUS`) from the target system's last scan for fast patch verification. If no open issues are tracked yet, it automatically falls back to `full_profile`.
- **`🗓️ Schedules & Systems` (`#btn-toggle-target-systems-manager`)**: Expands `#target-systems-manager-card` to view all saved systems, tracked open checks, and recurring schedules.

### 2.2 Target Systems Manager & Schedule Editor (`#target-systems-manager-card`)

Each saved card in `#target-systems-list` displays:
- **Environment & Profile Badges**: e.g., `PRODUCTION`, `STAGING`, `smart`, and linked `.lsr` sequence badge.
- **Schedule Status Pill**: `🗓️ hourly | every_6h | daily | weekly · Open Issues Only | Full Profile · Next: <timestamp>` or `⏸️ Manual`.
- **Delta Tracking & Open Issues**: Last security grade, count of tracked open check IDs (`🎯 N Open Check(s): headers, cors, ...`), and newly resolved checks (`🎉 N Fixed in Last Run!`) or `✅ All Verified Fixed (0 Open Issues)`.
- **Card Actions**:
  - **`🎯 Verify Open Issues Only`**: Launches a targeted delta scan against tracked unfixed checks.
  - **`🚀 Run Full Profile`**: Runs the complete configured scan profile.
  - **`📥 Load in Form`**: Loads the saved system configuration into Tab 1.
  - **`📋 Clone & Tweak`**: Clones the system via `POST /api/target-systems/:id/clone` and opens the inline editor pre-filled with the clone.
  - **`✏️ Schedule / Edit`**: Opens `#target-system-editor-panel` to configure system fields, linked `.lsr` sequence (`#ts-edit-lsr`), pinned check IDs (`#ts-edit-checks`), recurring schedule interval (`#ts-edit-schedule-interval`), and scheduled run mode (`#ts-edit-schedule-mode`).
  - **`🗑️ Delete`**: Removes the saved Target System.

### 2.3 How Delta Fix Verification Works

1. Run a **Full Profile** scan linked to a Target System (`targetSystemId` is automatically attached when a Target System is active in the form or launched from the manager).
2. On completion, `mergeDeltaScanSummary()` extracts all `VULNERABLE` and `SUSPICIOUS` check IDs into `lastScanSummary.unfixedCheckIds`.
3. After deploying a fix, click **`🎯 Verify Open Issues Only`** (`mode: "open_issues_only"`).
4. The scanner executes only `unfixedCheckIds` (plus any pinned `checks`). Checks that now pass move into `fixedInLastRunCheckIds` (`fixedInLastRunCount`), updating `unfixedCheckIds` until the system reaches `0 Open Issues` (`✅ All Verified Fixed`).
5. Target Systems persist automatically to `<historyDir>/target-systems.json` (when not running in `--in-memory` mode), and scheduled systems are checked automatically by the server scheduler loop.

---

## 3. Target Systems REST API Reference (`core/server.js`)

All endpoints require local `Host`/`Origin` validation and return JSON. Sensitive `authHeader` and `customHeaders` values (`Authorization`, `Cookie`, `X-Api-Key`, `Proxy-Authorization`) are redacted (`[REDACTED]`) in responses.

| Method & Path | Description | Request Body Highlights |
|---|---|---|
| `GET /api/target-systems` | List all saved Target Systems (`{ systems }`) | — |
| `POST /api/target-systems` | Create and validate a new Target System (`201`) | `{ name, environment, targetUrl, profile, sequenceId, checks, allowPrivate, schedule: { enabled, interval, mode } }` |
| `GET /api/target-systems/:id` | Fetch a single saved Target System (`{ system }`) | — |
| `PUT /api/target-systems/:id` | Update a Target System's config or schedule (`200`) | Partial or full Target System fields (`[REDACTED]` preserves existing secret headers) |
| `DELETE /api/target-systems/:id` | Delete a saved Target System (`{ deleted: true, id }`) | — |
| `POST /api/target-systems/:id/clone` | Clone a Target System with optional overrides (`201`) | Optional `{ name, environment, targetUrl, schedule, ... }` |
| `POST /api/target-systems/:id/run` | Launch an immediate scan for the Target System (`202`) | `{ mode: "open_issues_only" \| "full_profile", checks?: string[] }` — returns `{ scanId, mode, checks, checksCount, fallbackToFullProfile, targets }` |

### Example: Clone & Verify Open Issues via `curl`

```bash
# 1. List saved Target Systems
curl -s http://127.0.0.1:4321/api/target-systems

# 2. Clone a production system into staging with a new URL
curl -s -X POST http://127.0.0.1:4321/api/target-systems/<id>/clone \
  -H "Content-Type: application/json" \
  -d '{"name":"App Staging","environment":"staging","targetUrl":"https://staging.example.com"}'

# 3. Run fast delta fix verification (open issues only)
curl -s -X POST http://127.0.0.1:4321/api/target-systems/<id>/run \
  -H "Content-Type: application/json" \
  -d '{"mode":"open_issues_only"}'
```

---

## 4. Related Guides

- [🔐 Authentication, Visual `.lsr` Recorder, System Variables & TOTP MFA](authentication-and-lsr.md)
- [🖥️ 8-Tab Web UI Dashboard, Menus & Workbenches](web-ui-guide.md)
- [🧰 CLI Flags, `.secscanrc` & Complete REST API Reference](cli-and-api-reference.md)
