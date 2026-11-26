# 🔐 Authentication, Visual Login Sequence Recorder (`.lsr`), System Variables & TOTP MFA Guide

Security Scanner v2.7 includes a full stateful authentication engine (`core/auth-session.js`) capable of handling single-step form/JSON login macros, bearer/custom header authentication, **multi-step Login Sequence Recorder (`.lsr`)** flows (e.g., SSO/Wrapper login $\rightarrow$ application login $\rightarrow$ RFC 6238 TOTP MFA prompt), **System Variables (`{{VAR:name}}`)**, a masked **Secrets Vault (`{{SECRET:name}}`)**, **Top Failure Diagnostics**, an interactive **Visual `Play` Preview**, and automatic mid-scan session recovery.

---

## 1. Overview of the 3 Authentication Methods

In **Tab 1 (`New Scan`) → `⚙️ Advanced Options` → `🔐 Website Authentication & Login Sequence Recorder`** (`#adv-auth-method`), choose the authentication strategy that matches your target:

| Method (`#adv-auth-method`) | Best For | Key Capabilities |
|---|---|---|
| **`Login Sequence Recorder (.lsr) — Multi-Step & MFA/OTP`** (`login_sequence`) | Multi-page logins, SSO/wrapper portals, CSRF + dynamic form flows, TOTP 2FA targets | Ordered 6-action `.lsr` sequences (`MAX_SEQUENCE_STEPS = 25`), `#lsr-recorder-backdrop` visual DOM inspector, `{{VAR:name}}` System Variables, `{{SECRET:name}}` vault, RFC 6238 TOTP (`fill_otp`), URL Restrictions, and Session Detection auto-reauth |
| **`Standard Login Macro (Username / Password & Auto-CSRF)`** (`macro`) | Single-form HTML logins (`application/x-www-form-urlencoded`) or JSON API logins (`application/json`) | Auto-discovers `/login`, `/signin`, `/api/auth/login`, `/api/login`, etc.; extracts hidden form/meta CSRF tokens (`_token`, `csrf_token`, `authenticity_token`, `__RequestVerificationToken`); promotes `XSRF-TOKEN` cookies; captures `Set-Cookie` and JSON JWTs (`access_token`, `token`, `jwt`, `id_token`) |
| **`Custom Authorization Header / Bearer Token`** (`header`) | Stateless REST/GraphQL APIs with static API keys or pre-issued JWTs | Injects `#adv-auth` (`Authorization: Bearer ...` / `Basic ...`) plus optional multi-line `#custom-headers-input` headers across every request |

---

## 2. System Variables & Shared Credentials Vault (`{{VAR:name}}` / `{{SECRET:name}}`)

Instead of hardcoding usernames, passwords, TOTP seeds, or login URLs inside individual `.lsr` sequence files, Security Scanner provides two complementary credential mechanisms:

1. **System Variables (`{{VAR:name}}`)**: Global, reusable variables shared across **all** saved `.lsr` login sequences (`#sys-vars-panel`). Updating a System Variable in one place automatically updates every `.lsr` sequence that references `{{VAR:name}}`—ideal for password rotation or switching staging/production accounts.
   - **Categories (`#sys-var-category-select`)**:
     - `username` — 👤 Username / Email (e.g., `corp_user`)
     - `password` — 🔒 Password / Secret (e.g., `corp_pass`, masked in UI & API listings)
     - `otp_seed` — 🔑 TOTP / MFA Base32 Seed (e.g., `corp_otp_seed`, usable in OTP config or `fill_otp`)
     - `url` — 🌐 Login / Target URL (e.g., `corp_login_url`)
     - `token` — 🎟️ API Key / Token (e.g., `api_key`)
     - `custom` — ⚙️ Custom Variable
   - **Quick-Access Modal Bar (`#lsr-modal-sysvars-bar`)**: Inside the Visual Recorder modal, click any variable chip (`#lsr-modal-sysvars-chips`) or **`⚙️ + Add / Rotate Variable`** (`#btn-lsr-toggle-modal-sysvar`) to add, rotate, or bind `{{VAR:name}}` without leaving the sequence editor.
2. **Per-Sequence Secrets Vault (`{{SECRET:name}}`)**: Scoped to a single `.lsr` sequence (`#lsr-secrets-chips`, `#btn-add-lsr-secret`). Masked as `[SECRET]` / `[REDACTED]` in UI chips, logs, and exported `.lsr` JSON files (`exportLsrSequence`).

### System Variables REST API (`GET|POST|PUT|DELETE /api/auth/variables`)

```bash
# List all configured System Variables (secret categories return masked values)
curl -sS http://127.0.0.1:4321/api/auth/variables

# Create or update a shared System Variable
curl -sS -X POST http://127.0.0.1:4321/api/auth/variables \
  -H "Content-Type: application/json" \
  -d '{
    "name": "corp_pass",
    "category": "password",
    "value": "RotatedSecret#2026!"
  }'

# Rotate an existing System Variable via PUT
curl -sS -X PUT http://127.0.0.1:4321/api/auth/variables/corp_pass \
  -H "Content-Type: application/json" \
  -d '{"value": "NewRotatedSecret#2027!"}'

# Delete a System Variable
curl -sS -X DELETE http://127.0.0.1:4321/api/auth/variables/corp_pass
```

---

## 3. Visual Step-by-Step Login Sequence Recorder Modal (`#lsr-recorder-backdrop`)

Click **`🎬 New sequence / Open Visual Login Sequence Recorder`** (`#btn-new-lsr-sequence`) to open `#lsr-recorder-backdrop`.

### Top Toolbar
- **Sequence Filename (`#lsr-sequence-name`)**: Name of your `.lsr` sequence (e.g., `WrapperSequence.lsr`).
- **`💾 Save` (`#btn-lsr-save`)**: Normalizes, validates target/step URLs under SSRF & scope guardrails, and saves to the backend store (`POST /api/auth/sequences` or `PUT /api/auth/sequences/:id` when updating an existing sequence).
- **`▶️ Play / Test Sequence` (`#btn-lsr-play`)**: Executes the full `.lsr` sequence live against the target (`POST /api/auth/record-session`), renders step-by-step HTTP results, updates the **Top Failure Diagnostics Banner** if any step fails, and populates the **Interactive Visual `Play` Preview** in `#lsr-visual-canvas`.
- **`⏺️ Inspect & Record Page` (`#btn-lsr-record`)**: Fetches the URL in `#lsr-inspect-url` via `POST /api/auth/inspect-page` (governed backend DOM parser, zero untrusted script execution) and automatically records a `navigate` step if not already present.
- **`⚡ Load Working Example` (`#btn-lsr-load-example` & `#btn-load-example-lsr-inline`)**: Loads `DemoEnterpriseMFA.lsr` bound to the built-in self-contained demo login & 2FA endpoint (`/api/auth/demo-login`) so you can immediately inspect, save, edit, and replay a working 5-step + TOTP MFA login sequence locally with zero external network dependencies.
- **`✨ New Blank` (`#btn-lsr-new-blank`)**: Resets the recorder editor to a clean blank sequence template.
- **`🔑 + OTP Step` (`#btn-lsr-add-otp-step`)**: Appends a `fill_otp` step targeting `#otp-selector-input` (or `auto`).

### Top Failure Diagnostics Banner (`#lsr-top-diagnostics-banner`)

When `▶️ Play / Test Sequence` (or **`▶️ Quick Play / Verify`**) encounters a failure or incomplete login, `#lsr-top-diagnostics-banner` displays a structured diagnostic code, the failing step number, and actionable remediation guidance:

| Diagnostic Code | Root Cause | How to Fix |
|---|---|---|
| `NETWORK_TIMEOUT_OR_ABORT` | A `navigate`, `click_button`, or `custom_request` step timed out or was aborted (`Fetch failed: The operation was aborted`, `ETIMEDOUT`, `ECONNREFUSED`, `ENOTFOUND`). | Check that the Step 1 `navigate` URL is reachable from the scanner host, configure `--source-ip` if the target sits behind a CDN/WAF, or click **`⚡ Load Working Example`** to test against `/api/auth/demo-login`. |
| `SELECTOR_NOT_FOUND` | A `change_input` or `fill_otp` step could not match an `<input>`, `<select>`, or `<textarea>` in the fetched page DOM using `selectorType` (`id`, `name`, `css`) and `selector`. | Click **`→ Load Page Forms`** on that page URL, verify the exact `id` or `name` attribute in **Discovered Form Inputs**, or set `fill_otp` selector to `auto`. |
| `BUTTON_SELECTOR_NOT_FOUND` | A `click_button` step could not locate the target `<button>` or `<input type="submit">` by `text`, `id`, `name`, or `css`, and no fallback login form was found. | Inspect the page in `#lsr-visual-canvas` and click the discovered button card (`+ Record Click`), or supply an explicit `submitUrl`, `method`, and `contentType`. |
| `UNRESOLVED_VARIABLE` | A step references `{{VAR:name}}` or `{{SECRET:name}}` that does not exist in System Variables or the sequence Secrets Vault (or contains a `[SECRET]` placeholder after an unhydrated import). | Define the missing variable in **`🌐 System Variables`** (`#sys-vars-panel`) or **`🗝️ Secrets Used in the Login Sequence`** (`#lsr-secrets-chips`). |
| `OTP_CONFIG_ERROR` | A `fill_otp` step executed without an active TOTP configuration, or the Base32 secret/digits/period/algorithm is invalid. | Open **`🔑 Configure OTP`** (`#btn-open-otp-config`), enter a valid Base32 secret (or bind `{{VAR:corp_otp_seed}}`), and click **`Verify & Preview TOTP`**. |
| `NAVIGATION_HTTP_ERROR` | A `navigate` or `custom_request` step returned an unexpected network error, SSRF/scope block, or HTTP `4xx`/`5xx` failure preventing form discovery. | Verify the URL is reachable, enable `--allow-private` for internal hosts, check `--source-ip` if behind a CDN, and confirm the target is within `--scope`. |
| `HTTP_AUTH_ERROR` | Form/API submission returned HTTP `401 Unauthorized` or `403 Forbidden` (bad credentials, expired token, or missing CSRF/Origin header). | Verify `{{VAR:...}}` / `{{SECRET:...}}` credentials, ensure the preceding `navigate` step harvested the CSRF token/cookie, or add required custom headers. |
| `LOGIN_ERROR_BANNER_DETECTED` | The post-submit HTML/JSON response returned HTTP `200` but contained an inline login failure banner (e.g., *"Invalid username or password"*, *"Incorrect OTP"*, *"Account locked"*). | Inspect the **Interactive Visual `Play` Preview** error banner in `#lsr-visual-canvas`, check the submitted username/password/OTP timing, and re-test. |
| `NO_POST_SUBMIT_SESSION_ARTIFACT` | The sequence finished without errors, but the target set no session `Set-Cookie`, returned no Bearer/JWT token, and failed `loggedInPattern` verification. | Add an `extract_token` step for non-standard JSON/header tokens, configure `loggedInPattern` in **Session detection**, or verify whether the app redirects to an SSO callback URL. |

### Interactive Visual `Play` Preview ("Show How It Looks") in `#lsr-visual-canvas`

After running **`▶️ Play / Test Sequence`**, `#lsr-visual-canvas` switches into an interactive **"Show How It Looks"** replay view so you can visually verify what the scanner saw at every step:
- **Step Timeline Switcher (`Step 1 -> Step 2 -> ...`)**: Click any step pill to jump between captured DOM snapshots before/after form submission.
- **Simulated Input Boxes & Bound Variables**: Shows each form field as a rendered input preview displaying bound variables (`{{VAR:corp_user}}`, masked `{{VAR:corp_pass}}` / `{{SECRET:...}}`, or generated OTP `••••••`) rather than exposing raw passwords.
- **Matched vs. Unmatched Selector Indicators**: Highlights matched selectors in green and flags missing selectors (`SELECTOR_NOT_FOUND` / `BUTTON_SELECTOR_NOT_FOUND`) directly beside the field or button.
- **Page Error Banners & Session Badges**: Renders any detected inline login error banners (`LOGIN_ERROR_BANNER_DETECTED`) plus captured CSRF tokens, cookies, and HTTP status codes per step.

### All 6 Action Types (`Login Actions` Tab)

1. **`navigate`**: Performs a governed `GET` to `url`, follows same-origin/in-scope redirects, harvests `Set-Cookie` and CSRF tokens (`_token`, `csrf_token`, `<meta name="csrf-token">`), and parses `<form>`, `<input>`, and `<button>` elements.
2. **`change_input`**: Binds a value (literal, `{{VAR:name}}`, or `{{SECRET:name}}`) to a form input matched by `selectorType` (`id`, `name`, or `css`). Supports `isSecret: true` masking (`***`).
3. **`fill_otp`**: Computes a live RFC 6238 TOTP code at execution time and populates the target OTP input (`selector: "auto"` auto-detects fields with `autocomplete="one-time-code"` or `otp|totp|mfa|2fa|passcode` names/labels).
4. **`click_button`**: Submits the enclosing form (including hidden fields, CSRF tokens, and filled `change_input`/`fill_otp` values) matched by `text`, `id`, `name`, or `css`, with optional `submitUrl`, `method`, and `contentType` (`form` or `json`) overrides.
5. **`extract_token`**: Extracts an authentication token from `json` (dot-path such as `data.accessToken`), `header` (e.g., `Authorization`, `X-Auth-Token`), `cookie`, `csrf` DOM meta/input, `local_storage` (`localStorage.setItem(key, val)`), or `session_storage` (`sessionStorage.setItem(key, val)`) into the `AuthSessionManager` bearer/header state.
6. **`custom_request`**: Executes a direct `GET`/`POST`/`PUT`/`PATCH`/`DELETE` request with custom headers and JSON/form/raw payload supporting `{{VAR:...}}`, `{{SECRET:...}}`, and `{{OTP}}` template interpolation.

### Top-of-Scan Token, Cookie & `localStorage` Harvester + Local Store Checker (`#top-auth-token-bar` & `#tab-login-lsr`)
- **Dedicated `🔐 Login & LSR Studio` Tab (`#tab-login-lsr`) vs. Compact Scan Selector**:
  - Manage all `.lsr` sequences, System Variables (`{{VAR:name}}`), Secrets (`{{SECRET:name}}`), and TOTP MFA inside the dedicated **`🔐 Login & LSR Studio`** navigation tab (`#tab-btn-login-lsr`).
  - Inside **Tab 1 (`New Scan`)**, both the top quick bar (`#top-auth-token-bar` -> `#top-lsr-select`) and `⚙️ Advanced Options` (`#adv-lsr-select`) provide a clean dropdown to select an existing `.lsr` sequence or click **`🎬 + Create New .lsr`**.
- **`🎟️ Get Token / Cookie` (`harvestAuthTokensAndCookies`)**:
  - Executes the selected `.lsr` sequence (or login macro) via `POST /api/auth/record-session` (`includeArtifactValues: true`) and harvests all returned authentication artifacts via `extractWebStorageAndTokensFromResponse()`:
    1. **API / Bearer Tokens** from JSON bodies (`access_token`, `accessToken`, `token`, `jwt`, `id_token`, `apiKey`), response headers (`Authorization`, `X-Auth-Token`, `X-Access-Token`, `X-Api-Token`), and OAuth redirect URL hashes/queries,
    2. **Session & CSRF Cookies** (`Set-Cookie` headers formatted as a ready-to-use `Cookie` header),
    3. **Web Storage Tokens** (`localStorage.setItem(...)` and `sessionStorage.setItem(...)` assignments in login responses).
- **`🔍 Check Local Store` (`checkLocalStoreForTargetAuth`)**:
  - Checks origin-scoped browser `localStorage` (`secscan_auth_artifact_vault_v1`), same-origin `localStorage`/`sessionStorage` token keys (`scanBrowserWebStorageForTokens`), and active backend sessions (`GET /api/auth/sessions?includeArtifactValues=1&origin=...`), inspects JWT expiration (`inspectExtractedJwtMeta`), and lets you apply cached tokens and cookies to your scan in 1 click.

### `Restrictions` Tab & `Session detection` Tab
- **`Restrictions` Tab (`#lsr-panel-restrictions`)**: Add URL paths or wildcard patterns (e.g., `/logout`, `/signout`, `/api/auth/revoke`, `/admin/delete*`) that the crawler, active fuzzers, and checks must **never** request during an authenticated scan. Built-in logout protection (`isLogoutOrDestructiveUrl`) also blocks `/logout`, `/signout`, `/logoff`, `/kill-session`, `/destroy-session`, and query routes like `?r=site/logout` automatically.
- **`Session detection` Tab (`#lsr-panel-session`)**: Configure how `AuthSessionManager` detects session expiration mid-scan and triggers automatic `.lsr` replay (with a freshly generated TOTP code):
  - **Logged-Out HTTP Status Codes (`#lsr-session-status-codes`)**: Default `401, 403`.
  - **Login Redirect URL Pattern (`#lsr-session-redirect-pattern`)**: Default `/login`.
  - **Logged-Out Response Body Pattern (`#lsr-session-logged-out-pattern`)**: Regex/text indicator (e.g., `Sign In|Session Expired`).
  - **Logged-In Response Body Pattern (`#lsr-session-logged-in-pattern`)**: Positive indicator confirming an active session (e.g., `Sign Out|Dashboard`).

### Yii 1 (`yii1`), Yii 2 (`yii2`) & PHP Framework Post-Login Crawling & RBAC Verification
- **Cross-Version Yii Selector Normalization**: `findMatchingInputInForm()` in `core/auth-session.js` automatically bridges Yii 1 (`id="LoginForm_username"`, `name="LoginForm[username]"`, `YII_CSRF_TOKEN`, submit button `name="yt0"`) and Yii 2 (`id="loginform-username"`, `name="LoginForm[username]"`, `_csrf` / `_csrf-frontend` / `_csrf-backend`) so `.lsr` sequences work across both Yii 1.1.x and Yii 2.0.x portals without manual selector rewriting.
- **In-Place `PHPSESSID` Promotion & Post-Login Seed Discovery (`getPostLoginSeedUrls`)**: When a scan targets a login URL directly (such as `https://example.com/broadbandAdmin/index.php/site/login`), `AuthSessionManager` tracks the post-login redirect landing page (`postLoginUrl`, e.g., `/broadbandAdmin/index.php/default/index`) plus base application entrypoints and seeds them directly into `runTargetCrawlPipeline()` (`core/crawler.js`).
- **SPA `$routeProvider`, Dropdown Submenu & JS AJAX Form Extraction**: After authenticating, the crawler automatically resolves AngularJS `$routeProvider.when('/route', { templateUrl })` views, `ng-click="selectPage(...)"` top menus and dropdown submenus, `ng-model` form inputs, and `$http`/`fetch`/`axios`/`$.ajax` endpoints while isolating sibling external apps on the same domain (`kind: 'external_app'`) so they cannot overwrite the active `PHPSESSID` cookie.
- **Automated In-Scan RBAC / BFLA Matrix (`core/rbac-matrix.js`)**: Every authenticated scan automatically audits discovered menus, submenus, SPA views, and forms for Broken Function Level Authorization (`CWE-285`) using an isolated unauthenticated fetcher (`Cookie: ''`, `Authorization: ''`, `followRedirects: false`) without touching or logging out the active authenticated session.

---

## 4. Multi-Factor Authentication (RFC 6238 TOTP / OTP)

`generateTotpCode()` in `core/auth-session.js` implements pure-crypto RFC 6238 TOTP / RFC 4226 HOTP using Node's native `node:crypto` (zero external dependencies):
- **Supported Algorithms**: `SHA1` (default), `SHA256`, `SHA512`.
- **Digits**: `6` (default) or `8`.
- **Period**: `15` to `120` seconds (default `30`).
- **Base32 Key Decoding (`decodeBase32`)**: Accepts standard RFC 4648 Base32 keys (case-insensitive, spaces/hyphens/`=` padding ignored) or a System Variable reference (`{{VAR:corp_otp_seed}}`).

### Web UI Setup
1. Click **`🔑 Configure OTP`** (`#btn-open-otp-config`).
2. Enter your Base32 secret (`#otp-secret-input`), choose **Digits** (`#otp-digits-select`), **Period** (`#otp-period-input`), **Algorithm** (`#otp-algorithm-select`), and **Target OTP Input ID / Name** (`#otp-selector-input`, default `auto`).
3. Click **`Verify & Preview TOTP`** (`#btn-test-otp-preview`) to call `POST /api/auth/otp-preview` and verify the live 6/8-digit code and remaining countdown seconds (`#otp-preview-status`).

### REST API Preview (`POST /api/auth/otp-preview`)
```bash
curl -sS -X POST http://127.0.0.1:4321/api/auth/otp-preview \
  -H "Content-Type: application/json" \
  -d '{
    "secret": "JBSWY3DPEHPK3PXP",
    "digits": 6,
    "period": 30,
    "algorithm": "SHA1"
  }'
```

---

## 5. Saving, Persisting & Reusing Login Sequences

### Persistence & Reuse Bar
- **Disk Persistence**: Saved `.lsr` sequences persist in `.secscan-history/auth-sequences.json` across server and Docker restarts (with secret vault entries masked on export unless executed locally by the auth engine).
- **Quick Reuse Bar (`#lsr-reuse-select`)**: Under **Login Sequence Recorder (`.lsr`)** in Tab 1 (`New Scan`):
  - Select any saved sequence from `#lsr-reuse-select`.
  - Click **`✅ Use Selected Sequence`** (`#btn-use-selected-lsr`) / **Use in Scan** to bind it to the next scan.
  - Click **`▶️ Quick Play / Verify`** (`#btn-play-selected-lsr`) to test login + System Variables + OTP immediately and view `#lsr-inline-diagnostics-summary`.
  - Click **`📋 Duplicate`** (`#btn-duplicate-selected-lsr`) to clone an existing sequence for another environment or user role.
  - Use **`📥 Export`** on any sequence card to download a secret-redacted `.lsr` JSON file, or **`📂 Import .lsr`** (`#btn-import-lsr-sequence`) to load a `.lsr` file into the editor.

### End-to-End REST API Examples

```bash
# 1. Inspect a target login page DOM safely (forms, inputs, OTP candidates, CSRF tokens)
curl -sS -X POST http://127.0.0.1:4321/api/auth/inspect-page \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://app.example.com/login"}'

# 2. Save a reusable .lsr sequence referencing System Variables ({{VAR:...}})
curl -sS -X POST http://127.0.0.1:4321/api/auth/sequences \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CorpPortal.lsr",
    "targetUrl": "https://app.example.com",
    "otpConfig": { "enabled": true, "secretName": "corp_otp_seed", "digits": 6, "period": 30, "algorithm": "SHA1" },
    "actions": [
      { "type": "navigate", "url": "https://app.example.com/login" },
      { "type": "change_input", "selectorType": "id", "selector": "email", "value": "{{VAR:corp_user}}" },
      { "type": "change_input", "selectorType": "id", "selector": "password", "value": "{{VAR:corp_pass}}", "isSecret": true },
      { "type": "fill_otp", "selectorType": "id", "selector": "otp_code" },
      { "type": "click_button", "selectorType": "text", "selector": "Log In" }
    ],
    "restrictions": ["/logout", "/signout"],
    "sessionDetection": { "statusCodes": [401, 403], "redirectPattern": "/login" }
  }'

# 3. Play / test the sequence and record an authenticated session
curl -sS -X POST http://127.0.0.1:4321/api/auth/record-session \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://app.example.com", "sequenceId": "<sequence-id>"}'

# 4. List saved sequences or active recorded sessions (secrets redacted)
curl -sS http://127.0.0.1:4321/api/auth/sequences
curl -sS http://127.0.0.1:4321/api/auth/sessions
```

### CLI Session Recording Workflows
```bash
# Auto-discover login page & scan with username/password
secscan https://example.com --username admin@example.com --password "Secret123!"

# Explicit login URL + record & save reusable session JSON
secscan https://example.com --login-url https://example.com/login \
  --username admin --password "Secret123!" --record-session --save-session session.json

# Run scan using saved session file
secscan https://example.com --load-session session.json
```
