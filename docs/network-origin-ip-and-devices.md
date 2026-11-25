# 🌐 Real / Origin IP Discovery, Pinned Source-IP (`--source-ip`), Internal Networks & Device Scanning

Security Scanner v2.7 provides network-layer target discovery, direct origin socket pinning, authorized internal/LAN auditing, IoT/TV/Camera/Workstation scanning, and local host PC security auditing—all governed by SSRF and Scope/Deny guardrails.

---

## 1. Discovering & Scanning Real / Origin IPs Behind CDN/WAF (`--get-real-ip`, `--scan-real-ip`, `POST /api/real-ip`)

When a target website sits behind a CDN or WAF (Cloudflare, AWS CloudFront, Fastly, Akamai, Imperva, Sucuri), `core/real-ip-finder.js` combines DNS `A`/`AAAA`/`CNAME` inspection, `CDN_CIDR_PROVIDERS` fingerprinting, SPF `v=spf1` records, MX mail hosts (filtering out third-party mail relays like Google/Outlook), unproxied origin subdomains (`direct.`, `origin.`, `cpanel.`, `staging.`, etc.), and HTTP origin-leak headers (`X-Origin-IP`, `X-Backend-IP`, `X-Real-Server-IP`, `X-Upstream-Addr`, `X-Host-IP`) to discover and differentially verify the true origin server IP.

### CLI Usage
```bash
# Discover origin IP(s) and CDN posture without launching a full scan
secscan example.com --get-real-ip

# Discover the origin IP first and automatically pin --source-ip for the scan
secscan example.com --scan-real-ip --cve CVE-2026-123007 --html
```

### Web UI & REST API
- **Web UI (Tab 1 `New Scan`)**: Enter a domain/URL and click **`🌐 Get Real IP`** (`#get-real-ip-btn`), or click **`🌐 Auto-Find Real IP from Target URL`** (`#adv-get-real-ip-btn`) in **Advanced Options**. From `#real-ip-banner`, click **`📌 Pin as --source-ip`** or **`🎯 Switch Target to http://<IP>`**.
- **REST API**:
  ```bash
  curl -sS -X POST http://127.0.0.1:4321/api/real-ip \
    -H "Content-Type: application/json" \
    -d '{"target": "https://example.com"}'
  ```

---

## 2. Pinned Source-IP HTTP/HTTPS Routing (`--source-ip`, `ResolveCache` + `PinnedDialer`)

When auditing origin servers behind a CDN/WAF or testing pre-DNS cutover environments, `--source-ip` forces all governed HTTP and HTTPS connections to dial the specified IP at the TCP/TLS socket layer while preserving the original `Host` HTTP header and TLS SNI (`servername`).

### Transport Architecture (`core/validator.js`, `core/fetch.js`)
- **Single-Flight `ResolveCache`**: Coalesces concurrent DNS lookups per hostname (`singleflight`), caches positive answers for `10 s` (`ttlMs`), unmaps IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1` $\rightarrow$ `192.0.2.1`), strips IPv6 zone suffixes (`%eth0`), and deterministically sorts IPv4 before IPv6 (`canonicalizeResolvedIps`).
- **Direct Socket Dialing (`dialPinnedSourceIpRequest`)**: Connects directly to `<sourceIp>:<port>` with `agent: false` (preventing keep-alive socket reuse across pin updates) while sending `Host: <hostname>` and TLS `servername: <hostname>`.
- **Automatic `--resolve` Reproduction Commands**: Every `curl` command emitted by CLI output, JSON/HTML/Markdown/SARIF reports, and the Web UI Evidence Drawer includes `--resolve '<hostname>:<port>:<sourceIp>'` whenever Source-IP pinning is active.

### CLI, Web UI & REST API Examples
```bash
# Pin all requests for example.com to origin IP 203.0.113.50
secscan https://example.com --source-ip 203.0.113.50 --html --json

# Map multiple hosts or wildcard subdomains
secscan https://app.example.com https://api.example.com \
  --source-ip "app.example.com=203.0.113.10,*.example.com=203.0.113.20"

# Pin an authorized internal origin IP (combine with --allow-private)
secscan https://staging.corp.example.com --source-ip 10.20.30.40 --allow-private
```

- **Web UI**: Set `#adv-source-ip` under **Tab 1 (`New Scan`) → `⚙️ Advanced Options`**.
- **REST API**: Pass `"sourceIp": "203.0.113.50"` or `"sourceIpMap": { "app.example.com": "203.0.113.10" }` in `POST /api/scan`.

---

## 3. Authorized Internal & Private Network Scanning (`--allow-private`) & Scope/Deny Rules

By default, Security Scanner **fails closed** against RFC1918 and loopback addresses to prevent SSRF. Enable **`--allow-private`** (or toggle **`🏢 Allow Authorized Internal / Private Targets`** in the Web UI) when auditing authorized internal staging servers, VPN-hosted apps, or LAN devices (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`, `fc00::/7`, `localhost`, `.internal`, `.local`).

### Scope & Deny Asset Gate (`evaluateAssetGate` in `core/guard.js`)
Combine `--allow-private` with `--scope` rules (evaluated block-first, both pre-DNS and post-DNS across `exact_domain`, `fuzzy_domain`, `exact_ip`, `fuzzy_ip`, `cidr`, `exact_url`, and `fuzzy_url`):

```bash
# Audit an internal subnet while explicitly denying a sensitive host
secscan https://portal.corp.internal --allow-private \
  --scope "allow:10.20.0.0/16,deny:10.20.0.5" \
  --auth "Bearer eyJhbGci..." --noise-profile quiet
```

### Guardrails That Always Stay Enforced (Even With `--allow-private`)
- **Cloud Instance Metadata Blocked**: `169.254.0.0/16` (including `169.254.169.254`), Alibaba `100.100.100.200`, AWS IPv6 `fd00:ec2::254`, IPv6 link-local `fe80::/10`, `0.0.0.0/8`, `::`, multicast `224.0.0.0/4` / `ff00::/8`, and hostnames (`metadata.google.internal`, `metadata.goog`, `metadata`, `instance-data`).
- **Obfuscated IP Formats Blocked**: Decimal integers (`2130706433`), hex (`0x7f000001`), octal (`0177.0.0.1`), and shorthand dotted IPs (`127.1`).
- **URL Authority Confusion Blocked**: Embedded `user:pass@` credentials and backslashes (`\`) before `?`/`#`.
- **Per-Hop Redirect & DNS-Rebinding Checks**: Every redirect hop is re-validated, and `TargetPinStore` blocks public-to-private DNS rebinding mid-scan.

---

## 4. Smart TV, IP Camera, PC/Workstation & IoT Device Scanning (`--device-category`, `core/device-scanner.js`)

Security Scanner includes non-intrusive multi-port LAN device discovery (`core/device-scanner.js`, `checks/device-security.js`, `--profile device`) across 9 `DEVICE_CATEGORIES` (`smart_tv`, `ip_camera`, `pc_workstation`, `upnp_dlna`, `router_gateway`, `printer`, `nas_media_server`, `smart_home_iot`, `device_web`).

### CLI Shortcuts & Category Filtering
Using `--device`, `--tv`, `--camera`, `--pc`, or `--iot` automatically enables `--profile device --allow-private` and sets the category filter:

```bash
# Auto-detect and audit any LAN device
secscan 192.168.1.50 --device --html

# Scan a Smart TV (Samsung Tizen 8001/8002/9197, LG webOS, Roku ECP 8060, Google Cast 8008/8009, AirPlay)
secscan 192.168.1.25 --tv

# Scan an IP Camera / NVR (RTSP, ONVIF, Hikvision ISAPI, Dahua, Axis)
secscan 192.168.1.80 --camera

# Scan a PC / Workstation / Local Server (SMB, RDP, WinRM, SSH, VNC, CUPS, Docker TCP, Ollama, dev servers)
secscan 192.168.1.10 --pc

# Explicit category filter
secscan 192.168.1.25 --profile device --allow-private --device-category smart_tv
```

In the Web UI, toggling **Allow Authorized Internal / Private Targets** reveals **`📺 Device Category`** (`#opt-device-category`) in **Tab 1 (`New Scan`)**.

---

## 5. Local Host PC Deep Security Auditor (`--pc-local`, `core/pc-local-auditor.js`)

Audit the security posture of the local machine running Security Scanner with **zero shell execution** (`execFile`, `shell: false`) and a strict frozen binary allowlist (`ALLOWED_LOCAL_BINARIES`: `netstat`, `powershell`, `pwsh`, `ss`, `lsof`, `ufw`, `dpkg-query`, `rpm`, `apk`, `uname`):

1. **Wildcard High-Risk Listening Ports**: Detects `0.0.0.0` / `::` bindings on Telnet (`23`), SMB (`445`), Docker Daemon TCP (`2375`), RDP (`3389`), Android ADB (`5555`), VNC (`5900`), WinRM (`5985`), Redis (`6379`), Ollama, etc.
2. **Host Firewall Posture**: Evaluates Windows `AdvFirewall`/`NetFirewallProfile`, Linux `UFW`, or macOS Application Firewall state.
3. **Endpoint Protection / Real-Time Defense**: Checks Windows Defender, Linux AppArmor/SELinux/ClamAV, or macOS posture.
4. **Unquoted Windows Service Paths (`CWE-428`)**: Identifies unquoted service binary paths with spaces outside `System32` / `SysWOW64`.

```bash
# CLI local host PC audit
npm run pc:audit
# or: secscan --pc-local --json

# REST API local host PC audit
curl -sS http://127.0.0.1:4321/api/system/pc-audit
```
