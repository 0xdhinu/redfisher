# Redfisher v2.0 — Redfish API Security Testing Extension for Burp Suite

A Burp Suite extension (Jython 2.7) for penetration testing and security assessment of **Redfish API** endpoints on BMC (Baseboard Management Controller) hardware — including Dell iDRAC, HPE iLO, OpenBMC, Supermicro, AMI MegaRAC, Lenovo XCC, and others.

---

## Features

### Session Management
- Automatic `X-Auth-Token` injection via Burp session handling rules
- Login / logout with session lifecycle management
- Auto-refresh on 401 responses
- BMC vendor fingerprinting (Dell, HPE, OpenBMC, Supermicro, AMI, Lenovo, Fujitsu, Cisco)

---

### Explorer Tab
- One-click discovery of all `/redfish/v1/` endpoints via `@odata.id` traversal
- **Spider** — BFS traversal up to 3 levels deep, up to 200 unique paths automatically
- Inline response viewer — click any link to see the full response
- Action link extraction — detects `@Redfish.ActionInfo` and `target` links as child entries
- OEM endpoint extraction — parses `Oem.<vendor>.Children` arrays for hidden paths
- **Export Postman Collection** — one click exports all discovered URLs as a Postman v2.1 collection (with auth token pre-filled)
- **Endpoint Bookmarks** — right-click any URL → Bookmark; bookmarks persist to `bookmarks.json` and appear in a panel below the link list with open/remove options
- Right-click context menu:
  - Send to Repeater tab
  - Send to Scanner
  - **Test All HTTP Methods** → populates the SSRF tab's method-tampering panel with the URL
  - Bookmark this URL

---

### Repeater Tab
- Mini-Repeater with GET / POST / PATCH / DELETE / PUT / HEAD support
- Quick path dropdown for common Redfish endpoints
- **Back / Forward** history navigation — last 30 requests stored in session
- Resource type and risk level display per URL
- **ActionInfo auto-fill** — GET response containing `#ActionInfo` automatically:
  - Populates request body with a typed JSON template (`"<required>"` for mandatory fields)
  - Switches method to `POST`
  - Infers and sets the action URL (e.g. `.../SubmitTestEventActionInfo` → `.../Actions/EventService.SubmitTestEvent`)
- **Auto-PATCH template** — for regular resource GET responses, auto-fills the body with writable fields and switches method to `PATCH`
- **Auto-ETag / If-Match** — when a response contains `@odata.etag`, automatically injects `If-Match` into request headers (required by many BMCs for PATCH)
- **Diff view** — third Response tab shows a unified diff between the current response and the previous response for the same URL, making state changes after PATCH instantly visible
- Right-click on request body/headers:
  - **Send to Burp Repeater** — builds a raw HTTP request (with active token) and opens it in Burp's native Repeater
  - **Send to Burp Intruder** — sends the current request to Burp Intruder for fuzzing

---

### Scanner Tab
- Signature-driven passive and active scanning
- Scan individual URLs or all Explorer endpoints in one click
- Live findings table with severity colouring
- **Export findings** as CSV, JSON, Markdown, or **HTML Report** (styled, severity-badged, sortable by severity)
- **CVE Check (Firmware)** — cross-references version strings found in Explorer and logs against the offline CVE database; matching CVEs appear directly in the findings table
- Signature editor — add / edit / delete / enable checks without restarting

**Built-in passive checks:**

| ID | Check | Severity |
|----|-------|----------|
| REDFISH-P01 | Redfish over unencrypted HTTP | High |
| REDFISH-P02 | Session token in response body | Low |
| REDFISH-P03 | Cleartext credentials (HTTP POST) | Critical |
| REDFISH-P04 | Missing security headers | Medium |
| REDFISH-P05 | Sensitive fields in response (Password, Token, PrivateKey…) | High |
| REDFISH-P06 | X-Auth-Token in request headers (passive observation) | Info |
| REDFISH-P07 | Server banner disclosure | Info |
| REDFISH-P08 | Auth token in URL query string | High |
| REDFISH-P09 | BIOS attributes with sensitive data | High |
| REDFISH-P10 | Firmware HTTP upload URI exposed | Medium |
| REDFISH-P11 | BMC version in Server header | Info |

**Built-in active checks:**

| ID | Check | Severity |
|----|-------|----------|
| REDFISH-A01 | Unauthenticated access (strip token, replay) | High |
| REDFISH-A02 | Default credentials spray (vendor-specific) | Critical |
| REDFISH-A03 | Privilege escalation via PATCH account role | Critical |
| REDFISH-A04 | Unauthenticated session creation | Critical |

---

### Cred Spray Tab
- Spray all built-in default credentials (generic, Dell, HPE, OpenBMC, Supermicro, AMI) or custom lists
- Vendor filter, configurable delay (ms), stop button
- Live results table: username, password, vendor, HTTP status, token obtained
- Export results as CSV

---

### IDOR Tab
- **Account Enumeration** — walks `/AccountService/Accounts/1..N` testing both authenticated and unauthenticated access; shows Username, RoleId, Enabled, and whether each account is accessible without a token
- **Session Enumeration** — same for `/SessionService/Sessions/1..N`
- Click any row to see the raw response body
- Configurable ID range (from/to spinners)

---

### Batch Tab (Mini-Intruder)
- Paste a request template with a `§payload§` marker in the body
- Paste payloads one per line
- Fires each payload sequentially with configurable delay
- Results table: payload, HTTP status, response length, snippet
- Click any row to inspect the full response

---

### SSRF Tab
Two sub-panels:

#### EventService SSRF
- Auto-builds a Redfish subscription POST body pointing to a callback URL
- **Use Burp Collaborator** — one click generates a Collaborator payload URL and inserts it as the callback
- **Poll Collaborator** — fetches and displays all received interactions (type, client IP, data)
- Sends the subscription and shows the response

#### HTTP Method Tampering
- Enter any URL (or right-click from Explorer → Test All HTTP Methods to pre-fill)
- Check any combination of HEAD, OPTIONS, TRACE, DELETE, PUT, PATCH, GET
- Fires each method and flags responses that are **not** 405/501/404 as unexpected
- Click any result row to see the full response headers and body

---

### AI / MCP Tab
Three backend modes:

| Mode | Description |
|------|-------------|
| **Claude API (Direct)** | Anthropic hosted models (claude-opus-4-6, claude-sonnet-4-6, etc.) |
| **OpenAI-compatible API** | Ollama, Together AI, or any `/v1/chat/completions` server |
| **MCP Server (HTTP)** | Any MCP server over HTTP/JSON-RPC 2.0 |

Actions: Analyze URL, Analyze Explorer URLs, Analyze Current Findings, Generate Payload, CVE Lookup (Firmware), Import Findings to Scanner.

---

### Dashboard Tab
Live summary panel — click **Refresh Dashboard**:
- **Discovered Endpoints** — total count
- **High Risk / Medium Risk** — endpoint counts by risk level
- **Scanner Findings** — total finding count
- **Session Token** — active token (truncated), status colour
- **Token Entropy (bits)** — Shannon entropy rating with strength assessment
- **Accounts / Sessions Found** — from IDOR tab results
- **Session Token Analyser** — full text analysis: length, entropy, charset, strength rating, format hint (hex / JWT / opaque), JWT claim extraction
- **Endpoint Risk Breakdown** — full list of endpoints grouped by risk level

---

### Log Tab
Two sub-tabs:
- **Log** — text activity log with Clear button
- **Timeline** — structured table of every request: timestamp, method, URL, HTTP status, response size; exportable as CSV

---

## Installation

### Requirements
- Burp Suite Pro or Community Edition
- [Jython 2.7.x standalone JAR](https://www.jython.org/download)

### Steps

1. **Configure Jython in Burp Suite:**
   - Go to **Extender → Options → Python Environment**
   - Set the path to your `jython-standalone-2.7.x.jar`

2. **Load the extension:**
   - Go to **Extender → Extensions → Add**
   - Extension type: **Python**
   - Extension file: select `redfisher_burp.py`
   - Click **Next** — the "Redfisher" tab will appear

3. **Configure:**
   - Open **Redfisher → Config** tab
   - Enter BMC host, port, username, password
   - Click **Login**

4. **(Optional) Session handling for automatic token injection:**
   - **Project Options → Sessions → Session Handling Rules → Add**
   - Action: **Invoke a Burp extension** → `Redfisher: inject/refresh Redfish X-Auth-Token`

---

## Usage Workflows

### Testing an Action Endpoint
1. Spider the target in **Explorer**
2. Click an ActionInfo URL (e.g. `/redfish/v1/EventService/SubmitTestEventActionInfo`) — the Repeater body, method (`POST`), and URL auto-fill
3. Edit `"<required>"` fields → **Send**
4. Right-click body → **Send to Burp Repeater** for continued manual testing

### SSRF via EventService
1. Open **SSRF → EventService SSRF**
2. Click **Use Burp Collaborator** (or paste a callback URL manually)
3. Click **Send Subscription** — the BMC POSTs a subscription pointing to your listener
4. Click **Poll Collaborator** to see incoming HTTP interactions

### HTTP Method Tampering
1. In **Explorer**, right-click any URL → **Test All HTTP Methods**
2. Switch to **SSRF → HTTP Method Tampering** — URL is pre-filled
3. Click **Test Methods** — unexpected responses (non-405/501) are flagged

### IDOR / Account Enumeration
1. Open **IDOR** tab → **Fill from Config**
2. Select **Accounts** or **Sessions**, set ID range
3. Click **Run Enumeration** — authenticated vs unauthenticated responses shown side by side
4. Rows where **Accessible Unauth?** = `YES !` are the findings

### Batch Payload Testing
1. Open **Batch** tab, paste the target URL
2. Modify the `§payload§` template (default injects into `UserName`)
3. Paste your payloads list → **Run**

### Full Scan + HTML Report
1. **Explorer → Discover → Spider** to enumerate all endpoints
2. **Scanner → Passive** / **Active** under "Scan Explorer URLs"
3. Click **CVE Check (Firmware)** to cross-reference discovered versions
4. Click **Export HTML Report** → styled deliverable-ready report

---

## Project Structure

```
redfisher_burp.py          Main entry point loaded by Burp Suite
signatures.json            Scan signature definitions (editable)
bookmarks.json             Persisted Explorer bookmarks (auto-created)
lib/
  extender.py              BurpExtender — registers all components
  auth_handler.py          Main UI (Config, Repeater, Explorer, Log/Timeline)
  scanner.py               Passive/active check engine + IScannerCheck
  scanner_tab.py           Scanner UI (signatures, findings, HTML export, CVE check)
  ai_tab.py                AI/MCP analysis tab
  cred_spray_tab.py        Credential spray tab
  idor_tab.py              IDOR / account & session enumeration tab
  batch_tab.py             Batch payload sender (mini-Intruder)
  ssrf_tab.py              SSRF / EventService / Burp Collaborator / method tampering
  dashboard_tab.py         Risk dashboard + session token analyser
  cve_db.py                Offline BMC firmware CVE database
  editor.py                Redfish-aware message editor tab
  redfish_utils.py         Shared helpers (vendor detection, resource types, etc.)
```

---

## Adding Custom Signatures

Use **Scanner → Edit / Add Signature** or edit `signatures.json` directly:

```json
{
  "id": "CUSTOM-001",
  "name": "My custom check",
  "type": "passive",
  "severity": "Medium",
  "confidence": "Firm",
  "enabled": true,
  "check_type": "response_body_contains",
  "description": "Detects ...",
  "background": "Why this matters ...",
  "remediation": "How to fix ...",
  "config": { "match": "some string to find in the response body" }
}
```

**Supported `check_type` values:**

| Check type | Config keys | Description |
|------------|-------------|-------------|
| `http_protocol` | — | URL starts with `http://` |
| `response_body_contains` | `match` | Body contains substring |
| `body_regex` | `pattern` | Body matches regex |
| `sensitive_fields` | `fields` | JSON body has non-null sensitive fields |
| `missing_headers` | `headers` | Response missing required headers |
| `url_contains` | `match` | URL contains substring |
| `url_regex` | `pattern` | URL matches regex |
| `cleartext_credentials` | — | Password POSTed over HTTP |
| `response_header_contains` | `header`, `match` | Response header check |
| `token_in_url` | — | Auth token in URL query string |
| `bios_attributes_exposed` | — | Sensitive BIOS attributes returned |
| `firmware_push_uri` | — | `HttpPushUri` present in UpdateService |
| `server_banner` | `keywords` | BMC version in Server header |
| `unauthenticated_access` | — | Resource accessible without auth (active) |
| `default_credentials` | `credentials` | Credential pairs to try (active) |
| `privilege_escalation` | — | PATCH role to Administrator (active) |
| `unauth_post_session` | — | Session created without auth (active) |

---

## Disclaimer

This tool is intended for **authorised security testing** only. Use only against systems you own or have explicit written permission to test. Unauthorised use against BMC management interfaces is illegal and may cause hardware damage or outages.

---

## License

MIT
