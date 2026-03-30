# Redfisher — Redfish API Security Testing Extension for Burp Suite

A Burp Suite extension (Jython 2.7) for penetration testing and security assessment of **Redfish API** endpoints on BMC (Baseboard Management Controller) hardware — including Dell iDRAC, HPE iLO, OpenBMC, Supermicro, AMI MegaRAC, Lenovo XCC, and others.

---

## Features

### Session Management
- Automatic `X-Auth-Token` injection via Burp session handling rules
- Login / logout with session lifecycle management
- Auto-refresh on 401 responses
- BMC vendor fingerprinting (Dell, HPE, OpenBMC, Supermicro, AMI, Lenovo, Fujitsu, Cisco)

### Explorer Tab
- One-click discovery of all `/redfish/v1/` endpoints via `@odata.id` traversal
- **Auto-Walk / Spider** — BFS traversal up to 3 levels deep, discovers up to 200 unique paths automatically
- Inline response viewer — click any link to see the response without leaving the tab
- Action link extraction — automatically detects `@Redfish.ActionInfo` and `target` links from responses and attaches them as child entries
- OEM endpoint extraction — parses `Oem.<vendor>.Children` arrays and arbitrary JSON for hidden paths
- Right-click context menu: **Send to Repeater tab**, **Send to Scanner**

### Repeater Tab
- Mini-Repeater with GET / POST / PATCH / DELETE / PUT / HEAD support
- Quick path dropdown for common Redfish endpoints
- **Request history** navigation (Back / Forward) — last 30 requests stored in session
- Resource type and risk level display per URL
- **Right-click context menu on request body/headers** → **Send to Burp Repeater** — sends the current request (with active session token) directly to Burp Suite's native Repeater tab
- **ActionInfo auto-fill** — when a GET response is a Redfish `ActionInfo` schema, the request body is automatically populated with a ready-to-submit JSON template, the method is switched to `POST`, and the URL is updated to the corresponding action endpoint:
  - Required fields are marked as `"<required>"`
  - Optional fields use type-appropriate defaults (`""`, `[]`, `0`, `false`, `{}`)
  - Action URL inferred from `@odata.id` (e.g. `.../SubmitTestEventActionInfo` → `.../Actions/EventService.SubmitTestEvent`)

### Scanner Tab
- Signature-driven passive and active scanning (integrates with Burp's scanner engine)
- Scan individual URLs or all Explorer endpoints in one click
- Live findings table with severity colouring
- **Export findings** as CSV, JSON, or Markdown report
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

### Cred Spray Tab
- Spray all built-in default credentials (generic, Dell, HPE, OpenBMC, Supermicro, AMI) or custom lists
- Vendor filter — test only relevant credential pairs
- Configurable delay (ms) between attempts to avoid lockouts
- Live results table: username, password, vendor, HTTP status, token obtained
- Stop button for immediate abort
- Export results as CSV

### AI / MCP Tab
Three backend modes for AI-assisted analysis:

| Mode | Description |
|------|-------------|
| **Claude API (Direct)** | Anthropic hosted models (claude-opus-4-6, claude-sonnet-4-6, etc.) |
| **OpenAI-compatible API** | Ollama, Together AI, or any `/v1/chat/completions` server |
| **MCP Server (HTTP)** | Any MCP server over HTTP/JSON-RPC 2.0 |

**Analyze actions:**
- **Analyze URL** — fetch a Redfish endpoint and send response to AI for security review
- **Analyze Explorer URLs** — send full discovered endpoint list for AI assessment
- **Analyze Current Findings** — send active scanner signatures for AI review
- **Generate Payload** — ask AI to produce a JSON test payload + method for a specific endpoint
- **CVE Lookup (Firmware)** — collect firmware version strings from Explorer/Scanner, query AI for known CVEs

**MCP Tools tab** — browse tools exposed by a connected MCP server, view schemas, call tools with custom JSON arguments.

**Import Findings to Scanner** — parse AI response text and import detected severity findings directly into the Scanner findings table.

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

3. **Configure the extension:**
   - Open the **Redfisher → Config** tab
   - Enter your BMC host, port, username, and password
   - Click **Login** to create a session

4. **(Optional) Set up session handling for automatic token injection:**
   - Go to **Project Options → Sessions → Session Handling Rules → Add**
   - Add a rule action: **Run a post-request macro**
   - Or use **Invoke a Burp extension** → select `Redfisher: inject/refresh Redfish X-Auth-Token`
   - Set the scope to Redfish endpoints

---

## Usage Workflow

### Testing an Action Endpoint
1. Browse to an action's `ActionInfo` URL in the **Explorer** tab (e.g. `/redfish/v1/EventService/SubmitTestEventActionInfo`)
2. Right-click → **Send to Repeater tab**
3. In the **Repeater** tab, click **Send** (GET)
4. The response body is detected as ActionInfo — the request body, method (`POST`), and URL are **auto-filled** ready to submit
5. Edit any `"<required>"` fields, then click **Send** to execute the action
6. Right-click the request body → **Send to Burp Repeater** to continue testing in Burp's native Repeater

### Credential Spraying
1. Open the **Cred Spray** tab
2. Click **Fill from Config** to auto-populate the sessions URL from your configured host
3. Select a vendor filter or leave as `all`
4. Set a safe delay (≥ 500 ms recommended) to avoid account lockouts
5. Click **Start Spray** — results appear live in the table
6. Export findings as CSV for reporting

### Running a Full Scan
1. In the **Explorer** tab, click **Discover** then **Spider** to enumerate all endpoints
2. Switch to the **Scanner** tab
3. Click **Passive** or **Active** under **Scan Explorer URLs** to scan everything discovered
4. Review findings in the **Findings** table and export as CSV / JSON / Markdown

---

## Project Structure

```
redfisher_burp.py          Main entry point loaded by Burp Suite
signatures.json            Scan signature definitions (editable)
lib/
  extender.py              BurpExtender — registers all components
  auth_handler.py          Main UI tab (Config, Repeater, Explorer, Log)
  scanner.py               Passive/active check engine + IScannerCheck
  scanner_tab.py           Scanner UI (signatures table, findings, export)
  ai_tab.py                AI/MCP analysis tab
  cred_spray_tab.py        Credential spray tab
  editor.py                Redfish-aware message editor tab
  redfish_utils.py         Shared helpers (vendor detection, resource types, etc.)
```

---

## Adding Custom Signatures

Use the **Scanner → Edit / Add Signature** form, or edit `signatures.json` directly:

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
  "config": {
    "match": "some string to find in the response body"
  }
}
```

**Supported `check_type` values:**

| Check type | Config keys | Description |
|------------|-------------|-------------|
| `http_protocol` | — | URL starts with `http://` |
| `response_body_contains` | `match` (string) | Body contains a substring |
| `body_regex` | `pattern` (regex) | Body matches a regex |
| `sensitive_fields` | `fields` (list) | JSON body has non-null sensitive fields |
| `missing_headers` | `headers` (list) | Response missing required headers |
| `url_contains` | `match` (string or list) | URL contains a substring |
| `url_regex` | `pattern` (regex) | URL matches a regex |
| `cleartext_credentials` | — | Password POSTed over HTTP |
| `response_header_contains` | `header`, `match` | Response header value check |
| `token_in_url` | — | Auth token in URL query string |
| `bios_attributes_exposed` | — | Sensitive BIOS attributes returned |
| `firmware_push_uri` | — | `HttpPushUri` present in UpdateService |
| `server_banner` | `keywords` (list) | BMC version in Server header |
| `unauthenticated_access` | — | Resource accessible without auth (active) |
| `default_credentials` | `credentials` (list) | Credential pairs to try (active) |
| `privilege_escalation` | — | PATCH role to Administrator (active) |
| `unauth_post_session` | — | Session created without auth (active) |

---

## Disclaimer

This tool is intended for **authorised security testing** only. Use only against systems you own or have explicit written permission to test. Unauthorised use against BMC management interfaces is illegal and can cause hardware damage or outages.

---

## License

MIT
