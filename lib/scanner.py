# -*- coding: utf-8 -*-
"""
RedfishScannerCheck — signature-driven passive and active scan checks.

Signatures are loaded from signatures.json at the project root.
Each signature defines a check_type that maps to an executor function.

Supported check_types:
  Passive:
    http_protocol          — URL starts with http://
    response_body_contains — response body contains config.match (str)
    sensitive_fields       — JSON response has non-null sensitive fields
    missing_headers        — response missing headers in config.headers list
    url_contains           — URL contains any string in config.match (list or str)
    cleartext_credentials  — Password POSTed over http:// to a session endpoint
    response_header_contains — a specific response header contains/exists

  Active:
    unauthenticated_access — strip auth headers and retry; flag if not 401/403/404
    default_credentials    — POST credential pairs from config.credentials to session endpoint
"""

import json
import os
import re
import ssl
import urllib2

from burp import IScannerCheck, IScanIssue
from java.net import URL

from redfish_utils import (
    is_redfish_request, get_resource_type,
    parse_json_body, find_sensitive_in_body,
    get_header_value, bytes_to_str,
)

# ---------------------------------------------------------------------------
# Signature store — module-level, shared with scanner_tab.py
# ---------------------------------------------------------------------------

_signatures = []
_sigs_path  = None


def load_signatures(path):
    """Load signatures from the JSON file. Updates module-level _signatures."""
    global _signatures, _sigs_path
    _sigs_path = path
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        _signatures = data.get('signatures', [])
        return True, 'Loaded {0} signatures.'.format(len(_signatures))
    except Exception as e:
        _signatures = []
        return False, 'Failed to load signatures: ' + str(e)


def save_signatures(path=None):
    """Write current signatures back to the JSON file."""
    target = path or _sigs_path
    if not target:
        return False, 'No signatures path set.'
    try:
        data = {'version': '1.0', 'signatures': _signatures}
        with open(target, 'w') as f:
            json.dump(data, f, indent=2)
        return True, 'Saved {0} signatures.'.format(len(_signatures))
    except Exception as e:
        return False, 'Failed to save: ' + str(e)


def get_signatures():
    return list(_signatures)


def upsert_signature(sig):
    """Add or replace a signature by id."""
    for i, s in enumerate(_signatures):
        if s.get('id') == sig.get('id'):
            _signatures[i] = sig
            return
    _signatures.append(sig)


def delete_signature(sig_id):
    global _signatures
    _signatures = [s for s in _signatures if s.get('id') != sig_id]


# ---------------------------------------------------------------------------
# IScanIssue implementation
# ---------------------------------------------------------------------------

class RedfishScanIssue(IScanIssue):

    def __init__(self, http_service, url, http_messages, sig, detail):
        self._service  = http_service
        self._url      = url
        self._messages = http_messages
        self._sig      = sig
        self._detail   = detail

    def getUrl(self):            return self._url
    def getIssueName(self):      return self._sig.get('name', 'Redfisher issue')
    def getIssueType(self):      return 0x08000000
    def getSeverity(self):       return self._sig.get('severity', 'Medium')
    def getConfidence(self):     return self._sig.get('confidence', 'Certain')
    def getIssueBackground(self):    return self._sig.get('background', '')
    def getRemediationBackground(self): return self._sig.get('remediation', '')
    def getIssueDetail(self):    return self._detail
    def getRemediationDetail(self):  return None
    def getHttpMessages(self):   return self._messages
    def getHttpService(self):    return self._service


# ---------------------------------------------------------------------------
# Passive check executors
# ---------------------------------------------------------------------------

def _check_http_protocol(sig, url, req_headers, req_body, resp_headers, resp_body):
    if url.startswith('http://'):
        return sig.get('description', '')
    return None


def _check_response_body_contains(sig, url, req_headers, req_body, resp_headers, resp_body):
    match = sig.get('config', {}).get('match', '')
    if resp_body and match and match in resp_body:
        return 'Match found: <code>{0}</code>'.format(match)
    return None


def _check_sensitive_fields(sig, url, req_headers, req_body, resp_headers, resp_body):
    fields = sig.get('config', {}).get('fields', [])
    if not resp_body or not fields:
        return None
    data, _ = parse_json_body(resp_body)
    if not data:
        return None
    hits = [p for p, f in find_sensitive_in_body(data) if f in fields]
    if hits:
        return 'Sensitive fields with non-null values: {0}'.format(
            ', '.join('<code>{0}</code>'.format(h) for h in hits)
        )
    return None


def _check_missing_headers(sig, url, req_headers, req_body, resp_headers, resp_body):
    required = sig.get('config', {}).get('headers', [])
    missing  = [h for h in required if get_header_value(resp_headers, h) is None]
    if missing:
        return 'Missing headers: {0}'.format(
            ', '.join('<code>{0}</code>'.format(h) for h in missing)
        )
    return None


def _check_url_contains(sig, url, req_headers, req_body, resp_headers, resp_body):
    matches = sig.get('config', {}).get('match', [])
    if isinstance(matches, basestring):  # noqa: F821
        matches = [matches]
    url_lower = url.lower()
    for m in matches:
        if m.lower() in url_lower:
            return 'URL contains: <code>{0}</code>'.format(m)
    return None


def _check_cleartext_credentials(sig, url, req_headers, req_body, resp_headers, resp_body):
    if url.startswith('http://') and ('SessionService/Sessions' in url or 'login' in url.lower()):
        data, _ = parse_json_body(req_body)
        if data and 'Password' in data:
            return sig.get('description', '')
    return None


def _check_response_header_contains(sig, url, req_headers, req_body, resp_headers, resp_body):
    cfg     = sig.get('config', {})
    header  = cfg.get('header', '')
    match   = cfg.get('match', '')
    value   = get_header_value(resp_headers, header)
    if value is not None:
        if not match or match in value:
            return 'Header <code>{0}</code>: {1}'.format(header, value)
    return None


def _check_url_regex(sig, url, req_headers, req_body, resp_headers, resp_body):
    pattern = sig.get('config', {}).get('pattern', '')
    if pattern and re.search(pattern, url):
        return 'URL matched pattern: <code>{0}</code>'.format(pattern)
    return None


def _check_body_regex(sig, url, req_headers, req_body, resp_headers, resp_body):
    pattern = sig.get('config', {}).get('pattern', '')
    body    = resp_body or ''
    if pattern and re.search(pattern, body):
        return 'Body matched pattern: <code>{0}</code>'.format(pattern)
    return None


def _check_token_in_url(sig, url, req_headers, req_body, resp_headers, resp_body):
    lower = url.lower()
    for param in ('token=', 'x-auth-token=', 'authtoken=', 'sessiontoken='):
        if param in lower:
            return 'Auth token found in URL query string: <code>{0}</code>'.format(param)
    return None


def _check_bios_attributes_exposed(sig, url, req_headers, req_body, resp_headers, resp_body):
    if '/bios' not in url.lower():
        return None
    data, _ = parse_json_body(resp_body)
    if not data:
        return None
    attrs = data.get('Attributes', {})
    if not isinstance(attrs, dict):
        return None
    sensitive_keywords = ('password', 'passwd', 'key', 'secret', 'credential', 'token')
    hits = [k for k in attrs if any(kw in k.lower() for kw in sensitive_keywords)
            if attrs[k] not in (None, '', 0, False)]
    if hits:
        return 'BIOS attributes may contain sensitive values: {0}'.format(
            ', '.join('<code>{0}</code>'.format(h) for h in hits[:5])
        )
    return None


def _check_firmware_push_uri(sig, url, req_headers, req_body, resp_headers, resp_body):
    if '/updateservice' not in url.lower():
        return None
    data, _ = parse_json_body(resp_body)
    if not data:
        return None
    uri = data.get('HttpPushUri') or data.get('MultipartHttpPushUri')
    if uri:
        return 'Firmware upload URI exposed: <code>{0}</code>. Verify upload requires auth and signature validation.'.format(uri)
    return None


def _check_server_banner(sig, url, req_headers, req_body, resp_headers, resp_body):
    server = get_header_value(resp_headers, 'Server') or get_header_value(resp_headers, 'X-Powered-By')
    if server:
        keywords = sig.get('config', {}).get('keywords', ['iDRAC', 'iLO', 'OpenBMC', 'MegaRAC', 'Redfish'])
        for kw in keywords:
            if kw.lower() in server.lower():
                return 'BMC version disclosed in Server header: <code>{0}</code>'.format(server)
    return None


def _check_unauth_create_session(sig, url, req_headers, req_body, resp_headers, resp_body):
    """Flag if a Session was successfully created without authentication headers."""
    if 'sessions' not in url.lower():
        return None
    auth_present = any(
        h.lower().startswith('x-auth-token') or h.lower().startswith('authorization')
        for h in req_headers
    )
    if not auth_present and resp_body:
        data, _ = parse_json_body(resp_body)
        if data and data.get('@odata.type', '').lower().endswith('session.session'):
            return 'Session created without authentication — unauthenticated session creation allowed.'
    return None


_PASSIVE_EXECUTORS = {
    'http_protocol':           _check_http_protocol,
    'response_body_contains':  _check_response_body_contains,
    'sensitive_fields':        _check_sensitive_fields,
    'missing_headers':         _check_missing_headers,
    'url_contains':            _check_url_contains,
    'cleartext_credentials':   _check_cleartext_credentials,
    'response_header_contains':_check_response_header_contains,
    'url_regex':               _check_url_regex,
    'body_regex':              _check_body_regex,
    'token_in_url':              _check_token_in_url,
    'bios_attributes_exposed':   _check_bios_attributes_exposed,
    'firmware_push_uri':         _check_firmware_push_uri,
    'server_banner':             _check_server_banner,
    'unauth_create_session':     _check_unauth_create_session,
}


# ---------------------------------------------------------------------------
# Manual scan helpers (used by scanner_tab.py, no Burp API dependency)
# ---------------------------------------------------------------------------

def _make_ssl_ctx(verify_tls):
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    return ctx


def _fetch(url, token=None, verify_tls=False, timeout=15):
    """GET a URL and return (status, resp_headers_list, body_str) or raise."""
    ctx = _make_ssl_ctx(verify_tls)
    req = urllib2.Request(url)
    if token:
        req.add_header('X-Auth-Token', token)
    req.add_header('Accept', 'application/json')
    try:
        resp        = urllib2.urlopen(req, context=ctx, timeout=timeout)
        status      = resp.getcode()
        hdrs        = ['{0}: {1}'.format(k, v) for k, v in resp.info().items()]
        body        = resp.read()
    except urllib2.HTTPError as e:
        status = e.code
        hdrs   = ['{0}: {1}'.format(k, v) for k, v in (e.info().items() if e.info() else [])]
        try:
            body = e.read()
        except Exception:
            body = ''
    return status, hdrs, bytes_to_str(body) if body else ''


def run_passive_scan_manual(url, token=None, verify_tls=False, timeout=15):
    """
    Fetch url and run all enabled passive signatures against it.
    Returns a list of finding dicts.
    """
    findings = []
    try:
        status, resp_headers, resp_body = _fetch(url, token, verify_tls, timeout)
    except Exception as ex:
        return [{'sig_id': 'ERROR', 'name': 'Fetch failed', 'url': url,
                 'severity': 'Info', 'detail': str(ex)}]

    req_headers = ['X-Auth-Token: ' + token] if token else []
    req_body    = ''

    for sig in _signatures:
        if not sig.get('enabled', True) or sig.get('type') != 'passive':
            continue
        executor = _PASSIVE_EXECUTORS.get(sig.get('check_type'))
        if not executor:
            continue
        try:
            detail = executor(sig, url, req_headers, req_body, resp_headers, resp_body)
            if detail:
                findings.append({
                    'sig_id':     sig['id'],
                    'name':       sig['name'],
                    'url':        url,
                    'severity':   sig.get('severity', 'Info'),
                    'confidence': sig.get('confidence', 'Certain'),
                    'detail':     detail,
                })
        except Exception:
            pass

    return findings


def run_active_scan_manual(url, token=None, verify_tls=False, timeout=15):
    """
    Run all enabled active signatures against url.
    Returns a list of finding dicts.
    """
    findings = []

    for sig in _signatures:
        if not sig.get('enabled', True) or sig.get('type') != 'active':
            continue
        check_type = sig.get('check_type')

        try:
            if check_type == 'unauthenticated_access':
                status, _, _ = _fetch(url, token=None, verify_tls=verify_tls, timeout=timeout)
                if status not in (401, 403, 404):
                    findings.append({
                        'sig_id':     sig['id'],
                        'name':       sig['name'],
                        'url':        url,
                        'severity':   sig.get('severity', 'High'),
                        'confidence': sig.get('confidence', 'Certain'),
                        'detail':     'Returned HTTP {0} without auth headers.'.format(status),
                    })

            elif check_type == 'default_credentials':
                # Only run against the sessions endpoint
                if 'SessionService/Sessions' not in url:
                    continue
                ctx     = _make_ssl_ctx(verify_tls)
                creds   = sig.get('config', {}).get('credentials', [])
                for cred in creds:
                    payload = json.dumps({
                        'UserName': cred.get('username', ''),
                        'Password': cred.get('password', ''),
                    })
                    try:
                        req = urllib2.Request(url, data=payload.encode('utf-8'))
                        req.add_header('Content-Type', 'application/json')
                        req.add_header('Accept', 'application/json')
                        resp = urllib2.urlopen(req, context=ctx, timeout=timeout)
                        if resp.getcode() in (200, 201):
                            findings.append({
                                'sig_id':     sig['id'],
                                'name':       sig['name'],
                                'url':        url,
                                'severity':   sig.get('severity', 'High'),
                                'confidence': sig.get('confidence', 'Certain'),
                                'detail':     'Accepted: {0} / {1} ({2})'.format(
                                    cred['username'], cred['password'],
                                    cred.get('vendor', '?')
                                ),
                            })
                            break  # stop after first working credential
                    except urllib2.HTTPError:
                        continue
                    except Exception:
                        break

            elif check_type == 'privilege_escalation':
                # Try PATCH to set RoleId=Administrator without admin rights
                # Only attempt against account URLs
                if '/accounts/' not in url.lower():
                    continue
                ctx     = _make_ssl_ctx(verify_tls)
                payload = json.dumps({'RoleId': 'Administrator'})
                try:
                    req = urllib2.Request(url, data=payload.encode('utf-8'))
                    req.get_method = lambda: 'PATCH'
                    req.add_header('Content-Type', 'application/json')
                    req.add_header('Accept',       'application/json')
                    if token:
                        req.add_header('X-Auth-Token', token)
                    resp = urllib2.urlopen(req, context=ctx, timeout=timeout)
                    if resp.getcode() in (200, 204):
                        findings.append({
                            'sig_id':     sig['id'],
                            'name':       sig['name'],
                            'url':        url,
                            'severity':   sig.get('severity', 'Critical'),
                            'confidence': sig.get('confidence', 'Firm'),
                            'detail':     'PATCH RoleId=Administrator succeeded (HTTP {0}).'.format(resp.getcode()),
                        })
                except urllib2.HTTPError:
                    pass
                except Exception:
                    pass

            elif check_type == 'unauth_post_session':
                # POST to Sessions without auth; flag if 201
                if 'sessions' not in url.lower():
                    continue
                ctx     = _make_ssl_ctx(verify_tls)
                creds   = sig.get('config', {}).get('credentials', [{'username': 'test', 'password': 'test'}])
                for cred in creds[:1]:  # just one probe
                    payload = json.dumps({'UserName': cred.get('username','test'), 'Password': cred.get('password','test')})
                    try:
                        req = urllib2.Request(url, data=payload.encode('utf-8'))
                        req.add_header('Content-Type', 'application/json')
                        req.add_header('Accept',       'application/json')
                        # no auth header — intentional
                        resp2 = urllib2.urlopen(req, context=ctx, timeout=timeout)
                        if resp2.getcode() in (200, 201) and resp2.info().get('X-Auth-Token'):
                            findings.append({
                                'sig_id':     sig['id'],
                                'name':       sig['name'],
                                'url':        url,
                                'severity':   sig.get('severity', 'Critical'),
                                'confidence': sig.get('confidence', 'Certain'),
                                'detail':     'Session created without authentication (HTTP {0}).'.format(resp2.getcode()),
                            })
                    except urllib2.HTTPError:
                        pass
                    except Exception:
                        break
        except Exception:
            pass

    return findings


# ---------------------------------------------------------------------------
# Burp IScannerCheck integration
# ---------------------------------------------------------------------------

class RedfishScannerCheck(IScannerCheck):

    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()

    def doPassiveScan(self, base_request_response):
        request_info = self._helpers.analyzeRequest(base_request_response)
        url          = str(request_info.getUrl())
        if not is_redfish_request(url):
            return None

        service  = base_request_response.getHttpService()
        request  = base_request_response.getRequest()
        response = base_request_response.getResponse()

        req_headers  = [str(h) for h in request_info.getHeaders()]
        req_body     = bytes_to_str(request[request_info.getBodyOffset():]) if request else ''
        resp_info    = self._helpers.analyzeResponse(response) if response else None
        resp_headers = [str(h) for h in resp_info.getHeaders()] if resp_info else []
        resp_body    = bytes_to_str(response[resp_info.getBodyOffset():]) if (response and resp_info) else ''

        issues = []
        for sig in _signatures:
            if not sig.get('enabled', True) or sig.get('type') != 'passive':
                continue
            executor = _PASSIVE_EXECUTORS.get(sig.get('check_type'))
            if not executor:
                continue
            try:
                detail = executor(sig, url, req_headers, req_body, resp_headers, resp_body)
                if detail:
                    issues.append(RedfishScanIssue(
                        service, request_info.getUrl(),
                        [base_request_response], sig,
                        '{0}: {1}'.format(url, detail),
                    ))
            except Exception:
                pass

        return issues or None

    def doActiveScan(self, base_request_response, insertion_point):
        request_info = self._helpers.analyzeRequest(base_request_response)
        url          = str(request_info.getUrl())
        if not is_redfish_request(url):
            return None

        service          = base_request_response.getHttpService()
        original_request = base_request_response.getRequest()
        req_headers      = list(request_info.getHeaders())
        issues           = []

        for sig in _signatures:
            if not sig.get('enabled', True) or sig.get('type') != 'active':
                continue
            check_type = sig.get('check_type')

            try:
                if check_type == 'unauthenticated_access':
                    stripped = [
                        h for h in req_headers
                        if not str(h).lower().startswith('x-auth-token')
                        and not str(h).lower().startswith('authorization')
                    ]
                    unauth_req  = self._helpers.buildHttpMessage(
                        stripped, original_request[request_info.getBodyOffset():]
                    )
                    unauth_resp = self._callbacks.makeHttpRequest(service, unauth_req)
                    if unauth_resp:
                        ri = self._helpers.analyzeResponse(unauth_resp.getResponse())
                        status = ri.getStatusCode() if ri else 0
                        if status not in (401, 403, 404):
                            issues.append(RedfishScanIssue(
                                service, request_info.getUrl(),
                                [base_request_response, unauth_resp], sig,
                                'HTTP {0} returned without auth at {1}.'.format(status, url),
                            ))

                elif check_type == 'default_credentials' and 'SessionService/Sessions' in url:
                    creds = sig.get('config', {}).get('credentials', [])
                    for cred in creds:
                        payload = json.dumps({
                            'UserName': cred.get('username', ''),
                            'Password': cred.get('password', ''),
                        })
                        cred_req = self._helpers.buildHttpMessage(
                            req_headers,
                            self._helpers.stringToBytes(payload),
                        )
                        cred_resp = self._callbacks.makeHttpRequest(service, cred_req)
                        if cred_resp:
                            ri = self._helpers.analyzeResponse(cred_resp.getResponse())
                            if ri and ri.getStatusCode() in (200, 201):
                                issues.append(RedfishScanIssue(
                                    service, request_info.getUrl(),
                                    [base_request_response, cred_resp], sig,
                                    'Default credentials accepted: {0} / {1} ({2})'.format(
                                        cred['username'], cred['password'],
                                        cred.get('vendor', '?')
                                    ),
                                ))
                                break
            except Exception:
                pass

        return issues or None

    def consolidateDuplicateIssues(self, existing, new_issue):
        if (existing.getIssueName() == new_issue.getIssueName()
                and str(existing.getUrl()) == str(new_issue.getUrl())):
            return -1
        return 0
