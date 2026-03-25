# -*- coding: utf-8 -*-
"""
Redfish-specific helpers: endpoint detection, resource typing, credential lists.
Jython 2.7 compatible.
"""

import json
import re

# ---------------------------------------------------------------------------
# Explorer hierarchy helpers
# ---------------------------------------------------------------------------

EXPLORER_CHILD_PREFIX = u'  \u2514\u2500 '


def explorer_actual_path(entry):
    """
    Return the bare Redfish path, stripping the child-entry indent if present.
    Uses unicode() instead of str() so the non-ASCII └─ prefix is preserved
    on Jython 2.7 (str() would raise UnicodeEncodeError on non-ASCII chars).
    """
    try:
        s = unicode(entry)  # noqa: F821  unicode is a Jython 2.7 built-in
    except NameError:       # Python 3 fallback
        s = str(entry)
    return s[len(EXPLORER_CHILD_PREFIX):] if s.startswith(EXPLORER_CHILD_PREFIX) else s


# ---------------------------------------------------------------------------
# Resource type detection from URL path
# ---------------------------------------------------------------------------

_RESOURCE_PATTERNS = [
    (re.compile(r'/redfish/v\d+/?$', re.IGNORECASE), 'ServiceRoot'),
    (re.compile(r'/redfish/v\d+/Systems/[^/]+/Processors', re.IGNORECASE), 'ProcessorCollection'),
    (re.compile(r'/redfish/v\d+/Systems/[^/]+/Memory', re.IGNORECASE), 'MemoryCollection'),
    (re.compile(r'/redfish/v\d+/Systems/[^/]+/Storage', re.IGNORECASE), 'StorageCollection'),
    (re.compile(r'/redfish/v\d+/Systems/[^/]+/EthernetInterfaces', re.IGNORECASE), 'EthernetInterfaceCollection'),
    (re.compile(r'/redfish/v\d+/Systems/[^/]+/Bios', re.IGNORECASE), 'Bios'),
    (re.compile(r'/redfish/v\d+/Systems/[^/]+/Actions', re.IGNORECASE), 'ComputerSystemActions'),
    (re.compile(r'/redfish/v\d+/Systems/[^/]+', re.IGNORECASE), 'ComputerSystem'),
    (re.compile(r'/redfish/v\d+/Systems', re.IGNORECASE), 'ComputerSystemCollection'),
    (re.compile(r'/redfish/v\d+/Chassis/[^/]+/Power', re.IGNORECASE), 'Power'),
    (re.compile(r'/redfish/v\d+/Chassis/[^/]+/Thermal', re.IGNORECASE), 'Thermal'),
    (re.compile(r'/redfish/v\d+/Chassis/[^/]+', re.IGNORECASE), 'Chassis'),
    (re.compile(r'/redfish/v\d+/Chassis', re.IGNORECASE), 'ChassisCollection'),
    (re.compile(r'/redfish/v\d+/Managers/[^/]+/EthernetInterfaces', re.IGNORECASE), 'EthernetInterfaceCollection'),
    (re.compile(r'/redfish/v\d+/Managers/[^/]+/LogServices', re.IGNORECASE), 'LogServiceCollection'),
    (re.compile(r'/redfish/v\d+/Managers/[^/]+/NetworkProtocol', re.IGNORECASE), 'ManagerNetworkProtocol'),
    (re.compile(r'/redfish/v\d+/Managers/[^/]+', re.IGNORECASE), 'Manager'),
    (re.compile(r'/redfish/v\d+/Managers', re.IGNORECASE), 'ManagerCollection'),
    (re.compile(r'/redfish/v\d+/SessionService/Sessions/[^/]+', re.IGNORECASE), 'Session'),
    (re.compile(r'/redfish/v\d+/SessionService/Sessions', re.IGNORECASE), 'SessionCollection'),
    (re.compile(r'/redfish/v\d+/SessionService', re.IGNORECASE), 'SessionService'),
    (re.compile(r'/redfish/v\d+/AccountService/Accounts/[^/]+', re.IGNORECASE), 'ManagerAccount'),
    (re.compile(r'/redfish/v\d+/AccountService/Accounts', re.IGNORECASE), 'ManagerAccountCollection'),
    (re.compile(r'/redfish/v\d+/AccountService/Roles/[^/]+', re.IGNORECASE), 'Role'),
    (re.compile(r'/redfish/v\d+/AccountService/Roles', re.IGNORECASE), 'RoleCollection'),
    (re.compile(r'/redfish/v\d+/AccountService', re.IGNORECASE), 'AccountService'),
    (re.compile(r'/redfish/v\d+/EventService/Subscriptions', re.IGNORECASE), 'EventDestinationCollection'),
    (re.compile(r'/redfish/v\d+/EventService', re.IGNORECASE), 'EventService'),
    (re.compile(r'/redfish/v\d+/UpdateService/FirmwareInventory', re.IGNORECASE), 'SoftwareInventoryCollection'),
    (re.compile(r'/redfish/v\d+/UpdateService', re.IGNORECASE), 'UpdateService'),
    (re.compile(r'/redfish/v\d+/TaskService/Tasks/[^/]+', re.IGNORECASE), 'Task'),
    (re.compile(r'/redfish/v\d+/TaskService', re.IGNORECASE), 'TaskService'),
    (re.compile(r'/redfish/v\d+/CertificateService', re.IGNORECASE), 'CertificateService'),
    (re.compile(r'/redfish/v\d+/JsonSchemas', re.IGNORECASE), 'JsonSchemaFileCollection'),
    (re.compile(r'/redfish/v\d+/Registries', re.IGNORECASE), 'MessageRegistryFileCollection'),
]

# Risk level per resource type (for scan prioritisation)
RESOURCE_RISK = {
    'Bios': 'High',
    'ManagerAccount': 'High',
    'ManagerAccountCollection': 'High',
    'Role': 'High',
    'RoleCollection': 'High',
    'AccountService': 'High',
    'Session': 'High',
    'SessionCollection': 'High',
    'UpdateService': 'High',
    'ComputerSystem': 'Medium',
    'ComputerSystemActions': 'High',
    'Manager': 'Medium',
    'ManagerNetworkProtocol': 'High',
    'Power': 'Medium',
    'Thermal': 'Low',
    'EventService': 'Medium',
    'EventDestinationCollection': 'Medium',
}

# Fields whose values must never appear in responses
SENSITIVE_FIELDS = frozenset([
    'Password', 'OldPassword', 'NewPassword', 'Token',
    'PrivateKey', 'CertificateString', 'Passphrase',
    'SNMPv3AuthenticationKey', 'SNMPv3EncryptionKey',
])

# ---------------------------------------------------------------------------
# Default credentials to try in active scan
# ---------------------------------------------------------------------------

DEFAULT_CREDS = [
    # (username, password, vendor_hint)
    ('admin',         'admin',        'generic'),
    ('admin',         'password',     'generic'),
    ('root',          'root',         'generic'),
    ('Administrator', 'password',     'generic'),
    ('root',          'calvin',       'dell'),       # Dell iDRAC
    ('admin',         'calvin',       'dell'),
    ('Administrator', '',             'hpe'),        # HPE iLO (blank default)
    ('admin',         'admin',        'hpe'),
    ('root',          '0penBmc',      'openbmc'),    # OpenBMC
    ('root',          'OpenBmc',      'openbmc'),
    ('ADMIN',         'ADMIN',        'supermicro'),
    ('admin',         'ADMIN',        'supermicro'),
    ('admin',         '1234',         'generic'),
    ('admin',         'Admin1234!',   'generic'),
    ('sysadmin',      'superuser',    'ami'),        # AMI MegaRAC
    ('admin',         'admin123',     'generic'),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VENDOR_SIGNATURES = [
    # (vendor_name, [(header_name, substring), ...], [body_substrings, ...])
    ('Dell iDRAC',   [('Server', 'idrac'), ('X-IDRAC-SN', '')],       ['idrac', 'Dell Inc']),
    ('HPE iLO',      [('Server', 'iLO'), ('X-Auth-Token-Type', '')],   ['Hewlett Packard', 'iLO']),
    ('OpenBMC',      [('Server', 'OpenBMC')],                          ['openbmc', 'OpenBMC']),
    ('Supermicro',   [('Server', 'supermicro')],                       ['Supermicro']),
    ('AMI MegaRAC',  [('Server', 'AMI'), ('Server', 'megarac')],       ['MegaRAC', 'ami_yaft']),
    ('Lenovo XCC',   [('Server', 'XCC'), ('Server', 'Lenovo')],        ['Lenovo', 'XClarity']),
    ('Fujitsu iRMC', [('Server', 'iRMC')],                             ['Fujitsu', 'iRMC']),
    ('Cisco CIMC',   [('Server', 'CIMC'), ('Server', 'Cisco')],        ['Cisco', 'CIMC']),
]


def detect_vendor(resp_headers, body_str=''):
    """
    Fingerprint the BMC vendor from response headers and body text.
    resp_headers: list of 'Name: Value' strings (same format used throughout).
    Returns a vendor name string or 'Unknown'.
    """
    body_lower = (body_str or '').lower()
    for vendor, header_hints, body_hints in _VENDOR_SIGNATURES:
        for hdr_name, hdr_substr in header_hints:
            val = get_header_value(resp_headers, hdr_name) or ''
            if val and (not hdr_substr or hdr_substr.lower() in val.lower()):
                return vendor
        for hint in body_hints:
            if hint.lower() in body_lower:
                return vendor
    return 'Unknown'


def is_redfish_request(url):
    """Return True if the URL looks like a Redfish API endpoint."""
    return bool(re.search(r'/redfish/v\d+', url, re.IGNORECASE))


def get_resource_type(url):
    """Return a human-readable Redfish resource type from a URL."""
    for pattern, resource_type in _RESOURCE_PATTERNS:
        if pattern.search(url):
            return resource_type
    if re.search(r'/redfish/', url, re.IGNORECASE):
        return 'Redfish (unknown resource)'
    return None


def get_resource_risk(url):
    """Return risk level string for the resource at the given URL."""
    rtype = get_resource_type(url)
    return RESOURCE_RISK.get(rtype, 'Info')


def parse_json_body(body_bytes):
    """
    Parse bytes/string into a dict. Returns (dict, None) or (None, error_str).
    """
    if not body_bytes:
        return None, 'Empty body'
    try:
        if isinstance(body_bytes, (bytes, bytearray)):
            text = body_bytes.tostring() if hasattr(body_bytes, 'tostring') else bytes(body_bytes).decode('utf-8', errors='replace')
        else:
            text = str(body_bytes)
        data = json.loads(text)
        return data, None
    except Exception as e:
        return None, str(e)


def pretty_json(body_bytes):
    """Return a pretty-printed JSON string, or raw text on failure."""
    data, err = parse_json_body(body_bytes)
    if data is not None:
        return json.dumps(data, indent=2, sort_keys=True)
    if body_bytes:
        try:
            return body_bytes.tostring().decode('utf-8', errors='replace')
        except Exception:
            return str(body_bytes)
    return ''


def get_header_value(headers, name):
    """
    Case-insensitive header lookup from a list of IParameter or strings.
    Accepts a list of header strings in 'Name: Value' format.
    Returns the value string or None.
    """
    name_lower = name.lower()
    for h in headers:
        h_str = str(h)
        if ':' in h_str:
            k, _, v = h_str.partition(':')
            if k.strip().lower() == name_lower:
                return v.strip()
    return None


def headers_to_dict(headers):
    """Convert a list of 'Name: Value' header strings to a dict."""
    result = {}
    for h in headers:
        h_str = str(h)
        if ':' in h_str:
            k, _, v = h_str.partition(':')
            result[k.strip()] = v.strip()
    return result


def find_sensitive_in_body(data, path=''):
    """
    Recursively walk a parsed JSON dict and return a list of
    (json_path, field_name) tuples for any sensitive fields with non-null values.
    """
    findings = []
    if isinstance(data, dict):
        for k, v in data.items():
            current_path = '{0}.{1}'.format(path, k) if path else k
            if k in SENSITIVE_FIELDS and v not in (None, '', 'null'):
                findings.append((current_path, k))
            elif isinstance(v, (dict, list)):
                findings.extend(find_sensitive_in_body(v, current_path))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            findings.extend(find_sensitive_in_body(item, '{0}[{1}]'.format(path, i)))
    return findings


def bytes_to_str(b):
    """Convert Jython byte array or bytes to a Python string."""
    if b is None:
        return ''
    if hasattr(b, 'tostring'):
        return b.tostring().decode('utf-8', errors='replace')
    if isinstance(b, (bytes, bytearray)):
        return b.decode('utf-8', errors='replace')
    return str(b)


def str_to_bytes(s):
    """Convert a Python string to a Java byte array (for Burp APIs)."""
    if isinstance(s, unicode):  # noqa: F821  (Jython 2.7)
        return s.encode('utf-8')
    return s
