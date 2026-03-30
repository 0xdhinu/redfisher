# -*- coding: utf-8 -*-
"""
Offline BMC / Redfish firmware CVE database.

Keyed by (vendor_hint, version_substring) — both compared case-insensitively.
Each entry is a list of dicts: {cve, cvss, summary, affected, remediation}.

Extend this list as new advisories are published.
"""

_DB = [
    # ── Dell iDRAC ─────────────────────────────────────────────────────────────
    {
        'vendor':      'dell',
        'version':     '3.30',
        'cve':         'CVE-2021-21513',
        'cvss':        '9.8',
        'summary':     'iDRAC9 < 4.40.00.00: unauthenticated remote code execution via Redfish API',
        'affected':    'iDRAC9 firmware < 4.40.00.00',
        'remediation': 'Update to iDRAC9 firmware 4.40.00.00 or later',
    },
    {
        'vendor':      'dell',
        'version':     '4.10',
        'cve':         'CVE-2021-21514',
        'cvss':        '6.5',
        'summary':     'iDRAC9 < 4.40: reflected XSS in Redfish web interface',
        'affected':    'iDRAC9 firmware < 4.40.00.00',
        'remediation': 'Update to iDRAC9 firmware 4.40.00.00 or later',
    },
    {
        'vendor':      'dell',
        'version':     '2.',
        'cve':         'CVE-2018-1244',
        'cvss':        '8.8',
        'summary':     'iDRAC7/8: stack overflow via crafted Redfish login request',
        'affected':    'iDRAC7 < 2.60.60.60, iDRAC8 < 2.75.75.75',
        'remediation': 'Update iDRAC7/8 firmware',
    },
    {
        'vendor':      'dell',
        'version':     '5.',
        'cve':         'CVE-2022-34435',
        'cvss':        '7.2',
        'summary':     'iDRAC9 5.x: improper input validation allows remote code execution',
        'affected':    'iDRAC9 firmware 5.00.x - 5.10.x',
        'remediation': 'Update to iDRAC9 firmware 5.10.50.00 or later',
    },
    # ── HPE iLO ────────────────────────────────────────────────────────────────
    {
        'vendor':      'hpe',
        'version':     '1.',
        'cve':         'CVE-2018-7078',
        'cvss':        '7.2',
        'summary':     'iLO 4 < 2.53: remote code execution via crafted HTTPS request',
        'affected':    'HPE iLO 4 firmware < 2.53',
        'remediation': 'Update to iLO 4 firmware 2.53 or later',
    },
    {
        'vendor':      'hpe',
        'version':     '2.',
        'cve':         'CVE-2017-12542',
        'cvss':        '9.8',
        'summary':     'iLO 4 < 2.53: authentication bypass via crafted URL (trivially exploitable)',
        'affected':    'HPE iLO 4 firmware < 2.53',
        'remediation': 'Update to iLO 4 firmware 2.53 immediately — actively exploited in wild',
    },
    {
        'vendor':      'hpe',
        'version':     '5.',
        'cve':         'CVE-2021-29203',
        'cvss':        '7.8',
        'summary':     'iLO 5 < 2.44: local privilege escalation in Redfish service',
        'affected':    'HPE iLO 5 firmware < 2.44',
        'remediation': 'Update to iLO 5 firmware 2.44 or later',
    },
    {
        'vendor':      'hpe',
        'version':     '6.',
        'cve':         'CVE-2023-28082',
        'cvss':        '5.3',
        'summary':     'iLO 6 < 1.05: information disclosure via unauthenticated Redfish endpoint',
        'affected':    'HPE iLO 6 firmware < 1.05',
        'remediation': 'Update to iLO 6 firmware 1.05 or later',
    },
    # ── OpenBMC ────────────────────────────────────────────────────────────────
    {
        'vendor':      'openbmc',
        'version':     '2.9',
        'cve':         'CVE-2021-39297',
        'cvss':        '9.8',
        'summary':     'OpenBMC 2.9.x: unauthenticated IPMI command execution via Redfish bridge',
        'affected':    'OpenBMC < 2.10',
        'remediation': 'Update to OpenBMC 2.10 or later',
    },
    {
        'vendor':      'openbmc',
        'version':     '2.8',
        'cve':         'CVE-2020-14156',
        'cvss':        '6.5',
        'summary':     'OpenBMC: SessionService does not enforce session token expiry',
        'affected':    'OpenBMC < 2.9',
        'remediation': 'Update firmware and restrict BMC network access',
    },
    # ── Supermicro ─────────────────────────────────────────────────────────────
    {
        'vendor':      'supermicro',
        'version':     '3.',
        'cve':         'CVE-2021-42779',
        'cvss':        '9.8',
        'summary':     'Supermicro BMC < 3.12: hardcoded credentials in Redfish service',
        'affected':    'Supermicro BMC firmware < 3.12',
        'remediation': 'Update to BMC firmware 3.12 or later; change default credentials',
    },
    {
        'vendor':      'supermicro',
        'version':     '3.1',
        'cve':         'CVE-2022-26259',
        'cvss':        '8.8',
        'summary':     'Supermicro BMC: CSRF in Redfish web interface leads to account takeover',
        'affected':    'Supermicro BMC firmware < 3.17',
        'remediation': 'Update to BMC firmware 3.17 or later',
    },
    # ── AMI MegaRAC ────────────────────────────────────────────────────────────
    {
        'vendor':      'ami',
        'version':     '12.',
        'cve':         'CVE-2022-40259',
        'cvss':        '9.9',
        'summary':     'AMI MegaRAC: arbitrary code execution via Redfish API (BMC&C vulnerability)',
        'affected':    'AMI MegaRAC firmware (multiple versions)',
        'remediation': 'Apply AMI MegaRAC patches; isolate BMC from production network',
    },
    {
        'vendor':      'ami',
        'version':     '12.',
        'cve':         'CVE-2022-40242',
        'cvss':        '9.8',
        'summary':     'AMI MegaRAC: default credentials allow unauthenticated Redfish access',
        'affected':    'AMI MegaRAC firmware (multiple versions)',
        'remediation': 'Change default credentials; update firmware',
    },
    {
        'vendor':      'ami',
        'version':     '13.',
        'cve':         'CVE-2023-34329',
        'cvss':        '9.9',
        'summary':     'AMI MegaRAC 13.x: authentication bypass via HTTP header manipulation',
        'affected':    'AMI MegaRAC firmware < 13.08',
        'remediation': 'Update to MegaRAC firmware 13.08 or later immediately',
    },
]


def lookup(version_string, vendor_hint=''):
    """
    Match version_string + vendor_hint against the CVE database.

    Parameters
    ----------
    version_string : str   Firmware version string from the BMC response
    vendor_hint    : str   Vendor name from detect_vendor() or empty string

    Returns
    -------
    list of matching CVE dicts (may be empty)
    """
    results  = []
    v_lower  = (version_string or '').lower()
    vh_lower = (vendor_hint   or '').lower()

    for entry in _DB:
        # vendor match: substring check (e.g. 'dell' in 'dell idrac')
        if entry['vendor'] not in vh_lower and vh_lower not in entry['vendor']:
            continue
        # version match: the DB key is a prefix/substring of the real version
        if entry['version'].lower() in v_lower:
            results.append(entry)

    return results


def lookup_all(version_vendor_pairs):
    """
    Run lookup() over a list of (version_string, vendor_hint) tuples
    and return a deduplicated list of CVE dicts.
    """
    seen  = set()
    found = []
    for version, vendor in version_vendor_pairs:
        for entry in lookup(version, vendor):
            if entry['cve'] not in seen:
                seen.add(entry['cve'])
                found.append(entry)
    return found
