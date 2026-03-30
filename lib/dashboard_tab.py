# -*- coding: utf-8 -*-
"""
DashboardTab — Risk summary dashboard for Redfisher.

Shows at a glance:
  - Discovered endpoint count by risk level
  - Active session token status + analyser (entropy, length, expiry probe)
  - Account and session enumeration counts
  - Scan findings breakdown by severity
  - Refresh button
"""

import math
import string
import json

from javax.swing import (
    JPanel, JLabel, JButton, JTextArea, JScrollPane,
    BorderFactory, SwingUtilities,
)
from java.awt import BorderLayout, FlowLayout, GridLayout, Color, Font

_MONO   = Font('Monospaced', Font.PLAIN, 12)
_BOLD   = Font('SansSerif',  Font.BOLD,  13)
_ORANGE = Color(230, 100, 0)
_GREEN  = Color(50,  150, 50)
_RED    = Color(200, 50,  50)
_GRAY   = Color(100, 100, 100)
_YELLOW = Color(200, 160, 0)

_RISK_COLORS = {
    'High':     Color(220, 50,  50),
    'Critical': Color(180, 0,   0),
    'Medium':   Color(220, 130, 30),
    'Low':      Color(50,  130, 220),
    'Info':     Color(100, 100, 100),
}


def _style(btn):
    btn.setBackground(_ORANGE)
    btn.setForeground(Color.WHITE)
    btn.setOpaque(True)
    btn.setBorderPainted(False)
    return btn


def _card(title, value_label, color=None):
    """Build a titled bordered panel showing a single metric."""
    p = JPanel(BorderLayout(4, 4))
    p.setBorder(BorderFactory.createTitledBorder(title))
    lbl = JLabel(value_label, JLabel.CENTER)
    lbl.setFont(Font('SansSerif', Font.BOLD, 22))
    if color:
        lbl.setForeground(color)
    p.add(lbl, BorderLayout.CENTER)
    return p, lbl


class DashboardTab(object):

    def __init__(self, auth_handler):
        self._auth  = auth_handler
        self._panel = self._build_ui()

    def get_panel(self):
        return self._panel

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self):
        panel = JPanel(BorderLayout(6, 6))
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        # ── top: metric cards ─────────────────────────────────────────
        cards = JPanel(GridLayout(2, 4, 8, 8))

        (p, self._lbl_endpoints),  = [_card('Discovered Endpoints', '0')]
        (p2, self._lbl_high),      = [_card('High Risk Endpoints',  '0', _RED)]
        (p3, self._lbl_medium),    = [_card('Medium Risk',          '0', _YELLOW)]
        (p4, self._lbl_findings),  = [_card('Scanner Findings',     '0', _RED)]
        (p5, self._lbl_token),     = [_card('Session Token',        'None', _GRAY)]
        (p6, self._lbl_entropy),   = [_card('Token Entropy (bits)', '—', _GRAY)]
        (p7, self._lbl_accounts),  = [_card('Accounts Found',       '0')]
        (p8, self._lbl_sessions),  = [_card('Sessions Found',       '0')]

        for card in (p, p2, p3, p4, p5, p6, p7, p8):
            cards.add(card)

        # ── middle: token analyser output ─────────────────────────────
        self._txt_analysis = JTextArea(10, 0)
        self._txt_analysis.setFont(_MONO)
        self._txt_analysis.setEditable(False)
        self._txt_analysis.setLineWrap(True)
        self._txt_analysis.setWrapStyleWord(True)
        analysis_scroll = JScrollPane(self._txt_analysis)
        analysis_scroll.setBorder(BorderFactory.createTitledBorder('Session Token Analyser'))

        # ── bottom: risk breakdown text ────────────────────────────────
        self._txt_breakdown = JTextArea(6, 0)
        self._txt_breakdown.setFont(_MONO)
        self._txt_breakdown.setEditable(False)
        breakdown_scroll = JScrollPane(self._txt_breakdown)
        breakdown_scroll.setBorder(BorderFactory.createTitledBorder('Endpoint Risk Breakdown'))

        from javax.swing import JSplitPane
        center_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, analysis_scroll, breakdown_scroll)
        center_split.setResizeWeight(0.55)

        # ── action bar ────────────────────────────────────────────────
        btn_refresh = _style(JButton('Refresh Dashboard'))
        btn_refresh.addActionListener(lambda e: self.refresh())
        btn_row = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_row.add(btn_refresh)

        panel.add(cards,        BorderLayout.NORTH)
        panel.add(center_split, BorderLayout.CENTER)
        panel.add(btn_row,      BorderLayout.SOUTH)
        return panel

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------

    def refresh(self):
        """Pull live data from the auth_handler state and update all widgets."""
        self._refresh_endpoints()
        self._refresh_token()
        self._refresh_findings()

    def _refresh_endpoints(self):
        from redfish_utils import get_resource_risk, explorer_actual_path, EXPLORER_CHILD_PREFIX
        model = self._auth._explorer_model
        total = 0
        risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Critical': 0}
        breakdown   = {}

        for i in range(model.size()):
            entry = str(model.get(i))
            if entry.startswith(EXPLORER_CHILD_PREFIX):
                continue
            total += 1
            risk = get_resource_risk(entry)
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
            breakdown[risk]   = breakdown.get(risk, [])
            breakdown[risk].append(entry)

        lines = []
        for risk in ('Critical', 'High', 'Medium', 'Low', 'Info'):
            paths = breakdown.get(risk, [])
            if paths:
                lines.append('── {0} ({1}) ──'.format(risk, len(paths)))
                for p in paths:
                    lines.append('  ' + p)

        def upd():
            self._lbl_endpoints.setText(str(total))
            self._lbl_high.setText(str(risk_counts.get('High', 0) + risk_counts.get('Critical', 0)))
            self._lbl_medium.setText(str(risk_counts.get('Medium', 0)))
            self._txt_breakdown.setText('\n'.join(lines))
            self._txt_breakdown.setCaretPosition(0)
        SwingUtilities.invokeLater(upd)

    def _refresh_token(self):
        token = self._auth._token
        lines = []
        if not token:
            def upd():
                self._lbl_token.setText('None')
                self._lbl_token.setForeground(_RED)
                self._lbl_entropy.setText('—')
                self._txt_analysis.setText('No active session token.')
            SwingUtilities.invokeLater(upd)
            return

        length  = len(token)
        entropy = _shannon_entropy(token)

        lines.append('Token length : {0} characters'.format(length))
        lines.append('Shannon entropy : {:.2f} bits'.format(entropy))
        lines.append('')

        # character set analysis
        has_upper  = any(c in string.uppercase for c in token)
        has_lower  = any(c in string.lowercase for c in token)
        has_digit  = any(c in string.digits    for c in token)
        has_punct  = any(c in string.punctuation for c in token)
        charset    = []
        if has_upper:  charset.append('uppercase')
        if has_lower:  charset.append('lowercase')
        if has_digit:  charset.append('digits')
        if has_punct:  charset.append('punctuation')
        lines.append('Character set : ' + (', '.join(charset) if charset else 'unknown'))

        # guessability rating
        if entropy < 40:
            rating = 'LOW  — token may be predictable or short'
            r_color = _RED
        elif entropy < 80:
            rating = 'MEDIUM — acceptable but not ideal'
            r_color = _YELLOW
        else:
            rating = 'HIGH — token appears sufficiently random'
            r_color = _GREEN
        lines.append('Strength rating : ' + rating)
        lines.append('')

        # format hints
        if all(c in string.hexdigits for c in token):
            lines.append('Format hint : looks like a hex-encoded token')
        elif token.count('.') == 2:
            lines.append('Format hint : looks like a JWT (three dot-separated segments)')
            try:
                import base64
                parts   = token.split('.')
                padding = 4 - len(parts[1]) % 4
                decoded = base64.b64decode(parts[1] + '=' * padding)
                payload = json.loads(decoded)
                if 'exp' in payload:
                    lines.append('JWT exp claim : {0}'.format(payload['exp']))
                if 'iat' in payload:
                    lines.append('JWT iat claim : {0}'.format(payload['iat']))
            except Exception:
                pass
        else:
            lines.append('Format hint : opaque token (non-hex, non-JWT)')

        text = '\n'.join(lines)
        token_short = token[:12] + '...' if length > 12 else token

        def upd():
            self._lbl_token.setText(token_short)
            self._lbl_token.setForeground(_GREEN)
            self._lbl_entropy.setText('{:.1f}'.format(entropy))
            self._lbl_entropy.setForeground(_GREEN if entropy >= 80 else (_YELLOW if entropy >= 40 else _RED))
            self._txt_analysis.setText(text)
            self._txt_analysis.setCaretPosition(0)
        SwingUtilities.invokeLater(upd)

    def _refresh_findings(self):
        try:
            scanner_tab = self._auth._scanner_tab
            model       = scanner_tab._find_model
            total       = model.getRowCount()
            # column 3 is Severity
            sev_counts  = {}
            for r in range(total):
                sev = str(model.getValueAt(r, 3) or '')
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            def upd():
                self._lbl_findings.setText(str(total))
            SwingUtilities.invokeLater(upd)
        except Exception:
            pass


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _shannon_entropy(s):
    """Shannon entropy in bits for a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = float(len(s))
    return -sum((v / n) * math.log(v / n, 2) for v in freq.values())
