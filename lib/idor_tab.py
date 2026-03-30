# -*- coding: utf-8 -*-
"""
IDORTab — IDOR / Account Enumeration tester for Redfish.

Tests:
  - Sequential account ID enumeration  (/AccountService/Accounts/1..N)
  - Authenticated vs unauthenticated access comparison per account
  - Role disclosure (reads Role field from each account response)
  - Session enumeration (/SessionService/Sessions/1..N)
"""

import json
import ssl
import urllib2

from java.lang import Thread, Runnable
from javax.swing import (
    JPanel, JLabel, JTextField, JButton, JComboBox,
    JScrollPane, JTable, JSplitPane, JTabbedPane,
    BorderFactory, SwingUtilities, JSpinner, SpinnerNumberModel,
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, Color, Font


_MONO = Font('Monospaced', Font.PLAIN, 12)
_GREEN  = Color(50,  150, 50)
_RED    = Color(200, 50,  50)
_ORANGE = Color(230, 100, 0)
_GRAY   = Color(100, 100, 100)

_ACCOUNT_COLS = ['ID', 'Username', 'Role', 'Enabled', 'Auth Status', 'Unauth Status', 'Accessible Unauth?']
_SESSION_COLS = ['ID', 'UserName', 'ClientOriginIPAddress', 'Auth Status', 'Unauth Status', 'Accessible Unauth?']


def _style(btn):
    btn.setBackground(_ORANGE)
    btn.setForeground(Color.WHITE)
    btn.setOpaque(True)
    btn.setBorderPainted(False)
    return btn


class _ResultModel(DefaultTableModel):
    def __init__(self, columns):
        DefaultTableModel.__init__(self, columns, 0)

    def isCellEditable(self, row, col):
        return False


class IDORTab(object):

    def __init__(self, auth_handler):
        self._auth  = auth_handler
        self._stop  = [False]
        self._panel = self._build_ui()

    def get_panel(self):
        return self._panel

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _build_ui(self):
        from javax.swing import BoxLayout
        panel = JPanel(BorderLayout())

        # ── toolbar ───────────────────────────────────────────────────
        toolbar = JPanel()
        toolbar.setLayout(BoxLayout(toolbar, BoxLayout.Y_AXIS))
        toolbar.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6))

        row1 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        row1.add(JLabel('Base URL:'))
        self._fld_base = JTextField(40)
        row1.add(self._fld_base)
        btn_fill = _style(JButton('Fill from Config'))
        btn_fill.addActionListener(lambda e: self._fill_base())
        row1.add(btn_fill)
        toolbar.add(row1)

        row2 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        row2.add(JLabel('Enumerate:'))
        self._cmb_target = JComboBox(['Accounts', 'Sessions'])
        row2.add(self._cmb_target)
        row2.add(JLabel('ID range:'))
        self._spn_from = JSpinner(SpinnerNumberModel(1, 1, 9999, 1))
        self._spn_to   = JSpinner(SpinnerNumberModel(20, 1, 9999, 1))
        row2.add(JLabel('from'))
        row2.add(self._spn_from)
        row2.add(JLabel('to'))
        row2.add(self._spn_to)

        self._btn_run  = _style(JButton('Run Enumeration'))
        self._btn_stop = _style(JButton('Stop'))
        self._btn_stop.setEnabled(False)
        self._btn_run.addActionListener(lambda e: self._on_run())
        self._btn_stop.addActionListener(lambda e: self._on_stop())
        row2.add(self._btn_run)
        row2.add(self._btn_stop)

        self._lbl_status = JLabel('Idle')
        self._lbl_status.setForeground(_GRAY)
        row2.add(self._lbl_status)
        toolbar.add(row2)

        panel.add(toolbar, BorderLayout.NORTH)

        # ── results split ─────────────────────────────────────────────
        tabs = JTabbedPane()

        self._acct_model = _ResultModel(_ACCOUNT_COLS)
        self._acct_table = JTable(self._acct_model)
        self._acct_table.setFont(_MONO)
        self._acct_table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        for i, w in enumerate([40, 120, 120, 60, 90, 90, 120]):
            self._acct_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        tabs.addTab('Accounts', JScrollPane(self._acct_table))

        self._sess_model = _ResultModel(_SESSION_COLS)
        self._sess_table = JTable(self._sess_model)
        self._sess_table.setFont(_MONO)
        self._sess_table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        for i, w in enumerate([40, 120, 150, 90, 90, 120]):
            self._sess_table.getColumnModel().getColumn(i).setPreferredWidth(w)
        tabs.addTab('Sessions', JScrollPane(self._sess_table))

        self._txt_detail = JPanel(BorderLayout())
        self._txt_raw    = _mk_textarea()
        self._txt_detail.setBorder(BorderFactory.createTitledBorder('Raw Response'))
        self._txt_detail.add(JScrollPane(self._txt_raw), BorderLayout.CENTER)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, tabs, self._txt_detail)
        split.setResizeWeight(0.65)

        # select row → show raw response
        for tbl, attr in [(self._acct_table, '_acct_raw'), (self._sess_table, '_sess_raw')]:
            setattr(self, attr, {})
            _tbl = tbl
            _attr = attr
            def _sel(e, t=_tbl, a=_attr):
                if e.getValueIsAdjusting():
                    return
                r = t.getSelectedRow()
                if r >= 0:
                    raw = getattr(self, a).get(r, '')
                    self._txt_raw.setText(raw)
                    self._txt_raw.setCaretPosition(0)
            tbl.getSelectionModel().addListSelectionListener(_sel)

        btn_clear = _style(JButton('Clear Results'))
        btn_clear.addActionListener(lambda e: self._clear())
        btn_row = JPanel(FlowLayout(FlowLayout.RIGHT))
        btn_row.add(btn_clear)

        center = JPanel(BorderLayout())
        center.add(split,   BorderLayout.CENTER)
        center.add(btn_row, BorderLayout.SOUTH)
        panel.add(center, BorderLayout.CENTER)
        return panel

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _fill_base(self):
        h = self._auth._host
        p = self._auth._port
        s = 'https' if self._auth._use_https else 'http'
        self._fld_base.setText('{0}://{1}:{2}/redfish/v1'.format(s, h, p))

    def _clear(self):
        self._acct_model.setRowCount(0)
        self._sess_model.setRowCount(0)
        self._acct_raw.clear()
        self._sess_raw.clear()
        self._txt_raw.setText('')

    def _on_stop(self):
        self._stop[0] = True

    def _on_run(self):
        base  = self._fld_base.getText().strip().rstrip('/')
        if not base:
            self._fill_base()
            base = self._fld_base.getText().strip().rstrip('/')
        target  = str(self._cmb_target.getSelectedItem())
        id_from = int(str(self._spn_from.getValue()))
        id_to   = int(str(self._spn_to.getValue()))
        token   = self._auth._token
        verify  = self._auth._verify_tls

        self._stop[0] = False
        self._clear()
        self._btn_run.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._set_status('Running...', None)

        stop_flag = self._stop
        add_row   = self._add_result_row

        def work():
            collection = 'AccountService/Accounts' if target == 'Accounts' else 'SessionService/Sessions'
            for id_val in range(id_from, id_to + 1):
                if stop_flag[0]:
                    break
                url = '{0}/{1}/{2}'.format(base, collection, id_val)
                auth_result   = _fetch(url, token, verify)
                unauth_result = _fetch(url, None,  verify)
                accessible_unauth = (
                    unauth_result['status'] is not None and
                    200 <= unauth_result['status'] < 300
                )
                if auth_result['status'] is None and unauth_result['status'] is None:
                    continue  # connection error — skip silently
                add_row(target, id_val, auth_result, unauth_result, accessible_unauth)

            def finish():
                self._btn_run.setEnabled(True)
                self._btn_stop.setEnabled(False)
                if stop_flag[0]:
                    self._set_status('Stopped.', None)
                else:
                    self._set_status('Done.', True)
            SwingUtilities.invokeLater(finish)

        class _W(Runnable):
            def run(self_w): work()
        Thread(_W()).start()

    def _add_result_row(self, target, id_val, auth_res, unauth_res, accessible_unauth):
        auth_status   = str(auth_res['status'])   if auth_res['status']   else 'N/A'
        unauth_status = str(unauth_res['status']) if unauth_res['status'] else 'N/A'
        unauth_flag   = 'YES !' if accessible_unauth else 'no'
        raw_body      = auth_res.get('body', '') or unauth_res.get('body', '')

        if target == 'Accounts':
            try:
                data     = json.loads(raw_body)
                username = data.get('UserName', '')
                role     = data.get('RoleId',   data.get('Role', {}).get('@odata.id', ''))
                enabled  = str(data.get('Enabled', ''))
            except Exception:
                username = role = enabled = ''
            row      = [str(id_val), username, role, enabled, auth_status, unauth_status, unauth_flag]
            raw_dict = self._acct_raw
            model    = self._acct_model
        else:
            try:
                data    = json.loads(raw_body)
                uname   = data.get('UserName', '')
                origin  = data.get('ClientOriginIPAddress', '')
            except Exception:
                uname  = origin = ''
            row      = [str(id_val), uname, origin, auth_status, unauth_status, unauth_flag]
            raw_dict = self._sess_raw
            model    = self._sess_model

        def update(r=row, rb=raw_body, rd=raw_dict, m=model):
            idx = m.getRowCount()
            m.addRow(r)
            rd[idx] = rb
        SwingUtilities.invokeLater(update)

    def _set_status(self, msg, ok):
        color = _GREEN if ok is True else (_RED if ok is False else _GRAY)
        def upd():
            self._lbl_status.setText(msg)
            self._lbl_status.setForeground(color)
        SwingUtilities.invokeLater(upd)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _mk_textarea():
    from javax.swing import JTextArea
    t = JTextArea()
    t.setFont(_MONO)
    t.setEditable(False)
    t.setLineWrap(True)
    return t


def _fetch(url, token, verify_tls):
    try:
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        req = urllib2.Request(url)
        req.add_header('Accept', 'application/json')
        if token:
            req.add_header('X-Auth-Token', token)
        resp   = urllib2.urlopen(req, context=ctx, timeout=10)
        status = resp.getcode()
        body   = resp.read()
        try:
            body = json.dumps(json.loads(body), indent=2)
        except Exception:
            pass
        return {'status': status, 'body': body}
    except urllib2.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = ''
        return {'status': e.code, 'body': body}
    except Exception:
        return {'status': None, 'body': ''}
