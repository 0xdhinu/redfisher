# -*- coding: utf-8 -*-
"""
BatchTab — Mini Intruder / batch payload sender for Redfish.

Paste a request URL, pick a method, write a JSON body template with
a §payload§ marker, paste one payload per line, click Run.
Results appear in a live table: payload, status, response length, snippet.
"""

import json
import ssl
import urllib2

from java.lang import Thread, Runnable
from javax.swing import (
    JPanel, JLabel, JTextField, JButton, JComboBox,
    JTextArea, JScrollPane, JTable, JSplitPane,
    BorderFactory, SwingUtilities, JProgressBar,
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, Color, Font

_MONO   = Font('Monospaced', Font.PLAIN, 12)
_ORANGE = Color(230, 100, 0)
_GREEN  = Color(50,  150, 50)
_RED    = Color(200, 50,  50)
_GRAY   = Color(100, 100, 100)

_COLS = ['#', 'Payload', 'Status', 'Length', 'Snippet']
_MARKER = u'\u00a7payload\u00a7'   # §payload§


def _style(btn):
    btn.setBackground(_ORANGE)
    btn.setForeground(Color.WHITE)
    btn.setOpaque(True)
    btn.setBorderPainted(False)
    return btn


class _BatchModel(DefaultTableModel):
    def __init__(self):
        DefaultTableModel.__init__(self, _COLS, 0)

    def isCellEditable(self, r, c):
        return False


class BatchTab(object):

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
        row1.add(JLabel('URL:'))
        self._fld_url = JTextField(44)
        row1.add(self._fld_url)
        self._cmb_method = JComboBox(['POST', 'PATCH', 'GET', 'PUT', 'DELETE'])
        row1.add(self._cmb_method)
        row1.add(JLabel('Delay (ms):'))
        self._fld_delay = JTextField('200', 5)
        row1.add(self._fld_delay)
        toolbar.add(row1)

        row2 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        self._btn_run  = _style(JButton('Run'))
        self._btn_stop = _style(JButton('Stop'))
        self._btn_stop.setEnabled(False)
        self._btn_run.addActionListener(lambda e: self._on_run())
        self._btn_stop.addActionListener(lambda e: self._on_stop())
        row2.add(self._btn_run)
        row2.add(self._btn_stop)
        self._progress = JProgressBar()
        self._progress.setStringPainted(True)
        row2.add(self._progress)
        self._lbl_status = JLabel('Idle')
        self._lbl_status.setForeground(_GRAY)
        row2.add(self._lbl_status)
        toolbar.add(row2)

        panel.add(toolbar, BorderLayout.NORTH)

        # ── editor area (body template + payloads) ────────────────────
        self._txt_body = JTextArea(8, 0)
        self._txt_body.setFont(_MONO)
        self._txt_body.setText(
            '{\n'
            '  "UserName": ' + _MARKER + '\n'
            '}'
        )
        body_scroll = JScrollPane(self._txt_body)
        body_scroll.setBorder(BorderFactory.createTitledBorder(
            u'Request body template  (use \u00a7payload\u00a7 as the injection marker)'
        ))

        self._txt_payloads = JTextArea(8, 0)
        self._txt_payloads.setFont(_MONO)
        self._txt_payloads.setText('admin\nroot\nsysadmin\nguest\nAdministrator')
        payload_scroll = JScrollPane(self._txt_payloads)
        payload_scroll.setBorder(BorderFactory.createTitledBorder('Payloads (one per line)'))

        editor_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, body_scroll, payload_scroll)
        editor_split.setResizeWeight(0.6)

        # ── results table ─────────────────────────────────────────────
        self._model = _BatchModel()
        self._table = JTable(self._model)
        self._table.setFont(_MONO)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        for i, w in enumerate([40, 160, 60, 70, 400]):
            self._table.getColumnModel().getColumn(i).setPreferredWidth(w)

        self._txt_resp = JTextArea()
        self._txt_resp.setFont(_MONO)
        self._txt_resp.setEditable(False)
        self._txt_resp.setLineWrap(True)
        self._raw_bodies = {}

        def _on_sel(e):
            if e.getValueIsAdjusting():
                return
            r = self._table.getSelectedRow()
            if r >= 0:
                self._txt_resp.setText(self._raw_bodies.get(r, ''))
                self._txt_resp.setCaretPosition(0)
        self._table.getSelectionModel().addListSelectionListener(_on_sel)

        result_split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                                  JScrollPane(self._table),
                                  JScrollPane(self._txt_resp))
        result_split.setResizeWeight(0.6)
        result_split.setBorder(BorderFactory.createTitledBorder('Results'))

        btn_clear = _style(JButton('Clear Results'))
        btn_clear.addActionListener(lambda e: self._clear())
        btn_row = JPanel(FlowLayout(FlowLayout.RIGHT))
        btn_row.add(btn_clear)

        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, editor_split, result_split)
        main_split.setResizeWeight(0.3)

        center = JPanel(BorderLayout())
        center.add(main_split, BorderLayout.CENTER)
        center.add(btn_row,    BorderLayout.SOUTH)
        panel.add(center, BorderLayout.CENTER)
        return panel

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _clear(self):
        self._model.setRowCount(0)
        self._raw_bodies.clear()
        self._txt_resp.setText('')
        self._progress.setValue(0)

    def _on_stop(self):
        self._stop[0] = True

    def _on_run(self):
        url     = self._fld_url.getText().strip()
        method  = str(self._cmb_method.getSelectedItem())
        tmpl    = self._txt_body.getText()
        lines   = [l for l in self._txt_payloads.getText().splitlines() if l.strip()]
        token   = self._auth._token
        verify  = self._auth._verify_tls
        try:
            delay = int(self._fld_delay.getText().strip())
        except ValueError:
            delay = 200

        if not url:
            self._set_status('Enter a URL.', False)
            return
        if not lines:
            self._set_status('Enter at least one payload.', False)
            return

        self._stop[0] = False
        self._clear()
        self._progress.setMaximum(max(len(lines), 1))
        self._btn_run.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._set_status('Running...', None)

        stop_flag = self._stop
        add_row   = self._add_row

        def work():
            for idx, payload in enumerate(lines):
                if stop_flag[0]:
                    break
                body = tmpl.replace(_MARKER, payload)
                result = _do_request(url, method, body, token, verify)
                add_row(idx + 1, payload, result)
                def upd(n=idx+1):
                    self._progress.setValue(n)
                SwingUtilities.invokeLater(upd)
                if delay > 0:
                    Thread.sleep(delay)

            stopped = stop_flag[0]
            def finish():
                self._btn_run.setEnabled(True)
                self._btn_stop.setEnabled(False)
                self._set_status('Stopped.' if stopped else 'Done.', not stopped)
            SwingUtilities.invokeLater(finish)

        class _W(Runnable):
            def run(self_w): work()
        Thread(_W()).start()

    def _add_row(self, num, payload, result):
        status  = result['status']
        body    = result.get('body', '')
        snippet = (body[:80].replace('\n', ' ') + '...') if len(body) > 80 else body.replace('\n', ' ')
        row     = [str(num), payload, str(status) if status else 'ERR', str(len(body)), snippet]

        def update(r=row, b=body):
            idx = self._model.getRowCount()
            self._model.addRow(r)
            self._raw_bodies[idx] = b
        SwingUtilities.invokeLater(update)

    def _set_status(self, msg, ok):
        color = _GREEN if ok is True else (_RED if ok is False else _GRAY)
        def upd():
            self._lbl_status.setText(msg)
            self._lbl_status.setForeground(color)
        SwingUtilities.invokeLater(upd)


# ------------------------------------------------------------------
# HTTP helper
# ------------------------------------------------------------------

def _do_request(url, method, body, token, verify_tls):
    try:
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

        data = body.encode('utf-8') if body and method in ('POST', 'PATCH', 'PUT') else None
        req  = urllib2.Request(url, data=data)
        req.get_method = lambda m=method: m
        req.add_header('Accept', 'application/json')
        req.add_header('Content-Type', 'application/json')
        if token:
            req.add_header('X-Auth-Token', token)

        resp   = urllib2.urlopen(req, context=ctx, timeout=15)
        status = resp.getcode()
        raw    = resp.read()
        try:
            raw = json.dumps(json.loads(raw), indent=2)
        except Exception:
            pass
        return {'status': status, 'body': raw}

    except urllib2.HTTPError as e:
        try:
            raw = e.read()
        except Exception:
            raw = ''
        return {'status': e.code, 'body': raw}
    except Exception as ex:
        return {'status': None, 'body': str(ex)}
