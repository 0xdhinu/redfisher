# -*- coding: utf-8 -*-
"""
ScannerTab — Signature management + manual scan UI for the Redfisher tab.

Provides:
  - Signatures table: view, enable/disable, add, edit, delete, save to file
  - Manual scan: run passive/active checks against a target URL
  - Findings table: live results with severity colouring
"""

import json

from java.lang import Boolean, String, Thread, Runnable
from javax.swing import (
    JPanel, JLabel, JTextField, JTextArea, JButton, JCheckBox,
    JScrollPane, JSplitPane, JTable, JTabbedPane, JComboBox,
    BorderFactory, SwingUtilities,
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, FlowLayout, Color, Font, Component

import scanner as _scanner  # module-level signature store
from redfish_utils import EXPLORER_CHILD_PREFIX, explorer_actual_path

_MONO = Font('Monospaced', Font.PLAIN, 12)

_SEV_COLORS = {
    'High':   Color(220, 50,  50),
    'Medium': Color(220, 130, 30),
    'Low':    Color(50,  130, 220),
    'Info':   Color(100, 100, 100),
}

_TYPES      = ['passive', 'active']
_SEVERITIES = ['High', 'Medium', 'Low', 'Info']
_CONFS      = ['Certain', 'Firm', 'Tentative']
_CHECK_TYPES = [
    'http_protocol', 'response_body_contains', 'sensitive_fields',
    'missing_headers', 'url_contains', 'cleartext_credentials',
    'response_header_contains', 'url_regex', 'body_regex',
    'unauthenticated_access', 'default_credentials',
    'token_in_url', 'bios_attributes_exposed', 'firmware_push_uri',
    'server_banner', 'unauth_create_session',
    'privilege_escalation', 'unauth_post_session',
]

# ---------------------------------------------------------------------------
# Severity cell renderer
# ---------------------------------------------------------------------------

class SeverityRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, selected, focused, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, selected, focused, row, col
        )
        color = _SEV_COLORS.get(str(value) if value else '', Color.BLACK)
        c.setForeground(color)
        return c


# ---------------------------------------------------------------------------
# Signature table model
# ---------------------------------------------------------------------------

_SIG_COLS  = ['', 'ID', 'Name', 'Type', 'Severity', 'Check Type']
_SIG_TYPES = [Boolean, String, String, String, String, String]


class SigTableModel(DefaultTableModel):

    def __init__(self):
        DefaultTableModel.__init__(self, _SIG_COLS, 0)

    def getColumnClass(self, col):
        return _SIG_TYPES[col]

    def isCellEditable(self, row, col):
        return col == 0  # only the Enabled checkbox column

    def setValueAt(self, value, row, col):
        DefaultTableModel.setValueAt(self, value, row, col)
        if col == 0:
            sig_id = str(self.getValueAt(row, 1))
            sigs   = _scanner.get_signatures()
            for sig in sigs:
                if sig.get('id') == sig_id:
                    sig['enabled'] = bool(value)
                    _scanner.upsert_signature(sig)
                    break

    def load_from_store(self):
        self.setRowCount(0)
        for sig in _scanner.get_signatures():
            self.addRow([
                Boolean(sig.get('enabled', True)),
                sig.get('id', ''),
                sig.get('name', ''),
                sig.get('type', ''),
                sig.get('severity', ''),
                sig.get('check_type', ''),
            ])


# ---------------------------------------------------------------------------
# Findings table model
# ---------------------------------------------------------------------------

_FIND_COLS = ['ID', 'Name', 'URL', 'Severity', 'Confidence', 'Detail']


class FindingsTableModel(DefaultTableModel):

    def __init__(self):
        DefaultTableModel.__init__(self, _FIND_COLS, 0)

    def isCellEditable(self, row, col):
        return False

    def add_finding(self, f):
        self.addRow([
            f.get('sig_id', ''),
            f.get('name', ''),
            f.get('url', ''),
            f.get('severity', ''),
            f.get('confidence', ''),
            f.get('detail', ''),
        ])


# ---------------------------------------------------------------------------
# Main ScannerTab class
# ---------------------------------------------------------------------------

class ScannerTab(object):

    def __init__(self, auth_handler):
        self._auth = auth_handler
        self._panel = self._build_ui()

    def get_panel(self):
        return self._panel

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        panel = JPanel(BorderLayout(4, 4))
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        panel.add(self._build_toolbar(), BorderLayout.NORTH)
        panel.add(self._build_main_split(), BorderLayout.CENTER)
        return panel

    def _build_toolbar(self):
        from javax.swing import BoxLayout, Box
        from java.awt import Dimension as _Dim

        wrapper = JPanel()
        wrapper.setLayout(BoxLayout(wrapper, BoxLayout.Y_AXIS))

        # ---- row 1: signature management + manual target ----
        row1 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))

        btn_reload = JButton('Reload Signatures')
        btn_save   = JButton('Save to File')
        btn_add    = JButton('Add New')
        btn_delete = JButton('Delete Selected')

        btn_reload.addActionListener(lambda e: self._reload())
        btn_save.addActionListener(  lambda e: self._save())
        btn_add.addActionListener(   lambda e: self._add_new())
        btn_delete.addActionListener(lambda e: self._delete_selected())

        row1.add(btn_reload)
        row1.add(btn_save)
        row1.add(btn_add)
        row1.add(btn_delete)

        row1.add(JLabel('   |   Target URL:'))
        self._fld_target = JTextField(30)
        row1.add(self._fld_target)

        btn_passive = JButton('Run Passive')
        btn_active  = JButton('Run Active')
        btn_passive.addActionListener(lambda e: self._run_scan('passive'))
        btn_active.addActionListener( lambda e: self._run_scan('active'))
        row1.add(btn_passive)
        row1.add(btn_active)

        # ---- row 2: scan all Explorer URLs ----
        row2 = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        row2.add(JLabel('Scan Explorer URLs:'))

        btn_exp_passive = JButton('Passive')
        btn_exp_active  = JButton('Active')
        btn_exp_passive.addActionListener(lambda e: self._run_scan_from_explorer('passive'))
        btn_exp_active.addActionListener( lambda e: self._run_scan_from_explorer('active'))
        row2.add(btn_exp_passive)
        row2.add(btn_exp_active)

        self._lbl_scan_status = JLabel('')
        row2.add(self._lbl_scan_status)

        wrapper.add(row1)
        wrapper.add(row2)
        return wrapper

    def _build_main_split(self):
        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           self._build_sigs_panel(),
                           self._build_bottom_tabs())
        split.setResizeWeight(0.45)
        return split

    def _build_sigs_panel(self):
        self._sig_model = SigTableModel()
        self._sig_model.load_from_store()

        self._sig_table = JTable(self._sig_model)
        self._sig_table.setFont(_MONO)
        self._sig_table.getColumnModel().getColumn(0).setMaxWidth(30)
        self._sig_table.getColumnModel().getColumn(1).setPreferredWidth(110)
        self._sig_table.getColumnModel().getColumn(2).setPreferredWidth(380)
        self._sig_table.getColumnModel().getColumn(3).setPreferredWidth(70)
        self._sig_table.getColumnModel().getColumn(4).setPreferredWidth(70)
        self._sig_table.getColumnModel().getColumn(5).setPreferredWidth(180)
        self._sig_table.getColumnModel().getColumn(4).setCellRenderer(SeverityRenderer())

        self._sig_table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_sig_select(e)
        )

        scroll = JScrollPane(self._sig_table)
        scroll.setBorder(BorderFactory.createTitledBorder('Signatures'))
        return scroll

    def _build_bottom_tabs(self):
        tabs = JTabbedPane()
        tabs.addTab('Edit / Add Signature', self._build_edit_panel())
        tabs.addTab('Findings',             self._build_findings_panel())
        self._bottom_tabs = tabs
        return tabs

    def _build_edit_panel(self):
        panel = JPanel(BorderLayout(6, 6))
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        # Left: basic fields
        form = JPanel()
        form.setLayout(None)  # absolute for compact layout

        def lbl(text, y):
            l = JLabel(text)
            l.setBounds(0, y, 120, 22)
            form.add(l)

        def field(w, x, y, width):
            w.setBounds(x, y, width, 22)
            form.add(w)
            return w

        y = 0
        lbl('ID:', y);               self._edit_id   = field(JTextField(), 125, y, 200); y += 28
        lbl('Name:', y);             self._edit_name = field(JTextField(), 125, y, 340); y += 28
        lbl('Type:', y);             self._edit_type = field(JComboBox(_TYPES), 125, y, 120); y += 28
        lbl('Severity:', y);         self._edit_sev  = field(JComboBox(_SEVERITIES), 125, y, 120); y += 28
        lbl('Confidence:', y);       self._edit_conf = field(JComboBox(_CONFS), 125, y, 120); y += 28
        lbl('Check Type:', y);       self._edit_ct   = field(JComboBox(_CHECK_TYPES), 125, y, 200); y += 28
        lbl('Enabled:', y);          self._edit_en   = field(JCheckBox('', True), 125, y, 80); y += 28

        form.setPreferredSize(form.getPreferredSize())

        form_scroll = JScrollPane(form)
        form_scroll.setBorder(BorderFactory.createTitledBorder('Properties'))
        form_scroll.setPreferredSize(None)

        # Right: text fields
        self._edit_desc   = JTextArea(4, 40); self._edit_desc.setLineWrap(True)
        self._edit_bg     = JTextArea(4, 40); self._edit_bg.setLineWrap(True)
        self._edit_remed  = JTextArea(4, 40); self._edit_remed.setLineWrap(True)
        self._edit_config = JTextArea();      self._edit_config.setFont(_MONO)

        text_tabs = JTabbedPane()
        text_tabs.addTab('Description',    JScrollPane(self._edit_desc))
        text_tabs.addTab('Background',     JScrollPane(self._edit_bg))
        text_tabs.addTab('Remediation',    JScrollPane(self._edit_remed))
        text_tabs.addTab('Config (JSON)',  JScrollPane(self._edit_config))

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, form_scroll, text_tabs)
        split.setDividerLocation(370)

        # Buttons
        btn_save   = JButton('Save Signature')
        btn_clear  = JButton('Clear Form')
        btn_save.addActionListener( lambda e: self._save_edit())
        btn_clear.addActionListener(lambda e: self._clear_edit())

        btns = JPanel(FlowLayout(FlowLayout.LEFT))
        btns.add(btn_save)
        btns.add(btn_clear)

        panel.add(split,  BorderLayout.CENTER)
        panel.add(btns,   BorderLayout.SOUTH)
        return panel

    def _build_findings_panel(self):
        self._find_model = FindingsTableModel()
        self._find_table = JTable(self._find_model)
        self._find_table.setFont(_MONO)
        self._find_table.getColumnModel().getColumn(0).setPreferredWidth(110)
        self._find_table.getColumnModel().getColumn(1).setPreferredWidth(320)
        self._find_table.getColumnModel().getColumn(2).setPreferredWidth(220)
        self._find_table.getColumnModel().getColumn(3).setPreferredWidth(70)
        self._find_table.getColumnModel().getColumn(3).setCellRenderer(SeverityRenderer())
        self._find_table.getColumnModel().getColumn(4).setPreferredWidth(80)
        self._find_table.getColumnModel().getColumn(5).setPreferredWidth(400)

        self._find_table.getSelectionModel().addListSelectionListener(
            lambda e: self._on_finding_select(e)
        )

        self._txt_find_detail = JTextArea(4, 0)
        self._txt_find_detail.setFont(_MONO)
        self._txt_find_detail.setEditable(False)
        self._txt_find_detail.setLineWrap(True)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                           JScrollPane(self._find_table),
                           JScrollPane(self._txt_find_detail))
        split.setResizeWeight(0.7)

        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder('Findings'))

        btn_clear      = JButton('Clear')
        btn_export_csv = JButton('Export CSV')
        btn_export_json = JButton('Export JSON')
        btn_export_md  = JButton('Export Markdown')
        btn_clear.addActionListener(       lambda e: self._find_model.setRowCount(0))
        btn_export_csv.addActionListener(  lambda e: self._export_findings('csv'))
        btn_export_json.addActionListener( lambda e: self._export_findings('json'))
        btn_export_md.addActionListener(   lambda e: self._export_findings('markdown'))
        top = JPanel(FlowLayout(FlowLayout.RIGHT))
        top.add(btn_export_md)
        top.add(btn_export_json)
        top.add(btn_export_csv)
        top.add(btn_clear)

        panel.add(top,   BorderLayout.NORTH)
        panel.add(split, BorderLayout.CENTER)
        return panel

    # ------------------------------------------------------------------
    # Signature table actions
    # ------------------------------------------------------------------

    def _reload(self):
        self._sig_model.load_from_store()
        self._set_scan_status('Reloaded {0} signatures.'.format(
            len(_scanner.get_signatures())
        ), Color(50, 150, 50))

    def _save(self):
        ok, msg = _scanner.save_signatures()
        self._set_scan_status(msg, Color(50, 150, 50) if ok else Color(200, 50, 50))

    def _add_new(self):
        self._clear_edit()
        self._edit_id.setText('CUSTOM-001')
        self._bottom_tabs.setSelectedIndex(0)

    def _delete_selected(self):
        row = self._sig_table.getSelectedRow()
        if row < 0:
            return
        sig_id = str(self._sig_model.getValueAt(row, 1))
        _scanner.delete_signature(sig_id)
        self._sig_model.removeRow(row)

    def _on_sig_select(self, event):
        if event.getValueIsAdjusting():
            return
        row = self._sig_table.getSelectedRow()
        if row < 0:
            return
        sig_id = str(self._sig_model.getValueAt(row, 1))
        sig    = next((s for s in _scanner.get_signatures() if s.get('id') == sig_id), None)
        if sig:
            self._populate_edit(sig)
            self._bottom_tabs.setSelectedIndex(0)

    # ------------------------------------------------------------------
    # Edit form actions
    # ------------------------------------------------------------------

    def _populate_edit(self, sig):
        self._edit_id.setText(sig.get('id', ''))
        self._edit_name.setText(sig.get('name', ''))
        self._edit_type.setSelectedItem(sig.get('type', 'passive'))
        self._edit_sev.setSelectedItem(sig.get('severity', 'Medium'))
        self._edit_conf.setSelectedItem(sig.get('confidence', 'Certain'))
        self._edit_ct.setSelectedItem(sig.get('check_type', ''))
        self._edit_en.setSelected(sig.get('enabled', True))
        self._edit_desc.setText(sig.get('description', ''))
        self._edit_bg.setText(sig.get('background', ''))
        self._edit_remed.setText(sig.get('remediation', ''))
        cfg = sig.get('config', {})
        self._edit_config.setText(
            json.dumps(cfg, indent=2) if cfg else '{}'
        )

    def _save_edit(self):
        sig_id = self._edit_id.getText().strip()
        if not sig_id:
            self._set_scan_status('ID is required.', Color(200, 50, 50))
            return
        try:
            cfg = json.loads(self._edit_config.getText() or '{}')
        except ValueError as e:
            self._set_scan_status('Config JSON invalid: ' + str(e), Color(200, 50, 50))
            return

        sig = {
            'id':          sig_id,
            'name':        self._edit_name.getText().strip(),
            'type':        str(self._edit_type.getSelectedItem()),
            'severity':    str(self._edit_sev.getSelectedItem()),
            'confidence':  str(self._edit_conf.getSelectedItem()),
            'check_type':  str(self._edit_ct.getSelectedItem()),
            'enabled':     self._edit_en.isSelected(),
            'description': self._edit_desc.getText(),
            'background':  self._edit_bg.getText(),
            'remediation': self._edit_remed.getText(),
            'config':      cfg,
        }
        _scanner.upsert_signature(sig)
        self._sig_model.load_from_store()
        self._set_scan_status('Signature {0} saved.'.format(sig_id), Color(50, 150, 50))

    def _clear_edit(self):
        for w in [self._edit_id, self._edit_name, self._edit_desc,
                  self._edit_bg, self._edit_remed]:
            w.setText('')
        self._edit_config.setText('{}')
        self._edit_en.setSelected(True)

    # ------------------------------------------------------------------
    # Manual scan
    # ------------------------------------------------------------------

    def _run_scan(self, scan_type):
        url = self._fld_target.getText().strip()
        if not url:
            self._set_scan_status('Enter a target URL.', Color(200, 50, 50))
            return

        token      = self._auth._token
        verify_tls = self._auth._verify_tls

        self._set_scan_status('Running {0} scan...'.format(scan_type), Color(100, 100, 100))

        def work():
            if scan_type == 'passive':
                return _scanner.run_passive_scan_manual(url, token, verify_tls)
            else:
                return _scanner.run_active_scan_manual(url, token, verify_tls)

        def done(findings):
            for f in findings:
                self._find_model.add_finding(f)
            self._bottom_tabs.setSelectedIndex(1)
            self._set_scan_status(
                '{0} scan complete — {1} finding(s).'.format(
                    scan_type.capitalize(), len(findings)
                ),
                Color(50, 150, 50) if findings else Color(100, 100, 100),
            )

        self._run_in_bg(work, done)

    def _on_finding_select(self, event):
        if event.getValueIsAdjusting():
            return
        row = self._find_table.getSelectedRow()
        if row < 0:
            return
        detail = str(self._find_model.getValueAt(row, 5) or '')
        self._txt_find_detail.setText(detail)
        self._txt_find_detail.setCaretPosition(0)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def add_scan_target(self, url):
        """Set the target URL field (called from Explorer right-click 'Send to Scanner')."""
        def update():
            self._fld_target.setText(url)
        SwingUtilities.invokeLater(update)

    def _run_scan_from_explorer(self, scan_type):
        """Scan every URL currently listed in the Explorer tab."""
        model = self._auth._explorer_model
        if model.size() == 0:
            self._set_scan_status(
                'Explorer is empty — run Discover first.',
                Color(200, 50, 50)
            )
            return

        token      = self._auth._token
        verify_tls = self._auth._verify_tls

        urls = []
        for i in range(model.size()):
            path     = explorer_actual_path(model.get(i))
            full_url = self._auth._build_url(path)
            urls.append(full_url)

        self._set_scan_status(
            'Scanning {0} URL(s) ({1})...'.format(len(urls), scan_type),
            Color(100, 100, 100)
        )

        def work():
            findings = []
            for url in urls:
                try:
                    if scan_type == 'passive':
                        findings.extend(_scanner.run_passive_scan_manual(url, token, verify_tls))
                    else:
                        findings.extend(_scanner.run_active_scan_manual(url, token, verify_tls))
                except Exception:
                    pass
            return findings

        def done(findings):
            for f in findings:
                self._find_model.add_finding(f)
            self._bottom_tabs.setSelectedIndex(1)
            self._set_scan_status(
                '{0} scan — {1} URL(s), {2} finding(s).'.format(
                    scan_type.capitalize(), len(urls), len(findings)
                ),
                Color(50, 150, 50) if findings else Color(100, 100, 100),
            )

        self._run_in_bg(work, done)

    def _set_scan_status(self, msg, color):
        def update():
            self._lbl_scan_status.setForeground(color)
            self._lbl_scan_status.setText(msg)
        SwingUtilities.invokeLater(update)

    def _run_in_bg(self, work_fn, done_fn):
        class Worker(Runnable):
            def run(self_w):
                result = work_fn()
                class Updater(Runnable):
                    def run(self_u):
                        done_fn(result)
                SwingUtilities.invokeLater(Updater())
        Thread(Worker()).start()
