import json
import ssl
import urllib2

from java.lang import Thread, Runnable
from javax.swing import (
    JPanel, JLabel, JTextField, JButton, JComboBox,
    JTextArea, JScrollPane, JTable, JSplitPane, JProgressBar,
    BorderFactory, SwingUtilities,
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, Color, Font

from redfish_utils import DEFAULT_CREDS


class SprayResultModel(DefaultTableModel):
    _COLUMNS = ['Username', 'Password', 'Vendor', 'Status', 'Token?', 'Detail']
    _COL_WIDTHS = [120, 120, 90, 60, 60, 300]

    def __init__(self):
        DefaultTableModel.__init__(self, 0, len(self._COLUMNS))
        self.setColumnIdentifiers(self._COLUMNS)

    def isCellEditable(self, row, col):
        return False


class CredSprayTab(object):

    def __init__(self, auth_handler):
        self._auth = auth_handler
        self._stop_flag = [False]
        self._panel = self._build_panel()

    def get_panel(self):
        return self._panel

    def _build_panel(self):
        from javax.swing import BoxLayout

        panel = JPanel(BorderLayout())

        # --- NORTH: toolbar ---
        toolbar = JPanel()
        toolbar.setLayout(BoxLayout(toolbar, BoxLayout.Y_AXIS))
        toolbar.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))

        # Row 1: target URL
        row1 = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        row1.add(JLabel("Target Sessions URL:"))
        self._fld_target = JTextField(42)
        row1.add(self._fld_target)
        btn_fill = JButton("Fill from Config")
        btn_fill.setBackground(Color(230, 100, 0))
        btn_fill.setForeground(Color.WHITE)
        btn_fill.setOpaque(True)
        btn_fill.setBorderPainted(False)
        btn_fill.addActionListener(lambda e: self._fill_target())
        row1.add(btn_fill)
        toolbar.add(row1)

        # Row 2: vendor, delay, start/stop, status
        row2 = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        row2.add(JLabel("Vendor filter:"))
        self._cmb_vendor = JComboBox(['all', 'generic', 'dell', 'hpe', 'openbmc', 'supermicro', 'ami'])
        row2.add(self._cmb_vendor)
        row2.add(JLabel("Delay (ms):"))
        self._fld_delay = JTextField('500', 5)
        row2.add(self._fld_delay)

        self._btn_start = JButton("Start Spray")
        self._btn_start.setBackground(Color(230, 100, 0))
        self._btn_start.setForeground(Color.WHITE)
        self._btn_start.setOpaque(True)
        self._btn_start.setBorderPainted(False)
        self._btn_start.addActionListener(lambda e: self._on_start())
        row2.add(self._btn_start)

        self._btn_stop = JButton("Stop")
        self._btn_stop.setBackground(Color(230, 100, 0))
        self._btn_stop.setForeground(Color.WHITE)
        self._btn_stop.setOpaque(True)
        self._btn_stop.setBorderPainted(False)
        self._btn_stop.setEnabled(False)
        self._btn_stop.addActionListener(lambda e: self._on_stop())
        row2.add(self._btn_stop)

        self._lbl_status = JLabel("Idle")
        self._lbl_status.setForeground(Color(100, 100, 100))
        row2.add(self._lbl_status)
        toolbar.add(row2)

        # Row 3: progress bar
        row3 = JPanel(FlowLayout(FlowLayout.LEFT, 4, 2))
        self._progress = JProgressBar()
        self._progress.setStringPainted(True)
        self._progress.setPreferredSize(
            self._progress.getPreferredSize().__class__(600, 18)
        )
        row3.add(self._progress)
        toolbar.add(row3)

        panel.add(toolbar, BorderLayout.NORTH)

        # --- CENTER: split pane ---
        # Top: results table
        self._result_model = SprayResultModel()
        self._result_table = JTable(self._result_model)
        self._result_table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
        col_model = self._result_table.getColumnModel()
        for i, w in enumerate(SprayResultModel._COL_WIDTHS):
            col_model.getColumn(i).setPreferredWidth(w)

        top_scroll = JScrollPane(self._result_table)
        top_scroll.setBorder(
            BorderFactory.createTitledBorder("Spray Results")
        )

        # Bottom: custom credentials input + button row
        self._txt_custom = JTextArea(5, 0)
        self._txt_custom.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._txt_custom.setText(
            "# Optional extra credentials, one per line.\n"
            "# Format: username:password:vendor  (vendor can be 'generic' or any tag)\n"
            "# Lines starting with # are ignored.\n"
        )
        custom_scroll = JScrollPane(self._txt_custom)
        custom_scroll.setBorder(
            BorderFactory.createTitledBorder("Custom Credentials (optional)")
        )

        btn_clear = JButton("Clear Results")
        btn_export = JButton("Export CSV")
        for _b in (btn_clear, btn_export):
            _b.setBackground(Color(230, 100, 0))
            _b.setForeground(Color.WHITE)
            _b.setOpaque(True)
            _b.setBorderPainted(False)
        btn_clear.addActionListener(lambda e: self._clear_results())
        btn_export.addActionListener(lambda e: self._export_csv())

        btn_row = JPanel(FlowLayout(FlowLayout.RIGHT, 4, 2))
        btn_row.add(btn_clear)
        btn_row.add(btn_export)

        bottom_panel = JPanel(BorderLayout())
        bottom_panel.add(custom_scroll, BorderLayout.CENTER)
        bottom_panel.add(btn_row, BorderLayout.SOUTH)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_scroll, bottom_panel)
        split.setResizeWeight(0.7)
        panel.add(split, BorderLayout.CENTER)

        return panel

    # ------------------------------------------------------------------
    # Toolbar actions
    # ------------------------------------------------------------------

    def _fill_target(self):
        url = self._auth._build_url('/redfish/v1/SessionService/Sessions')
        self._fld_target.setText(url)

    def _on_start(self):
        if not self._fld_target.getText().strip():
            self._fill_target()

        url = self._fld_target.getText().strip()
        vendor_filter = str(self._cmb_vendor.getSelectedItem())

        try:
            delay_ms = int(self._fld_delay.getText().strip())
        except ValueError:
            delay_ms = 500

        # Build credential list from built-ins + custom textarea
        creds = list(DEFAULT_CREDS)
        for line in self._txt_custom.getText().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':', 2)
            if len(parts) == 3:
                creds.append((parts[0], parts[1], parts[2]))
            elif len(parts) == 2:
                creds.append((parts[0], parts[1], 'generic'))

        # Apply vendor filter
        if vendor_filter != 'all':
            creds = [c for c in creds if c[2] == vendor_filter]

        verify_tls = getattr(self._auth, 'verify_tls', False)

        self._stop_flag[0] = False
        self._clear_results()
        self._progress.setMaximum(max(len(creds), 1))
        self._progress.setValue(0)
        self._btn_start.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._set_status("Running...", None)

        stop_flag = self._stop_flag
        result_model = self._result_model
        progress = self._progress
        btn_start = self._btn_start
        btn_stop = self._btn_stop
        set_status = self._set_status
        try_cred = self._try_cred

        def work():
            done = [0]
            for (username, password, vendor) in creds:
                if stop_flag[0]:
                    break
                status_code, has_token, detail = try_cred(url, username, password, verify_tls)
                row_data = [
                    username,
                    password,
                    vendor,
                    str(status_code),
                    'Yes' if has_token else 'No',
                    detail,
                ]
                done[0] += 1
                current_done = done[0]

                def update(r=row_data, n=current_done):
                    result_model.addRow(r)
                    progress.setValue(n)

                SwingUtilities.invokeLater(update)

                if delay_ms > 0:
                    Thread.sleep(delay_ms)

            total = done[0]
            stopped = stop_flag[0]

            def finish():
                btn_start.setEnabled(True)
                btn_stop.setEnabled(False)
                if stopped:
                    set_status("Stopped after {} attempts.".format(total), None)
                else:
                    set_status("Done. {} credential(s) tested.".format(total), True)

            SwingUtilities.invokeLater(finish)

        class Worker(Runnable):
            def run(self_w):
                work()

        Thread(Worker()).start()

    def _on_stop(self):
        self._stop_flag[0] = True

    # ------------------------------------------------------------------
    # Credential attempt
    # ------------------------------------------------------------------

    def _try_cred(self, url, username, password, verify_tls):
        try:
            ctx = ssl.create_default_context()
            if not verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            payload = json.dumps({'UserName': username, 'Password': password})
            req = urllib2.Request(url, payload)
            req.add_header('Content-Type', 'application/json')
            req.add_header('Accept', 'application/json')

            response = urllib2.urlopen(req, context=ctx)
            status = response.getcode()
            token = response.headers.get('X-Auth-Token', '')
            if token:
                detail = 'Token: {}...'.format(token[:12])
            else:
                detail = 'No token in response'
            return (status, bool(token), detail)

        except urllib2.HTTPError as e:
            try:
                reason = e.reason
            except AttributeError:
                reason = ''
            return (e.code, False, 'HTTP {} {}'.format(e.code, reason))

        except Exception as ex:
            return (0, False, str(ex))

    # ------------------------------------------------------------------
    # Results helpers
    # ------------------------------------------------------------------

    def _clear_results(self):
        while self._result_model.getRowCount() > 0:
            self._result_model.removeRow(0)
        self._progress.setValue(0)

    def _export_csv(self):
        from javax.swing import JFileChooser
        import java.io

        chooser = JFileChooser()
        chooser.setDialogTitle("Save CSV")
        ret = chooser.showSaveDialog(self._panel)
        if ret != JFileChooser.APPROVE_OPTION:
            return

        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.endswith('.csv'):
            path += '.csv'

        model = self._result_model
        columns = SprayResultModel._COLUMNS

        def _quote(val):
            s = '' if val is None else str(val)
            if ',' in s or '"' in s or '\n' in s:
                s = '"' + s.replace('"', '""') + '"'
            return s

        fw = java.io.FileWriter(path)
        try:
            fw.write(','.join(_quote(c) for c in columns) + '\n')
            for row in xrange(model.getRowCount()):
                values = [model.getValueAt(row, col) for col in xrange(model.getColumnCount())]
                fw.write(','.join(_quote(v) for v in values) + '\n')
        finally:
            fw.close()

        self._set_status("Exported to {}".format(path), True)

    # ------------------------------------------------------------------
    # Status label helper
    # ------------------------------------------------------------------

    def _set_status(self, msg, ok):
        if ok is True:
            color = Color(50, 150, 50)
        elif ok is False:
            color = Color(200, 50, 50)
        else:
            color = Color(100, 100, 100)

        lbl = self._lbl_status

        def _update():
            lbl.setText(msg)
            lbl.setForeground(color)

        SwingUtilities.invokeLater(_update)
