# -*- coding: utf-8 -*-
"""
RedfishAuthHandler — ISessionHandlingAction + IHttpListener + ITab

Four-tab UI:
  Config           — connection settings, login/logout
  Request/Response — mini Repeater with Redfish-aware headers
  Explorer         — discover /redfish/v1/ links and navigate
  Log              — all extension activity
"""

import json
import ssl
import urllib2

from burp import ISessionHandlingAction, ITab, IHttpListener
from java.io import PrintWriter
from java.lang import Thread, Runnable

from javax.swing import (
    JPanel, JLabel, JTextField, JPasswordField, JButton,
    JCheckBox, JComboBox, JTextArea, JScrollPane,
    JTabbedPane, JSplitPane, JList, DefaultListModel,
    BorderFactory, BoxLayout, SwingUtilities,
    JPopupMenu, JMenuItem,
)
from java.awt import BorderLayout, GridLayout, Dimension, FlowLayout, Color, Font
from java.awt.event import MouseAdapter
from javax.swing.event import ListDataListener

from redfish_utils import (
    get_resource_type, get_resource_risk, pretty_json,
    EXPLORER_CHILD_PREFIX, explorer_actual_path, detect_vendor,
)
from scanner_tab import ScannerTab
from ai_tab import AITab
from cred_spray_tab import CredSprayTab

_QUICK_PATHS = [
    '--- select endpoint ---',
    '/redfish/v1/',
    '/redfish/v1/Systems',
    '/redfish/v1/Systems/1',
    '/redfish/v1/Systems/1/Bios',
    '/redfish/v1/Systems/1/Processors',
    '/redfish/v1/Systems/1/Memory',
    '/redfish/v1/Systems/1/Storage',
    '/redfish/v1/Systems/1/EthernetInterfaces',
    '/redfish/v1/Systems/1/Actions/ComputerSystem.Reset',
    '/redfish/v1/Chassis',
    '/redfish/v1/Chassis/1',
    '/redfish/v1/Chassis/1/Power',
    '/redfish/v1/Chassis/1/Thermal',
    '/redfish/v1/Managers',
    '/redfish/v1/Managers/1',
    '/redfish/v1/Managers/1/EthernetInterfaces',
    '/redfish/v1/Managers/1/NetworkProtocol',
    '/redfish/v1/Managers/1/LogServices',
    '/redfish/v1/SessionService',
    '/redfish/v1/SessionService/Sessions',
    '/redfish/v1/AccountService',
    '/redfish/v1/AccountService/Accounts',
    '/redfish/v1/AccountService/Roles',
    '/redfish/v1/EventService',
    '/redfish/v1/EventService/Subscriptions',
    '/redfish/v1/UpdateService',
    '/redfish/v1/UpdateService/FirmwareInventory',
    '/redfish/v1/TaskService',
    '/redfish/v1/CertificateService',
    '/redfish/v1/JsonSchemas',
    '/redfish/v1/Registries',
]

_SESSIONS_PATH = '/redfish/v1/SessionService/Sessions'
_MONO_FONT = Font('Monospaced', Font.PLAIN, 12)
_STATUS_COLORS = {
    'ok':      Color(50,  150, 50),
    'error':   Color(200, 50,  50),
    'neutral': Color(100, 100, 100),
}


def _u(x):
    """
    Unicode-safe string coercion for Jython 2.7.
    Java Strings returned by DefaultListModel.get() are Python unicode in Jython,
    but calling str() on them raises UnicodeEncodeError when they contain non-ASCII
    characters (e.g. the └─ prefix).  Always use this instead of str() on model items.
    """
    if isinstance(x, unicode):  # noqa: F821  unicode is a Jython 2.7 built-in
        return x
    try:
        return unicode(x)        # noqa: F821
    except Exception:
        return repr(x)


class RedfishAuthHandler(ISessionHandlingAction, IHttpListener, ITab):

    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True)

        self._token       = None
        self._session_url = None
        self._ssl_ctx     = None  # cached; invalidated when verify_tls changes

        self._host       = ''
        self._port       = 443
        self._use_https  = True
        self._username   = ''
        self._password   = ''
        self._verify_tls = False

        # Request history (circular buffer, max 30 entries)
        self._req_history   = []   # list of {'method', 'url', 'headers', 'body', 'result'}
        self._req_hist_idx  = 0    # current position when navigating
        self._pending_hist  = {}   # snapshot of current request before sending

        # Explorer state
        self._explorer_children       = {}    # parent_path → [child_path, …]; survives Discover
        self._explorer_fetch_seq      = 0     # incremented each click; stale done() callbacks dropped
        self._ctx_menu_entry          = None  # path captured at right-click time for menu actions
        self._suppress_explorer_fetch = False # True while right-click selection is being set

        self._panel = self._build_ui()

    # ------------------------------------------------------------------
    # ITab
    # ------------------------------------------------------------------

    def getTabCaption(self):
        return 'Redfisher'

    def getUiComponent(self):
        return self._panel

    # ------------------------------------------------------------------
    # ISessionHandlingAction
    # ------------------------------------------------------------------

    def getActionName(self):
        return 'Redfisher: inject/refresh Redfish X-Auth-Token'

    def performAction(self, current_request, macro_items):
        if not self._host or not self._username or not self._password:
            self._log('Auth handler not configured — skipping.')
            return
        if self._token is None:
            self._log('No session token — authenticating...')
            self._authenticate()
        if self._token:
            self._inject_token(current_request)

    def _inject_token(self, http_request_response):
        request      = http_request_response.getRequest()
        request_info = self._helpers.analyzeRequest(request)
        headers      = list(request_info.getHeaders())
        headers = [
            h for h in headers
            if not str(h).lower().startswith('x-auth-token')
            and not str(h).lower().startswith('authorization')
        ]
        headers.append('X-Auth-Token: ' + self._token)
        body        = request[request_info.getBodyOffset():]
        new_request = self._helpers.buildHttpMessage(headers, body)
        http_request_response.setRequest(new_request)

    # ------------------------------------------------------------------
    # IHttpListener
    # ------------------------------------------------------------------

    def processHttpMessage(self, tool_flag, is_request, message_info):
        if is_request:
            return
        response = message_info.getResponse()
        if not response:
            return
        try:
            service = message_info.getHttpService()
            if self._host and str(service.getHost()) != self._host:
                return
        except Exception:
            return
        resp_info = self._helpers.analyzeResponse(response)
        if resp_info and resp_info.getStatusCode() == 401:
            self._log('Received 401 from BMC — token cleared, will re-auth on next request.')
            self._token       = None
            self._session_url = None

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _authenticate(self):
        if not self._host:
            self._log('Cannot authenticate: host not configured.')
            return
        url     = self._build_url(_SESSIONS_PATH)
        payload = json.dumps({'UserName': self._username, 'Password': self._password})
        self._log('Creating Redfish session: POST ' + url)
        try:
            req = urllib2.Request(url, data=payload.encode('utf-8'))
            req.add_header('Content-Type', 'application/json')
            req.add_header('Accept',       'application/json')
            req.add_header('OData-Version','4.0')
            resp  = urllib2.urlopen(req, context=self._get_ssl_ctx(), timeout=15)
            token = resp.info().get('X-Auth-Token')
            if resp.getcode() in (200, 201) and token:
                self._token = token
                try:
                    self._session_url = json.loads(resp.read()).get('@odata.id', '')
                except Exception:
                    self._session_url = ''
                self._log('Session created. Token: {0}...'.format(token[:8]))
                self._set_status('Authenticated session active.', 'ok')
                self._refresh_req_headers()
                self._update_vendor_label(
                    ['{0}: {1}'.format(k, v) for k, v in resp.info().items()],
                    ''
                )
            else:
                self._log('Session creation returned HTTP {0}'.format(resp.getcode()))
                self._set_status('Auth failed: HTTP {0}'.format(resp.getcode()), 'error')
        except urllib2.HTTPError as e:
            self._log('Authentication error: HTTP Error {0}: {1}'.format(e.code, e.reason))
            self._set_status('Auth failed: HTTP {0}'.format(e.code), 'error')
        except Exception as e:
            self._log('Authentication error: ' + str(e))
            self._set_status('Error: ' + str(e), 'error')

    def _logout(self):
        if not self._token or not self._session_url:
            self._log('No active session.')
            return
        url = (
            self._session_url
            if not self._session_url.startswith('/')
            else self._build_url(self._session_url)
        )
        self._log('Deleting session: DELETE ' + url)
        try:
            req = urllib2.Request(url)
            req.add_header('X-Auth-Token', self._token)
            req.get_method = lambda: 'DELETE'
            resp = urllib2.urlopen(req, context=self._get_ssl_ctx(), timeout=10)
            self._log('Session deleted (HTTP {0}).'.format(resp.getcode()))
        except Exception as e:
            self._log('Failed to delete session: ' + str(e))
        finally:
            self._token       = None
            self._session_url = None
            self._set_status('Logged out.', 'neutral')
            self._refresh_req_headers()

    def _get_ssl_ctx(self):
        """Return cached SSL context, creating it once per verify_tls setting."""
        if self._ssl_ctx is None:
            ctx = ssl.create_default_context()
            if not self._verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
            self._ssl_ctx = ctx
        return self._ssl_ctx

    def _build_url(self, path):
        """Build an absolute URL from a Redfish path using current config."""
        scheme = 'https' if self._use_https else 'http'
        host   = self._host or 'TARGET'
        return '{0}://{1}:{2}{3}'.format(scheme, host, self._port, path)

    def _run_in_bg(self, work_fn, done_fn):
        """Run work_fn on a worker thread, then call done_fn(result) on the EDT."""
        class Worker(Runnable):
            def run(self_w):
                result = work_fn()
                class Updater(Runnable):
                    def run(self_u):
                        done_fn(result)
                SwingUtilities.invokeLater(Updater())
        Thread(Worker()).start()

    # ------------------------------------------------------------------
    # UI — top level
    # ------------------------------------------------------------------

    def _build_ui(self):
        outer = JPanel(BorderLayout())
        outer.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))
        self._tabs = JTabbedPane()
        self._tabs.addTab('Config',             self._build_config_tab())
        self._tabs.addTab('Repeater', self._build_repeater_tab())
        self._tabs.addTab('Explorer',           self._build_explorer_tab())
        self._scanner_tab = ScannerTab(self)
        self._tabs.addTab('Scanner',            self._scanner_tab.get_panel())
        self._ai_tab = AITab(self)
        self._tabs.addTab('AI Mode',           self._ai_tab.get_panel())
        self._cred_spray_tab = CredSprayTab(self)
        self._tabs.addTab('Cred Spray',         self._cred_spray_tab.get_panel())
        self._tabs.addTab('Log',                self._build_log_tab())
        outer.add(self._tabs, BorderLayout.CENTER)
        return outer

    # ------------------------------------------------------------------
    # Tab 1 — Config
    # ------------------------------------------------------------------

    def _build_config_tab(self):
        panel = JPanel(BorderLayout(8, 8))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        form = JPanel(GridLayout(0, 2, 8, 6))
        form.setBorder(BorderFactory.createTitledBorder('Redfish Connection'))

        self._fld_host   = JTextField(20)
        self._fld_port   = JTextField('443', 6)
        self._fld_user   = JTextField(20)
        self._fld_pass   = JPasswordField(20)
        self._chk_https  = JCheckBox('Use HTTPS', True)
        self._chk_verify = JCheckBox('Verify TLS certificate', False)

        for label, widget in [
            ('Host / IP:', self._fld_host),
            ('Port:',      self._fld_port),
            ('Username:',  self._fld_user),
            ('Password:',  self._fld_pass),
            ('',           self._chk_https),
            ('',           self._chk_verify),
        ]:
            form.add(JLabel(label))
            form.add(widget)

        self._btn_save   = JButton('Save config')
        self._btn_login  = JButton('Login (create session)')
        self._btn_logout = JButton('Logout (delete session)')
        for _b in (self._btn_save, self._btn_login, self._btn_logout):
            _b.setBackground(Color(230, 100, 0))
            _b.setForeground(Color.WHITE)
            _b.setOpaque(True)
            _b.setBorderPainted(False)
        self._btn_save.addActionListener(  lambda e: self._on_save())
        self._btn_login.addActionListener( lambda e: self._on_login())
        self._btn_logout.addActionListener(lambda e: self._logout())

        btn_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_panel.add(self._btn_save)
        btn_panel.add(self._btn_login)
        btn_panel.add(self._btn_logout)

        self._lbl_status = JLabel('Not configured.')
        self._lbl_status.setForeground(_STATUS_COLORS['neutral'])
        self._lbl_vendor = JLabel('Vendor: —')
        self._lbl_vendor.setForeground(_STATUS_COLORS['neutral'])
        status_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        status_panel.add(JLabel('Status: '))
        status_panel.add(self._lbl_status)
        status_panel.add(JLabel('    '))
        status_panel.add(self._lbl_vendor)

        # form + buttons share the NORTH slot via a wrapper panel
        top = JPanel(BorderLayout())
        top.add(form,      BorderLayout.CENTER)
        top.add(btn_panel, BorderLayout.SOUTH)

        panel.add(top,          BorderLayout.NORTH)
        panel.add(status_panel, BorderLayout.CENTER)
        return panel

    # ------------------------------------------------------------------
    # Tab 2 — Request / Response
    # ------------------------------------------------------------------

    def _build_repeater_tab(self):
        panel = JPanel(BorderLayout(4, 4))
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        top_bar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))

        self._btn_hist_prev = JButton('Back')
        self._btn_hist_next = JButton('Forward')
        for _b in (self._btn_hist_prev, self._btn_hist_next):
            _b.setBackground(Color(230, 100, 0))
            _b.setForeground(Color.WHITE)
            _b.setOpaque(True)
            _b.setBorderPainted(False)
        self._btn_hist_prev.setToolTipText('Previous request')
        self._btn_hist_next.setToolTipText('Next request')
        self._btn_hist_prev.addActionListener(lambda e: self._on_history_prev())
        self._btn_hist_next.addActionListener(lambda e: self._on_history_next())
        top_bar.add(self._btn_hist_prev)
        top_bar.add(self._btn_hist_next)

        top_bar.add(JLabel('URL:'))
        self._fld_req_url = JTextField(40)
        top_bar.add(self._fld_req_url)

        self._cmb_method = JComboBox(['GET', 'POST', 'PATCH', 'DELETE', 'PUT', 'HEAD'])
        top_bar.add(self._cmb_method)

        self._btn_send = JButton('Send')
        self._btn_send.addActionListener(lambda e: self._on_send())
        self._btn_send.setBackground(Color(230, 100, 0))
        self._btn_send.setForeground(Color.WHITE)
        self._btn_send.setOpaque(True)
        self._btn_send.setBorderPainted(False)
        top_bar.add(self._btn_send)

        top_bar.add(JLabel('  Quick paths:'))
        self._cmb_quick_paths = JComboBox(_QUICK_PATHS)
        self._cmb_quick_paths.addActionListener(lambda e: self._on_quick_path_select())
        top_bar.add(self._cmb_quick_paths)

        self._lbl_resource_info = JLabel(' ')
        self._lbl_resource_info.setFont(
            self._lbl_resource_info.getFont().deriveFont(Font.ITALIC)
        )
        info_bar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        info_bar.add(self._lbl_resource_info)

        self._txt_req_headers = JTextArea(6, 40)
        self._txt_req_headers.setFont(_MONO_FONT)
        self._txt_req_body = JTextArea()
        self._txt_req_body.setFont(_MONO_FONT)

        # Right-click context menu for the request areas
        _req_popup = JPopupMenu()
        _menu_send_burp = JMenuItem('Send to Burp Repeater')
        _menu_send_burp.addActionListener(lambda e: self._on_send_to_burp_repeater())
        _req_popup.add(_menu_send_burp)

        class _ReqMouseListener(MouseAdapter):
            def mousePressed(self_, e):
                if e.isPopupTrigger():
                    _req_popup.show(e.getComponent(), e.getX(), e.getY())
            def mouseReleased(self_, e):
                if e.isPopupTrigger():
                    _req_popup.show(e.getComponent(), e.getX(), e.getY())

        _listener = _ReqMouseListener()
        self._txt_req_body.addMouseListener(_listener)
        self._txt_req_headers.addMouseListener(_listener)

        req_tabs = JTabbedPane()
        req_tabs.addTab('Body',    JScrollPane(self._txt_req_body))
        req_tabs.addTab('Headers', JScrollPane(self._txt_req_headers))

        req_panel = JPanel(BorderLayout())
        req_panel.setBorder(BorderFactory.createTitledBorder('Request'))
        req_panel.add(req_tabs, BorderLayout.CENTER)

        self._lbl_resp_status = JLabel('\u2014')
        self._lbl_resp_status.setFont(
            self._lbl_resp_status.getFont().deriveFont(Font.BOLD, 13.0)
        )
        resp_status_bar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        resp_status_bar.add(JLabel('Status:'))
        resp_status_bar.add(self._lbl_resp_status)

        self._txt_resp_headers = JTextArea()
        self._txt_resp_headers.setFont(_MONO_FONT)
        self._txt_resp_headers.setEditable(False)
        self._txt_resp_body = JTextArea()
        self._txt_resp_body.setFont(_MONO_FONT)
        self._txt_resp_body.setEditable(False)

        resp_tabs = JTabbedPane()
        resp_tabs.addTab('Body',    JScrollPane(self._txt_resp_body))
        resp_tabs.addTab('Headers', JScrollPane(self._txt_resp_headers))

        resp_panel = JPanel(BorderLayout())
        resp_panel.setBorder(BorderFactory.createTitledBorder('Response'))
        resp_panel.add(resp_status_bar, BorderLayout.NORTH)
        resp_panel.add(resp_tabs,       BorderLayout.CENTER)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, req_panel, resp_panel)
        split.setResizeWeight(0.45)

        # top_bar + info_bar share the NORTH slot via a wrapper panel
        north = JPanel(BorderLayout())
        north.add(top_bar,  BorderLayout.NORTH)
        north.add(info_bar, BorderLayout.SOUTH)

        panel.add(north, BorderLayout.NORTH)
        panel.add(split, BorderLayout.CENTER)

        self._refresh_req_headers()
        return panel

    # ------------------------------------------------------------------
    # Tab 3 — Explorer
    # ------------------------------------------------------------------

    def _build_explorer_tab(self):
        panel = JPanel(BorderLayout(6, 6))
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        # ---- top toolbar ----
        self._btn_discover   = JButton('Discover')
        self._btn_auto_walk  = JButton('Spider')
        for _b in (self._btn_discover, self._btn_auto_walk):
            _b.setBackground(Color(230, 100, 0))
            _b.setForeground(Color.WHITE)
            _b.setOpaque(True)
            _b.setBorderPainted(False)
        self._lbl_explorer_status = JLabel('')
        self._btn_discover.addActionListener(  lambda e: self._on_discover())
        self._btn_auto_walk.addActionListener( lambda e: self._on_auto_walk())
        self._btn_auto_walk.setToolTipText('Recursively follow all @odata.id links (depth-limited)')

        top = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        top.add(self._btn_discover)
        top.add(self._btn_auto_walk)
        top.add(self._lbl_explorer_status)

        # count label — updated automatically by a ListDataListener on the model
        self._lbl_explorer_count = JLabel('0 links')
        top.add(JLabel('   |'))
        top.add(self._lbl_explorer_count)

        # ---- discovered links list + response detail ----
        self._explorer_model = DefaultListModel()
        self._lst_explorer   = JList(self._explorer_model)
        self._lst_explorer.setFont(_MONO_FONT)
        self._lst_explorer.addListSelectionListener(
            lambda e: self._on_explorer_select(e)
        )

        # keep count label in sync with the model
        class _CountSync(ListDataListener):
            def contentsChanged(self_, e): self._refresh_explorer_count()
            def intervalAdded(self_, e):   self._refresh_explorer_count()
            def intervalRemoved(self_, e): self._refresh_explorer_count()
        self._explorer_model.addListDataListener(_CountSync())

        # Right-click context menu (stored on self so _show_explorer_popup can reference it)
        self._explorer_popup = JPopupMenu()
        menu_send_repeater   = JMenuItem('Send to Request / Response tab')
        menu_send_scanner    = JMenuItem('Send to Scanner')
        menu_send_repeater.addActionListener(lambda e: self._explorer_send_to_repeater())
        menu_send_scanner.addActionListener( lambda e: self._explorer_send_to_scanner())
        self._explorer_popup.add(menu_send_repeater)
        self._explorer_popup.add(menu_send_scanner)

        class ExplorerMouseListener(MouseAdapter):
            def mousePressed(self_, e):
                if e.isPopupTrigger():
                    self._show_explorer_popup(e)
            def mouseReleased(self_, e):
                if e.isPopupTrigger():
                    self._show_explorer_popup(e)

        self._lst_explorer.addMouseListener(ExplorerMouseListener())

        list_scroll = JScrollPane(self._lst_explorer)
        list_scroll.setBorder(BorderFactory.createTitledBorder('Discovered links'))
        list_scroll.setPreferredSize(Dimension(320, 0))

        self._lbl_explorer_resp_status = JLabel('\u2014')
        self._lbl_explorer_resp_status.setFont(
            self._lbl_explorer_resp_status.getFont().deriveFont(Font.BOLD, 13.0)
        )
        resp_status_bar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        resp_status_bar.add(JLabel('Status:'))
        resp_status_bar.add(self._lbl_explorer_resp_status)

        self._txt_explorer_detail = JTextArea()
        self._txt_explorer_detail.setFont(_MONO_FONT)
        self._txt_explorer_detail.setEditable(False)
        detail_scroll = JScrollPane(self._txt_explorer_detail)

        detail_panel = JPanel(BorderLayout())
        detail_panel.setBorder(BorderFactory.createTitledBorder('Response'))
        detail_panel.add(resp_status_bar,  BorderLayout.NORTH)
        detail_panel.add(detail_scroll,    BorderLayout.CENTER)

        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, list_scroll, detail_panel)
        main_split.setResizeWeight(0.35)

        # ---- OEM / JSON parser panel ----
        oem_panel = self._build_oem_parser_panel()

        # stack the two halves vertically
        outer_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, main_split, oem_panel)
        outer_split.setResizeWeight(0.55)

        panel.add(top,          BorderLayout.NORTH)
        panel.add(outer_split,  BorderLayout.CENTER)
        return panel

    def _build_oem_parser_panel(self):
        """
        Paste any JSON response here; the panel recursively extracts every
        @odata.id value (including deeply-nested OEM ones) and lets you add
        them to the main discovered-links list.
        """
        panel = JPanel(BorderLayout(4, 4))
        panel.setBorder(BorderFactory.createTitledBorder(
            'OEM / JSON endpoint extractor paste any response body'
        ))

        # text area for raw JSON input
        self._txt_oem_input = JTextArea()
        self._txt_oem_input.setFont(_MONO_FONT)
        self._txt_oem_input.setLineWrap(False)
        input_scroll = JScrollPane(self._txt_oem_input)
        input_scroll.setBorder(BorderFactory.createTitledBorder('Paste JSON here'))

        # list of extracted endpoints
        self._oem_extract_model = DefaultListModel()
        self._lst_oem_extract   = JList(self._oem_extract_model)
        self._lst_oem_extract.setFont(_MONO_FONT)

        # right-click menu on the extract list
        oem_popup          = JPopupMenu()
        oem_send_repeater  = JMenuItem('Send to Request tab')
        oem_send_scanner   = JMenuItem('Send to Scanner')
        oem_send_explorer  = JMenuItem('Add to Explorer')
        oem_send_repeater.addActionListener( lambda e: self._oem_send_to_repeater())
        oem_send_scanner.addActionListener(  lambda e: self._oem_send_to_scanner())
        oem_send_explorer.addActionListener( lambda e: self._on_add_oem_selected())
        oem_popup.add(oem_send_repeater)
        oem_popup.add(oem_send_scanner)
        oem_popup.add(oem_send_explorer)

        class OemMouseListener(MouseAdapter):
            def mousePressed(self_, e):
                if e.isPopupTrigger():
                    self._show_oem_popup(e, oem_popup)
            def mouseReleased(self_, e):
                if e.isPopupTrigger():
                    self._show_oem_popup(e, oem_popup)

        self._lst_oem_extract.addMouseListener(OemMouseListener())

        extract_scroll = JScrollPane(self._lst_oem_extract)
        extract_scroll.setBorder(BorderFactory.createTitledBorder('Extracted links (@odata.id + Oem Children)'))

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, input_scroll, extract_scroll)
        split.setResizeWeight(0.55)

        # toolbar
        btn_extract = JButton('Extract @odata.id links')
        btn_add     = JButton('Add selected to Explorer')
        btn_add_all = JButton('Add all to Explorer')
        for _b in (btn_extract, btn_add, btn_add_all):
            _b.setBackground(Color(230, 100, 0))
            _b.setForeground(Color.WHITE)
            _b.setOpaque(True)
            _b.setBorderPainted(False)
        self._lbl_oem_status = JLabel('')

        btn_extract.addActionListener(lambda e: self._on_parse_oem_json())
        btn_add.addActionListener(    lambda e: self._on_add_oem_selected())
        btn_add_all.addActionListener(lambda e: self._on_add_oem_all())

        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        toolbar.add(btn_extract)
        toolbar.add(btn_add)
        toolbar.add(btn_add_all)
        toolbar.add(self._lbl_oem_status)

        panel.add(toolbar, BorderLayout.NORTH)
        panel.add(split,   BorderLayout.CENTER)
        return panel

    # ------------------------------------------------------------------
    # Tab 4 — Log
    # ------------------------------------------------------------------

    def _build_log_tab(self):
        panel = JPanel(BorderLayout(4, 4))
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        self._txt_log = JTextArea()
        self._txt_log.setFont(Font('Monospaced', Font.PLAIN, 11))
        self._txt_log.setEditable(False)

        btn_clear = JButton('Clear log')
        btn_clear.setBackground(Color(230, 100, 0))
        btn_clear.setForeground(Color.WHITE)
        btn_clear.setOpaque(True)
        btn_clear.setBorderPainted(False)
        btn_clear.addActionListener(lambda e: self._txt_log.setText(''))

        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        btn_panel.add(btn_clear)

        panel.add(JScrollPane(self._txt_log), BorderLayout.CENTER)
        panel.add(btn_panel,                  BorderLayout.SOUTH)
        return panel

    # ------------------------------------------------------------------
    # Config tab actions
    # ------------------------------------------------------------------

    def _on_save(self):
        self._host     = self._fld_host.getText().strip()
        self._username = self._fld_user.getText().strip()
        self._password = ''.join(self._fld_pass.getPassword())
        self._use_https  = self._chk_https.isSelected()
        self._verify_tls = self._chk_verify.isSelected()
        self._ssl_ctx    = None  # invalidate cached context when TLS setting may have changed
        try:
            self._port = int(self._fld_port.getText().strip())
        except ValueError:
            self._port = 443
        self._log('Config saved. Host: {0}:{1}, User: {2}, HTTPS: {3}'.format(
            self._host, self._port, self._username, self._use_https
        ))
        self._set_status('Config saved — not yet authenticated.', 'neutral')

    def _on_login(self):
        self._on_save()
        if self._token:
            self._logout()
        self._authenticate()

    # ------------------------------------------------------------------
    # Request / Response tab actions
    # ------------------------------------------------------------------

    def _on_quick_path_select(self):
        sel = str(self._cmb_quick_paths.getSelectedItem())
        if sel.startswith('---'):
            return
        self._fld_req_url.setText(self._build_url(sel))
        self._cmb_method.setSelectedItem('GET')
        self._refresh_req_headers()

    def _refresh_req_headers(self):
        token_line = (
            'X-Auth-Token: ' + self._token
            if self._token
            else '# X-Auth-Token: (login first in Config tab)'
        )
        self._txt_req_headers.setText(
            '\n'.join([
                token_line,
                'Content-Type: application/json',
                'Accept: application/json',
                'OData-Version: 4.0',
            ])
        )

    def _on_send(self):
        url    = self._fld_req_url.getText().strip()
        method = str(self._cmb_method.getSelectedItem())
        body   = self._txt_req_body.getText().strip()
        hdrs   = self._txt_req_headers.getText().strip()
        # snapshot for history (captured before async work runs)
        self._pending_hist = {'method': method, 'url': url, 'headers': hdrs, 'body': body}

        if not url:
            self._lbl_resp_status.setText('No URL entered.')
            return

        self._btn_send.setEnabled(False)
        self._lbl_resp_status.setForeground(_STATUS_COLORS['neutral'])
        self._lbl_resp_status.setText('Sending...')
        self._txt_resp_headers.setText('')
        self._txt_resp_body.setText('')

        rtype = get_resource_type(url)
        self._lbl_resource_info.setText(
            'Resource: {0}   Risk: {1}'.format(rtype, get_resource_risk(url))
            if rtype else ' '
        )

        def work():
            return self._do_request(method, url, hdrs, body)

        def done(result):
            self._display_response(result)
            self._btn_send.setEnabled(True)
            # push to history
            entry = dict(self._pending_hist)
            entry['result'] = result
            self._req_history.append(entry)
            if len(self._req_history) > 30:
                self._req_history.pop(0)
            self._req_hist_idx = len(self._req_history)  # past-end = not navigating

        self._run_in_bg(work, done)

    def _on_send_to_burp_repeater(self):
        url    = self._fld_req_url.getText().strip()
        method = str(self._cmb_method.getSelectedItem())
        body   = self._txt_req_body.getText().strip()
        hdrs   = self._txt_req_headers.getText().strip()

        if not url:
            self._lbl_resp_status.setText('No URL entered.')
            return

        try:
            from java.net import URL as _JURL
            parsed   = _JURL(url)
            host     = parsed.getHost()
            port     = parsed.getPort()
            protocol = parsed.getProtocol()
            path     = parsed.getFile() or '/'
            use_https = protocol.lower() == 'https'
            if port == -1:
                port = 443 if use_https else 80

            host_hdr = host if port in (80, 443) else '{0}:{1}'.format(host, port)
            headers = ['{0} {1} HTTP/1.1'.format(method, path)]
            headers.append('Host: ' + host_hdr)
            if self._token:
                headers.append('X-Auth-Token: ' + self._token)
            headers.append('Accept: application/json')
            if method in ('POST', 'PATCH', 'PUT'):
                headers.append('Content-Type: application/json')
            for line in hdrs.splitlines():
                line = line.strip()
                if line and not line.startswith('#') and ':' in line:
                    headers.append(line)

            body_bytes = body.encode('utf-8') if body and method in ('POST', 'PATCH', 'PUT') else None
            request = self._helpers.buildHttpMessage(headers, body_bytes)
            self._callbacks.sendToRepeater(host, port, use_https, request, 'Redfisher')
            self._log('Sent to Burp Repeater: {0} {1}'.format(method, url))
        except Exception as ex:
            self._lbl_resp_status.setText('Error sending to Repeater: ' + str(ex))
            self._log('Send to Repeater error: ' + str(ex))

    def _do_request(self, method, url, headers_raw, body):
        """Execute HTTP request. Returns a plain dict. Runs on worker thread."""
        try:
            extra = {}
            for line in headers_raw.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ':' in line:
                    k, _, v = line.partition(':')
                    extra[k.strip()] = v.strip()

            data = (
                body.encode('utf-8')
                if body and method in ('POST', 'PATCH', 'PUT')
                else None
            )

            req = urllib2.Request(url, data=data)
            req.get_method = lambda m=method: m
            for k, v in extra.items():
                req.add_header(k, v)
            if 'Accept' not in extra:
                req.add_header('Accept', 'application/json')

            self._log('{0} {1}'.format(method, url))
            resp      = urllib2.urlopen(req, context=self._get_ssl_ctx(), timeout=20)
            status    = resp.getcode()
            resp_hdrs = str(resp.info())
            resp_body = resp.read()

        except urllib2.HTTPError as e:
            status    = e.code
            resp_hdrs = str(e.info()) if e.info() else ''
            try:
                resp_body = e.read()
            except Exception:
                resp_body = ''
        except Exception as ex:
            self._log('Request error: ' + str(ex))
            return {'status': None, 'headers': '', 'body': '', 'error': str(ex)}

        self._log('Response: HTTP {0}'.format(status))
        return {
            'status':  status,
            'headers': resp_hdrs,
            'body':    pretty_json(resp_body),
            'error':   None,
        }

    def _display_response(self, result):
        if result.get('error'):
            self._lbl_resp_status.setForeground(_STATUS_COLORS['error'])
            self._lbl_resp_status.setText('Error: ' + result['error'])
            return

        status = result['status']
        if status and 200 <= status < 300:
            color = _STATUS_COLORS['ok']
        elif status and status >= 400:
            color = _STATUS_COLORS['error']
        else:
            color = _STATUS_COLORS['neutral']

        self._lbl_resp_status.setForeground(color)
        self._lbl_resp_status.setText('HTTP {0}'.format(status or '???'))
        hdrs_text = result.get('headers', '')
        body_text = result.get('body', '')
        self._txt_resp_headers.setText(hdrs_text)
        self._txt_resp_headers.setCaretPosition(0)
        self._txt_resp_body.setText(body_text)
        self._txt_resp_body.setCaretPosition(0)
        # update vendor label from response headers
        hdrs_list = [line for line in hdrs_text.splitlines() if ':' in line]
        self._update_vendor_label(hdrs_list, body_text)
        # auto-populate request body if this is an ActionInfo response
        action_info = self._action_info_template(body_text)
        if action_info:
            action_url, body_json = action_info
            self._txt_req_body.setText(body_json)
            self._cmb_method.setSelectedItem('POST')
            if action_url:
                self._fld_req_url.setText(self._build_url(action_url))

    def _action_info_template(self, body_text):
        """
        Detects a Redfish ActionInfo response and returns (action_url, body_json).
        action_url is inferred from @odata.id; body_json is a ready-to-submit JSON template.
        Returns None if the response is not an ActionInfo.
        """
        try:
            data = json.loads(body_text)
        except Exception:
            return None

        if 'ActionInfo' not in data.get('@odata.type', ''):
            return None

        params = data.get('Parameters', [])
        if not params:
            return None

        _defaults = {
            'String':      '',
            'StringArray': [],
            'Integer':     0,
            'Number':      0.0,
            'Boolean':     False,
            'Object':      {},
        }
        body = {}
        for p in params:
            name  = p.get('Name', '')
            dtype = p.get('DataType', 'String')
            if not name:
                continue
            # required fields get a placeholder so they stand out
            if p.get('Required', False):
                body[name] = '<required>' if dtype == 'String' else _defaults.get(dtype, '')
            else:
                body[name] = _defaults.get(dtype, '')

        body_json = json.dumps(body, indent=2)

        # Infer action URL from @odata.id
        # e.g. /redfish/v1/EventService/SubmitTestEventActionInfo
        #   -> /redfish/v1/EventService/Actions/EventService.SubmitTestEvent
        action_url = None
        odata_id = data.get('@odata.id', '')
        if odata_id:
            try:
                segments = odata_id.rstrip('/').split('/')
                last     = segments[-1]                   # SubmitTestEventActionInfo
                parent   = '/'.join(segments[:-1])        # /redfish/v1/EventService
                svc_name = segments[-2] if len(segments) >= 2 else ''  # EventService
                if last.endswith('ActionInfo'):
                    action_name = last[:-len('ActionInfo')]  # SubmitTestEvent
                    action_url  = '{0}/Actions/{1}.{2}'.format(parent, svc_name, action_name)
            except Exception:
                pass

        return action_url, body_json

    # ------------------------------------------------------------------
    # Explorer tab actions
    # ------------------------------------------------------------------

    def _on_discover(self):
        if not self._host:
            self._lbl_explorer_status.setText('Configure host in Config tab first.')
            return
        self._btn_discover.setEnabled(False)
        self._lbl_explorer_status.setForeground(_STATUS_COLORS['neutral'])
        self._lbl_explorer_status.setText('Discovering...')
        self._explorer_model.clear()
        self._txt_explorer_detail.setText('')
        self._lbl_explorer_resp_status.setText(u'\u2014')
        self._explorer_fetch_seq += 1  # cancel any in-flight explorer fetch

        def work():
            return self._fetch_top_level_links()

        def done(links):
            self._explorer_model.clear()
            if isinstance(links, basestring):  # noqa: F821 — Jython 2.7 builtin
                self._lbl_explorer_status.setForeground(_STATUS_COLORS['error'])
                self._lbl_explorer_status.setText(links)
            else:
                for path in links:
                    self._explorer_model.addElement(path)
                    # restore previously discovered children for this path
                    for child in self._explorer_children.get(path, []):
                        self._explorer_model.addElement(EXPLORER_CHILD_PREFIX + child)
                self._lbl_explorer_status.setForeground(_STATUS_COLORS['ok'])
                self._lbl_explorer_status.setText('Found {0} links.'.format(len(links)))
            self._btn_discover.setEnabled(True)

        self._run_in_bg(work, done)

    def _fetch_top_level_links(self):
        """GET /redfish/v1/ and return all @odata.id paths (including OEM). Worker thread."""
        url = self._build_url('/redfish/v1/')
        try:
            req = urllib2.Request(url)
            if self._token:
                req.add_header('X-Auth-Token', self._token)
            req.add_header('Accept', 'application/json')
            resp = urllib2.urlopen(req, context=self._get_ssl_ctx(), timeout=15)
            data = json.loads(resp.read())
            links = sorted(set(
                self._extract_all_odata_ids(data) +
                self._extract_oem_children_paths(data)
            ))
            self._log('Explorer: found {0} links (including OEM Children).'.format(len(links)))
            return links
        except Exception as ex:
            self._log('Explorer error: ' + str(ex))
            return 'Error: ' + str(ex)

    @staticmethod
    def _extract_all_odata_ids(data, found=None):
        """
        Recursively walk any JSON dict/list and collect every @odata.id string.
        Catches OEM endpoints nested at any depth under Oem, Links, etc.
        """
        if found is None:
            found = []
        if isinstance(data, dict):
            val = data.get('@odata.id')
            if isinstance(val, basestring) and val.startswith('/'):  # noqa: F821
                found.append(val)
            for v in data.values():
                RedfishAuthHandler._extract_all_odata_ids(v, found)
        elif isinstance(data, list):
            for item in data:
                RedfishAuthHandler._extract_all_odata_ids(item, found)
        return found

    @staticmethod
    def _extract_oem_children_paths(data, found=None):
        """
        Recursively walk JSON and synthesise /redfish/v1/Oem/<vendor>/<child> paths
        from any Oem.<vendor>.Children array found at any depth.

        Child names starting with '.' have the leading dot stripped
        (e.g. '.HiddenResources' → 'HiddenResources').
        """
        if found is None:
            found = []
        if isinstance(data, dict):
            oem = data.get('Oem')
            if isinstance(oem, dict):
                for vendor, vendor_data in oem.items():
                    if not isinstance(vendor_data, dict):
                        continue
                    children = vendor_data.get('Children')
                    if isinstance(children, list):
                        for child in children:
                            if not isinstance(child, basestring):  # noqa: F821
                                continue
                            name = child.lstrip('.')
                            if name:
                                found.append(
                                    '/redfish/v1/Oem/{0}/{1}'.format(vendor, name)
                                )
            for v in data.values():
                RedfishAuthHandler._extract_oem_children_paths(v, found)
        elif isinstance(data, list):
            for item in data:
                RedfishAuthHandler._extract_oem_children_paths(item, found)
        return found

    @staticmethod
    def _extract_action_links(data, found=None):
        """
        Recursively collect @Redfish.ActionInfo and target paths from every
        Actions object at any depth.  Both keys are vendor-independent and
        reliably mark action endpoints.
        """
        if found is None:
            found = []
        if isinstance(data, dict):
            actions = data.get('Actions')
            if isinstance(actions, dict):
                for action_data in actions.values():
                    if not isinstance(action_data, dict):
                        continue
                    for key in ('@Redfish.ActionInfo', 'target'):
                        val = action_data.get(key)
                        if (isinstance(val, basestring)  # noqa: F821
                                and val.startswith('/') and val not in found):
                            found.append(val)
            for v in data.values():
                RedfishAuthHandler._extract_action_links(v, found)
        elif isinstance(data, list):
            for item in data:
                RedfishAuthHandler._extract_action_links(item, found)
        return found

    def _add_explorer_child(self, parent_entry, child_path):
        """
        Insert child_path (indented) after parent_entry and its existing children.
        Also records the relationship in _explorer_children so it survives Discover.
        Skips silently if already present.
        """
        # persist so Discover re-runs can restore this child
        parent_path = explorer_actual_path(_u(parent_entry))
        known = self._explorer_children.setdefault(parent_path, [])
        if child_path not in known:
            known.append(child_path)

        child_entry = EXPLORER_CHILD_PREFIX + child_path
        for i in range(self._explorer_model.size()):
            if _u(self._explorer_model.get(i)) == child_entry:
                return  # already in the visual list
        # find insertion point: end of this parent's child block
        insert_at = self._explorer_model.size()
        parent_str = _u(parent_entry)
        for i in range(self._explorer_model.size()):
            if _u(self._explorer_model.get(i)) == parent_str:
                j = i + 1
                while j < self._explorer_model.size():
                    if _u(self._explorer_model.get(j)).startswith(EXPLORER_CHILD_PREFIX):
                        j += 1
                    else:
                        break
                insert_at = j
                break
        self._explorer_model.insertElementAt(child_entry, insert_at)

    def _add_to_explorer(self, entry):
        """
        Add entry to the Explorer list, deduped.
        If entry is a child-prefixed path, tries to place it under its parent.
        """
        entry    = _u(entry)
        existing = [_u(self._explorer_model.get(i))
                    for i in range(self._explorer_model.size())]
        if entry in existing:
            return
        if entry.startswith(EXPLORER_CHILD_PREFIX):
            actual = entry[len(EXPLORER_CHILD_PREFIX):]
            # find closest parent already in list
            best_parent = None
            for ex in existing:
                if not ex.startswith(EXPLORER_CHILD_PREFIX) and actual.startswith(ex):
                    if best_parent is None or len(ex) > len(best_parent):
                        best_parent = ex
            if best_parent:
                self._add_explorer_child(best_parent, actual)
                return
        self._explorer_model.addElement(entry)

    def _on_parse_oem_json(self):
        """
        Extract @odata.id links, Oem.Children paths, AND action links from the
        pasted JSON.  Action links are shown indented under their parent resource.
        """
        raw = self._txt_oem_input.getText().strip()
        if not raw:
            self._lbl_oem_status.setText('Paste a JSON body first.')
            return
        try:
            data         = json.loads(raw)
            # parent @odata.id of this pasted resource (used to attach action children)
            parent_path  = data.get('@odata.id', '') if isinstance(data, dict) else ''
            top_links    = sorted(set(
                self._extract_all_odata_ids(data) +
                self._extract_oem_children_paths(data)
            ))
            action_links = sorted(set(self._extract_action_links(data)))
            self._oem_extract_model.clear()
            for link in top_links:
                self._oem_extract_model.addElement(link)
            # action links shown indented under the resource's own @odata.id
            for link in action_links:
                if link not in top_links:
                    self._oem_extract_model.addElement(EXPLORER_CHILD_PREFIX + link)
            total = len(top_links) + len(action_links)
            self._lbl_oem_status.setText(
                'Found {0} link(s) ({1} action link(s)).'.format(total, len(action_links))
            )
        except ValueError as e:
            self._lbl_oem_status.setText('JSON parse error: ' + str(e))

    def _on_add_oem_selected(self):
        """Add the selected extracted links to the main discovered list."""
        selected = self._lst_oem_extract.getSelectedValuesList()
        added = 0
        for entry in selected:
            before = self._explorer_model.size()
            self._add_to_explorer(_u(entry))
            if self._explorer_model.size() > before:
                added += 1
        self._lbl_oem_status.setText('Added {0} link(s) to Explorer.'.format(added))

    def _on_add_oem_all(self):
        """Add all extracted links to the main discovered list."""
        added = 0
        for i in range(self._oem_extract_model.size()):
            before = self._explorer_model.size()
            self._add_to_explorer(_u(self._oem_extract_model.get(i)))
            if self._explorer_model.size() > before:
                added += 1
        self._lbl_oem_status.setText('Added {0} link(s) to Explorer.'.format(added))

    def _show_oem_popup(self, e, popup):
        """Select the right-clicked item in the OEM extract list and show its menu."""
        idx = self._lst_oem_extract.locationToIndex(e.getPoint())
        if idx >= 0:
            self._lst_oem_extract.setSelectedIndex(idx)
        popup.show(e.getComponent(), e.getX(), e.getY())

    def _oem_selected_path(self):
        """Return the actual Redfish path of the currently selected OEM extract item."""
        entry = self._lst_oem_extract.getSelectedValue()
        if entry is None:
            return None
        return explorer_actual_path(_u(entry))

    def _oem_send_to_repeater(self):
        """Send the right-clicked OEM extract link to the Request/Response tab."""
        path = self._oem_selected_path()
        if not path:
            return
        self._fld_req_url.setText(self._build_url(path))
        self._cmb_method.setSelectedItem('GET')
        self._refresh_req_headers()
        self._tabs.setSelectedIndex(1)

    def _oem_send_to_scanner(self):
        """Send the right-clicked OEM extract link to the Scanner target field."""
        path = self._oem_selected_path()
        if not path:
            return
        self._scanner_tab.add_scan_target(self._build_url(path))
        self._tabs.setSelectedIndex(3)

    def _show_explorer_popup(self, e):
        """
        Capture the right-clicked entry, select it visually (suppressing the
        fetch that _on_explorer_select would normally start), then show the menu.
        """
        idx = self._lst_explorer.locationToIndex(e.getPoint())
        if idx >= 0:
            self._ctx_menu_entry = _u(self._explorer_model.get(idx))
            self._suppress_explorer_fetch = True
            self._lst_explorer.setSelectedIndex(idx)  # visual highlight only
            self._suppress_explorer_fetch = False
        self._explorer_popup.show(e.getComponent(), e.getX(), e.getY())

    def _on_explorer_select(self, event):
        if event.getValueIsAdjusting() or self._suppress_explorer_fetch:
            return
        entry = self._lst_explorer.getSelectedValue()
        if not entry:
            return

        entry    = _u(entry)
        path     = explorer_actual_path(entry)
        full_url = self._build_url(path)

        # bump sequence so any in-flight request for a previous selection is discarded
        self._explorer_fetch_seq += 1
        my_seq = self._explorer_fetch_seq

        self._lbl_explorer_resp_status.setForeground(_STATUS_COLORS['neutral'])
        self._lbl_explorer_resp_status.setText('Loading...')
        self._txt_explorer_detail.setText('')

        token         = self._token
        captured_entry = _u(entry)  # unicode-safe explicit capture

        def work():
            hdrs = ('X-Auth-Token: {0}\nAccept: application/json'.format(token)
                    if token else 'Accept: application/json')
            return self._do_request('GET', full_url, hdrs, '')

        def done(result):
            if my_seq != self._explorer_fetch_seq:
                return  # user already clicked another link; discard stale result
            if result.get('error'):
                self._lbl_explorer_resp_status.setForeground(_STATUS_COLORS['error'])
                self._lbl_explorer_resp_status.setText('Error')
                self._txt_explorer_detail.setText(result['error'])
            else:
                status = result['status']
                color  = _STATUS_COLORS['ok'] if 200 <= status < 300 else _STATUS_COLORS['error']
                self._lbl_explorer_resp_status.setForeground(color)
                self._lbl_explorer_resp_status.setText('HTTP {0}'.format(status))
                body = result.get('body', '')
                self._txt_explorer_detail.setText(body)
                # auto-discover action links and attach as children
                try:
                    action_links = self._extract_action_links(json.loads(body))
                    for child in action_links:
                        self._add_explorer_child(captured_entry, child)
                except Exception:
                    pass
            self._txt_explorer_detail.setCaretPosition(0)

        self._run_in_bg(work, done)

    def _explorer_send_to_repeater(self):
        """Send the right-clicked Explorer link to the Request/Response tab."""
        entry = self._ctx_menu_entry
        if not entry:
            return
        self._fld_req_url.setText(self._build_url(explorer_actual_path(entry)))
        self._cmb_method.setSelectedItem('GET')
        self._refresh_req_headers()
        self._tabs.setSelectedIndex(1)

    def _explorer_send_to_scanner(self):
        """Send the right-clicked Explorer link to the Scanner target field."""
        entry = self._ctx_menu_entry
        if not entry:
            return
        full_url = self._build_url(explorer_actual_path(entry))
        self._scanner_tab.add_scan_target(full_url)
        self._tabs.setSelectedIndex(3)

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _refresh_explorer_count(self):
        """Update the link-count label next to the Discover button."""
        total    = self._explorer_model.size()
        parents  = sum(
            1 for i in range(total)
            if not _u(self._explorer_model.get(i)).startswith(EXPLORER_CHILD_PREFIX)
        )
        children = total - parents
        if children:
            text = u'{0} links  ({1} actions)'.format(parents, children)
        else:
            text = u'{0} links'.format(parents)
        def update():
            self._lbl_explorer_count.setText(text)
        SwingUtilities.invokeLater(update)

    # ------------------------------------------------------------------
    # Vendor detection
    # ------------------------------------------------------------------

    def _update_vendor_label(self, resp_headers_list, body_str):
        vendor = detect_vendor(resp_headers_list, body_str)
        def update():
            self._lbl_vendor.setText('Vendor: ' + vendor)
            self._lbl_vendor.setForeground(
                _STATUS_COLORS['ok'] if vendor != 'Unknown' else _STATUS_COLORS['neutral']
            )
        SwingUtilities.invokeLater(update)

    # ------------------------------------------------------------------
    # Request history navigation
    # ------------------------------------------------------------------

    def _on_history_prev(self):
        if not self._req_history:
            return
        if self._req_hist_idx > 0:
            self._req_hist_idx -= 1
        self._load_history_entry(self._req_hist_idx)

    def _on_history_next(self):
        if not self._req_history:
            return
        if self._req_hist_idx < len(self._req_history) - 1:
            self._req_hist_idx += 1
            self._load_history_entry(self._req_hist_idx)

    def _load_history_entry(self, idx):
        if idx < 0 or idx >= len(self._req_history):
            return
        entry = self._req_history[idx]
        self._fld_req_url.setText(entry.get('url', ''))
        self._cmb_method.setSelectedItem(entry.get('method', 'GET'))
        self._txt_req_headers.setText(entry.get('headers', ''))
        self._txt_req_body.setText(entry.get('body', ''))
        result = entry.get('result')
        if result:
            self._display_response(result)
        status_suffix = ' [{0}/{1}]'.format(idx + 1, len(self._req_history))
        self._lbl_resp_status.setText(
            self._lbl_resp_status.getText().split(' [')[0] + status_suffix
        )

    # ------------------------------------------------------------------
    # Explorer auto-walk
    # ------------------------------------------------------------------

    def _on_auto_walk(self):
        if not self._host:
            self._lbl_explorer_status.setText('Configure host first.')
            return
        self._btn_auto_walk.setEnabled(False)
        self._btn_discover.setEnabled(False)
        self._lbl_explorer_status.setForeground(_STATUS_COLORS['neutral'])
        self._lbl_explorer_status.setText('Spidering tree...')

        def work():
            return self._auto_walk_links()

        def done(result):
            self._btn_auto_walk.setEnabled(True)
            self._btn_discover.setEnabled(True)
            if isinstance(result, basestring):  # noqa: F821
                self._lbl_explorer_status.setForeground(_STATUS_COLORS['error'])
                self._lbl_explorer_status.setText(result)
            else:
                count = result
                self._lbl_explorer_status.setForeground(_STATUS_COLORS['ok'])
                self._lbl_explorer_status.setText(
                    'Spider completed — {0} unique link(s).'.format(count)
                )

        self._run_in_bg(work, done)

    def _auto_walk_links(self, max_depth=3, max_links=200):
        """
        BFS walk from /redfish/v1/, following every @odata.id link.
        Adds new paths to the explorer model; returns total count or error string.
        """
        visited = set()
        queue   = ['/redfish/v1/']
        depth   = {'/redfish/v1/': 0}

        while queue:
            path = queue.pop(0)
            if path in visited:
                continue
            if len(visited) >= max_links:
                break
            visited.add(path)

            # add to explorer on EDT
            def _add(p=path):
                self._add_to_explorer(p)
            SwingUtilities.invokeLater(_add)

            current_depth = depth.get(path, 0)
            if current_depth >= max_depth:
                continue

            try:
                url = self._build_url(path)
                req = urllib2.Request(url)
                if self._token:
                    req.add_header('X-Auth-Token', self._token)
                req.add_header('Accept', 'application/json')
                resp = urllib2.urlopen(req, context=self._get_ssl_ctx(), timeout=10)
                if resp.getcode() != 200:
                    continue
                data  = json.loads(resp.read())
                links = (
                    self._extract_all_odata_ids(data) +
                    self._extract_oem_children_paths(data) +
                    self._extract_action_links(data)
                )
                for link in links:
                    if link not in visited and link not in depth:
                        depth[link] = current_depth + 1
                        queue.append(link)
            except Exception as ex:
                self._log('Spider error at {0}: {1}'.format(path, ex))

        return len(visited)

    def _set_status(self, message, level='neutral'):
        color = _STATUS_COLORS.get(level, _STATUS_COLORS['neutral'])
        def update():
            self._lbl_status.setForeground(color)
            self._lbl_status.setText(message)
        SwingUtilities.invokeLater(update)

    def _log(self, message):
        self._stdout.println('[Redfisher] ' + message)
        def append():
            self._txt_log.append(message + '\n')
            self._txt_log.setCaretPosition(self._txt_log.getDocument().getLength())
        SwingUtilities.invokeLater(append)
