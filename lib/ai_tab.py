# -*- coding: utf-8 -*-
"""
AITab — AI / MCP assisted Redfish pentesting.

Supports three backends (user-selectable):
  1. Claude API (Direct)       — Anthropic hosted models
  2. OpenAI-compatible API     — Ollama, Together, any /v1/chat/completions server
  3. MCP Server (HTTP/JSON-RPC) — any MCP server reachable over HTTP

Tabs:
  Connection  — configure endpoint, key, model; test connectivity
  Analyze     — send Explorer URLs / single URL / findings to the AI
  MCP Tools   — browse and manually invoke tools on a connected MCP server
  Results     — scrolling log of all AI responses; import to Scanner
"""

import json
import ssl
import urllib2

from java.lang import Thread, Runnable
from javax.swing import (
    JPanel, JLabel, JTextField, JPasswordField, JButton, JComboBox,
    JTextArea, JScrollPane, JTabbedPane, JSplitPane, JList,
    DefaultListModel, BorderFactory, SwingUtilities,
)
from java.awt import BorderLayout, FlowLayout, GridLayout, Color, Font

_MONO = Font('Monospaced', Font.PLAIN, 12)

_MODES = ['Claude API (Direct)', 'OpenAI-compatible API', 'MCP Server (HTTP)']

_CLAUDE_URL    = 'https://api.anthropic.com/v1/messages'
_CLAUDE_MODELS = ['claude-opus-4-6', 'claude-sonnet-4-6', 'claude-haiku-4-5-20251001']

_SYSTEM_PROMPT = (
    'You are an expert penetration tester specialising in Redfish API security '
    'and BMC (Baseboard Management Controller) hardening.\n'
    'Analyse the provided Redfish API data for vulnerabilities including but not '
    'limited to: authentication/authorisation bypass, sensitive data exposure, '
    'missing security headers, insecure transport, default credentials, OEM '
    'endpoint misconfigurations, excessive data disclosure, and injection vectors.\n\n'
    'Format your response with three sections:\n'
    'FINDINGS — severity (Critical/High/Medium/Low/Info), description, evidence, remediation\n'
    'RECOMMENDATIONS — prioritised hardening actions\n'
    'RISK SUMMARY — one-paragraph overall assessment'
)

_ANALYSIS_TYPES = [
    'Full Redfish Pentest',
    'Authentication & Authorisation',
    'Sensitive Data Exposure',
    'Missing / Weak Security Headers',
    'Default Credentials Risk',
    'OEM Endpoint Analysis',
    'Transport Security (HTTP/TLS)',
]

_MODE_HINTS = {
    'Claude API (Direct)': (
        'API URL : https://api.anthropic.com  (pre-filled)\n'
        'API Key : obtain from console.anthropic.com\n'
        'Model   : select from the list\n\n'
        'Redfisher sends endpoint data directly to Claude and shows\n'
        'the analysis in the Results tab.'
    ),
    'OpenAI-compatible API': (
        'API URL : e.g. http://localhost:11434  (Ollama)\n'
        '          or any /v1/chat/completions-compatible server\n'
        'API Key : leave blank for local models; required for hosted APIs\n'
        'Model   : type the model name (e.g. llama3, mistral, gpt-4o)\n\n'
        'Redfisher will POST to <URL>/v1/chat/completions.'
    ),
    'MCP Server (HTTP)': (
        'API URL : e.g. http://localhost:3000  (your MCP server)\n'
        'API Key : optional Bearer token for the MCP server\n\n'
        'Redfisher acts as an MCP client over HTTP/JSON-RPC 2.0.\n'
        'After connecting, the MCP Tools tab shows available tools.\n'
        'The Analyze tab will call an "analyze" / "pentest" tool if present;\n'
        'otherwise it lists available tools for manual invocation.'
    ),
}


def _to_unicode(x):
    """Unicode-safe coercion — identical pattern to auth_handler._u()."""
    if isinstance(x, unicode):   # noqa: F821  Jython 2.7 built-in
        return x
    try:
        return unicode(x)         # noqa: F821
    except Exception:
        return repr(x)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class AITab(object):

    def __init__(self, auth_handler):
        self._auth       = auth_handler
        self._mcp_tools  = []   # list of dicts from tools/list
        self._ssl_ctx    = None
        self._panel      = self._build_ui()

    def get_panel(self):
        return self._panel

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        outer = JPanel(BorderLayout(4, 4))
        outer.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))
        self._ai_tabs = JTabbedPane()
        self._ai_tabs.addTab('Connection', self._build_connection_tab())
        self._ai_tabs.addTab('Analyze',    self._build_analyze_tab())
        self._ai_tabs.addTab('MCP Tools',  self._build_mcp_tools_tab())
        self._ai_tabs.addTab('Results',    self._build_results_tab())
        outer.add(self._ai_tabs, BorderLayout.CENTER)
        return outer

    # ---- Connection tab ----

    def _build_connection_tab(self):
        panel = JPanel(BorderLayout(8, 8))
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        form = JPanel(GridLayout(0, 2, 8, 6))
        form.setBorder(BorderFactory.createTitledBorder('AI / MCP Connection'))

        self._cmb_mode   = JComboBox(_MODES)
        self._fld_url    = JTextField('https://api.anthropic.com', 40)
        self._fld_key    = JPasswordField(40)
        self._fld_model  = JTextField('claude-opus-4-6', 30)

        for lbl, widget in [
            ('Mode:',          self._cmb_mode),
            ('API / Server URL:', self._fld_url),
            ('API Key:',       self._fld_key),
            ('Model:',         self._fld_model),
        ]:
            form.add(JLabel(lbl))
            form.add(widget)

        self._cmb_mode.addActionListener(lambda e: self._on_mode_change())

        btn_connect = JButton('Connect / Test')
        btn_connect.addActionListener(lambda e: self._on_connect())

        self._lbl_conn_status = JLabel('Not connected.')
        self._lbl_conn_status.setForeground(Color(100, 100, 100))

        btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        btn_row.add(btn_connect)
        btn_row.add(self._lbl_conn_status)

        top = JPanel(BorderLayout())
        top.add(form,    BorderLayout.CENTER)
        top.add(btn_row, BorderLayout.SOUTH)

        self._txt_hint = JTextArea()
        self._txt_hint.setFont(_MONO)
        self._txt_hint.setEditable(False)
        self._txt_hint.setLineWrap(True)
        self._txt_hint.setWrapStyleWord(True)
        self._txt_hint.setText(_MODE_HINTS['Claude API (Direct)'])

        panel.add(top,                        BorderLayout.NORTH)
        panel.add(JScrollPane(self._txt_hint), BorderLayout.CENTER)
        return panel

    # ---- Analyze tab ----

    def _build_analyze_tab(self):
        panel = JPanel(BorderLayout(6, 6))
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        target_form = JPanel(GridLayout(0, 2, 6, 6))
        target_form.setBorder(BorderFactory.createTitledBorder('Target'))

        self._fld_ai_target   = JTextField(40)
        self._cmb_analysis    = JComboBox(_ANALYSIS_TYPES)

        target_form.add(JLabel('URL (blank = use all Explorer URLs):'))
        target_form.add(self._fld_ai_target)
        target_form.add(JLabel('Analysis type:'))
        target_form.add(self._cmb_analysis)

        self._txt_extra = JTextArea(4, 0)
        self._txt_extra.setFont(_MONO)
        self._txt_extra.setLineWrap(True)
        self._txt_extra.setWrapStyleWord(True)
        self._txt_extra.setText('Optional extra instructions...')
        extra_scroll = JScrollPane(self._txt_extra)
        extra_scroll.setBorder(BorderFactory.createTitledBorder('Extra Instructions'))

        btn_url      = JButton('Analyze URL')
        btn_explorer = JButton('Analyze Explorer URLs')
        btn_findings = JButton('Analyze Current Findings')
        btn_payload  = JButton('Generate Payload')
        btn_cve      = JButton('CVE Lookup (Firmware)')
        btn_url.addActionListener(     lambda e: self._on_analyze_url())
        btn_explorer.addActionListener(lambda e: self._on_analyze_explorer())
        btn_findings.addActionListener(lambda e: self._on_analyze_findings())
        btn_payload.addActionListener( lambda e: self._on_generate_payload())
        btn_cve.addActionListener(     lambda e: self._on_cve_lookup())

        self._lbl_ai_status = JLabel('')
        btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        btn_row.add(btn_url)
        btn_row.add(btn_explorer)
        btn_row.add(btn_findings)
        btn_row.add(btn_payload)
        btn_row.add(btn_cve)
        btn_row.add(self._lbl_ai_status)

        north = JPanel(BorderLayout(4, 4))
        north.add(target_form, BorderLayout.NORTH)
        north.add(extra_scroll, BorderLayout.CENTER)

        panel.add(north,   BorderLayout.CENTER)
        panel.add(btn_row, BorderLayout.SOUTH)
        return panel

    # ---- MCP Tools tab ----

    def _build_mcp_tools_tab(self):
        panel = JPanel(BorderLayout(6, 6))
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        self._mcp_model = DefaultListModel()
        self._lst_tools = JList(self._mcp_model)
        self._lst_tools.setFont(_MONO)
        self._lst_tools.addListSelectionListener(
            lambda e: self._on_tool_select(e)
        )
        tools_scroll = JScrollPane(self._lst_tools)
        tools_scroll.setBorder(BorderFactory.createTitledBorder('Available Tools'))
        tools_scroll.setPreferredSize(
            tools_scroll.getPreferredSize().__class__(240, 0)
        )

        self._txt_tool_detail = JTextArea()
        self._txt_tool_detail.setFont(_MONO)
        self._txt_tool_detail.setEditable(False)
        detail_scroll = JScrollPane(self._txt_tool_detail)
        detail_scroll.setBorder(BorderFactory.createTitledBorder('Tool Schema'))

        top_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tools_scroll, detail_scroll)
        top_split.setResizeWeight(0.3)

        self._txt_tool_args = JTextArea(4, 0)
        self._txt_tool_args.setFont(_MONO)
        self._txt_tool_args.setText('{}')
        args_scroll = JScrollPane(self._txt_tool_args)
        args_scroll.setBorder(BorderFactory.createTitledBorder('Call Arguments (JSON)'))

        btn_refresh = JButton('Refresh Tools')
        btn_call    = JButton('Call Tool')
        btn_refresh.addActionListener(lambda e: self._on_refresh_tools())
        btn_call.addActionListener(   lambda e: self._on_call_tool())

        self._lbl_tool_status = JLabel('')
        tool_btn_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        tool_btn_row.add(btn_refresh)
        tool_btn_row.add(btn_call)
        tool_btn_row.add(self._lbl_tool_status)

        bottom = JPanel(BorderLayout())
        bottom.add(args_scroll,   BorderLayout.CENTER)
        bottom.add(tool_btn_row,  BorderLayout.SOUTH)

        outer = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_split, bottom)
        outer.setResizeWeight(0.65)

        panel.add(outer, BorderLayout.CENTER)
        return panel

    # ---- Results tab ----

    def _build_results_tab(self):
        panel = JPanel(BorderLayout(4, 4))
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6))

        self._txt_results = JTextArea()
        self._txt_results.setFont(_MONO)
        self._txt_results.setEditable(False)
        self._txt_results.setLineWrap(True)
        self._txt_results.setWrapStyleWord(True)

        btn_clear  = JButton('Clear')
        btn_import = JButton('Import Findings to Scanner')
        btn_clear.addActionListener( lambda e: self._txt_results.setText(''))
        btn_import.addActionListener(lambda e: self._on_import_findings())

        btn_row = JPanel(FlowLayout(FlowLayout.RIGHT))
        btn_row.add(btn_import)
        btn_row.add(btn_clear)

        panel.add(JScrollPane(self._txt_results), BorderLayout.CENTER)
        panel.add(btn_row,                        BorderLayout.SOUTH)
        return panel

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_mode(self):
        return str(self._cmb_mode.getSelectedItem())

    def _get_api_key(self):
        return ''.join(self._fld_key.getPassword())

    def _get_base_url(self):
        return self._fld_url.getText().strip().rstrip('/')

    def _get_model(self):
        return self._fld_model.getText().strip()

    def _get_ssl_ctx(self):
        if self._ssl_ctx is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            self._ssl_ctx = ctx
        return self._ssl_ctx

    def _run_in_bg(self, work_fn, done_fn):
        class Worker(Runnable):
            def run(self_w):
                result = work_fn()
                class Updater(Runnable):
                    def run(self_u): done_fn(result)
                SwingUtilities.invokeLater(Updater())
        Thread(Worker()).start()

    def _set_status(self, lbl, msg, ok=None):
        def update():
            if ok is True:
                lbl.setForeground(Color(50, 150, 50))
            elif ok is False:
                lbl.setForeground(Color(200, 50, 50))
            else:
                lbl.setForeground(Color(100, 100, 100))
            lbl.setText(msg)
        SwingUtilities.invokeLater(update)

    def _append_result(self, text):
        def update():
            self._txt_results.append(text + '\n')
            self._txt_results.setCaretPosition(
                self._txt_results.getDocument().getLength()
            )
        SwingUtilities.invokeLater(update)

    # ------------------------------------------------------------------
    # Connection tab actions
    # ------------------------------------------------------------------

    def _on_mode_change(self):
        mode = self._get_mode()
        hint = _MODE_HINTS.get(mode, '')
        if 'Claude' in mode:
            self._fld_url.setText('https://api.anthropic.com')
            self._fld_model.setText('claude-opus-4-6')
        elif 'OpenAI' in mode:
            self._fld_url.setText('http://localhost:11434')
            self._fld_model.setText('llama3')
        elif 'MCP' in mode:
            self._fld_url.setText('http://localhost:3000')
            self._fld_model.setText('')
        self._ssl_ctx = None
        self._txt_hint.setText(hint)

    def _on_connect(self):
        self._ssl_ctx = None
        self._set_status(self._lbl_conn_status, 'Connecting...', None)
        mode = self._get_mode()

        def work():
            if 'Claude' in mode:
                return self._test_claude()
            elif 'OpenAI' in mode:
                return self._test_openai()
            elif 'MCP' in mode:
                return self._test_mcp()
            return False, 'Unknown mode.'

        def done(result):
            ok, msg = result
            self._set_status(self._lbl_conn_status, msg, ok)

        self._run_in_bg(work, done)

    def _test_claude(self):
        key = self._get_api_key()
        if not key:
            return False, 'API key required.'
        try:
            payload = json.dumps({
                'model':      self._get_model() or 'claude-opus-4-6',
                'max_tokens': 5,
                'messages':   [{'role': 'user', 'content': 'Hi'}],
            })
            req = urllib2.Request(_CLAUDE_URL, data=payload.encode('utf-8'))
            req.add_header('x-api-key',         key)
            req.add_header('anthropic-version', '2023-06-01')
            req.add_header('content-type',      'application/json')
            resp = urllib2.urlopen(req, context=self._get_ssl_ctx(), timeout=15)
            return resp.getcode() in (200, 201), 'Claude API connected.'
        except urllib2.HTTPError as e:
            if e.code == 401:
                return False, 'Invalid API key (401 Unauthorized).'
            return False, 'HTTP {0}: {1}'.format(e.code, e.reason)
        except Exception as ex:
            return False, str(ex)

    def _test_openai(self):
        try:
            url = self._get_base_url() + '/v1/models'
            req = urllib2.Request(url)
            key = self._get_api_key()
            if key:
                req.add_header('Authorization', 'Bearer ' + key)
            req.add_header('Accept', 'application/json')
            resp = urllib2.urlopen(req, context=self._get_ssl_ctx(), timeout=10)
            data = json.loads(resp.read())
            n    = len(data.get('data', []))
            return True, 'Connected — {0} model(s) available.'.format(n)
        except urllib2.HTTPError as e:
            return False, 'HTTP {0}: {1}'.format(e.code, e.reason)
        except Exception as ex:
            return False, str(ex)

    def _test_mcp(self):
        ok, msg, tools = self._mcp_initialize()
        if ok:
            self._mcp_tools = tools
            def update():
                self._mcp_model.clear()
                for t in tools:
                    self._mcp_model.addElement(t.get('name', '?'))
            SwingUtilities.invokeLater(update)
            return True, 'MCP connected — {0} tool(s).'.format(len(tools))
        return False, msg

    # ------------------------------------------------------------------
    # MCP JSON-RPC helpers
    # ------------------------------------------------------------------

    def _mcp_call(self, method, params=None, rpc_id=1):
        """POST a JSON-RPC 2.0 request to <server>/mcp. Returns (ok, result_or_error)."""
        url = self._get_base_url() + '/mcp'
        try:
            payload = json.dumps({
                'jsonrpc': '2.0',
                'id':      rpc_id,
                'method':  method,
                'params':  params or {},
            })
            req = urllib2.Request(url, data=payload.encode('utf-8'))
            req.add_header('Content-Type', 'application/json')
            key = self._get_api_key()
            if key:
                req.add_header('Authorization', 'Bearer ' + key)
            resp = urllib2.urlopen(req, context=self._get_ssl_ctx(), timeout=60)
            data = json.loads(resp.read())
            if 'error' in data:
                return False, data['error'].get('message', str(data['error']))
            return True, data.get('result', {})
        except Exception as ex:
            return False, str(ex)

    def _mcp_initialize(self):
        """Initialize MCP session and list tools. Returns (ok, msg, tools_list)."""
        ok, result = self._mcp_call('initialize', {
            'protocolVersion': '2024-11-05',
            'capabilities':    {'roots': {}, 'sampling': {}},
            'clientInfo':      {'name': 'Redfisher', 'version': '1.0.0'},
        })
        if not ok:
            return False, 'MCP init failed: ' + str(result), []
        ok2, tools_result = self._mcp_call('tools/list', rpc_id=2)
        if not ok2:
            return True, 'Connected (no tools endpoint)', []
        tools = tools_result.get('tools', []) if isinstance(tools_result, dict) else []
        return True, 'OK', tools

    # ------------------------------------------------------------------
    # AI call dispatch
    # ------------------------------------------------------------------

    def _call_claude(self, prompt):
        key = self._get_api_key()
        if not key:
            return False, 'API key not configured.'
        try:
            payload = json.dumps({
                'model':      self._get_model() or 'claude-opus-4-6',
                'max_tokens': 4096,
                'system':     _SYSTEM_PROMPT,
                'messages':   [{'role': 'user', 'content': prompt}],
            })
            req = urllib2.Request(_CLAUDE_URL, data=payload.encode('utf-8'))
            req.add_header('x-api-key',         key)
            req.add_header('anthropic-version', '2023-06-01')
            req.add_header('content-type',      'application/json')
            resp = urllib2.urlopen(req, context=self._get_ssl_ctx(), timeout=120)
            data = json.loads(resp.read())
            text = data.get('content', [{}])[0].get('text', '')
            return True, text
        except urllib2.HTTPError as e:
            try:
                err = json.loads(e.read()).get('error', {}).get('message', e.reason)
            except Exception:
                err = e.reason
            return False, 'Claude error {0}: {1}'.format(e.code, err)
        except Exception as ex:
            return False, str(ex)

    def _call_openai(self, prompt):
        try:
            url     = self._get_base_url() + '/v1/chat/completions'
            payload = json.dumps({
                'model':      self._get_model() or 'llama3',
                'messages':   [
                    {'role': 'system', 'content': _SYSTEM_PROMPT},
                    {'role': 'user',   'content': prompt},
                ],
                'max_tokens': 4096,
            })
            req = urllib2.Request(url, data=payload.encode('utf-8'))
            req.add_header('Content-Type', 'application/json')
            key = self._get_api_key()
            if key:
                req.add_header('Authorization', 'Bearer ' + key)
            resp = urllib2.urlopen(req, context=self._get_ssl_ctx(), timeout=120)
            data = json.loads(resp.read())
            return True, data['choices'][0]['message']['content']
        except urllib2.HTTPError as e:
            return False, 'API error {0}: {1}'.format(e.code, e.reason)
        except Exception as ex:
            return False, str(ex)

    def _call_mcp_analyze(self, prompt):
        """Try known analysis tool names on the MCP server."""
        for candidate in ('analyze', 'pentest', 'assess', 'audit', 'scan'):
            for t in self._mcp_tools:
                if t.get('name', '').lower() == candidate:
                    ok, result = self._mcp_call('tools/call', {
                        'name': t['name'],
                        'arguments': {'prompt': prompt},
                    }, rpc_id=10)
                    if ok:
                        content = result.get('content', result)
                        if isinstance(content, list):
                            return True, '\n'.join(
                                c.get('text', str(c)) for c in content
                            )
                        return True, json.dumps(result, indent=2)
        names = ', '.join(t.get('name', '?') for t in self._mcp_tools) or 'none'
        return False, (
            'No generic analysis tool found on MCP server.\n'
            'Available tools: ' + names + '\n'
            'Use the MCP Tools tab to call them manually, '
            'or switch to Claude/OpenAI mode.'
        )

    def _dispatch(self, prompt):
        mode = self._get_mode()
        if 'Claude' in mode:
            return self._call_claude(prompt)
        elif 'OpenAI' in mode:
            return self._call_openai(prompt)
        elif 'MCP' in mode:
            return self._call_mcp_analyze(prompt)
        return False, 'No AI mode selected.'

    def _build_prompt(self, context):
        analysis = str(self._cmb_analysis.getSelectedItem())
        extra    = self._txt_extra.getText().strip()
        parts    = [
            'Analysis type: ' + analysis,
            '',
            'CONTEXT:',
            context,
        ]
        if extra and extra != 'Optional extra instructions...':
            parts += ['', 'ADDITIONAL INSTRUCTIONS:', extra]
        return '\n'.join(parts)

    # ------------------------------------------------------------------
    # Analyze tab actions
    # ------------------------------------------------------------------

    def _on_analyze_url(self):
        url = self._fld_ai_target.getText().strip()
        if not url:
            url = self._auth._build_url('/redfish/v1/')
        self._set_status(self._lbl_ai_status, 'Fetching ' + url + '...', None)
        token = self._auth._token

        def work():
            try:
                req = urllib2.Request(url)
                if token:
                    req.add_header('X-Auth-Token', token)
                req.add_header('Accept', 'application/json')
                resp   = urllib2.urlopen(req, context=self._get_ssl_ctx(), timeout=20)
                body   = resp.read()
                status = resp.getcode()
                hdrs   = str(resp.info())
                ctx    = (
                    'URL: {0}\nHTTP Status: {1}\n'
                    'Response Headers:\n{2}\n'
                    'Response Body (first 6000 chars):\n{3}'
                ).format(url, status, hdrs, body[:6000])
            except Exception as ex:
                ctx = 'URL: {0}\nFetch error: {1}'.format(url, ex)
            return self._dispatch(self._build_prompt(ctx))

        def done(result):
            ok, text = result
            self._append_result('=== AI Analysis: {0} ===\n{1}\n{2}\n'.format(
                url, text, '-' * 60
            ))
            self._set_status(self._lbl_ai_status, 'Done.' if ok else 'Error.', ok)
            if ok:
                self._ai_tabs.setSelectedIndex(3)

        self._run_in_bg(work, done)

    def _on_analyze_explorer(self):
        self._set_status(self._lbl_ai_status, 'Collecting Explorer data...', None)

        def work():
            model = self._auth._explorer_model
            lines = ['Discovered Redfish endpoints ({0} total):'.format(model.size())]
            for i in range(model.size()):
                lines.append('  ' + _to_unicode(model.get(i)))
            lines += [
                '',
                'Host: '   + (self._auth._host or 'not configured'),
                'Token: '  + ('active' if self._auth._token else 'none'),
                'HTTPS: '  + str(self._auth._use_https),
            ]
            ctx = '\n'.join(lines)
            return self._dispatch(self._build_prompt(ctx))

        def done(result):
            ok, text = result
            self._append_result(
                '=== AI Analysis: Explorer URLs ===\n{0}\n{1}\n'.format(text, '-' * 60)
            )
            self._set_status(self._lbl_ai_status, 'Done.' if ok else 'Error.', ok)
            if ok:
                self._ai_tabs.setSelectedIndex(3)

        self._run_in_bg(work, done)

    def _on_analyze_findings(self):
        self._set_status(self._lbl_ai_status, 'Sending findings to AI...', None)

        def work():
            import scanner as _sc
            sigs = _sc.get_signatures()
            lines = [
                'Active signatures ({0}):'.format(
                    sum(1 for s in sigs if s.get('enabled', True))
                )
            ]
            for s in sigs:
                if s.get('enabled', True):
                    lines.append(
                        '  [{type}] [{severity}] {name}'.format(**s)
                    )
            ctx = '\n'.join(lines)
            return self._dispatch(self._build_prompt(ctx))

        def done(result):
            ok, text = result
            self._append_result(
                '=== AI Analysis: Signature Review ===\n{0}\n{1}\n'.format(text, '-' * 60)
            )
            self._set_status(self._lbl_ai_status, 'Done.' if ok else 'Error.', ok)
            if ok:
                self._ai_tabs.setSelectedIndex(3)

        self._run_in_bg(work, done)

    def _on_generate_payload(self):
        url   = self._fld_ai_target.getText().strip()
        extra = self._txt_extra.getText().strip()
        if not url and self._auth._host:
            url = self._auth._build_url('/redfish/v1/')
        prompt = (
            'You are a Redfish/BMC security expert. Generate a JSON request body '
            'for a security test against this Redfish endpoint: {0}\n\n'
            'Analysis type: {1}\n'
            '{2}\n\n'
            'Provide:\n'
            '1. The exact JSON payload to send\n'
            '2. The HTTP method (GET/POST/PATCH/DELETE)\n'
            '3. Any required headers beyond X-Auth-Token\n'
            '4. What vulnerability or behaviour this tests\n'
            '5. Expected response if vulnerable'
        ).format(
            url or '(no URL set)',
            str(self._cmb_analysis.getSelectedItem()),
            extra if extra and not extra.startswith('Optional') else '',
        )
        self._set_status(self._lbl_ai_status, 'Generating payload...', None)

        def done(result):
            ok, text = result
            self._append_result(
                '=== Payload Generator ===\n{0}\n{1}\n'.format(text, '-' * 60)
            )
            self._set_status(self._lbl_ai_status, 'Done.' if ok else 'Error.', ok)
            if ok:
                self._ai_tabs.setSelectedIndex(3)

        self._run_in_bg(lambda: self._dispatch(prompt), done)

    def _on_cve_lookup(self):
        version_info = []
        try:
            model = self._auth._explorer_model
            for i in range(model.size()):
                entry = _to_unicode(model.get(i))
                if 'firmware' in entry.lower() or 'updateservice' in entry.lower():
                    version_info.append(entry)
        except Exception:
            pass
        try:
            fm = self._auth._scanner_tab._find_model
            for r in range(fm.getRowCount()):
                detail = str(fm.getValueAt(r, 5) or '')
                if 'version' in detail.lower() or 'firmware' in detail.lower():
                    version_info.append(detail[:200])
        except Exception:
            pass

        context = (
            '\n'.join(version_info)
            if version_info
            else 'No firmware version data collected yet. Use Explorer to discover /UpdateService/FirmwareInventory first.'
        )
        prompt = (
            'You are a CVE research assistant specialising in BMC/IPMI firmware vulnerabilities.\n\n'
            'Firmware/version context collected from target:\n{0}\n\n'
            'Task:\n'
            '1. Identify specific firmware versions or BMC products mentioned\n'
            '2. List known CVEs (CVE ID, CVSS score, brief description)\n'
            '3. For each CVE, state whether it is exploitable via the Redfish API\n'
            '4. Recommend specific Redfish endpoints or checks to verify exposure\n'
            '5. Provide remediation (firmware upgrade versions where known)'
        ).format(context)

        self._set_status(self._lbl_ai_status, 'Looking up CVEs...', None)

        def done(result):
            ok, text = result
            self._append_result(
                '=== CVE Lookup ===\n{0}\n{1}\n'.format(text, '-' * 60)
            )
            self._set_status(self._lbl_ai_status, 'Done.' if ok else 'Error.', ok)
            if ok:
                self._ai_tabs.setSelectedIndex(3)

        self._run_in_bg(lambda: self._dispatch(prompt), done)

    def _on_import_findings(self):
        text = self._txt_results.getText()
        if not text.strip():
            self._set_status(self._lbl_ai_status, 'No results to import.', False)
            return

        def work():
            return self._parse_ai_findings(text)

        def done(findings):
            if not findings:
                self._set_status(self._lbl_ai_status, 'No structured findings found in results.', None)
                return
            try:
                fm = self._auth._scanner_tab._find_model
                for f in findings:
                    fm.add_finding(f)
                self._auth._scanner_tab._bottom_tabs.setSelectedIndex(1)
                self._set_status(
                    self._lbl_ai_status,
                    'Imported {0} finding(s) to Scanner.'.format(len(findings)),
                    True,
                )
            except Exception as ex:
                self._set_status(self._lbl_ai_status, 'Import failed: ' + str(ex), False)

        self._run_in_bg(work, done)

    @staticmethod
    def _parse_ai_findings(text):
        """
        Heuristic: extract finding entries from AI response text.
        Looks for severity keywords followed by a description.
        Returns list of dicts compatible with FindingsTableModel.add_finding().
        """
        import re
        findings = []
        pattern  = re.compile(
            r'(?:^|\n)\s*(?:\*+|#+|-+)?\s*'
            r'(Critical|High|Medium|Low|Info(?:rmational)?)\s*[:\-]\s*(.+)',
            re.IGNORECASE
        )
        for m in pattern.finditer(text):
            sev  = m.group(1).capitalize()
            if sev.lower() == 'informational':
                sev = 'Info'
            name   = m.group(2).strip()[:120]
            start  = m.end()
            detail = text[start:start + 300].strip().split('\n')[0]
            findings.append({
                'sig_id':     'AI-IMPORT',
                'name':       name,
                'url':        '',
                'severity':   sev,
                'confidence': 'Tentative',
                'detail':     detail,
            })
        return findings

    # ------------------------------------------------------------------
    # MCP Tools tab actions
    # ------------------------------------------------------------------

    def _on_tool_select(self, event):
        if event.getValueIsAdjusting():
            return
        idx = self._lst_tools.getSelectedIndex()
        if idx < 0 or idx >= len(self._mcp_tools):
            return
        tool = self._mcp_tools[idx]
        self._txt_tool_detail.setText(json.dumps(tool, indent=2))
        self._txt_tool_detail.setCaretPosition(0)
        # pre-fill args skeleton from input schema
        props     = tool.get('inputSchema', {}).get('properties', {})
        skeleton  = {k: '' for k in props}
        self._txt_tool_args.setText(
            json.dumps(skeleton, indent=2) if skeleton else '{}'
        )

    def _on_refresh_tools(self):
        self._set_status(self._lbl_tool_status, 'Refreshing...', None)

        def work():
            return self._mcp_initialize()

        def done(result):
            ok, msg, tools = result
            if ok:
                self._mcp_tools = tools
                self._mcp_model.clear()
                for t in tools:
                    self._mcp_model.addElement(t.get('name', '?'))
                self._set_status(
                    self._lbl_tool_status,
                    '{0} tool(s) loaded.'.format(len(tools)), True
                )
            else:
                self._set_status(self._lbl_tool_status, 'Error: ' + msg, False)

        self._run_in_bg(work, done)

    def _on_call_tool(self):
        idx = self._lst_tools.getSelectedIndex()
        if idx < 0 or idx >= len(self._mcp_tools):
            self._set_status(self._lbl_tool_status, 'Select a tool first.', False)
            return
        tool_name = self._mcp_tools[idx].get('name', '')
        try:
            args = json.loads(self._txt_tool_args.getText() or '{}')
        except ValueError as e:
            self._set_status(self._lbl_tool_status, 'Args JSON error: ' + str(e), False)
            return

        self._set_status(self._lbl_tool_status, 'Calling ' + tool_name + '...', None)

        def work():
            return self._mcp_call('tools/call', {
                'name': tool_name, 'arguments': args
            }, rpc_id=99)

        def done(result):
            ok, data = result
            if ok:
                content = data.get('content', data) if isinstance(data, dict) else data
                if isinstance(content, list):
                    text = '\n'.join(c.get('text', str(c)) for c in content)
                else:
                    text = json.dumps(data, indent=2)
                self._append_result(
                    '=== MCP Tool: {0} ===\n{1}\n{2}\n'.format(
                        tool_name, text, '-' * 60
                    )
                )
                self._ai_tabs.setSelectedIndex(3)
                self._set_status(self._lbl_tool_status, 'Done.', True)
            else:
                self._set_status(self._lbl_tool_status, 'Error: ' + str(data), False)

        self._run_in_bg(work, done)
