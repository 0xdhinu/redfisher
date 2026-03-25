# -*- coding: utf-8 -*-
"""
RedfishEditorTabFactory + RedfishEditorTab

Adds a 'Redfish' tab to every request/response message editor in Burp Suite
that shows parsed Redfish context: resource type, risk level, auth headers,
and a pretty-printed JSON body.
"""

from burp import IMessageEditorTabFactory, IMessageEditorTab

from javax.swing import (
    JPanel, JTextArea, JScrollPane, JLabel,
    BorderFactory, Box, BoxLayout,
    JTable, JScrollPane as JScroll2,
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, Color, Dimension, Font

from redfish_utils import (
    is_redfish_request, get_resource_type, get_resource_risk,
    pretty_json, get_header_value, bytes_to_str, headers_to_dict,
)


# ---------------------------------------------------------------------------
# Tab factory
# ---------------------------------------------------------------------------

class RedfishEditorTabFactory(IMessageEditorTabFactory):

    def __init__(self, callbacks):
        self._callbacks = callbacks

    def createNewInstance(self, controller, editable):
        return RedfishEditorTab(self._callbacks, controller, editable)


# ---------------------------------------------------------------------------
# Editor tab
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    'High':   Color(220, 50,  50),
    'Medium': Color(220, 130, 30),
    'Low':    Color(50,  130, 220),
    'Info':   Color(100, 100, 100),
}

_MONO_FONT = Font('Monospaced', Font.PLAIN, 12)


class RedfishEditorTab(IMessageEditorTab):

    def __init__(self, callbacks, controller, editable):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._controller = controller
        self._editable = editable
        self._current_message = None
        self._panel = self._build_ui()

    # ------------------------------------------------------------------
    # IMessageEditorTab contract
    # ------------------------------------------------------------------

    def getTabCaption(self):
        return 'Redfish'

    def getUiComponent(self):
        return self._panel

    def isEnabled(self, content, is_request):
        """Show the tab only for Redfish requests/responses."""
        if not content:
            return False
        try:
            if is_request:
                info = self._helpers.analyzeRequest(content)
            else:
                info = self._helpers.analyzeRequest(self._controller.getRequest())
            url = str(info.getUrl())
            return is_redfish_request(url)
        except Exception:
            return False

    def setMessage(self, content, is_request):
        self._current_message = content
        if not content:
            self._clear_ui()
            return
        try:
            self._populate(content, is_request)
        except Exception as e:
            self._txt_body.setText('Error rendering Redfish tab:\n' + str(e))

    def getMessage(self):
        return self._current_message

    def isModified(self):
        return False

    def getSelectedData(self):
        selected = self._txt_body.getSelectedText()
        if selected:
            return self._helpers.stringToBytes(selected)
        return None

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        panel = JPanel(BorderLayout(0, 4))
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        # --- Top: resource info bar ---
        info_panel = JPanel()
        info_panel.setLayout(BoxLayout(info_panel, BoxLayout.X_AXIS))
        info_panel.setBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Color(200, 200, 200)),
                BorderFactory.createEmptyBorder(4, 8, 4, 8),
            )
        )

        self._lbl_resource = JLabel('Resource: —')
        self._lbl_resource.setFont(self._lbl_resource.getFont().deriveFont(Font.BOLD))

        self._lbl_risk = JLabel('Risk: —')
        self._lbl_risk.setFont(self._lbl_risk.getFont().deriveFont(Font.BOLD))

        self._lbl_auth = JLabel('Auth: —')

        info_panel.add(self._lbl_resource)
        info_panel.add(Box.createHorizontalStrut(20))
        info_panel.add(self._lbl_risk)
        info_panel.add(Box.createHorizontalStrut(20))
        info_panel.add(self._lbl_auth)
        info_panel.add(Box.createHorizontalGlue())

        # --- Middle: headers table ---
        col_names = ['Header', 'Value']
        self._headers_model = DefaultTableModel(col_names, 0)
        self._headers_table = JTable(self._headers_model)
        self._headers_table.setFont(_MONO_FONT)
        self._headers_table.getColumnModel().getColumn(0).setPreferredWidth(220)
        self._headers_table.getColumnModel().getColumn(1).setPreferredWidth(600)
        headers_scroll = JScrollPane(self._headers_table)
        headers_scroll.setPreferredSize(Dimension(0, 140))
        headers_scroll.setBorder(BorderFactory.createTitledBorder('Headers'))

        # --- Bottom: JSON body ---
        self._txt_body = JTextArea()
        self._txt_body.setFont(_MONO_FONT)
        self._txt_body.setEditable(self._editable)
        self._txt_body.setLineWrap(False)
        body_scroll = JScrollPane(self._txt_body)
        body_scroll.setBorder(BorderFactory.createTitledBorder('Body (JSON)'))

        panel.add(info_panel, BorderLayout.NORTH)
        panel.add(headers_scroll, BorderLayout.CENTER)
        panel.add(body_scroll, BorderLayout.SOUTH)

        # Give most vertical space to body
        body_scroll.setPreferredSize(Dimension(0, 400))

        return panel

    # ------------------------------------------------------------------
    # UI population
    # ------------------------------------------------------------------

    def _clear_ui(self):
        self._lbl_resource.setText('Resource: —')
        self._lbl_risk.setText('Risk: —')
        self._lbl_risk.setForeground(Color.BLACK)
        self._lbl_auth.setText('Auth: —')
        self._headers_model.setRowCount(0)
        self._txt_body.setText('')

    def _populate(self, content, is_request):
        self._clear_ui()

        if is_request:
            info = self._helpers.analyzeRequest(content)
            url = str(info.getUrl())
            headers = [str(h) for h in info.getHeaders()]
            body_offset = info.getBodyOffset()
            body_bytes = content[body_offset:]
            method = info.getMethod()
        else:
            # For responses we still read the URL from the paired request
            req = self._controller.getRequest()
            req_info = self._helpers.analyzeRequest(req) if req else None
            url = str(req_info.getUrl()) if req_info else ''
            info = self._helpers.analyzeResponse(content)
            headers = [str(h) for h in info.getHeaders()]
            body_offset = info.getBodyOffset()
            body_bytes = content[body_offset:]
            method = 'RESPONSE ({0})'.format(info.getStatusCode())

        # Resource type & risk
        resource_type = get_resource_type(url) or 'Unknown'
        risk = get_resource_risk(url)
        self._lbl_resource.setText(
            '[{0}]  {1}'.format(method, resource_type)
        )
        self._lbl_risk.setText('Risk: ' + risk)
        color = _SEVERITY_COLORS.get(risk, Color.BLACK)
        self._lbl_risk.setForeground(color)

        # Auth header info
        token = get_header_value(headers, 'X-Auth-Token')
        basic = get_header_value(headers, 'Authorization')
        if token:
            auth_text = 'Session (X-Auth-Token: {0}...)'.format(token[:8])
        elif basic:
            auth_text = 'Basic auth present'
        else:
            auth_text = 'No auth header'
        self._lbl_auth.setText('Auth: ' + auth_text)
        no_auth_color = Color(200, 50, 50) if (not token and not basic) else Color(50, 150, 50)
        self._lbl_auth.setForeground(no_auth_color)

        # Headers table (skip the request-line row)
        self._headers_model.setRowCount(0)
        for h in headers[1:]:  # skip first row (GET /path HTTP/1.1 or HTTP/1.1 200)
            if ':' in h:
                k, _, v = h.partition(':')
                self._headers_model.addRow([k.strip(), v.strip()])

        # Body
        body_text = pretty_json(body_bytes)
        self._txt_body.setText(body_text)
        self._txt_body.setCaretPosition(0)
