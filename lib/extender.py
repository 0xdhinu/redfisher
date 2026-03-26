# -*- coding: utf-8 -*-
"""
BurpExtender — main entry point registered with Burp Suite.

Registers:
  - RedfishAuthHandler       (ISessionHandlingAction + IHttpListener + ITab)
  - RedfishEditorTabFactory  (IMessageEditorTabFactory)
  - RedfishScannerCheck      (IScannerCheck)

Initialises the signature store from signatures.json before any component loads.
"""

import inspect
import os

from burp import IBurpExtender
from java.io import PrintWriter

import scanner as _scanner
from editor import RedfishEditorTabFactory
from scanner import RedfishScannerCheck
from auth_handler import RedfishAuthHandler

EXTENSION_NAME = 'Redfisher API Tester'
VERSION        = '1.0.0'

# signatures.json lives one level above lib/
_LIB_DIR   = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
_SIGS_PATH = os.path.join(_LIB_DIR, '..', 'signatures.json')


class BurpExtender(IBurpExtender):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        stdout.println('[Redfisher] Loading {0} v{1}...'.format(EXTENSION_NAME, VERSION))
        callbacks.setExtensionName(EXTENSION_NAME)

        # Load signatures before registering any checks
        ok, msg = _scanner.load_signatures(_SIGS_PATH)
        if ok:
            stdout.println('[Redfisher] ' + msg)
        else:
            stderr.println('[Redfisher] WARNING: ' + msg)

        # Auth handler — also owns the Redfisher suite tab
        try:
            auth_handler = RedfishAuthHandler(callbacks)
            callbacks.registerSessionHandlingAction(auth_handler)
            callbacks.registerHttpListener(auth_handler)
            callbacks.addSuiteTab(auth_handler)
            stdout.println('[Redfisher] Auth handler + UI tab registered.')
        except Exception as e:
            stderr.println('[Redfisher] ERROR registering auth handler: ' + str(e))
            return

        # Message editor tab
        try:
            callbacks.registerMessageEditorTabFactory(RedfishEditorTabFactory(callbacks))
            stdout.println('[Redfisher] Message editor tab registered.')
        except Exception as e:
            stderr.println('[Redfisher] ERROR registering editor tab: ' + str(e))

        # Scanner check (Burp passive/active scan integration)
        try:
            callbacks.registerScannerCheck(RedfishScannerCheck(callbacks))
            stdout.println('[Redfisher] Scanner check registered.')
        except Exception as e:
            stderr.println('[Redfisher] ERROR registering scanner check: ' + str(e))

        stdout.println('[Redfisher] Ready.')
        stdout.println('[Redfisher] Add a session handling rule:')
        stdout.println('[Redfisher]   Project Options > Sessions > Session Handling Rules')
        stdout.println('[Redfisher]   Action: "Redfisher: inject/refresh Redfish X-Auth-Token"')
