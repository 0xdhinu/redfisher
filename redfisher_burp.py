# -*- coding: utf-8 -*-
"""
Redfisher — Burp Suite extension for Redfish API testing.

LOADING IN BURP SUITE:
  1. Extender > Options > Python Environment: point to jython-standalone-*.jar
  2. Extender > Extensions > Add
     - Extension type: Python
     - Extension file: this file (redfisher_burp.py)
  3. The 'Redfisher' tab will appear in the Burp Suite UI.

REQUIRES:
  - Burp Suite Pro (for active scanning) or Community (passive + editor tab)
  - Jython 2.7.x standalone JAR

PROJECT LAYOUT:
  redfisher_burp.py   <- this file (loaded by Burp)
  lib/
    extender.py       <- BurpExtender class
    scanner.py        <- passive + active scan checks
    editor.py         <- Redfish message editor tab
    auth_handler.py   <- session auth + config UI tab
    redfish_utils.py  <- shared helpers
"""

import sys
import os
import inspect

# Burp loads extensions via execfile(), which does not set __file__.
# inspect.getfile(currentframe()) reads the path from the bytecode frame instead.
_HERE = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
_LIB = os.path.join(_HERE, 'lib')
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# Burp discovers BurpExtender by name in this module's namespace.
from extender import BurpExtender  # noqa: F401, E402
