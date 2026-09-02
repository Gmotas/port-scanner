"""scanner — a small, dependency-free TCP port scanner package.

This package implements the core of a lightweight network-diagnostics tool:

* ``service_db``    — port → service mappings plus a built-in risk
                      classification table for insecure / commonly
                      vulnerable services.
* ``scanner_core``  — concurrent TCP connect scanning with per-port
                      timeouts (open / closed / filtered states).
* ``banner_grabber``— optional, guarded banner grab on open ports.
* ``report``        — human-readable table + JSON report builders.

Everything here runs on the Python standard library only, so the tool
works out of the box on any modern CPython 3.9+ install.
"""

from .service_db import (
    ServiceDB,
    RiskRule,
    RISK_SAFE,
    RISK_WARN,
    RISK_RISKY,
    DEFAULT_TOP_PORTS,
    WELL_KNOWN_SERVICES,
    RISK_TABLE,
)
from .scanner_core import PortResult, PortState, PortScanner, ScanAborted
from .banner_grabber import BannerGrabber
from .report import render_scan_summary, render_json, has_risky

__version__ = "1.0.0"
TOOL_NAME = "port-scanner"
TOOL_TAGLINE = "Lightweight TCP port & service-risk scanner (educational)"

__all__ = [
    "ServiceDB",
    "RiskRule",
    "RISK_SAFE",
    "RISK_WARN",
    "RISK_RISKY",
    "DEFAULT_TOP_PORTS",
    "WELL_KNOWN_SERVICES",
    "RISK_TABLE",
    "PortResult",
    "PortState",
    "PortScanner",
    "ScanAborted",
    "BannerGrabber",
    "render_scan_summary",
    "render_json",
    "has_risky",
    "__version__",
    "TOOL_NAME",
    "TOOL_TAGLINE",
]
