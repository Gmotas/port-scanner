"""Report builders for the port scanner.

Turns a list of :class:`~scanner.scanner_core.PortResult` objects into a
colorized console table or a JSON payload, so the CLI has a single place to
render output.

Only the Python standard library is used.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import List, Optional

from scanner.scanner_core import PortResult, PortState
from scanner.service_db import RISK_SAFE, RISK_WARN, RISK_RISKY

_RESET = "\033[0m"
_BOLD = "\033[1m"
_BLUE = "\033[94m"
_GRAY = "\033[90m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"

_STATE_COLOR = {
    PortState.OPEN: _GREEN,
    PortState.CLOSED: _GRAY,
    PortState.FILTERED: _YELLOW,
}

_RISK_COLOR = {
    RISK_SAFE: _GREEN,
    RISK_WARN: _YELLOW,
    RISK_RISKY: _RED,
}


def _paint(text: str, color: str, use_color: bool) -> str:
    return f"{color}{text}{_RESET}" if use_color else text


def render_scan_summary(
    results: List[PortResult],
    host: str,
    ip: str,
    scanned: int,
    grab_banners: bool,
    use_color: bool = True,
) -> str:
    """Render the console report table and summary."""
    open_ports = [r for r in results if r.is_open]
    risky = [r for r in open_ports if r.risk_level != RISK_SAFE]
    risk_counts = {RISK_SAFE: 0, RISK_WARN: 0, RISK_RISKY: 0}
    for r in open_ports:
        risk_counts[r.risk_level] = risk_counts.get(r.risk_level, 0) + 1

    lines: list[str] = []
    lines.append(_paint("Port Scan Report", _BOLD + _BLUE, use_color))
    lines.append(_paint("=" * 56, _GRAY, use_color))
    lines.append(f"  Target : {host} ({ip})")
    lines.append(f"  Scanned: {scanned} ports ({'with banners' if grab_banners else 'no banners'})")
    lines.append(f"  Open   : {len(open_ports)}   Closed: {len(results) - len(open_ports) - len([r for r in results if r.state is PortState.FILTERED])}   Filtered: {len([r for r in results if r.state is PortState.FILTERED])}")
    lines.append("")

    if open_ports:
        header = f"  {'PORT':<8}{'STATE':<10}{'SERVICE':<16}{'RISK':<8}NOTES"
        lines.append(_paint(header, _BOLD, use_color))
        lines.append(_paint("  " + "-" * 56, _GRAY, use_color))
        for r in open_ports:
            state_txt = _paint(r.state.value, _STATE_COLOR.get(r.state, _GRAY), use_color)
            risk_txt = _paint(r.risk_level, _RISK_COLOR.get(r.risk_level, _GRAY), use_color)
            notes = r.risk_reason if r.risk_level != RISK_SAFE else ""
            if r.banner:
                notes = (notes + " " + r.banner[:40]) if notes else r.banner[:40]
            lines.append(
                f"  {r.port:<8}{state_txt:<10}{r.service or '-':<16}{risk_txt:<8}{notes}"
            )
        lines.append("")
    else:
        lines.append(_paint("  No open ports found.", _GRAY, use_color))
        lines.append("")

    lines.append(_paint("Risk summary", _BOLD, use_color))
    lines.append(_paint(f"  {RISK_SAFE} : {risk_counts.get(RISK_SAFE, 0)}", _GREEN, use_color))
    lines.append(_paint(f"  {RISK_WARN} : {risk_counts.get(RISK_WARN, 0)}", _YELLOW, use_color))
    lines.append(_paint(f"  {RISK_RISKY} : {risk_counts.get(RISK_RISKY, 0)}", _RED, use_color))
    lines.append("")
    if risky:
        lines.append(_paint("! {0} risky/insecure service(s) detected. Investigate before exposing.".format(len(risky)), _RED, use_color))
    else:
        lines.append(_paint("+ No risky services detected.", _GREEN, use_color))

    lines.append("")
    lines.append(_paint("[-] Scan complete.", _BOLD, use_color))
    return "\n".join(lines) + "\n"


def render_json(
    results: List[PortResult],
    host: str,
    ip: str,
    scanned: int,
) -> str:
    """Serialize scan results to a JSON string."""
    payload = {
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "target": host,
        "resolved_ip": ip,
        "ports_scanned": scanned,
        "port_states": {
            "open": sum(1 for r in results if r.is_open),
            "closed": sum(1 for r in results if r.state is PortState.CLOSED),
            "filtered": sum(1 for r in results if r.state is PortState.FILTERED),
        },
        "open_ports": [r.to_dict() for r in results if r.is_open],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def has_risky(results: List[PortResult]) -> bool:
    """True when any open port is classified above SAFE."""
    return any(r.is_open and r.risk_level != RISK_SAFE for r in results)
