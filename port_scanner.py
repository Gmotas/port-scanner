#!/usr/bin/env python3
"""
Port Scanner — lightweight TCP port & service-risk scanner (educational).

A dependency-free network-diagnostics CLI that scans a target host for open
TCP ports, identifies the listening service, and flags insecure / commonly
vulnerable services (telnet, FTP, SMB, unauthenticated databases, etc.) with
an educational reason.

Usage examples:
    python port_scanner.py example.com --ports 1-1024
    python port_scanner.py 192.168.1.10 --top-ports 100 --banner
    python port_scanner.py db.internal --ports 22,3306,5432 --json --no-risk
    python port_scanner.py host --top-ports 50 --just-important --quiet

Exit codes: 0 = clean, 1 = risky service found or scan aborted, 2 = usage error.
"""

from __future__ import annotations

import argparse
import socket
import sys
from typing import List, Optional

import scanner.banner_grabber as banner_grabber
import scanner.report as report
from scanner import ServiceDB, TOOL_NAME, TOOL_TAGLINE, __version__
from scanner.scanner_core import PortScanner, ScanAborted

DEFAULT_TIMEOUT = 3.0
DEFAULT_CONCURRENCY = 64


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=TOOL_TAGLINE,
        epilog="Authorized use only. Only scan systems you own or have written permission to test.",
    )
    ap.add_argument("host", help="Target hostname or IPv4 address.")
    ap.add_argument("--ports", default=None,
                    help="Ports to scan: '80', '22,443,8080', '1-1024', or '80,443,8000-8100'.")
    ap.add_argument("--top-ports", type=int, default=None,
                    help="Scan the N most common ports instead of --ports.")
    ap.add_argument("--min-port", type=int, default=None,
                    help="Lower bound when scanning a range (e.g. --ports1-1024).")
    ap.add_argument("--max-port", type=int, default=None,
                    help="Upper bound when scanning a range.")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help=f"Per-port connect timeout in seconds (default {DEFAULT_TIMEOUT}).")
    ap.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                    help=f"Simultaneous probes (default {DEFAULT_CONCURRENCY}).")
    ap.add_argument("--banner", action="store_true", help="Grab a short banner on open ports.")
    ap.add_argument("--just-important", action="store_true",
                    help="Only report open ports; skip closed/filtered detail.")
    ap.add_argument("--no-risk", action="store_true",
                    help="Disable risk classification (all open ports report SAFE).")
    ap.add_argument("--json", action="store_true", help="Emit a machine-readable JSON report.")
    ap.add_argument("--quiet", action="store_true", help="Only print a verdict line.")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap.parse_args(argv)


def build_port_list(args: argparse.Namespace) -> List[int]:
    """Resolve the target port set from --ports / --top-ports / min/max."""
    ports: List[int] = []

    if args.top_ports is not None:
        return ServiceDB.top_ports(args.top_ports)

    if args.ports:
        for token in args.ports.split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                lo, hi = token.split("-", 1)
                lo, hi = int(lo), int(hi)
                if lo > hi:
                    lo, hi = hi, lo
                ports.extend(range(lo, hi + 1))
            else:
                ports.append(int(token))
    else:
        lo = args.min_port if args.min_port is not None else 1
        hi = args.max_port if args.max_port is not None else 1024
        ports.extend(range(lo, hi + 1))

    # De-duplicate while preserving order, clamp to 1..65535.
    seen: set[int] = set()
    ordered: List[int] = []
    for p in ports:
        if 1 <= p <= 65535 and p not in seen:
            seen.add(p)
            ordered.append(p)
    if not ordered:
        raise ValueError("no valid ports in the requested set")
    return ordered


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    try:
        ip = ServiceDB.resolve(args.host)
    except socket.gaierror:
        print(f"error: could not resolve host {args.host!r}", file=sys.stderr)
        return 2

    try:
        ports = build_port_list(args)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    scanner = PortScanner(timeout=args.timeout, concurrency=args.concurrency)
    db = ServiceDB()

    try:
        results = scanner.scan(
            host=args.host,
            ports=ports,
            service_db=db,
            grab_banners=args.banner,
            classify=not args.no_risk,
            ip=ip,
        )
    except ScanAborted as exc:
        # Clean partial summary on Ctrl+C.
        print("\n[!] Scan interrupted by user.", file=sys.stderr)
        results = exc.partial
        if args.json:
            print(report.render_json(results, args.host, ip, len(ports)))
        elif not args.quiet:
            print(report.render_scan_summary(results, args.host, ip, len(ports), args.banner,
                                             use_color=not args.no_color))
        return 1

    if args.json:
        print(report.render_json(results, args.host, ip, len(ports)))
    else:
        if args.just_important:
            open_ports = [r for r in results if r.is_open]
            for r in open_ports:
                line = f"{r.port}\t{r.state.value}\t{r.service or '-'}\t{r.risk_level}"
                if r.risk_reason:
                    line += f"\t{r.risk_reason}"
                print(line)
            if not args.quiet:
                print(f"# {len(open_ports)} open port(s) on {args.host} ({ip})")
        else:
            if not args.quiet:
                print(report.render_scan_summary(results, args.host, ip, len(ports), args.banner,
                                                 use_color=not args.no_color))
            else:
                print("RISKY" if report.has_risky(results) else "CLEAN")

    return 1 if report.has_risky(results) else 0


if __name__ == "__main__":
    sys.exit(main())
