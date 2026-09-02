"""Optional, guarded banner grab for open ports.

Banner grabbing is a best-effort read of whatever a service sends after a
TCP connection is established. It is inherently probe-like and can hang on a
misbehaving service, so every grab runs under a hard time cap and never
blocks a scan for long.

This is an educational, defensive diagnostic facility — the banner text helps
a network owner confirm which service is actually running, not to attack it.
"""

from __future__ import annotations

import socket
from typing import Optional

from scanner.service_db import ServiceDB


class BannerGrabber:
    """Grab a short banner from an open TCP port, safely."""

    #: Maximum bytes to read from a service banner.
    MAX_BANNER = 512

    def __init__(self, timeout: float = 2.0) -> None:
        self.timeout = max(0.1, float(timeout))

    def grab(self, host: str, port: int, ip: Optional[str] = None) -> str:
        """Return the banner text (possibly '') for *host:port*.

        Never raises for a normal failure: an unresponsive or non-speaking
        service yields ``''``, not an error.
        """
        target = ip or host
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((target, port))
            sock.settimeout(self.timeout)
            data = sock.recv(self.MAX_BANNER)
            # Some services wait for input first; send a harmless CRLF to coax
            # a response from protocols like SMTP/FTP/HTTP without injecting
            # anything meaningful.
            if not data:
                try:
                    sock.sendall(b"\r\n")
                    sock.settimeout(self.timeout)
                    data = sock.recv(self.MAX_BANNER)
                except (OSError, socket.timeout):
                    return ""
            text = data.decode("utf-8", errors="replace")
            return text.strip()
        except (OSError, socket.timeout):
            return ""
        finally:
            sock.close()

    def classify_banner(self, text: str) -> str:
        """Best-effort service name inferred from a banner string."""
        if not text:
            return ""
        text_l = text.lower()
        # Order matters: more specific signatures first.
        for sig, name in BANNER_SIGNATURES:
            if sig(text_l):
                return name
        return ""


# A curated list of (matcher_fn, service_name) to infer a service from a
# banner. Kept small and conservative; an unknown banner simply returns "".
def _has(text: str, *needles: str) -> bool:
    return any(n in text for n in needles)


BANNER_SIGNATURES = [
    (lambda t: _has(t, "ssh"), "ssh"),
    (lambda t: _has(t, "ftp"), "ftp"),
    (lambda t: _has(t, "telnet"), "telnet"),
    (lambda t: "http" in t or t.startswith("220"), "http"),
    (lambda t: _has(t, "smtp", "esmtp", "mail"), "smtp"),
    (lambda t: _has(t, "pop3", "pop"), "pop3"),
    (lambda t: _has(t, "imap"), "imap"),
    (lambda t: _has(t, "mysql"), "mysql"),
    (lambda t: _has(t, "redis"), "redis"),
    (lambda t: _has(t, "mongodb", "mongo"), "mongodb"),
    (lambda t: _has(t, "postgresql", "postgres"), "postgresql"),
]
