"""Concurrent TCP connect-scan engine.

This module implements the actual network probe: a plain **TCP connect
scan** using ``socket`` + ``concurrent.futures``.  No raw sockets, no
superuser privileges, no third-party packages — every open port is a
successful ``connect()``, every closed port is a ``ConnectionRefused``,
and everything that times out is reported as filtered.

The scanner is a small class, :class:`PortScanner`, which:

* resolves the target hostname to an IPv4 address up front,
* fans the port list out across a :class:`ThreadPoolExecutor` honoring
  ``--timeout`` and ``--concurrency``,
* classifies each result with :class:`ServiceDB` (service name + risk),
* optionally grabs a banner on open ports (with a hard time cap),
* raises :class:`ScanAborted` on ``KeyboardInterrupt`` carrying the
  partial results collected so far, so the CLI can print a clean
  partial summary instead of dying mid-table.
"""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional, Sequence, Tuple

from scanner.service_db import ServiceDB, RISK_SAFE


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class PortState(str, Enum):
    """The three states a probed TCP port can be in."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass
class PortResult:
    """Outcome of probing a single port.

    Attributes
    ----------
    port:
        TCP port number that was probed.
    state:
        :class:`PortState` — open, closed or filtered.
    service:
        Service name resolved from the port table ('' if unknown).
    risk_level:
        One of ``SAFE`` / ``WARN`` / ``RISKY`` (only meaningful for open
        ports; closed/filtered ports are always ``SAFE``).
    risk_reason:
        Educational explanation when *risk_level* != SAFE.
    banner:
        Captured banner text ('' when banner grabbing is off or empty).
    unreachable:
        True when the OS reported the *host* as unreachable (no route),
        as opposed to the port being filtered.
    """

    port: int
    state: PortState
    service: str = ""
    risk_level: str = RISK_SAFE
    risk_reason: str = ""
    banner: str = ""
    unreachable: bool = False

    @property
    def is_open(self) -> bool:
        return self.state is PortState.OPEN

    def to_dict(self) -> dict:
        """JSON-serializable dict for the ``--json`` report."""
        return {
            "port": self.port,
            "state": self.state.value,
            "service": self.service,
            "risk_level": self.risk_level,
            "risk_reason": self.risk_reason,
            "banner": self.banner,
        }


class ScanAborted(Exception):
    """Raised when the user interrupts a scan mid-flight.

    Attributes
    ----------
    partial:
        Results collected before the interruption.
    host:
        The host that was being scanned.
    """

    def __init__(self, partial: List[PortResult], host: str) -> None:
        super().__init__("Scan interrupted by user")
        self.partial = partial
        self.host = host


# ---------------------------------------------------------------------------
# Single-port probe
# ---------------------------------------------------------------------------

#: OSError errnos that mean the *host* is unreachable (not the port).
_UNREACHABLE_ERRNOS = {
    10050,  # WSAENETDOWN
    10051,  # WSAENETUNREACH
    10065,  # WSAEHOSTUNREACH
    101,    # ENETUNREACH
    113,    # EHOSTUNREACH
    100,    # ENETDOWN
    112,    # EADDRNOTAVAIL-ish (host down on some stacks)
}


def probe_port(host: str, port: int, timeout: float) -> PortResult:
    """Attempt a single TCP connect to ``(host, port)``.

    Returns a :class:`PortResult` describing the outcome.  Never raises
    for network-level outcomes; only unexpected programming errors
    propagate.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    unreachable = False
    try:
        sock.connect((host, port))
        state = PortState.OPEN
    except socket.timeout:
        state = PortState.FILTERED
    except OSError as exc:
        errno = exc.errno
        if errno in _UNREACHABLE_ERRNOS:
            state = PortState.FILTERED
            unreachable = True
        elif errno in (10061, 111, 10054):  # WSAECONNREFUSED / ECONNREFUSED / WSAECONNRESET
            state = PortState.CLOSED
        else:
            # Anything else (e.g. WSAEADDRNOTAVAIL, ECONNRESET) is treated
            # as filtered — the port exists but did not answer.
            state = PortState.FILTERED
    finally:
        sock.close()
    return PortResult(port=port, state=state, unreachable=unreachable)


# ---------------------------------------------------------------------------
# Banner grabbing
# ---------------------------------------------------------------------------

#: Hard cap on any single banner read (seconds) — per spec, 2-3 s.
BANNER_MAX_WAIT = 3.0
BANNER_MAX_BYTES = 2048


def grab_banner(host: str, port: int, timeout: float) -> str:
    """Connect to an open port and read a short banner.

    The read is bounded by ``min(timeout, BANNER_MAX_WAIT)`` seconds and
    ``BANNER_MAX_BYTES`` bytes; a service that sends nothing (e.g. HTTP
    waiting for a request) simply yields an empty banner — that is
    expected and safe.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(min(timeout, BANNER_MAX_WAIT))
    try:
        sock.connect((host, port))
        data = sock.recv(BANNER_MAX_BYTES)
        return data.decode("utf-8", errors="replace").strip()
    except OSError:
        return ""
    finally:
        sock.close()


def detect_service_from_banner(banner: str) -> str:
    """Guess a service name from a banner string ('' when unknown)."""
    text = banner.strip().lower()
    if not text:
        return ""
    if text.startswith("ssh-"):
        return "ssh"
    if text.startswith("http/"):
        return "http"
    if "esmtp" in text or "smtp" in text:
        return "smtp"
    if text.startswith("220") and "ftp" in text:
        return "ftp"
    if text.startswith("+ok") and ("pop3" in text or "pop" in text):
        return "pop3"
    if text.startswith("* ok") or text.startswith("*ok"):
        return "imap"
    if text.startswith("220") and "imap" in text:
        return "imap"
    return ""


# ---------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------


class PortScanner:
    """TCP connect-scan engine with a thread pool.

    Parameters
    ----------
    timeout:
        Per-connect timeout in seconds (float).
    concurrency:
        Maximum number of simultaneous probes.
    """

    def __init__(self, timeout: float = 3.0, concurrency: int = 64) -> None:
        self.timeout = max(0.1, float(timeout))
        self.concurrency = max(1, int(concurrency))
        self._lock = threading.Lock()

    # -- public API ------------------------------------------------------------

    def resolve(self, host: str) -> str:
        """Resolve *host* to an IPv4 address (raises ``socket.gaierror``)."""
        return ServiceDB.resolve(host)

    def scan(
        self,
        host: str,
        ports: Sequence[int],
        service_db: Optional[ServiceDB] = None,
        grab_banners: bool = False,
        classify: bool = True,
        progress: Optional[Callable[[int, int], None]] = None,
        ip: Optional[str] = None,
    ) -> List[PortResult]:
        """Probe every port in *ports* against *host*.

        Parameters
        ----------
        host:
            Target hostname or IPv4 literal.
        ports:
            Iterable of port numbers to probe.
        service_db:
            Service/risk database; a default is created when omitted.
        grab_banners:
            When True, open ports get a banner grab.
        classify:
            When False, risk fields are left at ``SAFE`` (``--no-risk``).
        progress:
            Optional ``(done, total)`` callback invoked after each result.
        ip:
            Pre-resolved IP (avoids resolving twice when the CLI already
            resolved).

        Returns
        -------
        list[PortResult]
            Results sorted by port number.

        Raises
        ------
        socket.gaierror
            When *host* cannot be resolved.
        ScanAborted
            When the scan is interrupted (carries partial results).
        """
        target_ip = ip or self.resolve(host)
        db = service_db or ServiceDB()
        ports = list(ports)
        total = len(ports)
        results: List[PortResult] = []
        done = 0

        def _probe(port: int) -> PortResult:
            result = probe_port(target_ip, port, self.timeout)
            if result.is_open:
                if grab_banners:
                    result.banner = grab_banner(target_ip, port, self.timeout)
                if classify:
                    service = result.banner and detect_service_from_banner(result.banner)
                    result.service = service or db.service_name(port)
                    result.risk_level, result.risk_reason = db.classify(
                        port, result.service or None
                    )
                else:
                    result.service = db.service_name(port)
            return result

        pool = ThreadPoolExecutor(max_workers=self.concurrency)
        futures = {pool.submit(_probe, p): p for p in ports}
        try:
            for future in as_completed(futures):
                results.append(future.result())
                done += 1
                if progress is not None:
                    progress(done, total)
        except KeyboardInterrupt:
            for future in futures:
                future.cancel()
            pool.shutdown(wait=False, cancel_futures=True)
            raise ScanAborted(partial=results, host=host) from None
        else:
            pool.shutdown(wait=True)

        results.sort(key=lambda r: r.port)
        return results
