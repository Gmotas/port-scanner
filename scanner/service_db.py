"""Service identification and risk-classification database.

This module answers two questions for every port probed by the scanner:

1. "What service usually listens here?" — answered with a curated
   well-known table of :data:`WELL_KNOWN_SERVICES`, augmented by a
   best-effort read of the platform's ``/etc/services``-style file.
2. "Should an assessor look closer at this service?" — answered with a
   built-in :data:`RISK_TABLE` of insecure / commonly-vulnerable services.
   Every entry carries an *educational* reason phrased defensively: it
   tells a network owner what to check, never how to attack.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Well-known TCP services (curated subset, port -> service)
# ---------------------------------------------------------------------------

#: Curated port -> service map.  Kept deliberately human-sized so it stays
#: auditable; anything missing is filled from the OS services file.
WELL_KNOWN_SERVICES: Dict[int, str] = {
    7: "echo",
    9: "discard",
    13: "daytime",
    17: "qotd",
    19: "chargen",
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    42: "nameserver",
    43: "whois",
    49: "tacacs",
    53: "domain",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    70: "gopher",
    79: "finger",
    80: "http",
    81: "http-alt",
    88: "kerberos",
    109: "pop2",
    110: "pop3",
    111: "rpcbind",
    113: "ident",
    115: "sftp",
    117: "uucp-path",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    177: "xdmcp",
    179: "bgp",
    194: "irc",
    199: "smux",
    201: "at-rtmp",
    209: "quickmail",
    220: "imap3",
    259: "esro-gen",
    264: "bgmp",
    318: "tsp",
    381: "hp-collector",
    383: "hp-alarm-mgr",
    389: "ldap",
    411: "directconnect",
    443: "https",
    444: "snpp",
    445: "microsoft-ds",
    464: "kpasswd",
    465: "smtps",
    500: "isakmp",
    512: "exec",
    513: "login",
    514: "shell",
    515: "printer",
    520: "efs",
    540: "uucp",
    543: "klogin",
    544: "kshell",
    546: "dhcpv6",
    547: "dhcpv6",
    548: "afp",
    554: "rtsp",
    563: "nntps",
    587: "submission",
    591: "filemaker",
    631: "ipp",
    636: "ldaps",
    646: "ldp",
    660: "macsap",
    749: "kerberos-adm",
    873: "rsync",
    902: "vmware-auth",
    989: "ftps-data",
    990: "ftps",
    992: "telnets",
    993: "imaps",
    995: "pop3s",
    1025: "msrpc",
    1080: "socks",
    1099: "rmiregistry",
    1194: "openvpn",
    1433: "ms-sql-s",
    1434: "ms-sql-m",
    1521: "oracle",
    1723: "pptp",
    1745: "coda",
    1812: "radius",
    1813: "radius-acct",
    1883: "mqtt",
    1900: "upnp",
    2000: "cisco-sccp",
    2001: "dc",
    2049: "nfs",
    2082: "cpanel",
    2083: "cpanel-ssl",
    2086: "whm",
    2181: "zookeeper",
    2222: "ssh-alt",
    2375: "docker",
    2376: "docker-tls",
    2379: "etcd",
    2483: "oracle",
    2484: "oracle-ssl",
    3000: "http-alt",
    3001: "http-alt",
    3128: "squid",
    3268: "global-catalog",
    3269: "global-catalog-ssl",
    3306: "mysql",
    3389: "ms-wbt-server",
    3690: "svn",
    4000: "http-alt",
    4369: "epmd",
    4444: "metasploit",
    5000: "http-alt",
    5001: "http-alt",
    5004: "rtp",
    5005: "rtp",
    5060: "sip",
    5432: "postgresql",
    5555: "adb",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5901: "vnc-1",
    5984: "couchdb",
    6000: "x11",
    6379: "redis",
    6443: "kube-apiserver",
    6667: "irc",
    7001: "weblogic",
    8000: "http-alt",
    8008: "http-alt",
    8009: "ajp",
    8080: "http-proxy",
    8081: "http-alt",
    8082: "http-alt",
    8086: "influxdb",
    8088: "http-alt",
    8090: "http-alt",
    8443: "https-alt",
    8500: "consul",
    8888: "http-alt",
    9000: "http-alt",
    9001: "http-alt",
    9042: "cassandra",
    9092: "kafka",
    9100: "printer",
    9200: "elasticsearch",
    9300: "elasticsearch",
    9418: "git",
    9999: "http-alt",
    10000: "webmin",
    11211: "memcached",
    15672: "rabbitmq",
    20000: "webmin",
    27017: "mongodb",
    27018: "mongodb",
    28017: "mongodb-http",
    31337: "back-orifice",
    50000: "sap",
    50070: "hadoop-namenode",
    61616: "activemq",
}

#: Default "top ports" list — ordered roughly by how often they show up
#: in real-world scans.  ``--top-ports N`` takes the first N entries.
DEFAULT_TOP_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 443, 445,
    993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080,
    8443, 9200, 27017,
]


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------

#: Risk badge levels, from lowest to highest concern.
RISK_SAFE: str = "SAFE"
RISK_WARN: str = "WARN"
RISK_RISKY: str = "RISKY"


@dataclass(frozen=True)
class RiskRule:
    """A single entry in the built-in risk reference table.

    Attributes
    ----------
    level:
        One of :data:`RISK_SAFE`, :data:`RISK_WARN`, :data:`RISK_RISKY`.
    reason:
        Short educational explanation of *why* the service is flagged and
        what an owner should verify.  Always phrased defensively.
    """

    level: str
    reason: str


#: Service name -> risk rule.  Names are lowercase, protocol-stripped.
RISK_TABLE: Dict[str, RiskRule] = {
    # --- Legacy / cleartext remote administration ---------------------------
    "telnet": RiskRule(RISK_RISKY, "Legacy cleartext remote shell — credentials are sniffable on the wire; default credentials common on network gear; replace with SSH."),
    "login": RiskRule(RISK_RISKY, "Legacy Berkeley r* service (rlogin) with no encryption and weak host-based auth; obsolete, replace with SSH."),
    "shell": RiskRule(RISK_RISKY, "Legacy Berkeley r* service (rsh) — unauthenticated command execution by IP spoofing; obsolete, replace with SSH."),
    "exec": RiskRule(RISK_RISKY, "Legacy Berkeley r* service (rexec) — cleartext credentials, weak auth; obsolete, replace with SSH."),
    "tftp": RiskRule(RISK_RISKY, "TFTP has no authentication or encryption; commonly abused to exfiltrate configs or stage payloads on network gear."),
    "snmp": RiskRule(RISK_RISKY, "SNMP often runs with default 'public'/'private' community strings exposing device configuration; restrict to management VLANs and use SNMPv3."),
    "smux": RiskRule(RISK_RISKY, "SNMP multiplexer — associated with SNMP community-string risks and historic privilege issues; disable unless required."),
    "finger": RiskRule(RISK_WARN, "Finger discloses user account names (user enumeration) and system uptime; disable on internet-facing hosts."),
    "x11": RiskRule(RISK_RISKY, "X11 without access control lets anyone capture keystrokes/screens; tunnel over SSH or use xauth."),
    "rpcbind": RiskRule(RISK_WARN, "Portmapper enumerates RPC services; used in reconnaissance and classic NFS/rpc attacks; restrict with firewalls."),
    "nfs": RiskRule(RISK_WARN, "NFS exports are a frequent data-exposure source when exports are too broad; verify no_root_squash and export lists."),
    "efs": RiskRule(RISK_WARN, "Legacy Berkeley r* file service, no encryption; obsolete."),
    "uucp": RiskRule(RISK_WARN, "Legacy Unix-to-Unix copy protocol with weak auth; obsolete."),
    "uucp-path": RiskRule(RISK_WARN, "Legacy UUCP path service; obsolete."),
    # --- Cleartext application protocols --------------------------------------
    "ftp": RiskRule(RISK_RISKY, "FTP sends credentials and data in cleartext; anonymous access and default credentials are common; prefer SFTP/FTPS."),
    "ftp-data": RiskRule(RISK_WARN, "FTP data channel — part of the cleartext FTP family; prefer passive SFTP/FTPS."),
    "ftps": RiskRule(RISK_WARN, "FTPS (implicit TLS) is better than plain FTP but often misconfigured with weak ciphers; verify TLS config."),
    "http": RiskRule(RISK_WARN, "Cleartext HTTP — traffic and login forms are sniffable; consider HTTPS and HSTS."),
    "http-alt": RiskRule(RISK_WARN, "HTTP on an alternate port — check for admin panels, debug consoles, or unauthenticated APIs."),
    "http-proxy": RiskRule(RISK_WARN, "HTTP proxy/service — check for open-proxy abuse or exposed management interfaces."),
    "squid": RiskRule(RISK_WARN, "Caching proxy — open proxies are abused for anonymization and scanning; restrict ACLs."),
    "webmin": RiskRule(RISK_WARN, "Web-based admin panel — frequent target for credential brute force and historical CVEs; restrict access."),
    "cpanel": RiskRule(RISK_WARN, "Web hosting control panel — check for outdated versions and exposed admin endpoints."),
    "whm": RiskRule(RISK_WARN, "Web hosting control panel admin — keep patched and access-restricted."),
    "smtp": RiskRule(RISK_WARN, "Mail service — check for open relay, cleartext auth, and user enumeration; use TLS/STARTTLS."),
    "submission": RiskRule(RISK_WARN, "SMTP submission — verify auth requirements and TLS enforcement."),
    "pop3": RiskRule(RISK_RISKY, "POP3 retrieves mail in cleartext — credentials sniffable; use POP3S/IMAPS."),
    "imap": RiskRule(RISK_RISKY, "IMAP without TLS exposes mailbox credentials; enforce STARTTLS or use IMAPS."),
    "pop2": RiskRule(RISK_RISKY, "Obsolete POP2, cleartext; removed from modern clients."),
    "nntp": RiskRule(RISK_WARN, "Usenet protocol, usually cleartext; mostly obsolete."),
    "irc": RiskRule(RISK_WARN, "IRC channels are a classic C2/botnet coordination medium; verify the channel's purpose."),
    "rtsp": RiskRule(RISK_WARN, "Real Time Streaming — check for unauthenticated camera/streaming endpoints."),
    "sip": RiskRule(RISK_WARN, "VoIP signaling — check for SIP brute force, toll fraud, and unauthenticated registrars."),
    "mqtt": RiskRule(RISK_WARN, "MQTT brokers frequently ship with no authentication; check credentials and topic ACLs."),
    "amqp": RiskRule(RISK_WARN, "AMQP message broker — verify auth/ACLs; unauthenticated brokers leak messages."),
    "kafka": RiskRule(RISK_WARN, "Kafka broker — check for unauthenticated access and permissive ACLs."),
    # --- Remote desktop / admin -------------------------------------------------
    "ms-wbt-server": RiskRule(RISK_WARN, "RDP exposed — brute-force magnet with BlueKeep-class CVE history; use VPN + NLA and restrict source IPs."),
    "vnc": RiskRule(RISK_RISKY, "VNC historically ships with weak/no encryption and poor password hygiene; tunnel it or use a modern solution."),
    "vnc-1": RiskRule(RISK_RISKY, "VNC on an alternate port — see VNC risk; verify authentication."),
    "socks": RiskRule(RISK_WARN, "SOCKS proxy — open proxies are abused for anonymization; restrict to authorized clients."),
    "xdmcp": RiskRule(RISK_WARN, "X Display Manager Control Protocol — allows remote X sessions; restrict."),
    "directconnect": RiskRule(RISK_WARN, "Direct Connect file-sharing hub — check for unauthenticated shares."),
    # --- Windows / SMB family ----------------------------------------------------
    "microsoft-ds": RiskRule(RISK_RISKY, "SMB file sharing — the target of EternalBlue-class RCEs and credential attacks; keep patched, restrict exposure, disable SMBv1."),
    "netbios-ssn": RiskRule(RISK_RISKY, "NetBIOS/SMB session service — same exposure class as SMB; restrict and disable legacy NetBIOS."),
    "netbios-ns": RiskRule(RISK_WARN, "NetBIOS name service — leaks hostname/workgroup info during recon; consider disabling."),
    "netbios-dgm": RiskRule(RISK_WARN, "NetBIOS datagram service — legacy discovery; usually unnecessary on modern networks."),
    "msrpc": RiskRule(RISK_WARN, "Windows RPC endpoint mapper — used in enumeration and classic MS08-067-style attacks; restrict."),
    "ms-sql-s": RiskRule(RISK_WARN, "MS SQL Server — check for weak 'sa' passwords and unnecessary exposure."),
    "ms-sql-m": RiskRule(RISK_WARN, "MS SQL Browser service — discloses instance info; restrict."),
    "global-catalog": RiskRule(RISK_WARN, "AD Global Catalog — sensitive directory service; restrict to trusted networks."),
    # --- Databases ----------------------------------------------------------------
    "mysql": RiskRule(RISK_WARN, "MySQL — check for weak credentials, anonymous accounts, and exposure beyond trusted subnets."),
    "postgresql": RiskRule(RISK_WARN, "PostgreSQL — verify pg_hba.conf and that the 'postgres' superuser has a strong password."),
    "oracle": RiskRule(RISK_WARN, "Oracle listener/TNS — historic default accounts and CVE track record; keep patched."),
    "redis": RiskRule(RISK_RISKY, "Redis without authentication (or with weak defaults) enables remote code execution via config writes; set requirepass and bind localhost."),
    "mongodb": RiskRule(RISK_RISKY, "MongoDB historically ships with auth disabled — the cause of many internet data leaks; enable authorization."),
    "mongodb-http": RiskRule(RISK_WARN, "MongoDB HTTP status interface — exposes server info; disable it."),
    "couchdb": RiskRule(RISK_WARN, "CouchDB — historic unauthenticated admin/API CVEs; verify auth and version."),
    "cassandra": RiskRule(RISK_WARN, "Cassandra — check for default credentials and permissive listen addresses."),
    "elasticsearch": RiskRule(RISK_RISKY, "Elasticsearch historically ships with no auth — a common source of mass data exposure; enable security features."),
    "influxdb": RiskRule(RISK_WARN, "InfluxDB — verify authentication and admin token hygiene."),
    "memcached": RiskRule(RISK_RISKY, "Memcached — known UDP amplification vector for DDoS; disable UDP and restrict access."),
    "sap": RiskRule(RISK_WARN, "SAP services — check for default credentials and missing patches (ICM/Dispatcher)."),
    "hadoop-namenode": RiskRule(RISK_WARN, "Hadoop NameNode web UI — check for unauthenticated APIs; keep behind VPN."),
    "activemq": RiskRule(RISK_WARN, "ActiveMQ — check for default credentials and known deserialization CVEs."),
    "zookeeper": RiskRule(RISK_WARN, "ZooKeeper — unauthenticated by default; can leak coordination data."),
    # --- Developer / orchestration / IoT -------------------------------------------
    "docker": RiskRule(RISK_RISKY, "Docker API without TLS grants remote root — a favorite cryptominer target; require client certs."),
    "docker-tls": RiskRule(RISK_WARN, "Docker API with TLS — verify certs are properly managed and only trusted clients connect."),
    "etcd": RiskRule(RISK_WARN, "etcd — unauthenticated access leaks cluster secrets (TLS keys, tokens); require auth."),
    "consul": RiskRule(RISK_WARN, "Consul — unauthenticated HTTP API allows service/ACL tampering; enable ACLs."),
    "kibana": RiskRule(RISK_WARN, "Kibana — check for exposed dashboards and the Log4Shell-era reverse proxy misconfigs."),
    "kube-apiserver": RiskRule(RISK_WARN, "Kubernetes API server — check RBAC and anonymous auth; a control-plane exposure is critical."),
    "ajp": RiskRule(RISK_WARN, "Apache AJP connector — Ghostcat (CVE-2020-1938) class risk; restrict or remove."),
    "java-debug": RiskRule(RISK_WARN, "Java debug/management port — RMI/JMX with weak auth enables remote code execution; restrict."),
    "rmiregistry": RiskRule(RISK_RISKY, "RMI registry without security manager — historic deserialization RCE vector; disable or restrict."),
    "weblogic": RiskRule(RISK_WARN, "WebLogic — long history of unauthenticated RCE CVEs; keep patched and out of internet reach."),
    "metasploit": RiskRule(RISK_WARN, "Default Metasploit listener port — worth confirming whether this host is an intended testing/analysis box."),
    "back-orifice": RiskRule(RISK_RISKY, "Back Orifice default port — historical RAT; any listener here should be investigated."),
    "adb": RiskRule(RISK_RISKY, "Android Debug Bridge exposed over TCP — grants device control; disable wireless debugging on untrusted networks."),
    "epmd": RiskRule(RISK_WARN, "Erlang port mapper — discloses node names; check for unauthenticated Erlang distribution."),
    "rabbitmq": RiskRule(RISK_WARN, "RabbitMQ management — check default guest/guest credentials."),
    "printer": RiskRule(RISK_WARN, "Raw printing service — check for unauthenticated printer control/DoS exposure."),
    "ipp": RiskRule(RISK_WARN, "Internet Printing Protocol — check for unauthenticated printer management."),
    "afp": RiskRule(RISK_WARN, "Apple Filing Protocol — check share permissions and exposure."),
    "svn": RiskRule(RISK_WARN, "Subversion — check for unauthenticated repo access and credential reuse."),
    "git": RiskRule(RISK_WARN, "Git service — check for exposed repositories with secrets."),
    "upnp": RiskRule(RISK_WARN, "UPnP — check for device info disclosure and NAT-punching abuse; often disabled on routers."),
    "vmware-auth": RiskRule(RISK_WARN, "VMware auth service — check version for known vulnerabilities; restrict management network."),
    "tacacs": RiskRule(RISK_WARN, "TACACS+ — verify shared-secret strength and encryption (TACACS+ encrypts body, not header)."),
    "radius": RiskRule(RISK_WARN, "RADIUS — verify shared secrets and consider EAP/TLS; historic MD5 response attacks."),
    "pptp": RiskRule(RISK_RISKY, "PPTP VPN — MPPE/CHAP cryptography is broken; migrate to IPsec/OpenVPN/WireGuard."),
    "isakmp": RiskRule(RISK_WARN, "IPsec IKE — check aggressive-mode PSK usage (offline-crackable) and VPN configuration."),
    "openvpn": RiskRule(RISK_WARN, "OpenVPN — verify cipher config and that the management interface is not exposed."),
    "ntp": RiskRule(RISK_WARN, "NTP — check for monlist/amplification misconfiguration and version drift."),
    "chargen": RiskRule(RISK_RISKY, "Chargen — classic UDP/TCP amplification source for reflection DDoS; disable."),
    "echo": RiskRule(RISK_WARN, "Echo service — can be abused for reflection; disable when unused."),
    "discard": RiskRule(RISK_WARN, "Discard service — mostly obsolete; disable when unused."),
    "daytime": RiskRule(RISK_WARN, "Daytime service — leaks system time, historically used in reflection; disable when unused."),
    "qotd": RiskRule(RISK_WARN, "Quote of the Day — obsolete; disable when unused."),
    "time": RiskRule(RISK_WARN, "Time service — obsolete; disable when unused."),
    "whois": RiskRule(RISK_WARN, "Whois — check for open recursion/info disclosure on your own server."),
    "ident": RiskRule(RISK_WARN, "Ident — discloses usernames; mostly obsolete."),
    "gopher": RiskRule(RISK_WARN, "Gopher — obsolete protocol; check for legacy exposure."),
    "coda": RiskRule(RISK_WARN, "Coda file service — legacy distributed FS; obsolete."),
    "cisco-sccp": RiskRule(RISK_WARN, "Cisco Skinny (VoIP) — check for unauthenticated phone control."),
    "dc": RiskRule(RISK_WARN, "Direct Connect hub — see directconnect."),
    "mssql": RiskRule(RISK_WARN, "MS SQL Server alias — check weak sa passwords."),
}

#: Normalization aliases: raw service names -> canonical RISK_TABLE key.
SERVICE_ALIASES: Dict[str, str] = {
    "netbios-ssn": "microsoft-ds",
    "netbios": "microsoft-ds",
    "smb": "microsoft-ds",
    "cifs": "microsoft-ds",
    "rdp": "ms-wbt-server",
    "mssql": "ms-sql-s",
    "mysql-d": "mysql",
    "postgres": "postgresql",
    "ms-sql-server": "ms-sql-s",
    "http-alt": "http-alt",
    "web": "http",
    "www": "http",
    "webmin-ssl": "webmin",
    "winsock": "msrpc",
    "esmtp": "smtp",
    "smtp-submission": "submission",
    "oracle-tns": "oracle",
    "oracle-em": "oracle",
    "mongod": "mongodb",
    "memcache": "memcached",
    "vnc-server": "vnc",
    "x11-server": "x11",
    "echo-discard": "discard",
}


# ---------------------------------------------------------------------------
# /etc/services-style fallback
# ---------------------------------------------------------------------------


def etc_services_candidates() -> Iterable[str]:
    """Yield candidate paths of the platform services file.

    The search honors an optional ``PORT_SCANNER_SERVICES`` environment
    variable, then falls back to the conventional location for the
    current platform (``/etc/services`` on Unix, the Windows services
    file under ``%SystemRoot%\\System32\\drivers\\etc``).
    """
    env_path = os.environ.get("PORT_SCANNER_SERVICES")
    if env_path:
        yield env_path
    if sys.platform == "win32":
        root = os.environ.get("SystemRoot", r"C:\Windows")
        yield os.path.join(root, "System32", "drivers", "etc", "services")
    else:
        yield "/etc/services"


def load_etc_services(paths: Optional[Iterable[str]] = None) -> Dict[int, str]:
    """Parse ``name port/protocol`` lines from services files.

    The first readable file wins; well-known curated entries are never
    overwritten (the caller merges with ``setdefault`` semantics).

    Returns
    -------
    dict
        Mapping of ``{port: service_name}`` for TCP entries.
    """
    merged: Dict[int, str] = {}
    for path in paths or etc_services_candidates():
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    name, port_proto = parts[0], parts[1]
                    if "/" not in port_proto:
                        continue
                    port_str, proto = port_proto.split("/", 1)
                    if proto != "tcp" or not port_str.isdigit():
                        continue
                    merged[int(port_str)] = name
        except OSError:
            continue  # best-effort: never fail the scan over OS data
        if merged:
            break
    return merged


# ---------------------------------------------------------------------------
# ServiceDB
# ---------------------------------------------------------------------------


class ServiceDB:
    """Service name + risk lookups used by the scanner.

    Parameters
    ----------
    services_file:
        Optional explicit path to a services file; when ``None`` the
        platform candidates are tried.
    """

    def __init__(self, services_file: Optional[str] = None) -> None:
        self.services: Dict[int, str] = dict(WELL_KNOWN_SERVICES)
        if services_file:
            self._merge(load_etc_services([services_file]))
        else:
            self._merge(load_etc_services())

    def _merge(self, extra: Dict[int, str]) -> None:
        """Merge OS-provided names without overriding curated ones."""
        for port, name in extra.items():
            self.services.setdefault(port, name)

    # -- service names ---------------------------------------------------------

    def service_name(self, port: int) -> str:
        """Return the well-known service name for *port* ('' if unknown)."""
        return self.services.get(port, "")

    # -- risk classification -----------------------------------------------------

    def classify(self, port: int, service: Optional[str] = None) -> Tuple[str, str]:
        """Classify a (port, service) pair.

        Returns ``(risk_level, reason)`` where *risk_level* is one of
        ``SAFE`` / ``WARN`` / ``RISKY`` and *reason* is the educational
        explanation (empty for ``SAFE``).

        The service name comes from the caller (e.g. a banner) or is
        resolved from the port table.
        """
        name = (service or "").strip().lower()
        if not name:
            name = self.service_name(port)
        canonical = SERVICE_ALIASES.get(name, name)
        rule = RISK_TABLE.get(canonical)
        if rule is None:
            return RISK_SAFE, ""
        return rule.level, rule.reason

    # -- top-ports ---------------------------------------------------------------

    @staticmethod
    def top_ports(count: Optional[int] = None) -> List[int]:
        """Return up to *count* most common ports (all of them when None)."""
        if count is None:
            return list(DEFAULT_TOP_PORTS)
        return list(DEFAULT_TOP_PORTS[: max(0, count)])

    # -- misc ----------------------------------------------------------------------

    @staticmethod
    def resolve(host: str) -> str:
        """Resolve *host* to an IPv4 dotted-quad.

        Raises
        ------
        socket.gaierror
            When the host cannot be resolved.
        """
        import socket

        try:
            info = socket.getaddrinfo(host, None, socket.AF_INET)
        except socket.gaierror:
            raise
        return info[0][4][0]
