"""
Unit tests for the Port Scanner.

These tests exercise the port-list builder, the report builders, the service
database classification and the banner-classification logic without contacting
the network.
"""

from scanner import ServiceDB, RISK_RISKY, RISK_WARN, RISK_SAFE
from scanner.report import render_json, render_scan_summary, has_risky
from scanner.scanner_core import PortResult, PortState
from scanner.banner_grabber import BannerGrabber

import port_scanner as ps

import pytest


# --- Build port list ---------------------------------------------------------
def test_ports_single():
    args = ps.parse_args(["example.com", "--ports", "80"])
    assert ps.build_port_list(args) == [80]


def test_ports_list():
    args = ps.parse_args(["example.com", "--ports", "22,443,8080"])
    assert ps.build_port_list(args) == [22, 443, 8080]


def test_ports_range():
    args = ps.parse_args(["example.com", "--ports", "1-5"])
    assert ps.build_port_list(args) == [1, 2, 3, 4, 5]


def test_ports_mixed_range():
    args = ps.parse_args(["example.com", "--ports", "80,443,8000-8002"])
    assert ps.build_port_list(args) == [80, 443, 8000, 8001, 8002]


def test_top_ports():
    args = ps.parse_args(["example.com", "--top-ports", "5"])
    ports = ps.build_port_list(args)
    assert len(ports) == 5


def test_ports_clamped_and_deduped():
    args = ps.parse_args(["example.com", "--ports", "99999,80,80,0"])
    assert ps.build_port_list(args) == [80]


# --- Service database --------------------------------------------------------
def test_service_name_known():
    db = ServiceDB()
    assert db.service_name(22) == "ssh"
    assert db.service_name(443) == "https"


def test_classify_telnet_risky():
    db = ServiceDB()
    level, reason = db.classify(23, "telnet")
    assert level == RISK_RISKY
    assert reason


def test_classify_unknown_safe():
    db = ServiceDB()
    level, reason = db.classify(12345)
    assert level == RISK_SAFE
    assert reason == ""


def test_top_ports_subset():
    assert len(ServiceDB.top_ports(10)) == 10


# --- Report ------------------------------------------------------------------
def _open(port, service="", risk=RISK_SAFE, reason=""):
    return PortResult(port=port, state=PortState.OPEN, service=service, risk_level=risk, risk_reason=reason)


def test_report_has_risky():
    results = [_open(80, "http", RISK_WARN, "cleartext"), _open(8080, "http-alt", RISK_SAFE)]
    assert has_risky(results) is True


def test_report_clean():
    assert has_risky([_open(443, "https")]) is False


def test_render_json_shape():
    results = [_open(22, "ssh", RISK_SAFE)]
    payload = render_json(results, "example.com", "1.2.3.4", 1)
    assert '"ports_scanned": 1' in payload
    assert '"open_ports"' in payload
    assert '"port": 22' in payload


def test_render_scan_summary_contains_open():
    results = [_open(22, "ssh", RISK_SAFE)]
    text = render_scan_summary(results, "example.com", "1.2.3.4", 1, False, use_color=False)
    assert "22" in text
    assert "ssh" in text


# --- Banner classification ---------------------------------------------------
def test_banner_classify_ssh():
    g = BannerGrabber()
    assert g.classify_banner("SSH-2.0-OpenSSH_9.2") == "ssh"


def test_banner_classify_unknown():
    g = BannerGrabber()
    assert g.classify_banner("HELLO WORLD") == ""


# --- PortResult style --------------------------------------------------------
def test_port_result_to_dict():
    r = _open(22, "ssh", RISK_SAFE)
    d = r.to_dict()
    assert d["port"] == 22
    assert d["state"] == "open"
