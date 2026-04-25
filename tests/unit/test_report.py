import pytest
from unittest.mock import MagicMock
from cyberai.core.session import PentestSession, Finding, Severity
from cyberai.agents.report.markdown_renderer import render_markdown

def make_session():
    s = PentestSession(target="testhost.local")
    s.add_finding(Finding(
        title="Open SSH Port",
        description="SSH running on port 22",
        severity=Severity.INFO,
        target="testhost.local",
    ))
    s.add_finding(Finding(
        title="Log4Shell",
        description="CVE-2021-44228 detected",
        severity=Severity.CRITICAL,
        target="testhost.local",
        cve_ids=["CVE-2021-44228"],
        evidence=["CVSS: 10.0"],
    ))
    return s

def test_render_markdown_contains_target():
    s = make_session()
    md = render_markdown(s)
    assert "testhost.local" in md

def test_render_markdown_contains_findings():
    s = make_session()
    md = render_markdown(s)
    assert "Log4Shell" in md
    assert "CVE-2021-44228" in md

def test_render_markdown_severity_counts():
    s = make_session()
    md = render_markdown(s)
    assert "Critical | 1" in md
    assert "Info     | 1" in md

def test_render_markdown_has_summary_table():
    s = make_session()
    md = render_markdown(s)
    assert "Executive Summary" in md
    assert "Total" in md
