import pytest
from unittest.mock import patch, MagicMock
from cyberai.core.config import CyberAIConfig
from cyberai.core.session import PentestSession, SessionState
from cyberai.core.orchestrator import Orchestrator
from cyberai.agents.recon.agent import ReconAgent
from cyberai.agents.intel.agent import IntelAgent
from cyberai.agents.exploit.agent import ExploitAgent
from cyberai.agents.report.agent import ReportAgent

MOCK_PORTS = [
    {"port": 80,  "service": "http",  "state": "open", "protocol": "tcp"},
    {"port": 22,  "service": "ssh",   "state": "open", "protocol": "tcp"},
    {"port": 443, "service": "https", "state": "open", "protocol": "tcp"},
]

MOCK_CVES = [
    {
        "id": "CVE-2021-44228",
        "description": "Log4Shell RCE via JNDI injection",
        "cvss": {"score": 10.0, "severity": "CRITICAL"},
        "published": "2021-12-10",
        "references": [],
    }
]

@pytest.fixture
def config():
    return CyberAIConfig()

@pytest.fixture
def session():
    return PentestSession(target="testhost.local")

def test_session_state_machine(session):
    """Session should transition through states correctly"""
    assert session.state == SessionState.IDLE
    session.set_state(SessionState.RECON)
    assert session.state == SessionState.RECON
    session.set_state(SessionState.DONE)
    assert session.state == SessionState.DONE

def test_session_findings(session):
    """Findings should accumulate correctly"""
    from cyberai.core.session import Finding, Severity
    session.add_finding(Finding(
        title="Test Finding",
        severity=Severity.HIGH,
        target="testhost.local"
    ))
    assert len(session.findings) == 1
    assert session.summary()["findings"] == 1

@patch("cyberai.agents.recon.agent.run_nmap")
@patch("cyberai.agents.recon.agent.run_whois")
@patch("cyberai.agents.recon.agent.run_dns")
@patch("cyberai.agents.recon.agent.detect_subdomains")
def test_recon_agent(mock_sub, mock_dns, mock_whois, mock_nmap, config, session):
    """ReconAgent should populate KB with recon data"""
    mock_nmap.return_value = {"ports": MOCK_PORTS, "target": "testhost.local"}
    mock_whois.return_value = {"registrar": "Test Registrar"}
    mock_dns.return_value = {"records": {"A": ["1.2.3.4"]}}
    mock_sub.return_value = {"subdomains": ["www.testhost.local"]}

    agent = ReconAgent(config, session)
    result = agent.run({})

    assert result["status"] == "done"
    assert "recon.nmap" in session.knowledge_base
    assert session.knowledge_base["recon.nmap"]["ports"] == MOCK_PORTS

@patch("cyberai.agents.intel.agent.search_cves")
def test_intel_agent(mock_cves, config, session):
    """IntelAgent should surface HIGH/CRITICAL CVEs as findings"""
    session.knowledge_base["recon.nmap"] = {"ports": MOCK_PORTS}
    mock_cves.return_value = {"cves": MOCK_CVES}

    agent = IntelAgent(config, session)
    result = agent.run({})

    assert result["status"] == "done"
    assert "intel.cves" in session.knowledge_base
    # Log4Shell CVSS 10.0 → should create a finding
    critical = [f for f in session.findings if "CVE-2021-44228" in f.cve_ids]
    assert len(critical) >= 1

def test_exploit_agent_no_cves(config, session):
    """ExploitAgent should skip gracefully with no CVEs"""
    agent = ExploitAgent(config, session)
    result = agent.run({})
    assert result["status"] == "skipped"

@patch("cyberai.agents.exploit.agent.generate_attack_paths")
def test_exploit_agent_with_cves(mock_paths, config, session):
    """ExploitAgent should look up PoCs for known CVEs"""
    session.knowledge_base["intel.cves"] = MOCK_CVES
    session.knowledge_base["recon.nmap"] = {"ports": MOCK_PORTS}
    mock_paths.return_value = {"attack_paths": []}

    agent = ExploitAgent(config, session)
    result = agent.run({})

    assert result["status"] == "done"
    assert "exploit.pocs" in session.knowledge_base

def test_full_orchestrator_pipeline(config, session):
    """Orchestrator should run all registered agents in sequence"""
    # Use lightweight mock agents
    mock_agent = MagicMock()
    mock_agent.run.return_value = {"status": "done"}

    orch = Orchestrator(config)
    orch.register_agent("recon", mock_agent)
    orch.register_agent("intel", mock_agent)
    orch.register_agent("exploit", mock_agent)
    orch.register_agent("report", mock_agent)

    result = orch.run_pipeline(session)

    assert result.state == SessionState.DONE
    assert mock_agent.run.call_count == 4
