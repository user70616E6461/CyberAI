import pytest
from cyberai.core.config import CyberAIConfig
from cyberai.core.session import PentestSession

@pytest.fixture(scope="session")
def base_config():
    """Shared config for all tests — no real API keys needed"""
    return CyberAIConfig()

@pytest.fixture
def fresh_session():
    """Fresh session for each test"""
    return PentestSession(target="testhost.local")

@pytest.fixture
def session_with_recon(fresh_session):
    """Session pre-loaded with recon data"""
    fresh_session.knowledge_base["recon.nmap"] = {
        "ports": [
            {"port": 80,  "service": "http", "state": "open"},
            {"port": 22,  "service": "ssh",  "state": "open"},
        ]
    }
    return fresh_session
