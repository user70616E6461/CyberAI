import uuid
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

class SessionState(str, Enum):
    IDLE       = "idle"
    RECON      = "recon"
    INTEL      = "intel"
    EXPLOIT    = "exploit"
    REPORTING  = "reporting"
    COMPLETE   = "complete"

@dataclass
class Finding:
    id: int
    severity: Severity
    title: str
    description: str
    timestamp: str
    agent: str
    cve: Optional[str] = None
    data: Any = None

@dataclass
class PentestSession:
    session_id: str      = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target: str          = ""
    started_at: datetime = field(default_factory=datetime.utcnow)
    state: SessionState  = SessionState.IDLE
    findings: List[Finding] = field(default_factory=list)
    recon_data: Dict[str, Any]  = field(default_factory=dict)
    intel_data: Dict[str, Any]  = field(default_factory=dict)
    exploit_data: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, severity: Severity, title: str,
                    description: str, agent: str,
                    cve: str = None, data: Any = None) -> Finding:
        f = Finding(
            id=len(self.findings) + 1,
            severity=severity,
            title=title,
            description=description,
            timestamp=datetime.utcnow().isoformat(),
            agent=agent,
            cve=cve,
            data=data
        )
        self.findings.append(f)
        return f

    def set_state(self, state: SessionState):
        self.state = state

    def summary(self) -> Dict[str, Any]:
        severity_counts = {}
        for s in Severity:
            severity_counts[s.value] = sum(1 for f in self.findings if f.severity == s)
        return {
            "session_id": self.session_id,
            "target": self.target,
            "state": self.state.value,
            "duration_seconds": (datetime.utcnow() - self.started_at).seconds,
            "findings_total": len(self.findings),
            "severity_breakdown": severity_counts,
        }
