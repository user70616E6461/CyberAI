import json
from pathlib import Path
from datetime import datetime
from cyberai.core.session import PentestSession

def export_json(session: PentestSession, output_dir: str = "reports/") -> str:
    """Export full session as structured JSON report"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/report_{session.target}_{timestamp}.json"
    filename = filename.replace(":", "_").replace("/", "_")

    report = {
        "meta": {
            "generated": datetime.utcnow().isoformat(),
            "tool": "CyberAI",
            "version": "0.1.0",
        },
        "session": {
            "id": session.id,
            "target": session.target,
            "state": session.state.value,
            "created_at": session.created_at,
        },
        "summary": session.summary(),
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "target": f.target,
                "cve_ids": f.cve_ids,
                "evidence": f.evidence,
                "timestamp": f.timestamp,
            }
            for f in session.findings
        ],
        "attack_paths": session.knowledge_base.get(
            "exploit.attack_paths", {}
        ).get("attack_paths", []),
        "knowledge_base_keys": list(session.knowledge_base.keys()),
        "agent_log": session.agent_log,
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2, default=str)

    return filename

def export_summary(session: PentestSession) -> Dict:
    """Return lightweight summary dict — for CLI display"""
    from typing import Dict
    return {
        **session.summary(),
        "findings_by_severity": {
            sev: [
                {"id": f.id, "title": f.title}
                for f in session.findings
                if f.severity.value == sev
            ]
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        }
    }
