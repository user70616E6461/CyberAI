import subprocess
from typing import Dict, Any

def run_nmap(target: str, flags: str = "-sV -T4 --top-ports 1000") -> Dict[str, Any]:
    """
    Run nmap against target, return parsed results.
    Requires nmap installed on system.
    """
    cmd = ["nmap", "-oX", "-"] + flags.split() + [target]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        return {
            "target": target,
            "raw": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "ports": _parse_ports(result.stdout),
        }
    except subprocess.TimeoutExpired:
        return {"target": target, "error": "nmap timeout after 120s"}
    except FileNotFoundError:
        return {"target": target, "error": "nmap not found — install with: apt install nmap"}

def _parse_ports(xml_output: str) -> list:
    """Extract open ports from nmap XML output"""
    import re
    ports = []
    for match in re.finditer(
        r'<port protocol="(\w+)" portid="(\d+)">.*?'
        r'<state state="(\w+)".*?/>.*?'
        r'<service name="([^"]*)"',
        xml_output, re.DOTALL
    ):
        proto, port, state, service = match.groups()
        if state == "open":
            ports.append({
                "port": int(port),
                "protocol": proto,
                "service": service,
                "state": state,
            })
    return ports

