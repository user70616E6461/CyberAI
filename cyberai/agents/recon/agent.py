from typing import Dict, Any
from cyberai.core.base_agent import BaseAgent, Tool
from cyberai.core.session import Finding, Severity
from .nmap_tool import run_nmap
from .dns_tool import run_whois, run_dns, detect_subdomains

class ReconAgent(BaseAgent):
    """
    Reconnaissance agent.
    Runs: nmap → whois → DNS → subdomain enum
    Stores all results in session knowledge base.
    """

    def _register_tools(self):
        self.register_tool(Tool(
            name="nmap_scan",
            description="Port scan target with nmap",
            func=run_nmap,
            parameters={"target": "str", "flags": "str"}
        ))
        self.register_tool(Tool(
            name="whois_lookup",
            description="WHOIS lookup for domain info",
            func=run_whois,
            parameters={"target": "str"}
        ))
        self.register_tool(Tool(
            name="dns_enum",
            description="DNS record enumeration",
            func=run_dns,
            parameters={"target": "str"}
        ))
        self.register_tool(Tool(
            name="subdomain_scan",
            description="Subdomain bruteforce",
            func=detect_subdomains,
            parameters={"target": "str"}
        ))

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        target = self.session.target
        kb = {}

        # 1. nmap
        self._check_iteration_limit()
        nmap_result = run_nmap(target)
        kb["recon.nmap"] = nmap_result
        self._log("nmap_scan", nmap_result)

        # 2. whois
        self._check_iteration_limit()
        whois_result = run_whois(target)
        kb["recon.whois"] = whois_result
        self._log("whois_lookup", whois_result)

        # 3. DNS
        self._check_iteration_limit()
        dns_result = run_dns(target)
        kb["recon.dns"] = dns_result
        self._log("dns_enum", dns_result)

        # 4. Subdomains
        self._check_iteration_limit()
        sub_result = detect_subdomains(target)
        kb["recon.subdomains"] = sub_result
        self._log("subdomain_scan", sub_result)

        # Store in session KB
        for key, value in kb.items():
            self.session.knowledge_base[key] = value

        # Surface open ports as findings
        ports = nmap_result.get("ports", [])
        if ports:
            self.session.add_finding(Finding(
                title=f"Open ports on {target}",
                description=f"Found {len(ports)} open port(s)",
                severity=Severity.INFO,
                target=target,
                evidence=[str(p) for p in ports],
            ))

        return {"status": "done", "kb_keys": list(kb.keys())}
