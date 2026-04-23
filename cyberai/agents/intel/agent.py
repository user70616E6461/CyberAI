from typing import Dict, Any, List
from cyberai.core.base_agent import BaseAgent, Tool
from cyberai.core.session import Finding, Severity
from .nvd_client import search_cves, get_cve
from .service_mapper import ports_to_queries, score_to_severity
import time

class IntelAgent(BaseAgent):
    """
    CVE Intelligence Agent.
    Reads recon results → queries NVD → surfaces critical findings.
    """

    def _register_tools(self):
        self.register_tool(Tool(
            name="search_cves",
            description="Search NVD for CVEs by keyword",
            func=search_cves,
            parameters={"keyword": "str", "max_results": "int"}
        ))
        self.register_tool(Tool(
            name="get_cve",
            description="Get details for a specific CVE ID",
            func=get_cve,
            parameters={"cve_id": "str"}
        ))

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        target = self.session.target

        # Pull nmap results from session KB
        nmap_data = self.session.knowledge_base.get("recon.nmap", {})
        ports = nmap_data.get("ports", [])

        if not ports:
            self._log("intel", "no ports found in KB — skipping CVE lookup")
            return {"status": "skipped", "reason": "no ports"}

        # Build search queries from open ports
        queries = ports_to_queries(ports)
        all_cves: List[Dict] = []

        for query in queries[:5]:  # Limit to 5 queries — NVD rate limit
            self._check_iteration_limit()
            result = search_cves(query, max_results=5)
            cves = result.get("cves", [])
            all_cves.extend(cves)
            time.sleep(0.6)  # NVD rate limit: ~5 req/30s without API key

        # Store in KB
        self.session.knowledge_base["intel.cves"] = all_cves
        self._log("intel", f"found {len(all_cves)} CVEs for {len(queries)} services")

        # Surface high/critical as findings
        for cve in all_cves:
            score = cve.get("cvss", {}).get("score") or 0
            if score >= 7.0:
                sev_str = score_to_severity(score)
                sev = getattr(Severity, sev_str, Severity.HIGH)
                self.session.add_finding(Finding(
                    title=cve["id"],
                    description=cve["description"],
                    severity=sev,
                    target=target,
                    cve_ids=[cve["id"]],
                    evidence=[f"CVSS: {score}", cve.get("cvss", {}).get("vector", "")],
                ))

        return {
            "status": "done",
            "queries": queries,
            "cves_found": len(all_cves),
            "high_critical": sum(
                1 for c in all_cves
                if (c.get("cvss", {}).get("score") or 0) >= 7.0
            )
        }
