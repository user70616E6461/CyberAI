from typing import Dict, Any
from pathlib import Path
from cyberai.core.base_agent import BaseAgent, Tool
from .markdown_renderer import render_markdown
from .json_exporter import export_json

class ReportAgent(BaseAgent):
    """
    Report generation agent.
    Reads full session → renders Markdown + JSON → saves to disk.
    """

    def _register_tools(self):
        self.register_tool(Tool(
            name="render_markdown",
            description="Render Markdown pentest report",
            func=render_markdown,
            parameters={"session": "PentestSession"}
        ))
        self.register_tool(Tool(
            name="export_json",
            description="Export session as JSON report",
            func=export_json,
            parameters={"session": "PentestSession", "output_dir": "str"}
        ))

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        output_dir = str(self.config.output_dir)
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # 1. Render Markdown
        self._check_iteration_limit()
        md_content = render_markdown(self.session)

        from datetime import datetime
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_target = self.session.target.replace(":", "_").replace("/", "_")
        md_path = f"{output_dir}/report_{safe_target}_{ts}.md"

        with open(md_path, "w") as f:
            f.write(md_content)

        self._log("report", f"Markdown saved: {md_path}")

        # 2. Export JSON
        self._check_iteration_limit()
        json_path = export_json(self.session, output_dir)
        self._log("report", f"JSON saved: {json_path}")

        # Store paths in KB
        self.session.knowledge_base["report.markdown_path"] = md_path
        self.session.knowledge_base["report.json_path"] = json_path

        return {
            "status": "done",
            "markdown": md_path,
            "json": json_path,
            "total_findings": len(self.session.findings),
        }
