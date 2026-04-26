from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from .config import CyberAIConfig
from .session import PentestSession, SessionState
from .logger import AuditLogger
from .llm_client import LLMClient

console = Console()

BANNER = """
 ██████╗██╗   ██╗██████╗ ███████╗██████╗  █████╗ ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████║██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██║██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
"""

class Orchestrator:
    """
    Master controller — routes tasks between specialist agents.
    Pipeline: ReconAgent → IntelAgent → ExploitAgent → ReportAgent
    """
    VERSION = "0.2.0"

    def __init__(self, config: CyberAIConfig = None):
        self.config = config or CyberAIConfig()
        self.session: PentestSession = None
        self.audit: AuditLogger = None
        self.llm = LLMClient(self.config.llm)

    def start(self, target: str) -> PentestSession:
        self.session = PentestSession(target=target)
        self.audit = AuditLogger(self.session.session_id, str(self.config.output_dir))
        console.print(Panel(BANNER, style="bold red"))
        console.print(f"[bold green]✓ Session [{self.session.session_id}] started[/bold green]")
        console.print(f"[bold yellow]  Target: {target}[/bold yellow]")
        self.audit.agent_action("orchestrator", "session started", {"target": target})
        return self.session

    def run_pipeline(self, target: str, phases: list = None):
        """Run full pentest pipeline"""
        self.start(target)
        phases = phases or ["recon", "intel", "exploit", "report"]

        for phase in phases:
            console.print(f"\n[bold magenta]━━━ Phase: {phase.upper()} ━━━[/bold magenta]")
            if phase == "recon":
                self._run_recon(target)
            elif phase == "intel":
                self._run_intel(target)
            elif phase == "exploit":
                self._run_exploit(target)
            elif phase == "report":
                self._run_report(target)

        self._print_summary()

    def _run_recon(self, target: str):
        from cyberai.agents.recon.agent import ReconAgent
        self.session.set_state(SessionState.RECON)
        agent = ReconAgent(self.config, self.kb, self.audit, self.session.session_id)
        result = agent.run(target)
        self.kb.set("recon", result)

    def _run_intel(self, target: str):
        from cyberai.agents.intel.agent import IntelAgent
        self.session.set_state(SessionState.INTEL)
        agent = IntelAgent(self.config, self.kb, self.audit, self.session.session_id)
        result = agent.run(target)
        self.kb.set("intel", result)

    def _run_exploit(self, target: str):
        from cyberai.agents.exploit.agent import ExploitAgent
        self.session.set_state(SessionState.EXPLOIT)
        agent = ExploitAgent(self.config, self.kb, self.audit, self.session.session_id)
        result = agent.run(target)
        self.kb.set("exploit", result)

    def _run_report(self, target: str):
        from cyberai.agents.report.agent import ReportAgent
        self.session.set_state(SessionState.REPORTING)
        agent = ReportAgent(self.config, self.kb, self.audit, self.session.session_id)
        agent.run(target, session=self.session)
        self.session.set_state(SessionState.COMPLETE)

    def _print_summary(self):
        summary = self.session.summary()
        table = Table(title="Session Summary", style="bold blue")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        for k, v in summary.items():
            table.add_row(str(k), str(v))
        console.print(table)
