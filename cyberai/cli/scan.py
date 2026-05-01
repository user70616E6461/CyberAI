"""
CLI scan command — end-to-end pentest pipeline.
"""
import argparse
import sys
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cyberai.core.scan_session import ScanSession, ScanPhase
from cyberai.core.logger import get_logger

console = Console()
log = get_logger("cli.scan")

AVAILABLE_PHASES = ["recon", "intel", "exploit", "report"]


def run_scan(args: argparse.Namespace) -> int:
    target = args.target
    scope  = args.scope or []
    phases = _parse_phases(args.phases)

    session = ScanSession(target=target, authorized_scope=scope)

    console.print(Panel(
        f"[bold red]CyberAI Scan[/bold red]\n"
        f"Target : [yellow]{target}[/yellow]\n"
        f"Scope  : [yellow]{scope or 'not set'}[/yellow]\n"
        f"Phases : [yellow]{[p.value for p in phases]}[/yellow]\n"
        f"Session: [dim]{session.session_id}[/dim]",
        border_style="red"
    ))

    session.start()

    for phase in phases:
        _run_phase(session, phase, args)

    if all(p.success for p in session.phases):
        session.complete()
        _print_summary(session)
        return 0
    else:
        session.fail("One or more phases failed")
        _print_summary(session)
        return 1


def _run_phase(session, phase, args):
    started = datetime.now(timezone.utc).isoformat()
    session.set_phase(phase)
    console.print(f"\n[bold red]▶ Phase: {phase.value.upper()}[/bold red]")
    try:
        if phase == ScanPhase.RECON:
            data = _phase_recon(session)
        elif phase == ScanPhase.INTEL:
            data = _phase_intel(session)
        elif phase == ScanPhase.EXPLOIT:
            data = _phase_exploit(session)
        elif phase == ScanPhase.REPORT:
            data = _phase_report(session)
        else:
            data = {}
        session.record_phase(phase, success=True, started=started, data=data)
        console.print(f"[green]✓ {phase.value} complete[/green]")
    except Exception as e:
        session.record_phase(phase, success=False, started=started, error=str(e))
        console.print(f"[red]✗ {phase.value} failed: {e}[/red]")


def _phase_recon(session):
    from cyberai.agents.recon.agent import ReconAgent
    result = ReconAgent(kb=session.kb).run(session.target)
    session.kb_set("recon", result)
    return result


def _phase_intel(session):
    from cyberai.agents.intel.agent import IntelAgent
    result = IntelAgent(kb=session.kb).run(session.target)
    session.kb_set("intel", result)
    return result


def _phase_exploit(session):
    from cyberai.agents.exploit.agent import ExploitAgent
    from cyberai.agents.exploit.safety_validator import validate_exploit_scope
    attack_paths = session.kb_get("intel", {}).get("ranked_cves", [])
    validation = validate_exploit_scope(
        session.target, session.authorized_scope, attack_paths
    )
    if not validation.passed:
        raise RuntimeError(f"Scope validation failed: {validation.violations}")
    for w in validation.warnings:
        console.print(f"[yellow]⚠ {w}[/yellow]")
    result = ExploitAgent(kb=session.kb).run(session.target)
    session.kb_set("exploit", result)
    return result


def _phase_report(session):
    from cyberai.agents.report.agent import ReportAgent
    result = ReportAgent(kb=session.kb).run(session.target)
    session.kb_set("report", result)
    return result


def _parse_phases(phases_str):
    if not phases_str:
        return [ScanPhase(p) for p in AVAILABLE_PHASES]
    parts = [p.strip() for p in phases_str.split(",")]
    result = []
    for p in parts:
        if p not in AVAILABLE_PHASES:
            console.print(f"[red]Unknown phase: {p}[/red]")
            sys.exit(2)
        result.append(ScanPhase(p))
    return result


def _print_summary(session):
    summary = session.summary()
    table = Table(title="Scan Summary", style="red")
    table.add_column("Phase")
    table.add_column("Status")
    table.add_column("Duration")
    table.add_column("Error", style="red")
    for p in summary["phases"]:
        status = "[green]✓[/green]" if p["success"] else "[red]✗[/red]"
        table.add_row(p["phase"], status, f"{p['duration_s']:.1f}s", p["error"] or "")
    console.print(table)
    console.print(
        f"\n[bold]Session:[/bold] {summary['session_id']} | "
        f"[bold]State:[/bold] {summary['state']} | "
        f"[bold]Duration:[/bold] {summary['duration_s']}s"
    )


def build_parser():
    parser = argparse.ArgumentParser(prog="cyberai scan")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--scope", nargs="*", help="Authorized scope")
    parser.add_argument("--phases", help="recon,intel,exploit,report")
    parser.add_argument("--output", default="report.json")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(run_scan(args))


if __name__ == "__main__":
    main()
