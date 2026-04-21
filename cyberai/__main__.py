import click
from rich.console import Console
from rich.panel import Panel
from .core.config import CyberAIConfig
from .core.session import PentestSession
from .core.orchestrator import Orchestrator

console = Console()

BANNER = """
[bold red]
 ██████╗██╗   ██╗██████╗ ███████╗██████╗  █████╗ ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████║██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██║██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
[/bold red]
[dim]AI-native pentest platform[/dim]
"""

@click.group()
def cli():
    """CyberAI — AI-powered pentest platform"""
    pass

@cli.command()
@click.argument("target")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--provider", default="openai", help="LLM provider")
def scan(target: str, verbose: bool, provider: str):
    """Run full pentest pipeline against TARGET"""
    console.print(BANNER)
    console.print(Panel(f"[bold]Target:[/bold] {target}", style="red"))

    config = CyberAIConfig.from_env()
    config.verbose = verbose
    config.llm.provider = provider

    session = PentestSession(target=target)
    orchestrator = Orchestrator(config)

    console.print("[yellow]→[/yellow] Starting pipeline...")
    session = orchestrator.run_pipeline(session)

    console.print(f"\n[green]✓[/green] Done. Findings: {len(session.findings)}")
    summary = session.summary()
    for k, v in summary.items():
        console.print(f"  {k}: {v}")

@cli.command()
def status():
    """Show CyberAI status and config"""
    config = CyberAIConfig.from_env()
    console.print(Panel(
        f"Provider: {config.llm.provider}\n"
        f"Model: {config.llm.model}\n"
        f"Output: {config.output_dir}",
        title="CyberAI Status"
    ))

if __name__ == "__main__":
    cli()
