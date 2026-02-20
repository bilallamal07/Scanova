"""Rich terminal output formatter."""

from __future__ import annotations

from itertools import groupby
from operator import attrgetter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from skill_scanner.models import ScanReport, Severity, Verdict

SEVERITY_ICONS: dict[Severity, str] = {
    Severity.INFO: "[dim]INFO[/]",
    Severity.LOW: "[blue]LOW[/]",
    Severity.MEDIUM: "[yellow]MEDIUM[/]",
    Severity.HIGH: "[red]HIGH[/]",
    Severity.CRITICAL: "[bold red]CRITICAL[/]",
}

VERDICT_STYLE: dict[Verdict, str] = {
    Verdict.CLEAN: "[bold green]CLEAN[/]",
    Verdict.LOW_RISK: "[bold blue]LOW RISK[/]",
    Verdict.WARNING: "[bold yellow]WARNING[/]",
    Verdict.CRITICAL: "[bold red]CRITICAL[/]",
}


def _score_bar(score: int) -> str:
    """Build a colored score bar string."""
    filled = score // 5  # 0-20 blocks
    empty = 20 - filled
    if score <= 30:
        color = "green"
    elif score <= 60:
        color = "yellow"
    else:
        color = "red"
    return f"[{color}]{'█' * filled}[/][dim]{'░' * empty}[/] {score}/100"


def _shorten_path(file_path: str, base_path: str) -> str:
    """Make file paths relative to the scan root for readability."""
    if file_path.startswith(base_path):
        rel = file_path[len(base_path):].lstrip("/")
        return rel or file_path
    return file_path


def format_quiet(report: ScanReport, no_color: bool = False) -> None:
    """Print only score and verdict."""
    console = Console(no_color=no_color)
    verdict_str = VERDICT_STYLE.get(report.verdict, str(report.verdict))
    console.print(f"Score: {report.score}/100  Verdict: {verdict_str}")


def format_report(
    report: ScanReport,
    min_severity: Severity = Severity.LOW,
    no_color: bool = False,
) -> None:
    """Print full terminal report."""
    console = Console(no_color=no_color)
    base = report.metadata.scanned_path

    # --- Header panel ---
    header_lines = [
        f"Path:    {base}",
        f"Files:   {report.metadata.files_scanned}",
        f"Time:    {report.metadata.duration_ms:.0f}ms",
    ]
    console.print(Panel(
        "\n".join(header_lines),
        title="[bold]skill-scanner[/]",
        border_style="dim",
    ))

    # --- Score + verdict ---
    console.print()
    console.print(f"  Score:   {_score_bar(report.score)}")
    verdict_str = VERDICT_STYLE.get(report.verdict, str(report.verdict))
    console.print(f"  Verdict: {verdict_str}")
    console.print()

    # --- Findings ---
    filtered = [f for f in report.findings if f.severity >= min_severity]
    if not filtered:
        console.print("  [green]No findings above threshold.[/]")
        return

    # Group by dimension
    sorted_findings = sorted(filtered, key=lambda f: (f.dimension, -f.severity))
    for dimension, group in groupby(sorted_findings, key=attrgetter("dimension")):
        table = Table(
            title=f"[bold]{dimension.replace('_', ' ').title()}[/]",
            show_header=True,
            header_style="bold",
            border_style="dim",
            pad_edge=False,
        )
        table.add_column("Severity", width=10)
        table.add_column("Rule", width=22)
        table.add_column("Location", width=30)
        table.add_column("Match", max_width=40)

        for finding in group:
            sev = SEVERITY_ICONS.get(finding.severity, str(finding.severity))
            loc = f"{_shorten_path(finding.file_path, base)}:{finding.line_number}"
            match_text = finding.matched_text
            if len(match_text) > 40:
                match_text = match_text[:37] + "..."
            table.add_row(sev, finding.rule_name, loc, match_text)

        console.print(table)
        console.print()

    console.print(f"  [dim]Total: {len(filtered)} finding(s)[/]")
