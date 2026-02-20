"""CLI entry point for skill-scanner."""

from __future__ import annotations

import sys

import click

from skill_scanner import __version__
from skill_scanner.formatters import json_fmt, markdown_fmt, terminal
from skill_scanner.models import Severity
from skill_scanner.scanner import scan_folder, scan_single_file, scan_url


@click.command()
@click.argument("path", type=click.Path(exists=True, file_okay=True, dir_okay=True), required=False)
@click.option("--url", "remote_url", default=None, help="Fetch and scan a remote file URL.")
@click.option(
    "--format", "output_format",
    type=click.Choice(["terminal", "json", "markdown"]),
    default="terminal",
    help="Output format.",
)
@click.option(
    "--severity",
    type=click.Choice(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="LOW",
    help="Minimum severity to report.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default=None,
    help="Exit 2 if any finding meets this severity.",
)
@click.option("--quiet", is_flag=True, help="Only output score and verdict.")
@click.option("--no-color", is_flag=True, help="Disable terminal colors.")
@click.option(
    "--exclude",
    multiple=True,
    help="Glob pattern for files to skip (repeatable).",
)
@click.version_option(version=__version__)
def main(
    path: str | None,
    remote_url: str | None,
    output_format: str,
    severity: str,
    fail_on: str | None,
    quiet: bool,
    no_color: bool,
    exclude: tuple[str, ...],
) -> None:
    """Scan agent skill files for security risks.

    PATH is a local skill folder or file to scan.
    Use --url to fetch and scan a remote file instead.
    """
    if remote_url and path:
        raise click.UsageError("Provide either PATH or --url, not both.")
    if not remote_url and not path:
        raise click.UsageError("Provide a PATH or --url to scan.")

    if remote_url:
        try:
            report = scan_url(remote_url)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
    else:
        import pathlib
        p = pathlib.Path(path)  # type: ignore[arg-type]
        if p.is_file():
            report = scan_single_file(p)
        else:
            report = scan_folder(p, exclude_patterns=list(exclude) or None)

    min_severity = Severity[severity]
    fail_threshold = Severity[fail_on] if fail_on else None

    if output_format == "json":
        json_fmt.format_report(report, min_severity=min_severity)
    elif output_format == "markdown":
        markdown_fmt.format_report(report, min_severity=min_severity)
    elif quiet:
        terminal.format_quiet(report, no_color=no_color)
    else:
        terminal.format_report(report, min_severity=min_severity, no_color=no_color)

    sys.exit(report.exit_code(fail_on=fail_threshold))
