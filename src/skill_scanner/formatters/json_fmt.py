"""JSON output formatter."""

from __future__ import annotations

import json
import sys

from skill_scanner.models import ScanReport, Severity


def format_report(
    report: ScanReport,
    min_severity: Severity = Severity.LOW,
) -> None:
    """Print JSON report to stdout."""
    data = report.model_dump(mode="json")

    # Filter findings by severity threshold
    data["findings"] = [
        f for f in data["findings"]
        if f["severity"] >= int(min_severity)
    ]

    json.dump(data, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
