"""Tests for terminal and JSON formatters."""

from __future__ import annotations

import json

from skill_scanner.formatters import json_fmt, terminal
from skill_scanner.models import (
    Dimension,
    Finding,
    ScanMetadata,
    ScanReport,
    Severity,
)


def _meta(**overrides):
    defaults = {"scanned_path": "/tmp/test", "files_scanned": 2, "duration_ms": 15.5}
    return ScanMetadata(**(defaults | overrides))


def _finding(severity=Severity.HIGH, dimension=Dimension.REMOTE_EXECUTION, **overrides):
    defaults = {
        "dimension": dimension,
        "severity": severity,
        "file_path": "/tmp/test/SKILL.md",
        "line_number": 10,
        "rule_name": "test-rule",
        "description": "test finding",
        "matched_text": "eval(",
    }
    return Finding(**(defaults | overrides))


# ---------------------------------------------------------------------------
# Terminal formatter
# ---------------------------------------------------------------------------


class TestTerminalFormatter:
    def test_clean_report_output(self, capsys):
        report = ScanReport(findings=[], metadata=_meta())
        terminal.format_report(report, no_color=True)
        out = capsys.readouterr().out
        assert "CLEAN" in out
        assert "0/100" in out
        assert "No findings above threshold" in out

    def test_findings_grouped_by_dimension(self, capsys):
        findings = [
            _finding(Severity.HIGH, Dimension.REMOTE_EXECUTION),
            _finding(Severity.CRITICAL, Dimension.OBFUSCATION),
        ]
        report = ScanReport(findings=findings, metadata=_meta())
        terminal.format_report(report, no_color=True)
        out = capsys.readouterr().out
        assert "Remote Execution" in out
        assert "Obfuscation" in out

    def test_severity_filter(self, capsys):
        findings = [
            _finding(Severity.LOW),
            _finding(Severity.CRITICAL),
        ]
        report = ScanReport(findings=findings, metadata=_meta())
        terminal.format_report(report, min_severity=Severity.HIGH, no_color=True)
        out = capsys.readouterr().out
        # Only CRITICAL should appear (HIGH threshold filters out LOW)
        assert "1 finding(s)" in out

    def test_quiet_mode(self, capsys):
        report = ScanReport(
            findings=[_finding(Severity.CRITICAL)],
            metadata=_meta(),
        )
        terminal.format_quiet(report, no_color=True)
        out = capsys.readouterr().out
        assert "Score:" in out
        assert "Verdict:" in out

    def test_score_bar_green(self):
        bar = terminal._score_bar(0)
        assert "0/100" in bar

    def test_score_bar_red(self):
        bar = terminal._score_bar(80)
        assert "80/100" in bar

    def test_shorten_path(self):
        short = terminal._shorten_path("/tmp/test/SKILL.md", "/tmp/test")
        assert short == "SKILL.md"

    def test_shorten_path_no_match(self):
        short = terminal._shorten_path("/other/SKILL.md", "/tmp/test")
        assert short == "/other/SKILL.md"

    def test_long_match_truncated(self, capsys):
        long_text = "x" * 60
        findings = [_finding(matched_text=long_text)]
        report = ScanReport(findings=findings, metadata=_meta())
        terminal.format_report(report, no_color=True)
        out = capsys.readouterr().out
        # Full 60-char text should not appear — Rich truncates at max_width
        assert long_text not in out


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


class TestJsonFormatter:
    def test_valid_json(self, capsys):
        report = ScanReport(findings=[_finding()], metadata=_meta())
        json_fmt.format_report(report)
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "findings" in data
        assert "score" in data
        assert "verdict" in data
        assert "metadata" in data

    def test_sorted_keys(self, capsys):
        report = ScanReport(findings=[], metadata=_meta())
        json_fmt.format_report(report)
        out = capsys.readouterr().out
        data = json.loads(out)
        keys = list(data.keys())
        assert keys == sorted(keys)

    def test_severity_filter(self, capsys):
        findings = [
            _finding(Severity.LOW),
            _finding(Severity.CRITICAL),
        ]
        report = ScanReport(findings=findings, metadata=_meta())
        json_fmt.format_report(report, min_severity=Severity.HIGH)
        out = capsys.readouterr().out
        data = json.loads(out)
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == 4

    def test_clean_report(self, capsys):
        report = ScanReport(findings=[], metadata=_meta())
        json_fmt.format_report(report)
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["findings"] == []
        assert data["score"] == 0
        assert data["verdict"] == "CLEAN"

    def test_deterministic_output(self, capsys):
        report = ScanReport(findings=[_finding()], metadata=_meta())
        json_fmt.format_report(report)
        out1 = capsys.readouterr().out
        json_fmt.format_report(report)
        out2 = capsys.readouterr().out
        assert out1 == out2
