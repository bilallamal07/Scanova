"""Tests for CLI entry point and exit codes."""

from pathlib import Path

from click.testing import CliRunner

from skill_scanner.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN = str(FIXTURES / "clean_skill")
MALICIOUS = str(FIXTURES / "malicious_skill")


class TestExitCodes:
    def test_clean_exit_0(self):
        result = CliRunner().invoke(main, [CLEAN, "--no-color"])
        assert result.exit_code == 0

    def test_malicious_exit_2(self):
        result = CliRunner().invoke(main, [MALICIOUS, "--no-color"])
        assert result.exit_code == 2

    def test_fail_on_high_with_clean(self):
        result = CliRunner().invoke(main, [CLEAN, "--fail-on", "HIGH", "--no-color"])
        assert result.exit_code == 0

    def test_fail_on_high_with_malicious(self):
        result = CliRunner().invoke(main, [MALICIOUS, "--fail-on", "HIGH", "--no-color"])
        assert result.exit_code == 2


class TestOutputFormats:
    def test_terminal_default(self):
        result = CliRunner().invoke(main, [CLEAN, "--no-color"])
        assert "skill-scanner" in result.output

    def test_json_format(self):
        result = CliRunner().invoke(main, [CLEAN, "--format", "json"])
        assert '"findings"' in result.output
        assert '"score"' in result.output
        assert '"verdict"' in result.output

    def test_quiet_mode(self):
        result = CliRunner().invoke(main, [MALICIOUS, "--quiet", "--no-color"])
        assert "Score:" in result.output
        assert "Verdict:" in result.output

    def test_json_malicious(self):
        result = CliRunner().invoke(main, [MALICIOUS, "--format", "json"])
        assert '"remote_execution"' in result.output


class TestSeverityFilter:
    def test_severity_critical_only(self):
        result = CliRunner().invoke(
            main, [MALICIOUS, "--format", "json", "--severity", "CRITICAL"],
        )
        import json
        data = json.loads(result.output)
        for f in data["findings"]:
            assert f["severity"] >= 4  # CRITICAL = 4


class TestExcludeOption:
    def test_exclude_reduces_findings(self):
        result = CliRunner().invoke(
            main, [MALICIOUS, "--format", "json", "--exclude", "SKILL.md"],
        )
        import json
        data = json.loads(result.output)
        # SKILL.md is the main malicious file — excluding it should drop findings
        assert data["metadata"]["files_scanned"] == 0
        assert data["findings"] == []

    def test_help_shows_exclude(self):
        result = CliRunner().invoke(main, ["--help"])
        assert "--exclude" in result.output


class TestVersionAndHelp:
    def test_version(self):
        result = CliRunner().invoke(main, ["--version"])
        assert "0.1.0" in result.output

    def test_help(self):
        result = CliRunner().invoke(main, ["--help"])
        assert "Scan agent skill files" in result.output
