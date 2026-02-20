"""Tests for data models and scoring logic."""

from skill_scanner.models import (
    Dimension,
    Finding,
    ScanMetadata,
    ScanReport,
    Severity,
    Verdict,
)


def _meta(**overrides):
    defaults = {"scanned_path": "/tmp/test", "files_scanned": 1, "duration_ms": 10.0}
    return ScanMetadata(**(defaults | overrides))


def _finding(severity=Severity.HIGH, dimension=Dimension.REMOTE_EXECUTION, **overrides):
    defaults = {
        "dimension": dimension,
        "severity": severity,
        "file_path": "SKILL.md",
        "line_number": 1,
        "rule_name": "test-rule",
        "description": "test finding",
        "matched_text": "eval(",
    }
    return Finding(**(defaults | overrides))


# --- Severity ordering ---


def test_severity_ordering():
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


def test_severity_comparison():
    assert Severity.HIGH >= Severity.MEDIUM
    assert not (Severity.LOW >= Severity.HIGH)


# --- Score calculation ---


class TestScoreCalculation:
    def test_no_findings_score_zero(self):
        report = ScanReport(findings=[], metadata=_meta())
        assert report.score == 0

    def test_single_info_score_zero(self):
        report = ScanReport(findings=[_finding(Severity.INFO)], metadata=_meta())
        assert report.score == 0

    def test_single_low(self):
        report = ScanReport(findings=[_finding(Severity.LOW)], metadata=_meta())
        assert report.score == 5

    def test_single_medium(self):
        report = ScanReport(findings=[_finding(Severity.MEDIUM)], metadata=_meta())
        assert report.score == 15

    def test_single_high(self):
        report = ScanReport(findings=[_finding(Severity.HIGH)], metadata=_meta())
        assert report.score == 30

    def test_single_critical(self):
        report = ScanReport(findings=[_finding(Severity.CRITICAL)], metadata=_meta())
        assert report.score == 50

    def test_multiple_findings_same_dimension(self):
        # Same dimension: base (5+15) + compounding bonus (+5) = 25
        findings = [_finding(Severity.LOW), _finding(Severity.MEDIUM)]
        report = ScanReport(findings=findings, metadata=_meta())
        assert report.score == 25

    def test_multiple_findings_different_dimensions(self):
        # Different dimensions: no compounding bonus → 5 + 15 = 20
        findings = [
            _finding(Severity.LOW, dimension=Dimension.REMOTE_EXECUTION),
            _finding(Severity.MEDIUM, dimension=Dimension.EXFILTRATION),
        ]
        report = ScanReport(findings=findings, metadata=_meta())
        assert report.score == 20  # 5 + 15, no bonus

    def test_compounding_bonus_three_same_dimension(self):
        # 3 findings in one dimension: base (5+15+30) + bonus (5*2) = 60
        findings = [
            _finding(Severity.LOW),
            _finding(Severity.MEDIUM),
            _finding(Severity.HIGH),
        ]
        report = ScanReport(findings=findings, metadata=_meta())
        assert report.score == 60  # 50 base + 10 bonus

    def test_score_caps_at_100(self):
        findings = [_finding(Severity.CRITICAL) for _ in range(5)]  # well above 100
        report = ScanReport(findings=findings, metadata=_meta())
        assert report.score == 100

    def test_score_exactly_100(self):
        findings = [_finding(Severity.CRITICAL), _finding(Severity.CRITICAL)]  # 50 + 50 + 5 > 100
        report = ScanReport(findings=findings, metadata=_meta())
        assert report.score == 100


# --- Verdict thresholds ---


class TestVerdict:
    def test_clean(self):
        report = ScanReport(findings=[], metadata=_meta())
        assert report.verdict == Verdict.CLEAN

    def test_low_risk_boundary(self):
        # score = 30 → LOW_RISK
        findings = [_finding(Severity.HIGH)]  # weight 30
        report = ScanReport(findings=findings, metadata=_meta())
        assert report.score == 30
        assert report.verdict == Verdict.LOW_RISK

    def test_warning_at_31(self):
        # score = 35 → WARNING (cross-dimension: no compounding)
        findings = [
            _finding(Severity.HIGH, dimension=Dimension.REMOTE_EXECUTION),
            _finding(Severity.LOW, dimension=Dimension.EXFILTRATION),
        ]  # 30 + 5 = 35
        report = ScanReport(findings=findings, metadata=_meta())
        assert report.score == 35
        assert report.verdict == Verdict.WARNING

    def test_warning_boundary(self):
        # score = 60 → WARNING boundary (cross-dimension: no compounding)
        findings = [
            _finding(Severity.HIGH, dimension=Dimension.REMOTE_EXECUTION),
            _finding(Severity.HIGH, dimension=Dimension.EXFILTRATION),
        ]  # 30 + 30 = 60
        report = ScanReport(findings=findings, metadata=_meta())
        assert report.score == 60
        assert report.verdict == Verdict.WARNING

    def test_critical_at_61(self):
        # score = 65 → CRITICAL (cross-dimension: no compounding)
        findings = [
            _finding(Severity.HIGH, dimension=Dimension.REMOTE_EXECUTION),
            _finding(Severity.HIGH, dimension=Dimension.EXFILTRATION),
            _finding(Severity.LOW, dimension=Dimension.OBFUSCATION),
        ]  # 30 + 30 + 5 = 65
        report = ScanReport(findings=findings, metadata=_meta())
        assert report.score == 65
        assert report.verdict == Verdict.CRITICAL

    def test_info_only_is_clean(self):
        findings = [_finding(Severity.INFO) for _ in range(10)]
        report = ScanReport(findings=findings, metadata=_meta())
        assert report.verdict == Verdict.CLEAN


# --- Exit codes ---


class TestExitCode:
    def test_clean_exit_0(self):
        report = ScanReport(findings=[], metadata=_meta())
        assert report.exit_code() == 0

    def test_warning_findings_exit_1(self):
        report = ScanReport(findings=[_finding(Severity.HIGH)], metadata=_meta())
        assert report.exit_code() == 1

    def test_critical_finding_exit_2(self):
        report = ScanReport(findings=[_finding(Severity.CRITICAL)], metadata=_meta())
        assert report.exit_code() == 2

    def test_fail_on_high_with_high_finding(self):
        report = ScanReport(findings=[_finding(Severity.HIGH)], metadata=_meta())
        assert report.exit_code(fail_on=Severity.HIGH) == 2

    def test_fail_on_high_with_medium_finding(self):
        report = ScanReport(findings=[_finding(Severity.MEDIUM)], metadata=_meta())
        assert report.exit_code(fail_on=Severity.HIGH) == 1

    def test_fail_on_low_catches_everything(self):
        report = ScanReport(findings=[_finding(Severity.LOW)], metadata=_meta())
        assert report.exit_code(fail_on=Severity.LOW) == 2

    def test_default_threshold_is_critical(self):
        report = ScanReport(findings=[_finding(Severity.HIGH)], metadata=_meta())
        assert report.exit_code() == 1  # HIGH < CRITICAL threshold


# --- Serialization ---


class TestSerialization:
    def test_report_to_json(self):
        report = ScanReport(findings=[_finding()], metadata=_meta())
        data = report.model_dump()
        assert "findings" in data
        assert "score" in data
        assert "verdict" in data
        assert "metadata" in data
        assert data["findings"][0]["dimension"] == "remote_execution"

    def test_finding_to_dict(self):
        f = _finding(severity=Severity.CRITICAL, line_number=42)
        data = f.model_dump()
        assert data["severity"] == 4
        assert data["line_number"] == 42

    def test_report_json_roundtrip(self):
        report = ScanReport(findings=[_finding()], metadata=_meta())
        json_str = report.model_dump_json()
        restored = ScanReport.model_validate_json(json_str)
        assert restored.score == report.score
        assert restored.verdict == report.verdict
        assert len(restored.findings) == 1
