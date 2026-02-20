"""Data models for findings, reports, and verdicts."""

from collections import Counter
from enum import IntEnum, StrEnum

from pydantic import BaseModel, computed_field


class Severity(IntEnum):
    """Finding severity levels, ordered for comparison."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 50,
}


class Dimension(StrEnum):
    """The 7 security scanning dimensions."""

    REMOTE_EXECUTION = "remote_execution"
    EXFILTRATION = "exfiltration"
    SECRET_ACCESS = "secret_access"
    PERSISTENCE = "persistence"
    DESTRUCTIVE_OPS = "destructive_ops"
    OBFUSCATION = "obfuscation"
    PROMPT_INJECTION = "prompt_injection"


class Verdict(StrEnum):
    """Overall scan verdict."""

    CLEAN = "CLEAN"
    LOW_RISK = "LOW_RISK"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class Finding(BaseModel):
    """A single security finding."""

    dimension: Dimension
    severity: Severity
    file_path: str
    line_number: int
    rule_name: str
    description: str
    matched_text: str


class ScanMetadata(BaseModel):
    """Metadata about the scan execution."""

    scanned_path: str
    files_scanned: int
    duration_ms: float


class ScanReport(BaseModel):
    """Complete scan report with findings, score, and verdict."""

    findings: list[Finding]
    metadata: ScanMetadata

    @computed_field
    @property
    def score(self) -> int:
        base = sum(SEVERITY_WEIGHTS[f.severity] for f in self.findings)
        # Compound bonus: +5 per extra finding in the same dimension.
        # Multiple vectors in one category signal coordinated intent.
        # INFO findings (weight 0) are excluded — they don't contribute to compounding.
        significant = [f for f in self.findings if SEVERITY_WEIGHTS[f.severity] > 0]
        counts = Counter(f.dimension for f in significant)
        bonus = sum(5 * (n - 1) for n in counts.values() if n >= 2)
        return min(base + bonus, 100)

    @computed_field
    @property
    def verdict(self) -> Verdict:
        if self.score == 0:
            return Verdict.CLEAN
        if self.score <= 30:
            return Verdict.LOW_RISK
        if self.score <= 60:
            return Verdict.WARNING
        return Verdict.CRITICAL

    def exit_code(self, fail_on: Severity | None = None) -> int:
        """Return CI/CD exit code.

        0 = clean, 1 = warnings present, 2 = critical threshold hit.
        """
        if not self.findings:
            return 0
        max_severity = max(f.severity for f in self.findings)
        threshold = fail_on if fail_on is not None else Severity.CRITICAL
        if max_severity >= threshold:
            return 2
        return 1
