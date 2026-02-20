"""Dimension 6: Obfuscation detection rules (regex + structural)."""

from __future__ import annotations

import re
from typing import ClassVar

from skill_scanner.models import Dimension, Finding, Severity
from skill_scanner.rules.base import PatternDef, RegexRule, StructuralRule


def _truncate(text: str, limit: int = 80) -> str:
    return text[:limit] + "..." if len(text) > limit else text


class DecodeExecuteRule(RegexRule):
    name = "decode-execute"
    dimension = Dimension.OBFUSCATION
    severity = Severity.CRITICAL
    description = "Decodes base64 content and pipes to a shell"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"base64\s+(-d|--decode).*\|\s*(bash|sh|python)",
        )),
        PatternDef(regex=re.compile(
            r"echo\s+.*\|\s*base64\s+(-d|--decode).*\|\s*(bash|sh)",
        )),
    ]


class JsDecodeEvalRule(RegexRule):
    name = "js-decode-eval"
    dimension = Dimension.OBFUSCATION
    severity = Severity.CRITICAL
    description = "JavaScript pattern decoding and evaluating strings"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(r"\batob\s*\(.*eval\s*\("), code_only=True),
        PatternDef(regex=re.compile(r"\beval\s*\(\s*atob\s*\("), code_only=True),
    ]


# --- Structural rules ---


class LongEncodedStringRule(StructuralRule):
    name = "long-encoded-string"
    dimension = Dimension.OBFUSCATION
    severity = Severity.HIGH
    description = "Contains long hex or unicode escape sequences (likely encoded payload)"

    _HEX_RE = re.compile(r"(\\x[0-9a-fA-F]{2}){10,}")
    _UNICODE_RE = re.compile(r"(\\u[0-9a-fA-F]{4}){10,}")

    def scan_file(self, file_path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern in (self._HEX_RE, self._UNICODE_RE):
                m = pattern.search(line)
                if m:
                    findings.append(Finding(
                        dimension=self.dimension,
                        severity=self.severity,
                        file_path=file_path,
                        line_number=line_no,
                        rule_name=self.name,
                        description=self.description,
                        matched_text=_truncate(m.group(0)),
                    ))
        return findings


class CharCodeObfuscationRule(StructuralRule):
    name = "charcode-obfuscation"
    dimension = Dimension.OBFUSCATION
    severity = Severity.HIGH
    description = "JavaScript String.fromCharCode with many numeric args (obfuscation)"

    _CHARCODE_RE = re.compile(
        r"String\.fromCharCode\s*\("
        r"(\s*\d+\s*,){5,}",  # 6+ numeric args
    )

    def scan_file(self, file_path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            m = self._CHARCODE_RE.search(line)
            if m:
                findings.append(Finding(
                    dimension=self.dimension,
                    severity=self.severity,
                    file_path=file_path,
                    line_number=line_no,
                    rule_name=self.name,
                    description=self.description,
                    matched_text=m.group(0)[:80],
                ))
        return findings
