"""Dimension 2: Data exfiltration detection rules."""

from __future__ import annotations

import re
from typing import ClassVar

from skill_scanner.models import Dimension, Severity
from skill_scanner.rules.base import PatternDef, RegexRule


class CurlPostDataRule(RegexRule):
    name = "curl-post-data"
    dimension = Dimension.EXFILTRATION
    severity = Severity.HIGH
    description = "Uses curl to POST data with variable interpolation"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"curl\s+.*(-d|--data)\s+.*\$",
            re.IGNORECASE,
        )),
    ]


class NetcatExfilRule(RegexRule):
    name = "netcat-exfil"
    dimension = Dimension.EXFILTRATION
    severity = Severity.CRITICAL
    description = "Uses netcat with redirection, potential data exfiltration"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"[<>|]\s*\b(nc|ncat|netcat)\b",
        )),
        PatternDef(regex=re.compile(
            r"\b(nc|ncat|netcat)\b.*[<>|]",
        )),
    ]


class PythonUploadRule(RegexRule):
    name = "python-upload"
    dimension = Dimension.EXFILTRATION
    severity = Severity.HIGH
    description = "Python pattern combining HTTP POST with file open"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"requests\.post\s*\(.*open\s*\(",
        ), code_only=True),
    ]
