"""Dimension 1: Remote execution detection rules."""

from __future__ import annotations

import re
from typing import ClassVar

from skill_scanner.models import Dimension, Severity
from skill_scanner.rules.base import PatternDef, RegexRule


class PipeToShellRule(RegexRule):
    name = "pipe-to-shell"
    dimension = Dimension.REMOTE_EXECUTION
    severity = Severity.CRITICAL
    description = "Downloads and pipes directly to a shell interpreter"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"(curl|wget)\s+.*\|\s*(bash|sh|zsh|python[23]?|perl|ruby)",
            re.IGNORECASE,
        )),
    ]


class EvalRule(RegexRule):
    name = "eval-call"
    dimension = Dimension.REMOTE_EXECUTION
    severity = Severity.HIGH
    description = "Dynamic code execution via eval()"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(r"\beval\s*\("), code_only=True),
    ]


class ShellSpawnRule(RegexRule):
    name = "shell-spawn"
    dimension = Dimension.REMOTE_EXECUTION
    severity = Severity.HIGH
    description = "Spawns a system shell from code"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(r"\bos\.system\s*\("), code_only=True),
        PatternDef(regex=re.compile(
            r"\bsubprocess\.call\s*\(.*shell\s*=\s*True",
        ), code_only=True),
    ]


class ExecRule(RegexRule):
    name = "exec-call"
    dimension = Dimension.REMOTE_EXECUTION
    severity = Severity.HIGH
    description = "Dynamic code execution via exec()"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(r"(?<!\.)\bexec\s*\("), code_only=True),
    ]
