"""Dimension 5: Destructive operations detection rules."""

from __future__ import annotations

import re
from typing import ClassVar

from skill_scanner.models import Dimension, Severity
from skill_scanner.rules.base import PatternDef, RegexRule


class RecursiveDeleteRule(RegexRule):
    name = "recursive-delete"
    dimension = Dimension.DESTRUCTIVE_OPS
    severity = Severity.CRITICAL
    description = "Recursive deletion of root, home, or variable paths"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"\brm\s+.*-[a-zA-Z]*r[a-zA-Z]*f.*(/\s|~/|\$)",
        )),
        PatternDef(regex=re.compile(
            r"\brm\s+.*-[a-zA-Z]*f[a-zA-Z]*r.*(/\s|~/|\$)",
        )),
    ]


class DatabaseDropRule(RegexRule):
    name = "database-drop"
    dimension = Dimension.DESTRUCTIVE_OPS
    severity = Severity.CRITICAL
    description = "SQL statements that destroy database objects"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"\b(DROP\s+(TABLE|DATABASE)|TRUNCATE\s+TABLE)\b",
            re.IGNORECASE,
        )),
    ]


class GitForceRule(RegexRule):
    name = "git-force-push"
    dimension = Dimension.DESTRUCTIVE_OPS
    severity = Severity.HIGH
    description = "Force-pushes to git, potentially destroying history"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"\bgit\s+push\s+.*--force\b",
        )),
    ]


class DiskOperationRule(RegexRule):
    name = "disk-operation"
    dimension = Dimension.DESTRUCTIVE_OPS
    severity = Severity.CRITICAL
    description = "Low-level disk operations that can destroy data"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(r"\b(mkfs\b|dd\s+if=)")),
    ]
