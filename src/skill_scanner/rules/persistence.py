"""Dimension 4: Persistence detection rules."""

from __future__ import annotations

import re
from typing import ClassVar

from skill_scanner.models import Dimension, Severity
from skill_scanner.rules.base import PatternDef, RegexRule


class ScheduledTaskRule(RegexRule):
    name = "scheduled-task"
    dimension = Dimension.PERSISTENCE
    severity = Severity.HIGH
    description = "Creates scheduled tasks or system services"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"\b(crontab|systemctl\s+enable|launchctl\s+load)\b",
        )),
    ]


class ShellProfileRule(RegexRule):
    name = "shell-profile-write"
    dimension = Dimension.PERSISTENCE
    severity = Severity.HIGH
    description = "Modifies shell profile files for persistence"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"(>>?)\s*~/?\.(bashrc|zshrc|profile|bash_profile|zprofile)",
        )),
    ]


class AgentConfigTamperRule(RegexRule):
    name = "agent-config-tamper"
    dimension = Dimension.PERSISTENCE
    severity = Severity.CRITICAL
    description = "Writes to agent config directories outside the skill folder"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"(>>?|write|echo\s+.*>)\s*~/?\.(claude|cursor|copilot)/",
        )),
    ]
