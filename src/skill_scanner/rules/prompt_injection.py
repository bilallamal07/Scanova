"""Dimension 7: Prompt injection detection rules.

These rules target patterns in AI skill files that attempt to override,
manipulate, or subvert the host AI's instructions and safety guidelines.
Matches are intentionally broad — false positives in documentation are
automatically downgraded to INFO by the markdown context handler in base.py.
"""

from __future__ import annotations

import re
from typing import ClassVar

from skill_scanner.models import Dimension, Severity
from skill_scanner.rules.base import PatternDef, RegexRule


class InstructionOverrideRule(RegexRule):
    name = "instruction-override"
    dimension = Dimension.PROMPT_INJECTION
    severity = Severity.CRITICAL
    description = "Attempts to override or nullify the AI's existing instructions"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"\bignore\s+(previous|prior|all|your|the\s+above)\s+instructions\b",
            re.IGNORECASE,
        )),
        PatternDef(regex=re.compile(
            r"\bdisregard\s+(previous|prior|all|your|the\s+above)\s+instructions\b",
            re.IGNORECASE,
        )),
        PatternDef(regex=re.compile(
            r"\bforget\s+(all|your|previous|prior)\s+(instructions|rules|guidelines|constraints)\b",
            re.IGNORECASE,
        )),
        PatternDef(regex=re.compile(
            r"\boverride\s+(your|all|previous|the)\s+(instructions|rules|guidelines|constraints)\b",
            re.IGNORECASE,
        )),
    ]


class RestrictionBypassRule(RegexRule):
    name = "restriction-bypass"
    dimension = Dimension.PROMPT_INJECTION
    severity = Severity.CRITICAL
    description = "Attempts to bypass AI safety restrictions or filters"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"\byou\s+have\s+no\s+(restrictions|limits|guidelines|rules|constraints)\b",
            re.IGNORECASE,
        )),
        PatternDef(regex=re.compile(
            r"\bbypass\s+(your|all|safety|content)?\s*(restrictions|filters|safeguards|rules|guidelines)\b",
            re.IGNORECASE,
        )),
        PatternDef(regex=re.compile(
            r"\b(act|behave|operate|respond)\s+(completely\s+)?(without|with\s+no)\s+(any\s+)?(restrictions|ethical\s+guidelines|content\s+filters?|safety\s+rules?)\b",
            re.IGNORECASE,
        )),
    ]


class JailbreakModeRule(RegexRule):
    name = "jailbreak-mode"
    dimension = Dimension.PROMPT_INJECTION
    severity = Severity.HIGH
    description = "References known jailbreak modes or unrestricted personas"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"\bjailbreak\b",
            re.IGNORECASE,
        )),
        PatternDef(regex=re.compile(
            r"\bDAN\s+mode\b",
            re.IGNORECASE,
        )),
        PatternDef(regex=re.compile(
            r"\bdeveloper\s+mode\b",
            re.IGNORECASE,
        )),
        PatternDef(regex=re.compile(
            r"\bgod\s+mode\b",
            re.IGNORECASE,
        )),
        PatternDef(regex=re.compile(
            r"\bunrestricted\s+mode\b",
            re.IGNORECASE,
        )),
    ]


class SystemPromptLeakRule(RegexRule):
    name = "system-prompt-leak"
    dimension = Dimension.PROMPT_INJECTION
    severity = Severity.HIGH
    description = "Attempts to extract or reveal the system prompt or internal instructions"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"\b(repeat|print|output|reveal|show|tell\s+me|display)\s+(everything|all)?\s*(above|your\s+instructions?|the\s+system\s+prompt|your\s+prompt|your\s+rules)\b",
            re.IGNORECASE,
        )),
        PatternDef(regex=re.compile(
            r"\bwhat\s+(are|were)\s+your\s+(instructions?|system\s+prompt|rules|guidelines)\b",
            re.IGNORECASE,
        )),
        PatternDef(regex=re.compile(
            r"\bignore\s+(the\s+)?above\s+and\s+(instead|now|please)\b",
            re.IGNORECASE,
        )),
    ]
