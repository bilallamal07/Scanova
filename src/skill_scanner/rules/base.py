"""Rule base classes and registry."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from skill_scanner.models import Dimension, Finding, Severity

# ---------------------------------------------------------------------------
# Markdown context detection
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"^```(\w*)")
_FENCE_CLOSE_RE = re.compile(r"^```\s*$")
_TABLE_ROW_RE = re.compile(r"^\s*\|")


@dataclass
class CodeBlock:
    """A fenced code block extracted from a markdown file."""

    language: str
    start_line: int  # 1-based, line of opening fence
    end_line: int  # 1-based, line of closing fence
    lines: list[str]  # content lines (without fences)


def parse_code_blocks(content: str) -> list[CodeBlock]:
    """Extract fenced code blocks from markdown content."""
    blocks: list[CodeBlock] = []
    in_block = False
    current_lang = ""
    current_start = 0
    current_lines: list[str] = []

    for i, line in enumerate(content.splitlines(), start=1):
        if not in_block:
            m = _FENCE_RE.match(line)
            if m and line.strip().startswith("```"):
                in_block = True
                current_lang = m.group(1) or ""
                current_start = i
                current_lines = []
        else:
            if _FENCE_CLOSE_RE.match(line):
                blocks.append(CodeBlock(
                    language=current_lang,
                    start_line=current_start,
                    end_line=i,
                    lines=current_lines,
                ))
                in_block = False
            else:
                current_lines.append(line)

    return blocks


def lines_in_code_blocks(content: str) -> set[int]:
    """Return set of 1-based line numbers that are inside fenced code blocks."""
    result: set[int] = set()
    for block in parse_code_blocks(content):
        for line_no in range(block.start_line + 1, block.end_line):
            result.add(line_no)
    return result


def is_table_line(line: str) -> bool:
    """Return True if the line is a markdown table row."""
    return bool(_TABLE_ROW_RE.match(line))


# ---------------------------------------------------------------------------
# Rule base class
# ---------------------------------------------------------------------------


class Rule(ABC):
    """Abstract base for all security rules."""

    name: ClassVar[str]
    dimension: ClassVar[Dimension]
    severity: ClassVar[Severity]
    description: ClassVar[str]

    @abstractmethod
    def scan_file(self, file_path: str, content: str) -> list[Finding]:
        """Scan file content and return findings."""


# ---------------------------------------------------------------------------
# RegexRule — line-by-line pattern matching
# ---------------------------------------------------------------------------


@dataclass
class PatternDef:
    """A single regex pattern with optional context constraints."""

    regex: re.Pattern[str]
    code_only: bool = False  # only match inside code blocks


class RegexRule(Rule):
    """Rule that matches line-by-line regex patterns."""

    patterns: ClassVar[list[PatternDef]]

    def scan_file(self, file_path: str, content: str) -> list[Finding]:
        is_markdown = file_path.endswith(".md")
        code_lines = (
            lines_in_code_blocks(content)
            if self._has_code_only_patterns() or is_markdown
            else set()
        )
        findings: list[Finding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            for pat in self.patterns:
                if pat.code_only and line_no not in code_lines:
                    continue
                m = pat.regex.search(line)
                if m:
                    # In markdown files, patterns matching inside documentation
                    # context (fenced code blocks or table rows) are references,
                    # not instructions — downgrade to INFO.
                    severity = self.severity
                    if is_markdown and pat.code_only and line_no in code_lines:
                        severity = Severity.INFO
                    elif is_markdown and is_table_line(line):
                        severity = Severity.INFO
                    findings.append(Finding(
                        dimension=self.dimension,
                        severity=severity,
                        file_path=file_path,
                        line_number=line_no,
                        rule_name=self.name,
                        description=self.description,
                        matched_text=m.group(0),
                    ))
        return findings

    def _has_code_only_patterns(self) -> bool:
        return any(p.code_only for p in self.patterns)


# ---------------------------------------------------------------------------
# StructuralRule — full file analysis
# ---------------------------------------------------------------------------


class StructuralRule(Rule):
    """Rule that analyses full file content for structural patterns."""

    @abstractmethod
    def scan_file(self, file_path: str, content: str) -> list[Finding]:
        """Analyse full file content. Must be implemented by subclasses."""


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------


class RuleRegistry:
    """Collects and manages rule instances."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []

    def register(self, rule: Rule) -> None:
        self._rules.append(rule)

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def rules_for_dimension(self, dimension: Dimension) -> list[Rule]:
        return [r for r in self._rules if r.dimension == dimension]

    @classmethod
    def auto_discover(cls) -> RuleRegistry:
        """Create registry with instances of all concrete Rule subclasses.

        Discovers all non-abstract subclasses of Rule (including through
        RegexRule and StructuralRule) and instantiates them.
        """
        registry = cls()
        for rule_cls in _collect_concrete_subclasses(Rule):
            registry.register(rule_cls())
        return registry


def _collect_concrete_subclasses(base: type) -> list[type]:
    """Recursively collect all concrete (non-abstract) subclasses."""
    result: list[type] = []
    for sub in base.__subclasses__():
        # Skip intermediate ABCs (RegexRule, StructuralRule themselves)
        if _is_concrete_rule(sub):
            result.append(sub)
        result.extend(_collect_concrete_subclasses(sub))
    return result


def _is_concrete_rule(cls: type) -> bool:
    """Check if a class is a concrete rule (has all ClassVars set)."""
    return (
        hasattr(cls, "name")
        and hasattr(cls, "dimension")
        and hasattr(cls, "severity")
        and hasattr(cls, "description")
        and isinstance(getattr(cls, "name", None), str)
    )
