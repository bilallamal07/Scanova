"""Tests for rule engine base classes and registry."""

import re
from typing import ClassVar

from skill_scanner.models import Dimension, Finding, Severity
from skill_scanner.rules.base import (
    PatternDef,
    RegexRule,
    RuleRegistry,
    StructuralRule,
    is_table_line,
    lines_in_code_blocks,
    parse_code_blocks,
)

# ---------------------------------------------------------------------------
# Dummy rules for testing
# ---------------------------------------------------------------------------


class DummyRegexRule(RegexRule):
    name = "dummy-regex"
    dimension = Dimension.REMOTE_EXECUTION
    severity = Severity.HIGH
    description = "Detects eval() calls"
    patterns: ClassVar = [PatternDef(regex=re.compile(r"eval\("))]


class DummyCodeOnlyRule(RegexRule):
    name = "dummy-code-only"
    dimension = Dimension.REMOTE_EXECUTION
    severity = Severity.HIGH
    description = "Detects eval() only in code blocks"
    patterns: ClassVar = [PatternDef(regex=re.compile(r"eval\("), code_only=True)]


class DummyStructuralRule(StructuralRule):
    name = "dummy-structural"
    dimension = Dimension.OBFUSCATION
    severity = Severity.CRITICAL
    description = "Flags files with too many hex sequences"

    def scan_file(self, file_path: str, content: str) -> list[Finding]:
        hex_count = len(re.findall(r"\\x[0-9a-f]{2}", content))
        if hex_count > 5:
            return [Finding(
                dimension=self.dimension,
                severity=self.severity,
                file_path=file_path,
                line_number=1,
                rule_name=self.name,
                description=self.description,
                matched_text=f"{hex_count} hex sequences found",
            )]
        return []


# ---------------------------------------------------------------------------
# Markdown code block parser
# ---------------------------------------------------------------------------


class TestParseCodeBlocks:
    def test_single_block(self):
        md = "# Title\n```python\nprint('hi')\n```\nDone."
        blocks = parse_code_blocks(md)
        assert len(blocks) == 1
        assert blocks[0].language == "python"
        assert blocks[0].start_line == 2
        assert blocks[0].end_line == 4
        assert blocks[0].lines == ["print('hi')"]

    def test_multiple_blocks(self):
        md = "```bash\necho hi\n```\ntext\n```js\nconsole.log(1)\n```"
        blocks = parse_code_blocks(md)
        assert len(blocks) == 2
        assert blocks[0].language == "bash"
        assert blocks[1].language == "js"

    def test_no_language(self):
        md = "```\nsome code\n```"
        blocks = parse_code_blocks(md)
        assert len(blocks) == 1
        assert blocks[0].language == ""

    def test_no_code_blocks(self):
        md = "# Just a heading\nSome text."
        blocks = parse_code_blocks(md)
        assert len(blocks) == 0

    def test_unclosed_block_ignored(self):
        md = "```python\ncode here\nno closing"
        blocks = parse_code_blocks(md)
        assert len(blocks) == 0

    def test_nested_backticks_in_content(self):
        md = "```\nuse `inline code` here\n```"
        blocks = parse_code_blocks(md)
        assert len(blocks) == 1
        assert blocks[0].lines == ["use `inline code` here"]


class TestLinesInCodeBlocks:
    def test_identifies_code_lines(self):
        md = "line1\n```py\ncode_a\ncode_b\n```\nline6"
        code_lines = lines_in_code_blocks(md)
        # Lines 3, 4 are inside the block (between fences at 2 and 5)
        assert code_lines == {3, 4}

    def test_empty_content(self):
        assert lines_in_code_blocks("") == set()


# ---------------------------------------------------------------------------
# RegexRule
# ---------------------------------------------------------------------------


class TestRegexRule:
    def test_matches_line(self):
        rule = DummyRegexRule()
        content = "some code\nresult = eval(input)\nmore code"
        findings = rule.scan_file("test.md", content)
        assert len(findings) == 1
        assert findings[0].line_number == 2
        assert findings[0].matched_text == "eval("
        assert findings[0].rule_name == "dummy-regex"

    def test_no_match(self):
        rule = DummyRegexRule()
        findings = rule.scan_file("test.md", "nothing here")
        assert findings == []

    def test_multiple_matches(self):
        rule = DummyRegexRule()
        content = "eval(1)\nok\neval(2)"
        findings = rule.scan_file("test.md", content)
        assert len(findings) == 2
        assert findings[0].line_number == 1
        assert findings[1].line_number == 3

    def test_code_only_skips_prose(self):
        rule = DummyCodeOnlyRule()
        # eval in prose (line 1) should be skipped, eval in code block (line 3) should match
        content = "eval( in prose\n```python\neval(x)\n```"
        findings = rule.scan_file("test.md", content)
        assert len(findings) == 1
        assert findings[0].line_number == 3

    def test_code_only_no_code_blocks(self):
        rule = DummyCodeOnlyRule()
        content = "eval( but not in a code block"
        findings = rule.scan_file("test.md", content)
        assert findings == []

    def test_code_only_in_md_fence_downgraded_to_info(self):
        """code_only match inside a markdown code fence → INFO severity."""
        rule = DummyCodeOnlyRule()
        content = "```python\neval(x)\n```"
        findings = rule.scan_file("doc.md", content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_code_only_in_non_md_keeps_severity(self):
        """code_only match in a non-markdown file keeps original severity."""
        rule = DummyCodeOnlyRule()
        # .txt file with fenced block — not markdown, no downgrade
        content = "```python\neval(x)\n```"
        findings = rule.scan_file("notes.txt", content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_non_code_only_in_md_fence_keeps_severity(self):
        """Non-code_only patterns in markdown keep original severity."""
        rule = DummyRegexRule()  # code_only=False
        content = "```python\neval(x)\n```"
        findings = rule.scan_file("doc.md", content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_table_line_in_md_downgraded_to_info(self):
        """Pattern matching inside a markdown table row → INFO severity."""
        rule = DummyRegexRule()
        content = "| Dimension | Examples |\n| Remote Exec | eval(x) |"
        findings = rule.scan_file("doc.md", content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_table_line_in_non_md_keeps_severity(self):
        """Table rows in non-markdown files keep original severity."""
        rule = DummyRegexRule()
        content = "| col | eval(x) |"
        findings = rule.scan_file("data.txt", content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


class TestIsTableLine:
    def test_standard_table_row(self):
        assert is_table_line("| col1 | col2 |") is True

    def test_separator_row(self):
        assert is_table_line("|---|---|") is True

    def test_leading_whitespace(self):
        assert is_table_line("  | col1 | col2 |") is True

    def test_not_a_table(self):
        assert is_table_line("just some text") is False

    def test_pipe_in_code(self):
        assert is_table_line("echo foo | grep bar") is False

    def test_empty_line(self):
        assert is_table_line("") is False


# ---------------------------------------------------------------------------
# StructuralRule
# ---------------------------------------------------------------------------


class TestStructuralRule:
    def test_triggers_on_many_hex(self):
        rule = DummyStructuralRule()
        content = r"\x41\x42\x43\x44\x45\x46\x47"
        findings = rule.scan_file("test.md", content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_no_trigger_on_few_hex(self):
        rule = DummyStructuralRule()
        content = r"\x41\x42"
        findings = rule.scan_file("test.md", content)
        assert findings == []


# ---------------------------------------------------------------------------
# RuleRegistry
# ---------------------------------------------------------------------------


class TestRuleRegistry:
    def test_register_and_list(self):
        reg = RuleRegistry()
        rule = DummyRegexRule()
        reg.register(rule)
        assert len(reg.rules) == 1
        assert reg.rules[0] is rule

    def test_rules_for_dimension(self):
        reg = RuleRegistry()
        reg.register(DummyRegexRule())
        reg.register(DummyStructuralRule())
        remote = reg.rules_for_dimension(Dimension.REMOTE_EXECUTION)
        assert len(remote) == 1
        assert remote[0].name == "dummy-regex"
        obf = reg.rules_for_dimension(Dimension.OBFUSCATION)
        assert len(obf) == 1

    def test_auto_discover_finds_concrete_rules(self):
        registry = RuleRegistry.auto_discover()
        names = {r.name for r in registry.rules}
        # Our dummy rules defined in this module should be discovered
        assert "dummy-regex" in names
        assert "dummy-code-only" in names
        assert "dummy-structural" in names

    def test_auto_discover_skips_abstract(self):
        registry = RuleRegistry.auto_discover()
        # RegexRule and StructuralRule themselves should NOT appear
        for rule in registry.rules:
            assert type(rule) not in (RegexRule, StructuralRule)

    def test_empty_registry(self):
        reg = RuleRegistry()
        assert reg.rules == []
        assert reg.rules_for_dimension(Dimension.PERSISTENCE) == []
