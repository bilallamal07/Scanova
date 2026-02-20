"""Tests for obfuscation rules."""

from skill_scanner.rules.obfuscation import (
    CharCodeObfuscationRule,
    DecodeExecuteRule,
    JsDecodeEvalRule,
    LongEncodedStringRule,
)


class TestDecodeExecute:
    def test_base64_pipe_bash(self):
        content = "echo payload | base64 -d | bash"
        findings = DecodeExecuteRule().scan_file("f.md", content)
        # Both patterns match this line (base64 -d|bash and echo..|base64 -d|bash)
        assert len(findings) >= 1

    def test_base64_decode_python(self):
        content = "base64 --decode encoded.txt | python"
        assert len(DecodeExecuteRule().scan_file("f.md", content)) == 1

    def test_safe_base64_decode(self):
        content = "base64 -d file.b64 > output.bin"
        assert DecodeExecuteRule().scan_file("f.md", content) == []


class TestJsDecodeEval:
    def test_eval_atob(self):
        content = '```js\neval(atob("aGVsbG8="))\n```'
        assert len(JsDecodeEvalRule().scan_file("f.md", content)) == 1

    def test_atob_eval(self):
        content = '```js\nvar x = atob("enc"); eval(x)\n```'
        # This needs atob...eval on same line
        findings = JsDecodeEvalRule().scan_file("f.md", content)
        assert len(findings) == 1

    def test_safe_atob(self):
        content = '```js\nvar decoded = atob("base64string")\n```'
        assert JsDecodeEvalRule().scan_file("f.md", content) == []

    def test_prose_ignored(self):
        content = "Never use eval(atob()) in production."
        assert JsDecodeEvalRule().scan_file("f.md", content) == []


class TestLongEncodedString:
    def test_long_hex_sequence(self):
        # 15 hex sequences
        hex_str = "".join(f"\\x{i:02x}" for i in range(15))
        content = f'payload = "{hex_str}"'
        assert len(LongEncodedStringRule().scan_file("f.md", content)) == 1

    def test_long_unicode_sequence(self):
        uni_str = "".join(f"\\u{i:04x}" for i in range(15))
        content = f'var s = "{uni_str}"'
        assert len(LongEncodedStringRule().scan_file("f.md", content)) == 1

    def test_short_hex_ok(self):
        content = 'x = "\\x41\\x42\\x43"'
        assert LongEncodedStringRule().scan_file("f.md", content) == []

    def test_truncates_long_match(self):
        hex_str = "".join(f"\\x{i:02x}" for i in range(50))
        content = f'p = "{hex_str}"'
        findings = LongEncodedStringRule().scan_file("f.md", content)
        assert len(findings) == 1
        assert findings[0].matched_text.endswith("...")


class TestCharCodeObfuscation:
    def test_many_charcode_args(self):
        args = ", ".join(str(i) for i in range(72, 82))  # 10 args
        content = f"```js\nvar x = String.fromCharCode({args})\n```"
        assert len(CharCodeObfuscationRule().scan_file("f.md", content)) == 1

    def test_few_charcode_args(self):
        content = "```js\nvar x = String.fromCharCode(72, 101, 108)\n```"
        assert CharCodeObfuscationRule().scan_file("f.md", content) == []

    def test_no_charcode(self):
        content = "```js\nvar x = 'hello'\n```"
        assert CharCodeObfuscationRule().scan_file("f.md", content) == []
