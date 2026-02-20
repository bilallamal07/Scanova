"""Tests for browser file scanner functionality."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from skill_scanner.browser_scanner import (
    FileUrlParser,
    BrowserTabScanner,
    LocalDirectoryBrowser,
    DragDropFileHandler,
    BrowserFileAccessError,
)
from skill_scanner.models import ScanReport, ScanMetadata


class TestFileUrlParser:
    """Test file URL parsing."""

    def test_parse_unix_absolute_path(self):
        """Parse Unix absolute path."""
        parser = FileUrlParser()
        result = parser.parse_file_url("/home/user/project")

        assert result["path"] == "/home/user/project"
        assert result["type"] == "unix_path"
        assert result["original"] == "/home/user/project"

    def test_parse_file_url_unix(self):
        """Parse file:// URL (Unix)."""
        parser = FileUrlParser()
        result = parser.parse_file_url("file:///home/user/project")

        assert result["path"] == "/home/user/project"
        assert result["type"] == "file_url"

    def test_parse_file_url_windows(self):
        """Parse file:// URL (Windows)."""
        parser = FileUrlParser()
        result = parser.parse_file_url("file:///C:/Users/user/project")

        assert result["path"] == "C:/Users/user/project"
        assert result["type"] == "file_url"

    def test_parse_windows_path(self):
        """Parse Windows path."""
        parser = FileUrlParser()
        result = parser.parse_file_url("C:\\Users\\user\\project")

        assert result["path"] == "C:/Users/user/project"
        assert result["type"] == "windows_path"

    def test_parse_relative_path(self):
        """Parse relative path."""
        parser = FileUrlParser()
        result = parser.parse_file_url("./my-project")

        # The path should be resolved to absolute
        assert result["path"] is not None
        assert "my-project" in result["path"]
        assert result["type"] == "relative_path"

    def test_parse_home_path(self):
        """Parse home directory path."""
        parser = FileUrlParser()
        result = parser.parse_file_url("~/projects/skill")

        assert "projects/skill" in result["path"]
        assert result["type"] == "home_path"

    def test_is_valid_file_url(self):
        """Check valid file URL detection."""
        parser = FileUrlParser()

        # Valid URLs
        assert parser.is_valid_file_url("file:///path/to/file")
        assert parser.is_valid_file_url("/absolute/path")
        assert parser.is_valid_file_url("C:/Windows/path")
        assert parser.is_valid_file_url("~/home/path")
        assert parser.is_valid_file_url("./relative/path")

        # Invalid URLs
        assert not parser.is_valid_file_url("https://example.com")
        assert not parser.is_valid_file_url("not-a-path")


class TestBrowserTabScanner:
    """Test browser tab scanner."""

    @patch("skill_scanner.browser_scanner.scan_folder")
    def test_scan_file_url_success(self, mock_scan_folder):
        """Successfully scan a file URL."""
        mock_report = Mock(spec=ScanReport)
        mock_scan_folder.return_value = mock_report

        scanner = BrowserTabScanner()

        # Test with a path that exists
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "is_dir", return_value=True):
                with patch.object(Path, "resolve", return_value=Path("/test/path")):
                    result = scanner.scan_file_url("/test/path")

        assert result == mock_report
        mock_scan_folder.assert_called_once()

    def test_scan_file_url_not_exists(self):
        """Scan non-existent path raises error."""
        scanner = BrowserTabScanner()

        with pytest.raises(BrowserFileAccessError) as exc_info:
            scanner.scan_file_url("/nonexistent/path/that/does/not/exist")

        assert "Path does not exist" in str(exc_info.value)

    @patch("skill_scanner.browser_scanner.scan_folder")
    def test_scan_multiple_paths(self, mock_scan_folder):
        """Scan multiple paths."""
        mock_report = Mock(spec=ScanReport)
        mock_scan_folder.return_value = mock_report

        scanner = BrowserTabScanner()

        paths = ["/path/one", "/path/two"]

        # Mock exists check
        with patch.object(Path, "exists", return_value=True):
            with patch.object(Path, "is_dir", return_value=True):
                with patch.object(Path, "resolve", return_value=Path("/test")):
                    results = scanner.scan_multiple_paths(paths)

        assert len(results) == 2


class TestLocalDirectoryBrowser:
    """Test local directory browser."""

    def test_list_directory(self, tmp_path):
        """List directory contents."""
        # Create test files
        (tmp_path / "file1.txt").write_text("content1")
        (tmp_path / "file2.py").write_text("content2")
        (tmp_path / "subdir").mkdir()
        (tmp_path / ".hidden").write_text("hidden")

        browser = LocalDirectoryBrowser(str(tmp_path))
        items = browser.list_directory(str(tmp_path))

        # Should have 3 items (excluding hidden)
        assert len(items) == 3

        # Check sorting - directories first
        assert items[0]["is_directory"] is True
        assert items[0]["name"] == "subdir"

    def test_list_directory_with_hidden(self, tmp_path):
        """List directory with hidden files."""
        (tmp_path / ".hidden").write_text("hidden")
        (tmp_path / "visible").write_text("visible")

        browser = LocalDirectoryBrowser(str(tmp_path))
        items = browser.list_directory(str(tmp_path), include_hidden=True)

        assert len(items) == 2

    def test_find_skill_files(self, tmp_path):
        """Find skill files in directory."""
        # Create skill structure
        skill_dir = tmp_path / "skills" / "my-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("# Skill")

        browser = LocalDirectoryBrowser(str(tmp_path))
        skills = browser.find_skill_files(str(tmp_path))

        assert len(skills) > 0

        # Check skill detection
        skill_types = [s["type"] for s in skills]
        assert "skills_directory" in skill_types

    def test_find_skill_files_with_config(self, tmp_path):
        """Find skill files with config."""
        (tmp_path / "skill.yaml").write_text("name: test")

        browser = LocalDirectoryBrowser(str(tmp_path))
        skills = browser.find_skill_files(str(tmp_path))

        assert any(s["type"] == "skill_config" for s in skills)

    def test_get_directory_tree(self, tmp_path):
        """Get directory tree structure."""
        # Create structure
        (tmp_path / "file.txt").write_text("content")
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "nested.txt").write_text("nested")

        browser = LocalDirectoryBrowser(str(tmp_path))
        tree = browser.get_directory_tree(str(tmp_path), max_depth=2)

        # Name is the folder name, full path is in "path"
        assert tree["name"] == tmp_path.name
        assert tree["path"] == str(tmp_path)
        assert tree["is_directory"] is True
        assert len(tree["children"]) == 2


class TestDragDropFileHandler:
    """Test drag and drop file handler."""

    def test_process_uploaded_files_text(self, tmp_path):
        """Process text file uploads."""
        handler = DragDropFileHandler()
        handler.temp_dir = str(tmp_path)

        files_data = [{"name": "test.txt", "content": "Hello World", "encoding": "utf-8"}]

        result_path = handler.process_uploaded_files(files_data)

        assert result_path.exists()
        assert (result_path / "test.txt").exists()
        assert (result_path / "test.txt").read_text() == "Hello World"

    def test_process_uploaded_files_base64(self, tmp_path):
        """Process base64 file uploads."""
        import base64

        handler = DragDropFileHandler()
        handler.temp_dir = str(tmp_path)

        content = b"Binary content"
        encoded = base64.b64encode(content).decode()

        files_data = [{"name": "binary.dat", "content": encoded, "encoding": "base64"}]

        result_path = handler.process_uploaded_files(files_data)

        assert (result_path / "binary.dat").exists()
        assert (result_path / "binary.dat").read_bytes() == content

    def test_process_uploaded_files_with_subdirectories(self, tmp_path):
        """Process files with subdirectories."""
        handler = DragDropFileHandler()
        handler.temp_dir = str(tmp_path)

        files_data = [{"name": "src/main.py", "content": 'print("hello")', "encoding": "utf-8"}]

        result_path = handler.process_uploaded_files(files_data)

        assert (result_path / "src" / "main.py").exists()

    @patch("skill_scanner.browser_scanner.scan_folder")
    def test_scan_uploaded_files(self, mock_scan_folder, tmp_path):
        """Scan uploaded files."""
        mock_report = Mock(spec=ScanReport)
        mock_scan_folder.return_value = mock_report

        handler = DragDropFileHandler()
        handler.temp_dir = str(tmp_path)

        files_data = [{"name": "test.py", "content": 'print("test")', "encoding": "utf-8"}]

        result = handler.scan_uploaded_files(files_data)

        assert result == mock_report
        mock_scan_folder.assert_called_once()


class TestConvenienceFunctions:
    """Test convenience functions."""

    @patch("skill_scanner.browser_scanner.BrowserTabScanner")
    def test_scan_file_url_convenience(self, mock_scanner_class):
        """Test scan_file_url convenience function."""
        from skill_scanner.browser_scanner import scan_file_url

        mock_scanner = Mock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan_file_url.return_value = Mock(spec=ScanReport)

        result = scan_file_url("file:///test/path")

        mock_scanner.scan_file_url.assert_called_once_with("file:///test/path")
        assert result is not None

    @patch("skill_scanner.browser_scanner.LocalDirectoryBrowser")
    def test_list_local_directory(self, mock_browser_class):
        """Test list_local_directory convenience function."""
        from skill_scanner.browser_scanner import list_local_directory

        mock_browser = Mock()
        mock_browser_class.return_value = mock_browser
        mock_browser.list_directory.return_value = [{"name": "test.txt"}]

        result = list_local_directory("/test")

        assert len(result) == 1
        assert result[0]["name"] == "test.txt"

    @patch("skill_scanner.browser_scanner.LocalDirectoryBrowser")
    def test_find_local_skills(self, mock_browser_class):
        """Test find_local_skills convenience function."""
        from skill_scanner.browser_scanner import find_local_skills

        mock_browser = Mock()
        mock_browser_class.return_value = mock_browser
        mock_browser.find_skill_files.return_value = [{"type": "skill_md"}]

        result = find_local_skills("/test")

        assert len(result) == 1
        assert result[0]["type"] == "skill_md"
