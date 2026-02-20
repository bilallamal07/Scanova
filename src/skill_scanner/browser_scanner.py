"""Browser-based file access and scanning service.

This module provides capabilities to:
- Access files from browser tabs and local file system
- Parse file:// URLs and local paths
- Handle drag-and-drop file uploads
- Scan directories recursively through browser APIs
"""

from __future__ import annotations

import base64
import fnmatch
import json
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from skill_scanner.scanner import scan_folder
from skill_scanner.models import ScanReport


class BrowserFileAccessError(Exception):
    """Raised when browser file access fails."""

    pass


class FileUrlParser:
    """Parse various file URL formats and local paths."""

    @staticmethod
    def parse_file_url(url: str) -> dict[str, Any]:
        r"""Parse a file URL or local path.

        Supports formats:
        - file:///path/to/file (Unix absolute)
        - file:///C:/path/to/file (Windows absolute)
        - file://localhost/path/to/file
        - /absolute/path/to/file (Unix local)
        - C:\path\to\file (Windows local)
        - ./relative/path (Relative)
        - ~/home/path (Home directory)

        Returns:
            dict with 'path', 'is_directory', 'exists', 'type'
        """
        result = {
            "original": url,
            "path": None,
            "is_directory": False,
            "exists": False,
            "type": "unknown",
            "error": None,
        }

        try:
            # Handle file:// URLs
            if url.startswith("file://"):
                parsed = urlparse(url)
                path = unquote(parsed.path)

                # Handle Windows paths like /C:/path
                if re.match(r"^/[A-Za-z]:", path):
                    path = path[1:]  # Remove leading slash

                result["path"] = path
                result["type"] = "file_url"

            # Handle Windows paths
            elif re.match(r"^[A-Za-z]:[/\\]", url):
                result["path"] = url.replace("\\", "/")
                result["type"] = "windows_path"

            # Handle Unix absolute paths
            elif url.startswith("/"):
                result["path"] = url
                result["type"] = "unix_path"

            # Handle home directory expansion
            elif url.startswith("~/"):
                home = Path.home()
                result["path"] = str(home / url[2:])
                result["type"] = "home_path"

            # Handle relative paths
            else:
                result["path"] = str(Path.cwd() / url)
                result["type"] = "relative_path"

            # Check if path exists
            path_obj = Path(result["path"])
            result["exists"] = path_obj.exists()

            if result["exists"]:
                result["is_directory"] = path_obj.is_dir()
                result["resolved_path"] = str(path_obj.resolve())

        except Exception as e:
            result["error"] = str(e)

        return result

    @staticmethod
    def is_valid_file_url(url: str) -> bool:
        """Check if URL is a valid file URL or local path."""
        patterns = [
            r"^file://",
            r"^/[A-Za-z0-9_./-]+",
            r"^[A-Za-z]:[/\\]",
            r"^~[/\\]",
            r"^[./]",
        ]
        return any(re.match(pattern, url) for pattern in patterns)


class BrowserTabScanner:
    """Scan files accessible from browser context."""

    def __init__(self, temp_dir: str | None = None):
        self.temp_dir = temp_dir or tempfile.gettempdir()
        self.parser = FileUrlParser()

    def scan_file_url(self, url: str) -> ScanReport:
        """Scan a file or directory from a file:// URL or local path.

        Args:
            url: File URL or local path to scan

        Returns:
            ScanReport with findings

        Raises:
            BrowserFileAccessError: If file cannot be accessed
        """
        parsed = self.parser.parse_file_url(url)

        if parsed["error"]:
            raise BrowserFileAccessError(f"Failed to parse URL: {parsed['error']}")

        if not parsed["exists"]:
            raise BrowserFileAccessError(f"Path does not exist: {parsed['path']}")

        path = Path(parsed["resolved_path"] or parsed["path"])

        try:
            return scan_folder(path)
        except Exception as e:
            raise BrowserFileAccessError(f"Scan failed: {e}")

    def scan_multiple_paths(self, paths: list[str]) -> list[ScanReport]:
        """Scan multiple file paths.

        Args:
            paths: List of file URLs or local paths

        Returns:
            List of ScanReports
        """
        reports = []
        for path in paths:
            try:
                report = self.scan_file_url(path)
                reports.append(report)
            except BrowserFileAccessError as e:
                # Create error report
                from skill_scanner.models import ScanMetadata, Finding, Severity, Dimension

                reports.append(
                    ScanReport(
                        findings=[
                            Finding(
                                dimension=Dimension.REMOTE_EXECUTION,
                                severity=Severity.INFO,
                                file_path=path,
                                line_number=0,
                                rule_name="FileAccessError",
                                description=str(e),
                                matched_text="",
                            )
                        ],
                        metadata=ScanMetadata(scanned_path=path, files_scanned=0, duration_ms=0),
                    )
                )
        return reports


class LocalDirectoryBrowser:
    """Browse and scan local directories."""

    def __init__(self, root_path: str | Path | None = None):
        self.root = Path(root_path) if root_path else Path.cwd()

    def list_directory(
        self, path: str | Path | None = None, pattern: str = "*", include_hidden: bool = False
    ) -> list[dict[str, Any]]:
        """List files in a directory.

        Args:
            path: Directory path (defaults to root)
            pattern: Glob pattern to filter files
            include_hidden: Include hidden files

        Returns:
            List of file/directory info dicts
        """
        target = Path(path) if path else self.root

        if not target.exists():
            return []

        if not target.is_dir():
            return []

        items = []

        try:
            for item in target.iterdir():
                # Skip hidden files unless requested
                if not include_hidden and item.name.startswith("."):
                    continue

                # Apply pattern filter
                if not fnmatch.fnmatch(item.name, pattern):
                    continue

                stat = item.stat()
                items.append(
                    {
                        "name": item.name,
                        "path": str(item),
                        "relative_path": str(item.relative_to(self.root)),
                        "is_directory": item.is_dir(),
                        "is_file": item.is_file(),
                        "size": stat.st_size if item.is_file() else None,
                        "modified": stat.st_mtime,
                    }
                )
        except PermissionError:
            pass

        # Sort: directories first, then alphabetically
        items.sort(key=lambda x: (not x["is_directory"], x["name"].lower()))

        return items

    def find_skill_files(
        self, path: str | Path | None = None, max_depth: int = 3
    ) -> list[dict[str, Any]]:
        """Find potential skill files in directory.

        Looks for:
        - SKILL.md files
        - skill.yaml/skill.yml files
        - .agent/skills/ directories
        - skills/ directories

        Args:
            path: Root directory to search
            max_depth: Maximum directory depth to search

        Returns:
            List of found skill locations
        """
        target = Path(path) if path else self.root
        skills = []

        try:
            for item in target.rglob("*"):
                # Check depth
                try:
                    depth = len(item.relative_to(target).parts)
                    if depth > max_depth:
                        continue
                except ValueError:
                    continue

                # Check for skill indicators
                if item.is_file():
                    if item.name.upper() == "SKILL.MD":
                        skills.append(
                            {
                                "type": "skill_md",
                                "name": item.name,
                                "path": str(item.parent),
                                "file": str(item),
                            }
                        )
                    elif item.name.lower() in ["skill.yaml", "skill.yml"]:
                        skills.append(
                            {
                                "type": "skill_config",
                                "name": item.name,
                                "path": str(item.parent),
                                "file": str(item),
                            }
                        )

                elif item.is_dir():
                    if item.name.lower() == "skills" or item.name.lower() == "skill":
                        skills.append(
                            {
                                "type": "skills_directory",
                                "name": item.name,
                                "path": str(item),
                            }
                        )
        except PermissionError:
            pass

        return skills

    def get_directory_tree(
        self, path: str | Path | None = None, max_depth: int = 2
    ) -> dict[str, Any]:
        """Get directory tree structure.

        Args:
            path: Root directory
            max_depth: Maximum depth to traverse

        Returns:
            Tree structure dict
        """
        target = Path(path) if path else self.root

        def build_tree(current: Path, depth: int) -> dict[str, Any]:
            result = {
                "name": current.name or str(current),
                "path": str(current),
                "is_directory": current.is_dir(),
                "children": [],
            }

            if current.is_dir() and depth < max_depth:
                try:
                    for item in sorted(current.iterdir()):
                        if item.name.startswith("."):
                            continue
                        result["children"].append(build_tree(item, depth + 1))
                except PermissionError:
                    pass

            return result

        return build_tree(target, 0)


class DragDropFileHandler:
    """Handle drag-and-drop file uploads."""

    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="skill_scanner_upload_")

    def process_uploaded_files(self, files_data: list[dict[str, Any]]) -> Path:
        """Process uploaded files from browser.

        Args:
            files_data: List of file data dicts with:
                - name: filename
                - content: base64 encoded content or raw string
                - encoding: 'base64' or 'utf-8'

        Returns:
            Path to temporary directory containing files
        """
        upload_dir = Path(self.temp_dir)
        upload_dir.mkdir(parents=True, exist_ok=True)

        for file_info in files_data:
            name = file_info.get("name", "unnamed")
            content = file_info.get("content", "")
            encoding = file_info.get("encoding", "utf-8")

            # Create subdirectories if needed
            file_path = upload_dir / name
            file_path.parent.mkdir(parents=True, exist_ok=True)

            # Decode and save
            if encoding == "base64":
                decoded = base64.b64decode(content)
                file_path.write_bytes(decoded)
            else:
                file_path.write_text(content, encoding="utf-8")

        return upload_dir

    def scan_uploaded_files(self, files_data: list[dict[str, Any]]) -> ScanReport:
        """Process and scan uploaded files.

        Args:
            files_data: List of file data dicts

        Returns:
            ScanReport
        """
        upload_dir = self.process_uploaded_files(files_data)

        try:
            return scan_folder(upload_dir)
        finally:
            # Cleanup temp files
            import shutil

            shutil.rmtree(upload_dir, ignore_errors=True)

    def cleanup(self):
        """Clean up temporary upload directory."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)


# Convenience functions


def scan_file_url(url: str) -> ScanReport:
    """Quick function to scan a file URL or local path."""
    scanner = BrowserTabScanner()
    return scanner.scan_file_url(url)


def list_local_directory(path: str, pattern: str = "*") -> list[dict]:
    """Quick function to list directory contents."""
    browser = LocalDirectoryBrowser()
    return browser.list_directory(path, pattern)


def find_local_skills(path: str, max_depth: int = 3) -> list[dict]:
    """Quick function to find skill files locally."""
    browser = LocalDirectoryBrowser()
    return browser.find_skill_files(path, max_depth)
