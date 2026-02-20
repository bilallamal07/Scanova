"""Core scanning engine."""

from __future__ import annotations

import fnmatch
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from skill_scanner.models import Finding, ScanMetadata, ScanReport
from skill_scanner.rules import base as _  # noqa: F401 — ensure rules package loads
from skill_scanner.rules.base import RuleRegistry

IGNORE_DIRS: set[str] = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
}

SCANNABLE_EXTENSIONS: set[str] = {
    ".md",
    ".py",
    ".js",
    ".ts",
    ".sh",
    ".bash",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".txt",
}

MAX_FILE_SIZE = 1_048_576  # 1 MB


def discover_files(
    root: Path,
    exclude_patterns: list[str] | None = None,
) -> list[Path]:
    """Walk directory tree and return scannable files."""
    files: list[Path] = []
    if not root.is_dir():
        return files
    excludes = exclude_patterns or []
    for item in sorted(root.rglob("*")):
        if any(part in IGNORE_DIRS for part in item.parts):
            continue
        if not item.is_file():
            continue
        if item.suffix.lower() not in SCANNABLE_EXTENSIONS:
            continue
        if item.stat().st_size > MAX_FILE_SIZE:
            continue
        rel = str(item.relative_to(root))
        if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(item.name, pat) for pat in excludes):
            continue
        files.append(item)
    return files


def scan_file(path: Path, registry: RuleRegistry) -> list[Finding]:
    """Scan a single file with all rules."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[Finding] = []
    file_str = str(path)
    for rule in registry.rules:
        findings.extend(rule.scan_file(file_str, content))
    return findings


def scan_single_file(path: str | Path) -> ScanReport:
    """Scan a single file and return a complete report."""
    file_path = Path(path)
    start = time.monotonic()

    registry = RuleRegistry.auto_discover()
    findings = scan_file(file_path, registry)

    elapsed_ms = (time.monotonic() - start) * 1000
    metadata = ScanMetadata(
        scanned_path=str(file_path),
        files_scanned=1,
        duration_ms=round(elapsed_ms, 2),
    )
    return ScanReport(findings=findings, metadata=metadata)


def scan_url(url: str, timeout: int = 30) -> ScanReport:
    """Fetch a remote file and scan it with all rules.

    The URL must use http or https. Content is written to a temp file (never
    executed), scanned with the same rule engine used for local files, then
    deleted. The report's scanned_path and finding file_paths reflect the
    original URL, not the temp path.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme {parsed.scheme!r}. Use http or https.")

    # Preserve the file extension so rules know the file type (e.g. .md vs .py).
    suffix = Path(parsed.path).suffix.lower()
    if suffix not in SCANNABLE_EXTENSIONS:
        suffix = ".txt"

    req = urllib.request.Request(url, headers={"User-Agent": "skill-scanner/cli"})
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read(MAX_FILE_SIZE + 1)
    except urllib.error.HTTPError as exc:
        raise ValueError(f"HTTP {exc.code} fetching {url}") from exc
    except urllib.error.URLError as exc:
        raise ValueError(f"Could not fetch {url}: {exc.reason}") from exc

    if len(raw) > MAX_FILE_SIZE:
        raise ValueError(f"Remote content exceeds the {MAX_FILE_SIZE // 1024} KB limit.")

    registry = RuleRegistry.auto_discover()

    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(raw)
            tmp_path = Path(tmp.name)

        # Scan the temp file but label every finding with the original URL.
        raw_findings = scan_file(tmp_path, registry)
        findings = [f.model_copy(update={"file_path": url}) for f in raw_findings]
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)

    elapsed_ms = (time.monotonic() - start) * 1000
    metadata = ScanMetadata(
        scanned_path=url,
        files_scanned=1,
        duration_ms=round(elapsed_ms, 2),
    )
    return ScanReport(findings=findings, metadata=metadata)


def scan_folder(
    path: str | Path,
    exclude_patterns: list[str] | None = None,
) -> ScanReport:
    """Scan a skill folder and return a complete report."""
    root = Path(path)
    start = time.monotonic()

    registry = RuleRegistry.auto_discover()
    files = discover_files(root, exclude_patterns=exclude_patterns)

    all_findings: list[Finding] = []
    for file_path in files:
        all_findings.extend(scan_file(file_path, registry))

    elapsed_ms = (time.monotonic() - start) * 1000

    metadata = ScanMetadata(
        scanned_path=str(root),
        files_scanned=len(files),
        duration_ms=round(elapsed_ms, 2),
    )
    return ScanReport(findings=all_findings, metadata=metadata)
