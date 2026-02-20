# Testing Guide

This guide shows you how to test the skill-scanner project effectively.

## Quick Test Commands

```bash
# Run all tests
pytest

# Run with verbose output (shows test names)
pytest -v

# Run specific test file
pytest tests/test_browser_scanner.py

# Run specific test class
pytest tests/test_browser_scanner.py::TestFileUrlParser

# Run specific test method
pytest tests/test_browser_scanner.py::TestFileUrlParser::test_parse_unix_absolute_path

# Run tests matching a keyword
pytest -k "browser"

# Run with coverage report
pytest --cov=skill_scanner

# Run with HTML coverage report
pytest --cov=skill_scanner --cov-report=html
```

## Test Categories

### 1. Browser Scanner Tests

```bash
# Run all browser scanner tests
pytest tests/test_browser_scanner.py -v

# Test file URL parsing
pytest tests/test_browser_scanner.py::TestFileUrlParser -v

# Test directory browsing
pytest tests/test_browser_scanner.py::TestLocalDirectoryBrowser -v

# Test drag and drop
pytest tests/test_browser_scanner.py::TestDragDropFileHandler -v
```

**What these tests cover:**
- ✅ Parsing file:// URLs (Unix and Windows)
- ✅ Parsing local paths (absolute, relative, home)
- ✅ Scanning files from browser context
- ✅ Browsing directories
- ✅ Finding skill files
- ✅ Uploading and scanning files

### 2. Security Rule Tests

```bash
# Test all security rules
pytest tests/test_rules/ -v

# Test specific rule category
pytest tests/test_rules/test_remote_exec.py -v
pytest tests/test_rules/test_secret_access.py -v
pytest tests/test_rules/test_destructive.py -v
pytest tests/test_rules/test_persistence.py -v
pytest tests/test_rules/test_exfiltration.py -v
pytest tests/test_rules/test_obfuscation.py -v

# Test specific rule
pytest -k "test_eval" -v
```

### 3. Scanner Engine Tests

```bash
# Test core scanner functionality
pytest tests/test_scanner.py -v

# Test file discovery
pytest tests/test_scanner.py::TestDiscoverFiles -v

# Test with clean skill
pytest tests/test_scanner.py::TestScanClean -v

# Test with malicious skill
pytest tests/test_scanner.py::TestScanMalicious -v
```

### 4. CLI Tests

```bash
# Test CLI functionality
pytest tests/test_cli.py -v

# Test exit codes
pytest tests/test_cli.py::TestExitCodes -v

# Test output formats
pytest tests/test_cli.py::TestOutputFormats -v
```

### 5. Formatter Tests

```bash
# Test output formatters
pytest tests/test_formatters.py -v

# Test terminal formatter
pytest tests/test_formatters.py::TestTerminalFormatter -v

# Test JSON formatter
pytest tests/test_formatters.py::TestJsonFormatter -v
```

## Interactive Testing

### Test with Real Files

```bash
# Test with the included fixtures
echo "=== Testing with clean skill ==="
skill-scanner tests/fixtures/clean_skill/

echo "=== Testing with malicious skill ==="
skill-scanner tests/fixtures/malicious_skill/

# Test with JSON output
skill-scanner tests/fixtures/malicious_skill/ --format json

# Test with severity filter
skill-scanner tests/fixtures/malicious_skill/ --severity HIGH

# Test with exclude patterns
skill-scanner tests/fixtures/clean_skill/ --exclude "*.pyc"
```

### Test API Endpoints

First, start the backend:

```bash
cd dashboard/backend
./venv/bin/python3 server.py
```

Then test the API:

```bash
# Test root endpoint
curl http://localhost:8000/

# Test scanning a local path
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "tests/fixtures/clean_skill"}'

# Test file URL parsing
curl -X POST http://localhost:8000/api/parse-file-url \
  -H "Content-Type: application/json" \
  -d '{"url": "file:///Users"}'

# Test directory listing
curl -X POST http://localhost:8000/api/directory/list \
  -H "Content-Type: application/json" \
  -d '{"path": "."}'

# Test finding skills
curl -X POST http://localhost:8000/api/directory/find-skills \
  -H "Content-Type: application/json" \
  -d '{"path": "."}'
```

### Test Browser Components

```bash
# Start the dashboard
./run-dashboard.sh

# Then open http://localhost:5173 in your browser and:
# 1. Test the file browser (folder icon)
# 2. Test drag and drop (upload icon)
# 3. Test different path formats in the input field
```

## Writing New Tests

### Example: Adding a Test for New Rule

```python
# tests/test_rules/test_remote_exec.py

def test_my_new_rule():
    """Test that my new rule detects dangerous patterns."""
    rule = RemoteExecution.NewDangerousRule()
    
    # Should detect dangerous code
    findings = rule.scan_file("test.py", "dangerous_code_here()")
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    
    # Should not detect safe code
    findings = rule.scan_file("test.py", "safe_code_here()")
    assert len(findings) == 0
```

### Example: Adding Integration Test

```python
# tests/test_browser_scanner.py

def test_scan_real_directory(tmp_path):
    """Test scanning a real temporary directory."""
    # Create a test skill structure
    skill_dir = tmp_path / "my-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("# My Skill")
    (skill_dir / "helpers.py").write_text("print('hello')")
    
    # Scan it
    scanner = BrowserTabScanner()
    report = scanner.scan_file_url(str(skill_dir))
    
    # Verify results
    assert report.metadata.files_scanned >= 2
    assert report.verdict == Verdict.CLEAN
```

## Debugging Tests

### Run with Debugging

```bash
# Stop on first failure
pytest -x

# Run with pdb debugger on failure
pytest --pdb

# Show print statements
pytest -s

# Show full traceback
pytest --tb=long

# Show local variables on failure
pytest --showlocals
```

### Check Test Coverage

```bash
# Run with coverage
pytest --cov=skill_scanner --cov-report=term-missing

# Generate HTML report
pytest --cov=skill_scanner --cov-report=html
# Then open: open htmlcov/index.html

# Check coverage for specific module
pytest --cov=skill_scanner.browser_scanner --cov-report=term-missing
```

## Continuous Testing

### Watch Mode (with pytest-watch)

```bash
# Install pytest-watch
pip install pytest-watch

# Run tests on every file change
ptw

# Run specific tests on change
ptw tests/test_browser_scanner.py

# Run with extra options
ptw -- -v -x
```

### Pre-commit Testing

```bash
# Run all tests before committing
git add .
pytest
# If tests pass, then:
git commit -m "Your commit message"
```

## Common Testing Patterns

### Testing File Path Parsing

```python
def test_path_formats():
    parser = FileUrlParser()
    
    test_cases = [
        ("/absolute/path", "unix_path"),
        ("./relative/path", "relative_path"),
        ("~/home/path", "home_path"),
        ("file:///path", "file_url"),
    ]
    
    for url, expected_type in test_cases:
        result = parser.parse_file_url(url)
        assert result["type"] == expected_type, f"Failed for {url}"
```

### Testing API Responses

```python
import requests

def test_api_scan_endpoint():
    response = requests.post(
        "http://localhost:8000/api/scan",
        json={"path": "tests/fixtures/clean_skill"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "findings" in data
    assert "metadata" in data
    assert "score" in data
    assert "verdict" in data
```

### Testing Error Handling

```python
def test_invalid_path_raises_error():
    scanner = BrowserTabScanner()
    
    with pytest.raises(BrowserFileAccessError) as exc_info:
        scanner.scan_file_url("/nonexistent/path")
    
    assert "does not exist" in str(exc_info.value)
```

## Performance Testing

```bash
# Time the tests
pytest --durations=10

# Profile slow tests
pytest --profile

# Run with timing
pytest tests/test_scanner.py::TestScanMalicious -v --tb=short
```

## Test Checklist

Before submitting changes:

- [ ] All tests pass: `pytest`
- [ ] Coverage maintained: `pytest --cov=skill_scanner`
- [ ] Code formatted: `ruff format .`
- [ ] Linting passes: `ruff check .`
- [ ] New tests added for new features
- [ ] Documentation updated (if needed)
- [ ] Manual testing of dashboard components

## Troubleshooting

### Tests Failing with Import Errors

```bash
# Install in development mode
pip install -e ".[dev]"

# Or ensure PYTHONPATH includes src
export PYTHONPATH=src:$PYTHONPATH
pytest
```

### Tests Failing with Permission Errors

```bash
# Some tests create temp directories
# Make sure you have write permissions in /tmp
# Or set custom temp dir
export TMPDIR=/path/to/writable/dir
pytest
```

### Slow Tests

```bash
# Run only fast tests
pytest -m "not slow"

# Skip integration tests
pytest -m "not integration"

# Run unit tests only
pytest tests/unit/ -v
```

## Summary

The test suite includes:
- **219 tests** covering all major functionality
- **Unit tests** for rules, scanner, and models
- **Integration tests** for browser file access
- **CLI tests** for command-line interface
- **Formatter tests** for output handling

Run `pytest` to execute all tests, or use the specific commands above to test individual components.
