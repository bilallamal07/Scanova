# PLAN: Skill Security Scanner CLI

> Python CLI tool that scans agent skill files for security risks across 6 dimensions.

---

## Goal

Build `skill-scanner` — a Python CLI that takes a local folder path, scans all skill files (`.md`, `.py`, `.js`, `.sh`, `.json`, `.yaml`) against a ruleset of risky patterns, and outputs a risk report with score, verdict, and per-finding file + line references.

### Acceptance Criteria

- [ ] `skill-scanner /path/to/skill` scans a local skill folder
- [ ] Detects patterns across all 6 security dimensions
- [ ] Outputs JSON report (`--format json`)
- [ ] Outputs pretty terminal report (default)
- [ ] Returns exit code 0 (clean), 1 (warnings), 2 (critical findings)
- [ ] Each finding includes: dimension, severity, file path, line number, matched pattern, description
- [ ] Runs in < 2 seconds on a typical skill folder
- [ ] 80%+ test coverage on scanner engine

---

## Phase 1 — MVP: Local CLI Scanner

### Architecture

```
skill-scanner/
├── src/
│   └── skill_scanner/
│       ├── __init__.py
│       ├── cli.py              # CLI entry point (click or argparse)
│       ├── scanner.py          # Core scanning engine
│       ├── rules/
│       │   ├── __init__.py
│       │   ├── base.py         # Rule base class + severity enum
│       │   ├── remote_exec.py  # Dimension 1: Remote execution
│       │   ├── exfiltration.py # Dimension 2: Data exfiltration
│       │   ├── secret_access.py# Dimension 3: Secret access
│       │   ├── persistence.py  # Dimension 4: Persistence
│       │   ├── destructive.py  # Dimension 5: Destructive ops
│       │   └── obfuscation.py  # Dimension 6: Obfuscation
│       ├── models.py           # Finding, Report, Verdict dataclasses
│       └── formatters/
│           ├── __init__.py
│           ├── terminal.py     # Rich/colored terminal output
│           └── json_fmt.py     # JSON output
├── tests/
│   ├── conftest.py
│   ├── test_scanner.py
│   ├── test_rules/
│   │   ├── test_remote_exec.py
│   │   ├── test_exfiltration.py
│   │   ├── test_secret_access.py
│   │   ├── test_persistence.py
│   │   ├── test_destructive.py
│   │   └── test_obfuscation.py
│   ├── test_formatters.py
│   └── fixtures/               # Sample malicious + benign skill files
│       ├── clean_skill/
│       └── malicious_skill/
├── pyproject.toml
└── README.md
```

### Dependencies (minimal)

| Package | Purpose |
|---------|---------|
| `click` | CLI framework |
| `rich` | Terminal formatting (colors, tables, panels) |
| `pydantic` | Data models + validation |

Dev dependencies: `pytest`, `pytest-cov`, `ruff`

---

### Task Breakdown

#### Task 1: Project scaffolding
- [ ] Init `pyproject.toml` with metadata, dependencies, entry point
- [ ] Create package structure (`src/skill_scanner/`)
- [ ] Setup `ruff` config
- [ ] Verify `pip install -e .` works
- **Verification:** `skill-scanner --help` prints usage

#### Task 2: Data models (`models.py`)
- [ ] `Severity` enum: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- [ ] `Dimension` enum: the 6 security dimensions
- [ ] `Finding` dataclass: dimension, severity, file_path, line_number, pattern_name, description, matched_text
- [ ] `ScanReport` dataclass: findings list, score (0-100), verdict (CLEAN/WARNING/CRITICAL), scan_metadata (path, duration, files_scanned)
- [ ] Score calculation: weighted by severity counts
- **Verification:** Unit tests for score calculation edge cases

#### Task 3: Rule engine base (`rules/base.py`)
- [ ] `Rule` abstract base with two concrete strategies:
  - `RegexRule` — pattern-based line matching (covers most dimensions)
  - `StructuralRule` — file-level / multi-line analysis (for obfuscation entropy checks, AST-like code block parsing, cross-line correlation)
- [ ] Common interface: `name`, `dimension`, `severity`, `description`
- [ ] `RegexRule.scan_line(line, line_number, file_path) -> list[Finding]`
- [ ] `StructuralRule.scan_file(file_path, content) -> list[Finding]` — receives full file content for structural analysis
- [ ] `scan_file(file_path) -> list[Finding]` on base class orchestrates both strategies
- [ ] `RuleRegistry` that auto-discovers all rule subclasses
- [ ] Markdown code block parser utility — extracts fenced code blocks with language tags so rules can distinguish instructional text from executable code
- **Verification:** Unit tests with a dummy RegexRule and a dummy StructuralRule
- **Design note:** StructuralRule is the extension point for future AST checks (e.g., Python `ast.parse` on embedded code blocks). MVP ships with regex + a few structural rules for obfuscation detection (entropy scoring, long encoded string detection).

#### Task 4: Security rules — MVP core (3-5 high-confidence patterns per dimension)

> **Strategy:** Ship 3-5 battle-tested patterns per dimension (~22 total). Add more iteratively after testing against real skill folders. Each pattern below has a near-zero false-positive rate on legitimate skill files.

**Dimension 1 — Remote Execution** (`remote_exec.py`) — RegexRule
| # | Pattern | Severity | What it catches |
|---|---------|----------|-----------------|
| 1 | `curl\|sh`, `wget\|bash`, `curl.*\|.*python` | CRITICAL | Pipe-to-shell |
| 2 | `eval\(` inside code blocks | HIGH | Dynamic code execution |
| 3 | `os.system\(`, `subprocess.call\(.*shell=True` | HIGH | Shell spawning |
| 4 | `exec\(` inside code blocks | HIGH | Dynamic execution |

**Dimension 2 — Data Exfiltration** (`exfiltration.py`) — RegexRule
| # | Pattern | Severity | What it catches |
|---|---------|----------|-----------------|
| 1 | `curl.*(-d\|--data)` with variable interpolation | HIGH | POST local data out |
| 2 | `nc\|ncat\|netcat` with redirection | CRITICAL | Netcat exfil |
| 3 | `requests.post\(.*open\(` | HIGH | Python file upload |

**Dimension 3 — Secret Access** (`secret_access.py`) — RegexRule
| # | Pattern | Severity | What it catches |
|---|---------|----------|-----------------|
| 1 | `cat.*\.env`, `source.*\.env` | HIGH | Dotenv reads |
| 2 | `~/.ssh/`, `~/.aws/`, `~/.config/gcloud` | HIGH | Cloud/SSH credential paths |
| 3 | `CLAUDE_API_KEY\|ANTHROPIC_API_KEY\|OPENAI_API_KEY` | HIGH | AI API key access |
| 4 | `open.*\.(pem\|key\|p12)` | HIGH | Private key file access |

**Dimension 4 — Persistence** (`persistence.py`) — RegexRule
| # | Pattern | Severity | What it catches |
|---|---------|----------|-----------------|
| 1 | `crontab`, `systemctl enable`, `launchctl load` | HIGH | Scheduled task creation |
| 2 | Write to `~/.bashrc\|~/.zshrc\|~/.profile` | HIGH | Shell profile modification |
| 3 | Write to `~/.claude/` (outside own skill dir) | CRITICAL | Agent config tampering |

**Dimension 5 — Destructive Ops** (`destructive.py`) — RegexRule
| # | Pattern | Severity | What it catches |
|---|---------|----------|-----------------|
| 1 | `rm -rf /`, `rm -rf ~`, `rm -rf \$` | CRITICAL | Recursive deletion of root/home |
| 2 | `DROP TABLE\|DROP DATABASE` | CRITICAL | Database destruction |
| 3 | `git push.*--force` on main/master | HIGH | Git history destruction |
| 4 | `mkfs\|dd if=` | CRITICAL | Disk-level operations |

**Dimension 6 — Obfuscation** (`obfuscation.py`) — RegexRule + StructuralRule
| # | Pattern | Type | Severity | What it catches |
|---|---------|------|----------|-----------------|
| 1 | `base64 -d.*\|.*bash`, `echo.*\|.*base64 -d` | Regex | CRITICAL | Decode-then-execute |
| 2 | `atob\(.*eval\(`, `eval(atob(` | Regex | CRITICAL | JS decode + eval |
| 3 | Long hex/unicode sequences (>50 chars of `\x` or `\u`) | **Structural** | HIGH | Encoded payloads (entropy check) |
| 4 | `String.fromCharCode` with >5 numeric args | **Structural** | HIGH | JS char code obfuscation |

**Total MVP patterns: 22** (18 regex + 4 structural)

- **Verification:** Each dimension gets a test file with known-malicious and known-benign samples
- **Iteration plan:** After MVP, run against 20+ real skill folders from `skills.sh` registry. Tune thresholds, add patterns where false-negative rate is high.

#### Task 5: Scanner engine (`scanner.py`)
- [ ] `scan_folder(path) -> ScanReport`
- [ ] Discover all files in folder (respect ignore patterns: `.git`, `node_modules`, `__pycache__`)
- [ ] Filter to scannable extensions: `.md`, `.py`, `.js`, `.ts`, `.sh`, `.bash`, `.yaml`, `.yml`, `.json`, `.toml`
- [ ] Run all registered rules against each file
- [ ] Aggregate findings, calculate score, determine verdict
- [ ] Track timing metadata
- **Verification:** Integration test scanning `fixtures/malicious_skill/` returns expected findings

#### Task 6: CLI (`cli.py`)
- [ ] `skill-scanner <path>` — scan a folder
- [ ] `--format json|terminal` — output format (default: terminal)
- [ ] `--severity <level>` — minimum severity to report (default: LOW)
- [ ] `--quiet` — only output score + verdict
- [ ] `--no-color` — disable terminal colors
- [ ] **CI/CD exit codes** (must be reliable from day one):
  - `0` — CLEAN: no findings above threshold → pipeline passes
  - `1` — WARNING: findings present but no critical → pipeline can gate on this
  - `2` — CRITICAL: critical findings detected → pipeline must fail
- [ ] `--fail-on <severity>` — override exit code threshold (default: any finding = exit 1, critical = exit 2). Allows CI configs like `skill-scanner . --fail-on HIGH` to only fail on HIGH+CRITICAL.
- **Verification:** Automated test asserting exit codes for clean, warning, and critical scan results (not just manual). Shell script test: `skill-scanner fixtures/clean_skill; echo $?` → 0

#### Task 7: Terminal formatter (`formatters/terminal.py`)
- [ ] Rich panel with scan summary (path, files scanned, duration)
- [ ] Score bar (colored: green 0-30, yellow 31-60, red 61-100)
- [ ] Verdict badge: CLEAN / WARNING / CRITICAL
- [ ] Findings table grouped by dimension, sorted by severity
- [ ] Each finding shows: severity icon, file:line, pattern name, description
- **Verification:** Visual inspection on sample output

#### Task 8: JSON formatter (`formatters/json_fmt.py`)
- [ ] Machine-readable JSON matching `ScanReport` schema
- [ ] Deterministic output (sorted keys)
- **Verification:** JSON schema validation in tests

#### Task 9: Test fixtures + integration tests
- [ ] `fixtures/clean_skill/` — benign SKILL.md + helper files
- [ ] `fixtures/malicious_skill/` — files triggering all 6 dimensions
- [ ] Integration test: scan clean → score 0, verdict CLEAN
- [ ] Integration test: scan malicious → findings across all dimensions
- [ ] Edge cases: empty folder, binary files, symlinks, very large files
- **Verification:** `pytest --cov` shows 80%+ coverage

---

## Phase 2 — GitHub Fetching (Future)

- [ ] `skill-scanner https://github.com/user/repo` — fetch + scan
- [ ] Clone to temp dir via `gh` or GitHub API
- [ ] Support specific subdirectory paths
- [ ] Cache fetched repos to avoid re-cloning
- [ ] Rate limiting awareness

## Phase 3 — Web UI (Future)

- [ ] FastAPI backend wrapping scanner engine
- [ ] Input: paste GitHub URL → get report
- [ ] Styled HTML report page
- [ ] Shareable report URLs
- [ ] Batch scanning for skill registries

---

## Backlog (Not in MVP, prioritized for early addition)

| Item | Priority | Notes |
|------|----------|-------|
| `--watch` flag | P1 | Re-scan on file changes. Useful during skill development. Use `watchfiles` library. Add right after MVP. |
| AST parsing for Python code blocks | P2 | `ast.parse()` embedded Python to detect `eval`, `exec`, import hijacking structurally |
| Custom rule loading from `.skill-scanner.yaml` | P2 | Let users add project-specific rules |
| SARIF output format | P3 | Standard format for GitHub Code Scanning integration |
| Confidence scoring per finding | P3 | Reduce false positives by scoring context (is pattern in code block vs prose?) |

---

## Scoring Algorithm

```
score = 0
for finding in findings:
    score += weight[finding.severity]

weights = {
    INFO: 0,
    LOW: 5,
    MEDIUM: 15,
    HIGH: 30,
    CRITICAL: 50
}

score = min(score, 100)  # cap at 100

verdict:
    score == 0        → CLEAN
    score <= 30       → LOW_RISK
    score <= 60       → WARNING
    score > 60        → CRITICAL
```

---

## Key Design Decisions

1. **Dual-strategy rule engine** — `RegexRule` for line-level pattern matching (fast, transparent) + `StructuralRule` for file-level analysis (entropy, AST, multi-line). Both share the same `Rule` interface so the scanner treats them uniformly.
2. **Line-by-line + full-content scanning** — RegexRules get lines for precise references. StructuralRules get full content for cross-line analysis. Both report findings with line numbers.
3. **Rule auto-discovery** — new rules just subclass `Rule` and get picked up. No manual registration.
4. **Pydantic models** — type-safe, serializable, validatable.
5. **Click CLI** — standard, well-tested, supports help generation.
6. **Rich terminal output** — professional look with minimal effort.
7. **CI/CD-first exit codes** — deterministic exit codes so the scanner can gate pipelines from day one.

---

## Risks + Mitigations

| Risk | Mitigation |
|------|------------|
| False positives on benign patterns (e.g., `rm` in docs) | Context-aware rules: check if inside code block, check surrounding text |
| Missing novel attack patterns | Extensible rule system, regular rule updates |
| Large files causing slow scans | File size limit (1MB default), skip binary files |
| Regex performance on complex patterns | Pre-compiled patterns, timeout per file |

---

## Implementation Order

```
Task 1 (scaffolding)
  → Task 2 (models)
    → Task 3 (rule engine)
      → Task 4 (all rules)
        → Task 5 (scanner)
          → Task 6 (CLI) + Task 7 (terminal) + Task 8 (JSON)  [parallel]
            → Task 9 (tests + fixtures)
```

Estimated: 9 tasks, thin vertical slices, each independently testable.
