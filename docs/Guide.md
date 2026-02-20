## skill-scanner

A static analysis tool that scans AI agent skill files for security risks. It detects dangerous patterns across 6 dimensions before you install or trust a skill.

### Why

AI agent skills (Claude Code, Cursor, etc.) are markdown and code files that instruct agents what to do. A malicious skill can tell an agent to exfiltrate secrets, install backdoors, or destroy data. skill-scanner catches these patterns before they run.

### How it works

1. **File discovery** — walks the skill folder, picks up `.md`, `.py`, `.js`, `.ts`, `.sh`, `.yaml`, `.json`, `.toml` files. Skips `.git`, `node_modules`, `__pycache__`, and files over 1MB.
2. **Pattern matching** — runs 22 regex-based rules across 6 security dimensions. Each rule targets a specific attack pattern (e.g., `curl | bash`, `eval()`, `rm -rf /`).
3. **Context awareness** — in markdown files, matches inside fenced code blocks or table rows are recognized as documentation examples and downgraded to INFO severity. A negative lookbehind on `exec()` excludes JavaScript's `RegExp.exec()` method calls.
4. **Scoring** — each finding has a severity weight (INFO=0, LOW=5, MEDIUM=15, HIGH=30, CRITICAL=50). Weights sum to a 0-100 score, capped at 100.
5. **Verdict** — score maps to CLEAN (0), LOW RISK (1-30), WARNING (31-60), or CRITICAL (61-100).

### Install

```bash
pip install -e /path/to/skill-scanner
```

### Usage

```bash
skill-scanner <path-to-skill-folder>
```

### Options

| Flag | What it does |
|------|-------------|
| `--format json` | Machine-readable JSON output |
| `--severity INFO\|LOW\|MEDIUM\|HIGH\|CRITICAL` | Minimum severity to show (default: LOW) |
| `--fail-on HIGH` | Exit code 2 if any finding meets this severity |
| `--exclude "*.log"` | Glob pattern for files to skip (repeatable) |
| `--quiet` | Score and verdict only |
| `--no-color` | Strip ANSI colors (for logs/CI) |

---

### Use cases

**1. Vet a skill before installing it**
```bash
skill-scanner ~/.claude/skills/some-new-skill
```
CLEAN means safe. WARNING/CRITICAL means read the findings before trusting it.

**2. Scan all installed skills at once**
```bash
for skill in ~/.claude/skills/*/; do
  echo "=== $(basename "$skill") ==="
  skill-scanner "$skill" --quiet
done
```

**3. CI gate — block dangerous skills in a pipeline**
```bash
skill-scanner ./my-skill --fail-on HIGH
# Exit 0 = pass, Exit 2 = blocked
```

**4. Audit a third-party skill repo**
```bash
git clone https://github.com/someone/cool-skill.git
skill-scanner ./cool-skill --format json > audit.json
```

**5. See everything, including informational findings**
```bash
skill-scanner ./my-skill --severity INFO
```

**6. Pipe JSON into other tools**
```bash
skill-scanner ./my-skill --format json | jq '.findings[] | .rule_name'
```

**7. Skip noisy files**
```bash
skill-scanner ./my-skill --exclude "CHANGELOG.md" --exclude "vendor/*"
```

**8. Use as a Claude Code slash command**

Install the `/scan` skill, then:
```
/scan                          # scan all installed skills
/scan ~/.claude/skills/foo     # scan one skill
```

---

### Detection dimensions (6 dimensions, 22 patterns)

**Remote Execution** — downloads piped to shell interpreters, `eval()`, `exec()`, `os.system()`, `subprocess` with `shell=True`

**Exfiltration** — `curl -d` posting data out, netcat piping, `requests.post(open(...))` uploading local files

**Secret Access** — reading `.env` files, accessing `~/.ssh`, `~/.aws`, `~/.gcloud`, AI provider API key environment variables, opening private key files

**Persistence** — crontab/systemctl/launchctl scheduling, writing to shell profiles (`.bashrc`, `.zshrc`), tampering with agent config directories (`.claude/`, `.cursor/`)

**Destructive Ops** — `rm -rf` with dangerous paths, `DROP TABLE`/`DROP DATABASE`/`TRUNCATE`, `git push --force`, disk operations (`mkfs`, `dd` to devices)

**Obfuscation** — base64 decode piped to shell/exec, `eval(atob(...))`, long hex/unicode escape sequences, `String.fromCharCode` chains

---

### Context-aware false positive reduction

The scanner avoids false positives in documentation files through three mechanisms:

1. **Code fence detection** — `code_only` patterns matching inside markdown fenced code blocks (` ``` `) are downgraded to INFO. Code examples in docs are references, not instructions.

2. **Table row detection** — any pattern matching on a markdown table line (`| ... |`) is downgraded to INFO. Tables listing attack patterns (like this guide) are descriptions, not payloads.

3. **Regex refinement** — the `exec()` rule uses a negative lookbehind (`(?<!\.)`) to exclude JavaScript's `RegExp.prototype.exec()` method calls, which are safe.

---

### Scoring and verdicts

| Score | Verdict | What it means |
|-------|---------|---------------|
| 0 | CLEAN | No risky patterns detected |
| 1-30 | LOW RISK | Minor findings, review optional |
| 31-60 | WARNING | Review findings before using the skill |
| 61-100 | CRITICAL | Do not install without understanding every finding |

Severity weights: INFO=0, LOW=5, MEDIUM=15, HIGH=30, CRITICAL=50. Score is the sum of all finding weights, capped at 100.

Exit codes: 0 = clean, 1 = findings present, 2 = `--fail-on` threshold exceeded.

---

### Architecture

```
src/skill_scanner/
  cli.py              # Click CLI entry point
  scanner.py          # File discovery + orchestration
  models.py           # Finding, ScanReport, Severity, Verdict (Pydantic)
  rules/
    base.py           # Rule ABC, RegexRule, StructuralRule, registry, context detection
    remote_exec.py    # Dimension 1: pipe-to-shell, eval, exec, shell-spawn
    exfiltration.py   # Dimension 2: curl-post, netcat, python-upload
    secret_access.py  # Dimension 3: dotenv, credential paths, API keys, private keys
    persistence.py    # Dimension 4: scheduled tasks, shell profiles, agent config
    destructive.py    # Dimension 5: rm -rf, DROP TABLE, git force-push, disk ops
    obfuscation.py    # Dimension 6: decode-execute, hex blobs, charcode
  formatters/
    terminal.py       # Rich terminal output with color
    json_fmt.py       # JSON output for CI/tooling
```

488 source lines. 197 tests. 100% coverage. 0.34s runtime.



## This integration doesn't fit skill-scanner. Different problem domains.
Skill-scanner analyzes static text patterns in agent skill files. It looks for prompt injection, data exfiltration, and obfuscation in markdown and code. CVE databases track vulnerabilities in software packages and libraries. There's no overlap.