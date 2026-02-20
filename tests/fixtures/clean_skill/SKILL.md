---
name: clean-example
description: A perfectly safe skill that does nothing malicious.
---

# Clean Example Skill

This skill helps format markdown files.

## Usage

```bash
skill-scanner /path/to/skill
```

## How It Works

1. Reads markdown files from the target directory
2. Applies formatting rules
3. Outputs the result

```python
def format_markdown(text: str) -> str:
    """Format a markdown string."""
    return text.strip()
```

## Notes

- This skill only reads files, it does not modify anything.
- Works with `.md` files only.
