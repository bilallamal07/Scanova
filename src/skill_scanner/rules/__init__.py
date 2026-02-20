"""Security rule modules.

Importing this package loads all rule modules so RuleRegistry.auto_discover()
can find them via __subclasses__().
"""

from skill_scanner.rules import (  # noqa: F401
    destructive,
    exfiltration,
    obfuscation,
    persistence,
    prompt_injection,
    remote_exec,
    secret_access,
)
