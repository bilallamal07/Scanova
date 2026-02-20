"""Dimension 3: Secret access detection rules."""

from __future__ import annotations

import re
from typing import ClassVar

from skill_scanner.models import Dimension, Severity
from skill_scanner.rules.base import PatternDef, RegexRule


class DotenvReadRule(RegexRule):
    name = "dotenv-read"
    dimension = Dimension.SECRET_ACCESS
    severity = Severity.HIGH
    description = "Reads .env files which typically contain secrets"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(r"\b(cat|source|less|more)\s+.*\.env\b")),
    ]


class CredentialPathRule(RegexRule):
    name = "credential-path"
    dimension = Dimension.SECRET_ACCESS
    severity = Severity.HIGH
    description = "Accesses well-known credential storage paths"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"~/\.(ssh|aws|config/gcloud|azure|kube)/",
        )),
    ]


class AIApiKeyRule(RegexRule):
    name = "ai-api-key-access"
    dimension = Dimension.SECRET_ACCESS
    severity = Severity.HIGH
    description = "References specific AI service API key environment variables"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"\$(CLAUDE_API_KEY|ANTHROPIC_API_KEY|OPENAI_API_KEY|OPENAI_KEY)",
        )),
    ]


class PrivateKeyFileRule(RegexRule):
    name = "private-key-file"
    dimension = Dimension.SECRET_ACCESS
    severity = Severity.HIGH
    description = "Opens private key or certificate files"
    patterns: ClassVar[list[PatternDef]] = [
        PatternDef(regex=re.compile(
            r"\bopen\s*\(.*\.(pem|key|p12|pfx|jks)\b",
        ), code_only=True),
    ]
