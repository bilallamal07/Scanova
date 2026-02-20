"""Helper utilities for the clean skill."""


def sanitize(text: str) -> str:
    return text.replace("<", "&lt;").replace(">", "&gt;")
