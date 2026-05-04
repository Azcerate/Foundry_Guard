import re

REDACTION_PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
    "api_key": r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"
}


def redact_sensitive_data(text: str) -> dict:
    redacted = text
    findings = []

    for name, pattern in REDACTION_PATTERNS.items():
        if re.search(pattern, redacted):
            findings.append({
                "type": "sensitive_data",
                "severity": "high",
                "reason": f"Redacted sensitive data: {name}"
            })
            redacted = re.sub(pattern, f"[REDACTED_{name.upper()}]", redacted)

    return {
        "redacted_text": redacted,
        "findings": findings
    }