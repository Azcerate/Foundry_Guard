import re
import yaml
from pathlib import Path


SECRET_REQUEST_PATTERNS = [
    r"(?i)\bwhat\s+is\s+your\s+api\s+key\b",
    r"(?i)\bshow\s+me\s+your\s+api\s+key\b",
    r"(?i)\breveal\s+your\s+api\s+key\b",
    r"(?i)\bprint\s+your\s+api\s+key\b",
    r"(?i)\bwhat\s+is\s+your\s+secret\b",
    r"(?i)\breveal\s+your\s+secret\b",
    r"(?i)\bshow\s+me\s+your\s+token\b",
    r"(?i)\breveal\s+your\s+token\b",
    r"(?i)\bshow\s+me\s+your\s+credentials\b",
    r"(?i)\breveal\s+your\s+credentials\b"
]


class PolicyEngine:
    def __init__(self, policy_path="policies/default_policy.yaml"):
        self.policy_path = policy_path
        self.policy = yaml.safe_load(Path(policy_path).read_text())

    def evaluate(self, text: str) -> dict:
        findings = []

        for pattern in self.policy.get("block_patterns", []):
            if pattern.lower() in text.lower():
                findings.append({
                    "type": "prompt_injection",
                    "severity": "high",
                    "reason": f"Matched blocked phrase: {pattern}"
                })

        for name, pattern in self.policy.get("pii_patterns", {}).items():
            if re.search(pattern, text):
                findings.append({
                    "type": "sensitive_data",
                    "severity": "high",
                    "reason": f"Matched sensitive data pattern: {name}"
                })

        for pattern in SECRET_REQUEST_PATTERNS:
            if re.search(pattern, text):
                findings.append({
                    "type": "secret_extraction_attempt",
                    "severity": "critical",
                    "reason": "User attempted to extract secrets, tokens, API keys, or credentials."
                })

        for keyword in self.policy.get("memory_block_keywords", []):
            if keyword.lower() in text.lower():
                findings.append({
                    "type": "unsafe_memory",
                    "severity": "medium",
                    "reason": f"Unsafe memory request: {keyword}"
                })

        return {
            "allowed": len(findings) == 0,
            "findings": findings
        }
