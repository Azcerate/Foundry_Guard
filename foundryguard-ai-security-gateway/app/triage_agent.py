def classify_event(event: dict) -> dict:
    findings = event.get("findings", [])
    finding_types = [f.get("type") for f in findings]

    categories = []
    frameworks = []
    recommendations = []

    if "prompt_injection" in finding_types:
        categories.append("Prompt Injection")
        frameworks.extend([
            "OWASP LLM01: Prompt Injection",
            "MITRE ATLAS: Prompt Injection",
            "NIST AI RMF: Map, Measure, Manage"
        ])
        recommendations.extend([
            "Keep prompt blocked.",
            "Review source user/session for repeated attempts.",
            "Add similar payloads to policy test cases.",
            "Evaluate Azure Prompt Shields integration."
        ])

    if "sensitive_data" in finding_types:
        categories.append("Sensitive Data Exposure")
        frameworks.extend([
            "OWASP LLM06: Sensitive Information Disclosure",
            "NIST AI RMF: Govern, Manage",
            "ISO 27001: Access Control / Data Protection"
        ])
        recommendations.extend([
            "Redact sensitive values before model processing.",
            "Prevent sensitive data from being stored in memory, logs, or embeddings.",
            "Review DLP and secret scanning controls."
        ])

    if "unsafe_memory" in finding_types:
        categories.append("Unsafe Conversation Memory")
        frameworks.extend([
            "OWASP LLM06: Sensitive Information Disclosure",
            "NIST AI RMF: Manage"
        ])
        recommendations.extend([
            "Block memory retention for this content.",
            "Require explicit approval before storing user-provided memory.",
            "Review memory isolation by user and tenant."
        ])

    if "dangerous_agent_action" in finding_types:
        categories.append("Dangerous Agent Action")
        frameworks.extend([
            "OWASP LLM08: Excessive Agency",
            "MITRE ATLAS: Tool Abuse",
            "NIST AI RMF: Manage"
        ])
        recommendations.extend([
            "Require human approval before execution.",
            "Disable dangerous tool access for this agent.",
            "Verify least privilege for agent identity.",
            "Review kill-chain indicators."
        ])

    if "unauthorized_tool_use" in finding_types:
        categories.append("Unauthorized Tool Use")
        frameworks.extend([
            "OWASP LLM08: Excessive Agency",
            "ISO 27001: Identity and Access Management"
        ])
        recommendations.extend([
            "Verify agent privilege level.",
            "Restrict tool access using role-based policy.",
            "Require admin approval for elevated tools."
        ])

    if "privilege_verification_failed" in finding_types:
        categories.append("Privilege Verification Failure")
        frameworks.extend([
            "Zero Trust: Verify Explicitly",
            "NIST 800-53: Access Control",
            "NHI Security: Service Identity Verification"
        ])
        recommendations.extend([
            "Deny action until identity is verified.",
            "Require managed identity or signed token validation.",
            "Review NHI/service principal permissions."
        ])

    if not categories:
        categories.append("Low Risk / Informational")
        frameworks.append("NIST AI RMF: Monitor")
        recommendations.append("Continue monitoring.")

    # remove duplicates while preserving order
    frameworks = list(dict.fromkeys(frameworks))
    recommendations = list(dict.fromkeys(recommendations))

    return {
        "triage_status": "completed",
        "categories": categories,
        "framework_mapping": frameworks,
        "recommended_actions": recommendations,
        "human_approval_required": event.get("risk_level") in ["high", "critical"]
    }
