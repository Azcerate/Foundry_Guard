def calculate_risk_score(findings: list) -> dict:
    score = 0

    weights = {
        "prompt_injection": 70,
        "sensitive_data": 80,
        "unsafe_memory": 50,
        "dangerous_agent_action": 100,
	"secret_extraction_attempt": 100,
        "unauthorized_tool_use": 75,
        "privilege_verification_failed": 75
    }

    for finding in findings:
        score += weights.get(finding.get("type"), 25)

    score = min(score, 100)

    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_score": score,
        "risk_level": level
    }
