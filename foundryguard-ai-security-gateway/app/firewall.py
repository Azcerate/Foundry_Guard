from app.policy_engine import PolicyEngine
from app.agent_guard import evaluate_agent_action
from app.data_guard import redact_sensitive_data
from app.risk_scoring import calculate_risk_score

engine = PolicyEngine()


def inspect_prompt(prompt: str):
    evaluation = engine.evaluate(prompt)
    risk = calculate_risk_score(evaluation["findings"])

    decision = "allow"
    if not evaluation["allowed"]:
        decision = "block"

    return {
        "type": "prompt",
        "decision": decision,
        "findings": evaluation["findings"],
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"]
    }


def inspect_agent_action(action: str, tool: str, privilege_level: str):
    evaluation = evaluate_agent_action(action, tool, privilege_level)
    risk = calculate_risk_score(evaluation["findings"])

    decision = "allow"
    if not evaluation["allowed"]:
        decision = "block"

    return {
        "type": "agent",
        "decision": decision,
        "findings": evaluation["findings"],
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"]
    }


def inspect_data(text: str):
    result = redact_sensitive_data(text)
    risk = calculate_risk_score(result["findings"])

    return {
        "type": "data",
        "decision": "redact" if result["findings"] else "allow",
        "findings": result["findings"],
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "output": result["redacted_text"]
    }