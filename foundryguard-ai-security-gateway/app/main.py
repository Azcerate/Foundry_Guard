from datetime import datetime, timezone
from fastapi import FastAPI
from pydantic import BaseModel
from app.triage_agent import classify_event
from app.data_guard import redact_sensitive_data
from app.agent_guard import evaluate_agent_action
from app.firewall import inspect_prompt, inspect_agent_action, inspect_data

from app.policy_engine import PolicyEngine
from app.audit_trail import write_audit_record, read_audit_records
from app.foundry_client import call_model
from app.audit_logger import write_security_event
from app.risk_scoring import calculate_risk_score

app = FastAPI(
    title="FoundryGuard AI Security Gateway",
    description="A security gateway for Azure AI Foundry / Azure OpenAI workloads.",
    version="0.2.0"
)

engine = PolicyEngine()


class PromptRequest(BaseModel):
    prompt: str
    user_id: str = "anonymous"
    retain_memory: bool = False

class AgentActionRequest(BaseModel):
    agent_id: str
    action: str
    tool: str
    privilege_level: str = "unknown"

class RedactionRequest(BaseModel):
    text: str
    user_id: str = "anonymous"

@app.get("/")
def health_check():
    return {
        "status": "online",
        "tool": "FoundryGuard",
        "version": "0.2.0"
    }


@app.post("/secure-chat")
def secure_chat(req: PromptRequest):
    evaluation = engine.evaluate(req.prompt)
    risk = calculate_risk_score(evaluation["findings"])

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": req.user_id,
        "allowed": evaluation["allowed"],
        "findings": evaluation["findings"],
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "retain_memory": req.retain_memory
    }

    write_security_event(event)

    if not evaluation["allowed"]:
        return {
            "status": "blocked",
            "message": "Prompt blocked by FoundryGuard policy.",
            "security_event": event
        }

    response = call_model(req.prompt)

    return {
        "status": "allowed",
        "security_event": event,
        "response": response
    }


@app.get("/security-events")
def get_security_events():
    try:
        with open("logs/security_events.jsonl", "r", encoding="utf-8") as f:
            events = [line.strip() for line in f.readlines()]
        return {
            "count": len(events),
            "events": events[-25:]
        }
    except FileNotFoundError:
        return {
            "count": 0,
            "events": []
        }

@app.post("/agent-action/authorize")
def authorize_agent_action(req: AgentActionRequest):
    evaluation = evaluate_agent_action(
        action=req.action,
        tool=req.tool,
        privilege_level=req.privilege_level
    )

    risk = calculate_risk_score(evaluation["findings"])

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": req.agent_id,
        "action": req.action,
        "tool": req.tool,
        "privilege_level": req.privilege_level,
        "allowed": evaluation["allowed"],
        "findings": evaluation["findings"],
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"]
    }

    write_security_event(event)

    if not evaluation["allowed"]:
        return {
            "status": "blocked",
            "message": "Agent action blocked by FoundryGuard.",
            "security_event": event
        }

    return {
        "status": "allowed",
        "message": "Agent action authorized.",
        "security_event": event
    }

@app.post("/redact")
def redact(req: RedactionRequest):
    result = redact_sensitive_data(req.text)
    risk = calculate_risk_score(result["findings"])

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": req.user_id,
        "allowed": True,
        "findings": result["findings"],
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"]
    }

    write_security_event(event)

    return {
        "status": "redacted",
        "redacted_text": result["redacted_text"],
        "security_event": event
    }

@app.post("/triage-event")
def triage_event(event: dict):
    triage = classify_event(event)

    triage_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_event": event,
        "triage": triage
    }

    write_security_event(triage_record)

    return triage_record

@app.get("/audit-trail")
def get_audit_trail(limit: int = 50):
    return read_audit_records(limit=limit)

@app.post("/firewall/inspect")
def firewall_inspect(payload: dict):
    input_type = payload.get("type")

    if input_type == "prompt":
        return inspect_prompt(payload.get("prompt", ""))

    if input_type == "agent":
        return inspect_agent_action(
            action=payload.get("action", ""),
            tool=payload.get("tool", ""),
            privilege_level=payload.get("privilege_level", "unknown")
        )

    if input_type == "data":
        return inspect_data(payload.get("text", ""))

    return {
        "error": "Invalid type. Use prompt, agent, or data."
    }