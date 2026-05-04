import json
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path

AUDIT_FILE = Path("logs/audit_trail.jsonl")
AUDIT_FILE.parent.mkdir(exist_ok=True)


def hash_payload(payload: dict) -> str:
    payload_string = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(payload_string.encode("utf-8")).hexdigest()


def write_audit_record(
    actor_type: str,
    actor_id: str,
    action_type: str,
    resource_type: str,
    decision: str,
    risk_score: int,
    risk_level: str,
    findings: list,
    request_payload: dict,
    resource_id: str = None,
    source_ip: str = "local",
    user_agent: str = "local"
) -> dict:
    record = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action_type": action_type,
        "resource_type": resource_type,
        "resource_id": resource_id or str(uuid.uuid4()),
        "decision": decision,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": findings,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "request_payload_hash": hash_payload(request_payload)
    }

    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    return record


def read_audit_records(limit: int = 50) -> dict:
    if not AUDIT_FILE.exists():
        return {
            "count": 0,
            "records": []
        }

    with AUDIT_FILE.open("r", encoding="utf-8") as f:
        records = [json.loads(line) for line in f.readlines() if line.strip()]

    return {
        "count": len(records),
        "records": records[-limit:]
    }
