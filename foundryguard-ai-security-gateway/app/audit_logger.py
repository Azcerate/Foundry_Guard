import json
from pathlib import Path

LOG_FILE = Path("logs/security_events.jsonl")
LOG_FILE.parent.mkdir(exist_ok=True)


def write_security_event(event: dict):
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
