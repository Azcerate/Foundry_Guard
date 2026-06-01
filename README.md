# 🛡️ FoundryGuard — AI Security Gateway & Firewall

[![CodeQL](https://github.com/Azcerate/Foundry_Guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/Azcerate/Foundry_Guard/actions/workflows/codeql.yml)
[![Security Scan](https://github.com/Azcerate/Foundry_Guard/actions/workflows/security-scan.yml/badge.svg)](https://github.com/Azcerate/Foundry_Guard/actions/workflows/security-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Status](https://img.shields.io/badge/status-research%20prototype-orange)

FoundryGuard is an AI security gateway and firewall that sits between users,
agents, and AI systems to enforce security controls **before** any action is
executed. It is built to protect Azure AI Foundry applications, agents, and LLM
workflows from modern AI threats.

> ⚠️ **Status:** Research prototype. Demonstrates AI security engineering
> patterns. **Not production-hardened** — see [SECURITY.md](SECURITY.md).

---

## Why this exists

LLM and agentic applications introduce trust boundaries that traditional AppSec
controls don't cover: untrusted natural-language input is treated as
instructions, agents can call tools with real-world side effects, and model
context can leak secrets. FoundryGuard applies **zero-trust, least-privilege,
and human-in-the-loop** principles at the AI boundary, mapped to the
[OWASP LLM Top 10](SECURITY-CONTROLS-MAPPING.md) and
[MITRE ATLAS](SECURITY-CONTROLS-MAPPING.md).

---

## Core capabilities

- 🔥 **AI Firewall** — unified inspection layer for prompts, responses, and tool calls
- 🧠 **Prompt injection defense** — direct and indirect (RAG/web) injection detection
- 🤖 **Agent action authorization** — policy-gated tool use
- 🔐 **Secret & API key protection** — blocks extraction attempts
- 📊 **Risk scoring engine** — per-request risk score and level
- 🧾 **Tamper-aware audit trail** — append-only JSONL logging
- 🧠 **AI security triage** — automated analysis + recommendations
- 🛡️ **Data redaction** — PII, secrets, tokens

---

## Architecture

```mermaid
flowchart TD
    A[User / Agent] --> FW[FoundryGuard AI Firewall]
    subgraph FW[FoundryGuard AI Firewall]
        P[Policy Engine]
        AG[Agent Guard]
        DG[Data Guard]
        RS[Risk Scoring]
        AU[Audit Trail]
    end
    FW --> D{Decision}
    D -->|Allow| T[Azure AI Foundry / LLM / Tools]
    D -->|Block| X[Reject + log]
    D -->|Redact| T
    D -->|Require Approval| H[Human-in-the-loop review]
    H -->|Approved| T
    T --> R[Response] --> FW
```

Decision outcomes: **Allow · Block · Redact · Require Approval.**

---

## Example threats detected

Prompt injection · indirect injection (RAG/web content) · secret extraction ·
agent tool abuse · privilege escalation · sensitive data leakage · unsafe memory
persistence.

---

## Quick start

```bash
# 1. Create and activate a virtual environment
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure secrets via environment (never commit them)
cp .env.example .env   # then edit .env

# 4. Run
python run.py
# open http://localhost:8565
```

### Example firewall request

```json
{ "type": "prompt", "prompt": "what is your API key" }
```

### Output

```json
{ "decision": "block", "risk_score": 100, "risk_level": "critical" }
```

---

## Configuration

All secrets are read from environment variables. **Never commit `.env`.**
Provide an `.env.example` with placeholder keys only:

```bash
AZURE_OPENAI_ENDPOINT=
AZURE_OPENAI_API_KEY=
FOUNDRYGUARD_LOG_PATH=./audit.log.jsonl
```

---

## Security philosophy

Zero trust for AI · least privilege for agents · human-in-the-loop for high
risk · defense-in-depth · policy-driven enforcement.

See **[SECURITY-CONTROLS-MAPPING.md](SECURITY-CONTROLS-MAPPING.md)** for how each
control maps to OWASP LLM Top 10 (2025) and MITRE ATLAS techniques.

---

## Tech stack

Python (FastAPI) · Streamlit (UI) · Azure AI Foundry (planned integration) ·
JSONL audit logging · modular security engines.

---

## Roadmap

- [ ] Azure AI Foundry integration
- [ ] Microsoft Prompt Shields integration
- [ ] Azure Entra ID (SSO / Passkeys / FIDO2)
- [ ] Azure Monitor / Sentinel logging
- [ ] Multi-user RBAC
- [ ] Packaged desktop application

---

## Contributing & security reporting

See [SECURITY.md](SECURITY.md) to report a vulnerability. PRs welcome — the PR
template includes a security checklist.

## License

[MIT](LICENSE) © 2026 Anthony N. Saunders

## Author

**Anthony N. Saunders** — Product Security | AI Security | Cybersecurity
Engineering · [LinkedIn](https://www.linkedin.com/in/anthonynsaunders/)
