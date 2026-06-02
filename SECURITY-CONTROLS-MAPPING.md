# FoundryGuard — Control Mapping (OWASP LLM Top 10 & MITRE ATLAS)

This document maps FoundryGuard's controls to the
[OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/) and to
[MITRE ATLAS](https://atlas.mitre.org/) adversarial-ML techniques. It is intended
as a portfolio artifact demonstrating threat-informed design, not a compliance
attestation.

## OWASP LLM Top 10 (2025) coverage

| OWASP ID | Risk | FoundryGuard control | Coverage |
| --- | --- | --- | --- |
| LLM01 | Prompt Injection | AI Firewall + prompt-injection detection (direct & indirect) | Primary |
| LLM02 | Sensitive Information Disclosure | Data Guard redaction (PII, secrets, tokens); secret-extraction blocking | Primary |
| LLM03 | Supply Chain | SBOM (Syft) + Trivy + Dependabot in CI | Partial |
| LLM04 | Data & Model Poisoning | Indirect-injection inspection of RAG/web content | Partial |
| LLM05 | Improper Output Handling | Response inspection layer before output is returned | Partial |
| LLM06 | Excessive Agency | Agent Guard — policy-gated tool authorization, least privilege | Primary |
| LLM07 | System Prompt Leakage | Secret/system-prompt extraction detection + risk scoring | Primary |
| LLM08 | Vector & Embedding Weaknesses | Indirect-injection checks on retrieved context | Partial |
| LLM09 | Misinformation | Human-in-the-loop approval for high-risk actions | Partial |
| LLM10 | Unbounded Consumption | Risk scoring + policy enforcement (rate/budget — roadmap) | Planned |

## MITRE ATLAS technique mapping

| ATLAS Tactic | Technique (example) | FoundryGuard control |
| --- | --- | --- |
| Initial Access | AML.T0051 LLM Prompt Injection | AI Firewall prompt inspection |
| Initial Access | AML.T0051.001 Indirect Prompt Injection | RAG/web content inspection (Data Guard) |
| Execution | AML.T0053 LLM Plugin/Tool Compromise | Agent Guard tool authorization |
| Exfiltration | AML.T0024 Exfiltration via ML Inference API | Secret/PII redaction + response inspection |
| Defense Evasion | AML.T0054 LLM Jailbreak | Risk scoring + block/approve decisioning |
| Impact | AML.T0048 External Harms | Human-in-the-loop for high-risk actions |

## Decision model

Every request resolves to one of four enforced outcomes:

- **Allow** — risk below threshold, no sensitive content.
- **Redact** — sensitive data stripped before forwarding.
- **Require Approval** — high-risk action routed to a human reviewer.
- **Block** — critical risk; request rejected and logged to the audit trail.

## Notes & honest scoping

- "Primary" = a dedicated control directly addresses the risk. "Partial" = the
  risk is meaningfully reduced but not fully covered. "Planned" = on the roadmap.
- Detection is heuristic/policy-driven in this prototype; it is not a guarantee
  against a determined adversary. Treat as defense-in-depth, not a sole control.

## References

- OWASP Top 10 for LLM Applications (2025): https://genai.owasp.org/
- MITRE ATLAS: https://atlas.mitre.org/
- NIST AI RMF (AI 100-1): https://www.nist.gov/itl/ai-risk-management-framework
