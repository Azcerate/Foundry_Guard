DANGEROUS_ACTIONS = [
    "delete_file",
    "send_email",
    "transfer_money",
    "disable_security",
    "create_admin_user",
    "exfiltrate_data",
    "encrypt_files",
    "download_secrets",
    "modify_firewall",
    "run_powershell",
    "execute_code"
]


HIGH_RISK_TOOLS = [
    "email",
    "browser",
    "filesystem",
    "shell",
    "database",
    "cloud_admin",
    "identity_admin"
]


def evaluate_agent_action(action: str, tool: str, privilege_level: str) -> dict:
    findings = []

    if action in DANGEROUS_ACTIONS:
        findings.append({
            "type": "dangerous_agent_action",
            "severity": "critical",
            "reason": f"Agent attempted dangerous action: {action}"
        })

    if tool in HIGH_RISK_TOOLS and privilege_level not in ["approved_admin", "break_glass"]:
        findings.append({
            "type": "unauthorized_tool_use",
            "severity": "high",
            "reason": f"Tool {tool} requires elevated approval."
        })

    if privilege_level in ["unknown", "anonymous", "unverified"]:
        findings.append({
            "type": "privilege_verification_failed",
            "severity": "high",
            "reason": "Agent privilege level could not be verified."
        })

    return {
        "allowed": len(findings) == 0,
        "findings": findings
    }
