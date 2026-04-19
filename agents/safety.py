"""
Safety / Exploit-Blocker Agent.

Responsibilities:
- Verify that no disallowed target has slipped through scope validation
- Validate that all planned tool invocations are safe (no exploit payloads)
- Act as a final gate before any active tooling runs
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from core.blocklist import is_blocklisted
from core.models import RunResult, ScanStatus

AGENT_NAME = "SafetyAgent"

# Words that suggest an exploit payload rather than a safe probe
_PAYLOAD_KEYWORDS = [
    "<script", "' or 1=1", "\" or 1=1", "../../../", "etc/passwd",
    "cmd=", "exec=", "system(", "eval(", "base64_decode", "passthru",
    "UNION SELECT", "DROP TABLE", "INSERT INTO", "UPDATE SET",
    "${jndi:", "{{7*7}}", "#{7*7}",
]


def run(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    LangGraph node: perform pre-flight safety checks.

    Blocks the scan if any target is on the blocklist or if any planned
    command contains payload-like content.
    """
    if state.get("current_stage") in ("blocked", "failed"):
        return state  # already stopped

    result: RunResult = state["run_result"]
    result.add_audit(AGENT_NAME, "Starting safety pre-flight checks")

    issues: List[str] = []

    # ── 1. Re-verify all targets against blocklist ────────────────────────────
    for target in result.scope.targets:
        blocked, reason = is_blocklisted(target)
        if blocked:
            issues.append(f"BLOCKED target '{target}': {reason}")

    # ── 2. Verify exclusions don't contain blocklisted targets ────────────────
    for excluded in result.scope.excluded_targets:
        blocked, reason = is_blocklisted(excluded)
        if blocked:
            # Not a security issue – they're excluded – just note it
            result.add_audit(
                AGENT_NAME,
                "Excluded target is on blocklist (fine – it's excluded)",
                output=f"{excluded}: {reason}",
            )

    # ── 3. Validate planned commands don't look like payloads ─────────────────
    planned_commands: List[str] = state.get("planned_commands", [])
    for cmd in planned_commands:
        for kw in _PAYLOAD_KEYWORDS:
            if kw.lower() in cmd.lower():
                issues.append(f"Potential exploit payload in planned command: {cmd!r}")
                break

    if issues:
        msg = "Safety pre-flight failed:\n" + "\n".join(f"  • {i}" for i in issues)
        result.status = ScanStatus.BLOCKED
        result.error = msg
        result.completed_at = datetime.utcnow()
        result.add_audit(AGENT_NAME, "Safety check FAILED", output=msg)
        state["error"] = msg
        state["current_stage"] = "blocked"
        return state

    result.add_audit(AGENT_NAME, "Safety pre-flight PASSED")
    state["current_stage"] = "safety_cleared"
    return state
