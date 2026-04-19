"""
Scope & Policy Agent.

Responsibilities:
- Validate the scope configuration (targets, excluded targets, intensity)
- Enforce the hard blocklist
- Determine which tools are allowed based on passive/active settings
- Reject invalid or unsafe scope early
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from core.blocklist import is_blocklisted
from core.models import AuditEntry, RunResult, ScanStatus
from core.scope import validate_scope

AGENT_NAME = "ScopePolicyAgent"


def run(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    LangGraph node: validate scope and authorisation.

    Mutates ``state["run_result"]`` in-place and returns updated state.
    Sets ``state["error"]`` and status=BLOCKED if validation fails.
    """
    result: RunResult = state["run_result"]

    result.add_audit(AGENT_NAME, "Starting scope and policy validation")

    # ── 1. Authorization check ────────────────────────────────────────────────
    if not result.scope.authorization_note:
        _block(result, state, "Authorization not confirmed.")
        return state

    # ── 2. Scope validation (format + blocklist) ──────────────────────────────
    valid, issues = validate_scope(result.scope)
    if not valid:
        msg = "Scope validation failed:\n" + "\n".join(f"  • {i}" for i in issues)
        _block(result, state, msg)
        return state

    # ── 3. Log allowed tools ──────────────────────────────────────────────────
    allowed_tools = _determine_allowed_tools(result.scope)
    result.add_audit(
        AGENT_NAME,
        "Scope validated",
        output=f"Allowed tools: {', '.join(allowed_tools)}\n"
               f"Active testing: {result.scope.active_testing}\n"
               f"Intensity: {result.scope.test_intensity}",
    )

    state["allowed_tools"] = allowed_tools
    state["current_stage"] = "scope_validated"
    return state


def _block(result: RunResult, state: Dict[str, Any], reason: str) -> None:
    result.status = ScanStatus.BLOCKED
    result.error = reason
    result.completed_at = datetime.now(timezone.utc)
    result.add_audit(AGENT_NAME, "Scan blocked", output=reason)
    state["error"] = reason
    state["current_stage"] = "blocked"


def _determine_allowed_tools(scope: Any) -> List[str]:
    tools = ["dns_lookup", "http_headers", "tls_inspect", "robots_txt", "sitemap", "tech_fingerprint"]
    if scope.active_testing:
        tools += ["port_scan", "dir_fuzz", "vuln_check"]
    return tools
