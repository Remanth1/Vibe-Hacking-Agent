"""
LangGraph orchestration graph.

Defines the multi-agent state machine:

    [scope_policy] → [safety] → [recon] → [vuln_triage] → [reporter]
           ↓               ↓
         END (blocked)   END (blocked)

Each node is a pure function that receives/returns the shared AgentState dict.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

from langgraph.graph import END, StateGraph

from agents import scope_policy, safety, recon, vuln_triage, reporter
from core.evidence import save_run
from core.models import RunResult, ScanStatus, ScopeConfig

# ── State type ────────────────────────────────────────────────────────────────
# We use a plain dict to keep LangGraph's TypedDict requirement minimal.
# The canonical data lives in ``state["run_result"]`` (a RunResult instance).

AgentState = Dict[str, Any]


# ── Graph construction ────────────────────────────────────────────────────────

def _build_graph() -> Any:
    g = StateGraph(dict)  # type: ignore[arg-type]

    g.add_node("scope_policy", scope_policy.run)
    g.add_node("safety", safety.run)
    g.add_node("recon", recon.run)
    g.add_node("vuln_triage", vuln_triage.run)
    g.add_node("reporter", reporter.run)

    g.set_entry_point("scope_policy")

    # After scope_policy: go to safety if OK, else end
    g.add_conditional_edges(
        "scope_policy",
        lambda s: "safety" if s.get("current_stage") != "blocked" else END,
        {"safety": "safety", END: END},
    )

    # After safety: go to recon if OK, else end
    g.add_conditional_edges(
        "safety",
        lambda s: "recon" if s.get("current_stage") == "safety_cleared" else END,
        {"recon": "recon", END: END},
    )

    g.add_edge("recon", "vuln_triage")
    g.add_edge("vuln_triage", "reporter")
    g.add_edge("reporter", END)

    return g.compile()


_GRAPH = _build_graph()


# ── Public API ────────────────────────────────────────────────────────────────

def run_assessment(
    target: str,
    scope: ScopeConfig,
    authorization_confirmed: bool,
    progress_callback: Optional[Any] = None,
) -> RunResult:
    """
    Entry point for the Streamlit UI and CLI.

    Parameters
    ----------
    target:
        Primary target hostname/IP.
    scope:
        Validated ScopeConfig (includes active_testing flag).
    authorization_confirmed:
        Must be True; otherwise the run is immediately blocked.
    progress_callback:
        Optional callable(stage: str, message: str) called after each agent
        node finishes.

    Returns
    -------
    RunResult
        The complete, persisted result of the assessment.
    """
    result = RunResult(target=target, scope=scope, status=ScanStatus.PENDING)
    result.status = ScanStatus.RUNNING

    if not authorization_confirmed:
        result.status = ScanStatus.BLOCKED
        result.error = "Authorization not confirmed by user."
        save_run(result)
        return result

    # Attach authorization note to scope if not already set
    if not scope.authorization_note:
        scope.authorization_note = "Confirmed"

    # Resolve optional LLM
    llm = _resolve_llm()

    initial_state: AgentState = {
        "run_result": result,
        "current_stage": "init",
        "allowed_tools": [],
        "planned_commands": [],
        "llm": llm,
        "error": None,
        "progress_callback": progress_callback,
        "report_markdown": "",
    }

    # Stream node-by-node so the UI can show live progress
    final_state: AgentState = initial_state
    for step_state in _GRAPH.stream(initial_state):
        node_name, node_state = next(iter(step_state.items()))
        final_state = node_state
        result = node_state.get("run_result", result)
        if progress_callback:
            try:
                progress_callback(
                    node_name,
                    f"Stage: {node_state.get('current_stage', node_name)}",
                )
            except Exception:
                pass

    # Ensure we always return the latest RunResult
    return final_state.get("run_result", result)


def _resolve_llm() -> Optional[Any]:
    """
    Try to build an LLM client from environment variables.
    Returns None (graceful degradation) if no provider is configured.
    """
    openai_key = os.getenv("OPENAI_API_KEY", "")
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
    ollama_url = os.getenv("OLLAMA_BASE_URL", "")

    if openai_key:
        try:
            from langchain_openai import ChatOpenAI
            model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
            return ChatOpenAI(model=model, api_key=openai_key, temperature=0)
        except ImportError:
            pass

    if anthropic_key:
        try:
            from langchain_anthropic import ChatAnthropic
            model = os.getenv("ANTHROPIC_MODEL", "claude-3-haiku-20240307")
            return ChatAnthropic(model=model, api_key=anthropic_key, temperature=0)  # type: ignore[call-arg]
        except ImportError:
            pass

    if ollama_url:
        try:
            from langchain_community.chat_models import ChatOllama
            model = os.getenv("OLLAMA_MODEL", "llama3")
            return ChatOllama(model=model, base_url=ollama_url)
        except ImportError:
            pass

    return None
