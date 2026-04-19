"""
Vibe Hacking Agent — Streamlit web application.

Run with:
    streamlit run app.py
"""
from __future__ import annotations

import json
import os
import threading
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Vibe Hacking Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Imports (after path is set) ────────────────────────────────────────────────
from core.models import RunResult, ScanStatus, ScopeConfig, Severity
from core.evidence import list_runs, load_run, get_run_report_path, RUNS_DIR
from core.blocklist import is_blocklisted

# ── Colour palette for severities ─────────────────────────────────────────────
_SEV_COLOUR = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

# ── Session state helpers ─────────────────────────────────────────────────────

def _init_session():
    defaults = {
        "scan_running": False,
        "run_result": None,
        "progress_log": [],
        "report_markdown": "",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


_init_session()


# ══════════════════════════════════════════════════════════════════════════════
# Sidebar — Configuration
# ══════════════════════════════════════════════════════════════════════════════

def sidebar():
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/bug.png", width=64)
        st.title("⚙️ Configuration")

        # ── LLM status ────────────────────────────────────────────────────────
        llm_status = _detect_llm()
        if llm_status:
            st.success(f"LLM: {llm_status}", icon="🤖")
        else:
            st.info(
                "No LLM configured — running in **rule-based mode** "
                "(set OPENAI_API_KEY, ANTHROPIC_API_KEY, or OLLAMA_BASE_URL in `.env`).",
                icon="ℹ️",
            )

        st.divider()
        st.caption("Runs are saved to: `" + str(RUNS_DIR.resolve()) + "`")
        if st.button("🗂 View past runs", use_container_width=True):
            st.session_state["page"] = "history"


def _detect_llm() -> Optional[str]:
    if os.getenv("OPENAI_API_KEY"):
        return f"OpenAI ({os.getenv('OPENAI_MODEL', 'gpt-4o-mini')})"
    if os.getenv("ANTHROPIC_API_KEY"):
        return f"Anthropic ({os.getenv('ANTHROPIC_MODEL', 'claude-3-haiku-20240307')})"
    if os.getenv("OLLAMA_BASE_URL"):
        return f"Ollama ({os.getenv('OLLAMA_MODEL', 'llama3')})"
    return None


# ══════════════════════════════════════════════════════════════════════════════
# Main page — New Scan
# ══════════════════════════════════════════════════════════════════════════════

def page_new_scan():
    st.title("🛡️ Vibe Hacking Agent")
    st.markdown(
        "> **Autonomous multi-agent red-team testing service** — "
        "passive-first, authorization-gated, evidence-capturing."
    )

    # ── Safety notice ─────────────────────────────────────────────────────────
    with st.expander("⚠️ Safety & Legal Notice", expanded=True):
        st.warning(
            "**This tool is for authorized testing only.**\n\n"
            "- You must own the target system or hold **written permission** from its owner.\n"
            "- Unauthorized scanning is illegal in most jurisdictions.\n"
            "- Government, military, and critical-infrastructure targets are hard-blocked.\n"
            "- All actions are logged with timestamps for accountability.",
            icon="⚠️",
        )

    st.divider()

    # ── Authorization & Scope ─────────────────────────────────────────────────
    st.header("1️⃣ Authorization & Scope")

    authorized = st.checkbox(
        "✅ I own this system or have **written permission** to test it.",
        value=False,
        key="authorized",
    )

    col1, col2 = st.columns(2)

    with col1:
        target = st.text_input(
            "🎯 Primary target (domain or IP)",
            placeholder="example.com",
            key="target_input",
        )
        targets_raw = st.text_area(
            "📋 All in-scope targets (one per line)",
            placeholder="example.com\n192.168.1.0/24\napi.example.com",
            height=100,
            key="targets_raw",
        )
        excluded_raw = st.text_area(
            "🚫 Excluded targets (one per line, optional)",
            placeholder="legacy.example.com",
            height=80,
            key="excluded_raw",
        )

    with col2:
        authorization_note = st.text_area(
            "📝 Authorization note (who authorized this test)",
            placeholder="I am the system owner.  Company: Acme Corp.  Contact: security@acme.com",
            height=100,
            key="auth_note",
        )
        allowed_hours = st.text_input(
            "🕐 Allowed testing hours (optional)",
            placeholder="09:00-17:00 UTC",
            key="allowed_hours",
        )
        test_intensity = st.selectbox(
            "📊 Test intensity",
            options=["low", "medium", "high"],
            index=0,
            key="intensity",
            help="low: minimal footprint | medium: standard | high: more thorough",
        )

    st.divider()

    # ── Active testing ────────────────────────────────────────────────────────
    st.header("2️⃣ Active Testing (optional)")
    st.info(
        "**Default: Passive recon only** (DNS, HTTP headers, TLS, robots.txt, tech fingerprinting).\n\n"
        "Enable active testing for port scanning, directory fuzzing, and configuration probes. "
        "Requires nmap to be installed for port scanning.",
        icon="ℹ️",
    )

    active_testing = st.checkbox(
        "🔓 Enable active testing (port scan, directory fuzz, config checks)",
        value=False,
        key="active_testing",
    )

    if active_testing:
        st.warning(
            "Active testing sends probe packets to the target.  "
            "Ensure you have explicit written authorization before proceeding.",
            icon="⚠️",
        )

    st.divider()

    # ── Blocklist preview ─────────────────────────────────────────────────────
    if target:
        blocked, reason = is_blocklisted(target)
        if blocked:
            st.error(f"🚫 Target `{target}` is on the hard blocklist: {reason}", icon="🚫")

    # ── Run button ────────────────────────────────────────────────────────────
    can_run = (
        authorized
        and bool(target)
        and not st.session_state.get("scan_running", False)
    )

    run_btn = st.button(
        "🚀 Start Assessment",
        disabled=not can_run,
        type="primary",
        use_container_width=True,
    )

    if not authorized and run_btn:
        st.error("You must check the authorization checkbox before running.", icon="🚫")

    if run_btn and can_run:
        _start_scan(
            target=target,
            targets_raw=targets_raw,
            excluded_raw=excluded_raw,
            authorization_note=authorization_note,
            allowed_hours=allowed_hours,
            test_intensity=test_intensity,
            active_testing=active_testing,
        )

    # ── Progress + Results ────────────────────────────────────────────────────
    if st.session_state.get("scan_running"):
        _show_running()

    result: Optional[RunResult] = st.session_state.get("run_result")
    if result is not None:
        _show_results(result)


def _start_scan(
    target: str,
    targets_raw: str,
    excluded_raw: str,
    authorization_note: str,
    allowed_hours: str,
    test_intensity: str,
    active_testing: bool,
) -> None:
    """Validate inputs and kick off the assessment synchronously (Streamlit friendly)."""
    from agents.graph import run_assessment

    # Build target list
    all_targets = [t.strip() for t in targets_raw.splitlines() if t.strip()]
    if target and target not in all_targets:
        all_targets.insert(0, target)
    if not all_targets:
        st.error("Please enter at least one target.", icon="🚫")
        return

    excluded = [t.strip() for t in excluded_raw.splitlines() if t.strip()]

    scope = ScopeConfig(
        targets=all_targets,
        excluded_targets=excluded,
        allowed_hours=allowed_hours or None,
        test_intensity=test_intensity,
        active_testing=active_testing,
        authorization_note=authorization_note or "Confirmed",
    )

    st.session_state["scan_running"] = True
    st.session_state["progress_log"] = []
    st.session_state["run_result"] = None

    progress_placeholder = st.empty()
    log_lines: List[str] = []

    def _progress(stage: str, message: str):
        log_lines.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {stage}: {message}")
        st.session_state["progress_log"] = log_lines.copy()

    try:
        with st.status("🔍 Assessment in progress…", expanded=True) as status:
            st.write("▶ Initializing agents…")

            result = run_assessment(
                target=target,
                scope=scope,
                authorization_confirmed=True,
                progress_callback=_progress,
            )

            if result.status == ScanStatus.BLOCKED:
                status.update(label="🚫 Scan blocked", state="error")
                st.error(result.error or "Scan was blocked.", icon="🚫")
            elif result.status == ScanStatus.COMPLETED:
                status.update(label="✅ Assessment complete!", state="complete")
            else:
                status.update(label="⚠️ Assessment finished with issues", state="error")

        st.session_state["run_result"] = result
        st.session_state["report_markdown"] = getattr(result, "_report_md", "")

    except Exception as exc:
        st.error(f"Unexpected error: {exc}", icon="❌")
        st.code(traceback.format_exc())
    finally:
        st.session_state["scan_running"] = False
        st.rerun()


def _show_running():
    st.info("🔄 Scan is running… please wait.", icon="⏳")
    log = st.session_state.get("progress_log", [])
    if log:
        st.code("\n".join(log[-20:]))


def _show_results(result: RunResult):
    st.divider()
    st.header("📊 Assessment Results")

    # Status badge
    status_icon = {
        ScanStatus.COMPLETED: "✅",
        ScanStatus.BLOCKED: "🚫",
        ScanStatus.FAILED: "❌",
        ScanStatus.RUNNING: "🔄",
        ScanStatus.PENDING: "⏳",
    }.get(result.status, "❓")

    col_a, col_b, col_c, col_d = st.columns(4)
    col_a.metric("Status", f"{status_icon} {result.status.value.upper()}")
    col_b.metric("Total Findings", len(result.findings))
    critical_high = sum(1 for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
    col_c.metric("Critical / High", critical_high)
    col_d.metric("Technologies", len(result.asset_inventory.technologies))

    if result.status == ScanStatus.BLOCKED:
        st.error(f"Scan was blocked: {result.error}", icon="🚫")
        return

    # Executive summary
    if result.executive_summary:
        st.subheader("📝 Executive Summary")
        st.markdown(result.executive_summary)

    # Findings table
    if result.findings:
        st.subheader("🔍 Findings")
        _show_findings_table(result)
    else:
        st.success("No security issues were identified during this assessment. ✅")

    # Asset inventory
    with st.expander("🗺 Asset Inventory"):
        inv = result.asset_inventory
        if inv.hosts:
            st.write("**Hosts:**", ", ".join(inv.hosts))
        if inv.technologies:
            st.write("**Technologies:**", ", ".join(inv.technologies))
        if inv.open_ports:
            st.write("**Open Ports:**")
            for host, ports in inv.open_ports.items():
                st.write(f"  `{host}`: {', '.join(str(p) for p in ports)}")
        if inv.endpoints:
            st.write(f"**Endpoints discovered:** {len(inv.endpoints)}")
            with st.expander("Show endpoints"):
                for ep in inv.endpoints[:50]:
                    st.write(f"- {ep}")

    # Audit log
    with st.expander("📜 Audit Log"):
        for entry in result.audit_log:
            ts = entry.timestamp.strftime("%H:%M:%S")
            st.write(f"**{ts} — {entry.agent}**: {entry.action}")
            if entry.command:
                st.code(entry.command, language="bash")
            if entry.output:
                st.text(entry.output[:300] + ("…" if len(entry.output) > 300 else ""))

    # Report download
    st.subheader("💾 Download Report")
    report_path = result.report_path
    if report_path and Path(report_path).exists():
        md_text = Path(report_path).read_text(encoding="utf-8")
        st.download_button(
            label="⬇️ Download Markdown Report",
            data=md_text,
            file_name=f"vibe_hacking_report_{result.run_id[:8]}.md",
            mime="text/markdown",
            use_container_width=True,
        )

    json_data = result.model_dump_json(indent=2)
    st.download_button(
        label="⬇️ Download JSON Artefact",
        data=json_data,
        file_name=f"vibe_hacking_result_{result.run_id[:8]}.json",
        mime="application/json",
        use_container_width=True,
    )


def _show_findings_table(result: RunResult):
    """Render findings as expandable cards grouped by severity."""
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

    for sev in severity_order:
        group = [f for f in result.findings if f.severity == sev]
        if not group:
            continue
        icon = _SEV_COLOUR.get(sev.value, "")
        st.markdown(f"#### {icon} {sev.value} ({len(group)})")
        for finding in group:
            with st.expander(f"{icon} {finding.title} — `{finding.affected_asset}`"):
                col1, col2 = st.columns(2)
                col1.write(f"**Severity:** {finding.severity.value}")
                col1.write(f"**Confidence:** {finding.confidence.value}")
                col2.write(f"**Tool:** {finding.tool}")
                col2.write(f"**Agent:** {finding.agent}")
                st.markdown("**Description:**")
                st.write(finding.description)
                st.markdown("**Evidence:**")
                st.code(finding.evidence)
                st.markdown("**Remediation:**")
                st.info(finding.remediation)


# ══════════════════════════════════════════════════════════════════════════════
# History page
# ══════════════════════════════════════════════════════════════════════════════

def page_history():
    st.title("🗂 Past Runs")
    if st.button("← Back to New Scan"):
        st.session_state["page"] = "new_scan"
        st.rerun()

    run_ids = list_runs()
    if not run_ids:
        st.info("No past runs found.")
        return

    for run_id in run_ids[:20]:
        try:
            r = load_run(run_id)
            icon = _SEV_COLOUR.get("HIGH", "") if any(
                f.severity.value in ("CRITICAL", "HIGH") for f in r.findings
            ) else "✅"
            label = (
                f"{icon} **{r.target}** — "
                f"{r.started_at.strftime('%Y-%m-%d %H:%M')} UTC — "
                f"{r.status.value} — "
                f"{len(r.findings)} finding(s)"
            )
            with st.expander(label):
                st.write(f"**Run ID:** `{r.run_id}`")
                st.write(f"**Mode:** {'Active + Passive' if r.scope.active_testing else 'Passive only'}")
                if r.executive_summary:
                    st.write(r.executive_summary)

                report_path = get_run_report_path(r.run_id)
                if report_path:
                    md_text = report_path.read_text(encoding="utf-8")
                    st.download_button(
                        f"⬇️ Download Report",
                        data=md_text,
                        file_name=f"report_{run_id[:8]}.md",
                        mime="text/markdown",
                        key=f"dl_md_{run_id}",
                    )
                st.download_button(
                    f"⬇️ Download JSON",
                    data=r.model_dump_json(indent=2),
                    file_name=f"result_{run_id[:8]}.json",
                    mime="application/json",
                    key=f"dl_json_{run_id}",
                )
        except Exception as exc:
            st.warning(f"Could not load run `{run_id}`: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
# Router
# ══════════════════════════════════════════════════════════════════════════════

def main():
    sidebar()
    page = st.session_state.get("page", "new_scan")
    if page == "history":
        page_history()
    else:
        page_new_scan()


if __name__ == "__main__":
    main()
else:
    # Streamlit calls the module-level code; call main() to render
    main()
