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
from datetime import datetime, timezone
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

_SEV_HEX = {
    "CRITICAL": "#ff4757",
    "HIGH":     "#ff6b35",
    "MEDIUM":   "#ffd32a",
    "LOW":      "#2ed573",
    "INFO":     "#747d8c",
}

# ── Premium CSS injection ──────────────────────────────────────────────────────

def _inject_css():
    st.markdown(
        """
<style>
/* ── Google Font ─────────────────────────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Root variables ──────────────────────────────────────────────────── */
:root {
  --bg-primary:    #0a0e1a;
  --bg-secondary:  #0d1117;
  --bg-card:       #161b27;
  --bg-card-hover: #1a2133;
  --border:        #21262d;
  --border-glow:   rgba(0, 217, 255, 0.25);
  --accent:        #00d9ff;
  --accent-dim:    rgba(0, 217, 255, 0.12);
  --accent-green:  #00ff88;
  --text-primary:  #e6edf3;
  --text-secondary:#8b949e;
  --text-muted:    #484f58;
  --critical:      #ff4757;
  --high:          #ff6b35;
  --medium:        #ffd32a;
  --low:           #2ed573;
  --info:          #747d8c;
  --radius:        12px;
  --radius-sm:     8px;
  --shadow:        0 4px 24px rgba(0,0,0,0.4);
  --shadow-glow:   0 0 24px rgba(0, 217, 255, 0.15);
}

/* ── Global ──────────────────────────────────────────────────────────── */
html, body, [class*="css"] {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
  color: var(--text-primary) !important;
}

.stApp {
  background: var(--bg-primary) !important;
}

/* ── Hide default Streamlit branding ─────────────────────────────────── */
#MainMenu, footer, header { visibility: hidden; }
.stDeployButton { display: none; }

/* ── Sidebar ─────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
  background: var(--bg-secondary) !important;
  border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] > div:first-child {
  padding-top: 1.5rem;
}
[data-testid="stSidebarContent"] {
  background: transparent !important;
}

/* ── Main content area ───────────────────────────────────────────────── */
.main .block-container {
  padding: 1.5rem 2.5rem 3rem 2.5rem !important;
  max-width: 1200px !important;
}

/* ── Typography ──────────────────────────────────────────────────────── */
h1 { font-size: 2.4rem !important; font-weight: 800 !important; letter-spacing: -0.02em !important; }
h2 { font-size: 1.6rem !important; font-weight: 700 !important; }
h3 { font-size: 1.2rem !important; font-weight: 600 !important; }

/* ── Buttons ─────────────────────────────────────────────────────────── */
.stButton > button {
  font-family: 'Inter', sans-serif !important;
  font-weight: 600 !important;
  letter-spacing: 0.01em !important;
  border-radius: var(--radius-sm) !important;
  transition: all 0.2s ease !important;
  border: 1px solid var(--border) !important;
  background: var(--bg-card) !important;
  color: var(--text-primary) !important;
}
.stButton > button:hover {
  border-color: var(--accent) !important;
  background: var(--accent-dim) !important;
  color: var(--accent) !important;
  box-shadow: var(--shadow-glow) !important;
  transform: translateY(-1px) !important;
}
/* Primary (type="primary") button */
.stButton > button[kind="primary"],
div[data-testid="stFormSubmitButton"] > button {
  background: linear-gradient(135deg, #00d9ff 0%, #0099cc 100%) !important;
  color: #0a0e1a !important;
  border: none !important;
  font-weight: 700 !important;
}
.stButton > button[kind="primary"]:hover,
div[data-testid="stFormSubmitButton"] > button:hover {
  background: linear-gradient(135deg, #33e5ff 0%, #00b3ee 100%) !important;
  color: #0a0e1a !important;
  box-shadow: 0 0 32px rgba(0,217,255,0.35) !important;
  transform: translateY(-2px) !important;
}
.stButton > button:disabled {
  opacity: 0.35 !important;
  transform: none !important;
  cursor: not-allowed !important;
}

/* ── Text inputs & text areas ────────────────────────────────────────── */
.stTextInput > div > div > input,
.stTextArea > div > div > textarea,
.stSelectbox > div > div {
  background: var(--bg-card) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius-sm) !important;
  color: var(--text-primary) !important;
  font-family: 'Inter', sans-serif !important;
  transition: border-color 0.2s ease !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
  border-color: var(--accent) !important;
  box-shadow: 0 0 0 3px var(--accent-dim) !important;
  outline: none !important;
}
.stTextInput label, .stTextArea label, .stSelectbox label {
  font-weight: 500 !important;
  font-size: 0.875rem !important;
  color: var(--text-secondary) !important;
  letter-spacing: 0.01em !important;
}

/* ── Selectbox ───────────────────────────────────────────────────────── */
.stSelectbox > div > div {
  cursor: pointer !important;
}
.stSelectbox > div > div:hover {
  border-color: var(--accent) !important;
}

/* ── Checkbox ────────────────────────────────────────────────────────── */
.stCheckbox > label {
  font-weight: 500 !important;
  color: var(--text-primary) !important;
  gap: 0.5rem !important;
}
.stCheckbox > label > span[data-testid="stMarkdownContainer"] {
  font-size: 0.95rem !important;
}

/* ── Dividers ────────────────────────────────────────────────────────── */
hr {
  border: none !important;
  border-top: 1px solid var(--border) !important;
  margin: 1.5rem 0 !important;
}

/* ── Metric cards ────────────────────────────────────────────────────── */
[data-testid="stMetric"] {
  background: var(--bg-card) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius) !important;
  padding: 1.25rem 1.5rem !important;
  transition: border-color 0.2s ease !important;
}
[data-testid="stMetric"]:hover {
  border-color: var(--accent) !important;
  box-shadow: var(--shadow-glow) !important;
}
[data-testid="stMetricLabel"] {
  font-size: 0.8rem !important;
  font-weight: 600 !important;
  text-transform: uppercase !important;
  letter-spacing: 0.08em !important;
  color: var(--text-secondary) !important;
}
[data-testid="stMetricValue"] {
  font-size: 2rem !important;
  font-weight: 700 !important;
  color: var(--text-primary) !important;
}

/* ── Expanders ───────────────────────────────────────────────────────── */
[data-testid="stExpander"] {
  background: var(--bg-card) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius) !important;
  margin-bottom: 0.5rem !important;
  overflow: hidden !important;
  transition: border-color 0.2s ease !important;
}
[data-testid="stExpander"]:hover {
  border-color: rgba(0,217,255,0.4) !important;
}
[data-testid="stExpander"] > details > summary {
  padding: 0.875rem 1.25rem !important;
  font-weight: 600 !important;
  cursor: pointer !important;
  color: var(--text-primary) !important;
}
[data-testid="stExpander"] > details > div {
  padding: 0 1.25rem 1.25rem !important;
  border-top: 1px solid var(--border) !important;
}

/* ── Alerts / Info / Warning / Error ─────────────────────────────────── */
[data-testid="stAlert"] {
  border-radius: var(--radius) !important;
  border: 1px solid !important;
  font-size: 0.9rem !important;
}
div[data-testid="stNotification"][kind="info"],
[data-baseweb="notification"][kind="info"] {
  background: rgba(0,217,255,0.06) !important;
  border-color: rgba(0,217,255,0.3) !important;
}
div[data-testid="stNotification"][kind="warning"],
[data-baseweb="notification"][kind="warning"] {
  background: rgba(255,211,42,0.06) !important;
  border-color: rgba(255,211,42,0.3) !important;
}
div[data-testid="stNotification"][kind="error"],
[data-baseweb="notification"][kind="error"] {
  background: rgba(255,71,87,0.06) !important;
  border-color: rgba(255,71,87,0.3) !important;
}
div[data-testid="stNotification"][kind="success"],
[data-baseweb="notification"][kind="success"] {
  background: rgba(0,255,136,0.06) !important;
  border-color: rgba(0,255,136,0.3) !important;
}

/* ── Code blocks ─────────────────────────────────────────────────────── */
.stCodeBlock, pre, code {
  font-family: 'JetBrains Mono', 'Fira Code', monospace !important;
  background: #0d1117 !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius-sm) !important;
  font-size: 0.82rem !important;
}

/* ── Status widget ───────────────────────────────────────────────────── */
[data-testid="stStatusWidget"] {
  background: var(--bg-card) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius) !important;
}

/* ── Download button ─────────────────────────────────────────────────── */
[data-testid="stDownloadButton"] > button {
  background: var(--bg-card) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius-sm) !important;
  color: var(--accent) !important;
  font-weight: 600 !important;
  transition: all 0.2s ease !important;
}
[data-testid="stDownloadButton"] > button:hover {
  background: var(--accent-dim) !important;
  border-color: var(--accent) !important;
  box-shadow: var(--shadow-glow) !important;
  transform: translateY(-1px) !important;
}

/* ── Caption ─────────────────────────────────────────────────────────── */
.stCaption, [data-testid="stCaptionContainer"] {
  color: var(--text-muted) !important;
  font-size: 0.78rem !important;
}

/* ── Scrollbar ───────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-secondary); }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent); }

/* ── Custom utility classes (used via unsafe_allow_html) ─────────────── */
.vha-hero {
  background: linear-gradient(135deg, #0d1117 0%, #0a1628 50%, #0d1117 100%);
  border: 1px solid var(--border);
  border-top: 3px solid var(--accent);
  border-radius: var(--radius);
  padding: 2.5rem 2rem 2rem;
  margin-bottom: 1.5rem;
  position: relative;
  overflow: hidden;
}
.vha-hero::before {
  content: '';
  position: absolute;
  top: -50%;
  right: -20%;
  width: 400px;
  height: 400px;
  background: radial-gradient(circle, rgba(0,217,255,0.05) 0%, transparent 70%);
  pointer-events: none;
}
.vha-hero h1 {
  font-size: 2.4rem !important;
  font-weight: 800 !important;
  letter-spacing: -0.03em !important;
  background: linear-gradient(135deg, #ffffff 30%, #00d9ff 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin: 0 0 0.5rem 0 !important;
}
.vha-hero p {
  color: var(--text-secondary);
  font-size: 1rem;
  margin: 0;
  line-height: 1.6;
}
.vha-hero .badge {
  display: inline-block;
  background: var(--accent-dim);
  border: 1px solid rgba(0,217,255,0.3);
  color: var(--accent);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  padding: 0.2rem 0.65rem;
  border-radius: 999px;
  margin-bottom: 1rem;
}

.vha-section-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin: 1.5rem 0 1rem;
}
.vha-section-header .step-badge {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 2rem;
  height: 2rem;
  border-radius: 50%;
  background: var(--accent-dim);
  border: 1px solid rgba(0,217,255,0.4);
  color: var(--accent);
  font-size: 0.8rem;
  font-weight: 700;
  flex-shrink: 0;
}
.vha-section-header h2 {
  margin: 0 !important;
  font-size: 1.15rem !important;
  font-weight: 700 !important;
  color: var(--text-primary) !important;
}

.vha-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.5rem;
  margin-bottom: 1rem;
}
.vha-card-accent {
  border-top: 3px solid var(--accent);
}

.vha-finding-card {
  border-left: 4px solid;
  border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
  background: var(--bg-card);
  border-top: 1px solid var(--border);
  border-right: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
  padding: 0.9rem 1.1rem;
  margin-bottom: 0.4rem;
  transition: background 0.2s ease;
}
.vha-finding-card:hover { background: var(--bg-card-hover); }

.sev-badge {
  display: inline-block;
  padding: 0.15rem 0.6rem;
  border-radius: 999px;
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}
.sev-CRITICAL { background: rgba(255,71,87,0.18); color: #ff4757; border: 1px solid rgba(255,71,87,0.4); }
.sev-HIGH     { background: rgba(255,107,53,0.18); color: #ff6b35; border: 1px solid rgba(255,107,53,0.4); }
.sev-MEDIUM   { background: rgba(255,211,42,0.15); color: #ffd32a; border: 1px solid rgba(255,211,42,0.4); }
.sev-LOW      { background: rgba(46,213,115,0.15); color: #2ed573; border: 1px solid rgba(46,213,115,0.4); }
.sev-INFO     { background: rgba(116,125,140,0.18); color: #a4b0be; border: 1px solid rgba(116,125,140,0.4); }

.vha-terminal {
  background: #050810;
  border: 1px solid #21262d;
  border-radius: var(--radius-sm);
  padding: 1rem 1.25rem;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.8rem;
  color: #00ff88;
  line-height: 1.7;
  max-height: 300px;
  overflow-y: auto;
}
.vha-terminal .ts { color: #484f58; margin-right: 0.5rem; }
.vha-terminal .stage { color: #00d9ff; margin-right: 0.5rem; }

.vha-stat-row {
  display: flex;
  gap: 1rem;
  margin-bottom: 1rem;
  flex-wrap: wrap;
}
.vha-stat {
  flex: 1;
  min-width: 140px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 1.25rem 1.5rem;
  text-align: center;
  transition: border-color 0.2s ease, box-shadow 0.2s ease;
}
.vha-stat:hover {
  border-color: var(--accent);
  box-shadow: var(--shadow-glow);
}
.vha-stat .val {
  font-size: 2rem;
  font-weight: 800;
  letter-spacing: -0.02em;
  line-height: 1;
  margin-bottom: 0.35rem;
}
.vha-stat .lbl {
  font-size: 0.72rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--text-secondary);
}

.vha-sidebar-logo {
  text-align: center;
  padding: 0.5rem 1rem 1rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 1rem;
}
.vha-sidebar-logo .brand {
  font-size: 1.1rem;
  font-weight: 800;
  letter-spacing: -0.01em;
  color: var(--text-primary);
}
.vha-sidebar-logo .brand span { color: var(--accent); }
.vha-sidebar-logo .sub {
  font-size: 0.7rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-top: 0.2rem;
}
.vha-llm-badge {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: rgba(0,255,136,0.07);
  border: 1px solid rgba(0,255,136,0.25);
  border-radius: var(--radius-sm);
  padding: 0.55rem 0.85rem;
  font-size: 0.8rem;
  font-weight: 600;
  color: #00ff88;
  margin-bottom: 1rem;
}
.vha-llm-badge-none {
  background: rgba(116,125,140,0.1);
  border: 1px solid rgba(116,125,140,0.25);
  color: var(--text-secondary);
}
.dot-live {
  width: 8px; height: 8px; border-radius: 50%;
  background: #00ff88;
  box-shadow: 0 0 6px #00ff88;
  flex-shrink: 0;
  animation: pulse-dot 2s ease-in-out infinite;
}
@keyframes pulse-dot {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.4; }
}

.vha-notice {
  background: rgba(255,211,42,0.06);
  border: 1px solid rgba(255,211,42,0.25);
  border-radius: var(--radius);
  padding: 1rem 1.25rem;
  font-size: 0.875rem;
  color: #e6edf3;
  line-height: 1.7;
}
.vha-notice .notice-title {
  font-weight: 700;
  color: #ffd32a;
  margin-bottom: 0.4rem;
  font-size: 0.9rem;
}
.vha-notice ul { margin: 0; padding-left: 1.2rem; }
.vha-notice ul li { margin-bottom: 0.2rem; color: #8b949e; }

.vha-blocked {
  background: rgba(255,71,87,0.08);
  border: 1px solid rgba(255,71,87,0.35);
  border-radius: var(--radius-sm);
  padding: 0.75rem 1rem;
  color: #ff4757;
  font-weight: 600;
  font-size: 0.875rem;
}

.vha-summary-box {
  background: rgba(0,217,255,0.05);
  border: 1px solid rgba(0,217,255,0.2);
  border-radius: var(--radius);
  padding: 1.25rem 1.5rem;
  font-size: 0.9rem;
  line-height: 1.8;
  color: var(--text-primary);
}
</style>
""",
        unsafe_allow_html=True,
    )

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
_inject_css()


# ══════════════════════════════════════════════════════════════════════════════
# Sidebar — Configuration
# ══════════════════════════════════════════════════════════════════════════════

def sidebar():
    with st.sidebar:
        # Brand header
        st.markdown(
            """
<div class="vha-sidebar-logo">
  <div style="font-size:2rem;margin-bottom:0.4rem">🛡️</div>
  <div class="brand">Vibe <span>Hacking</span> Agent</div>
  <div class="sub">Autonomous Red-Team Platform</div>
</div>
""",
            unsafe_allow_html=True,
        )

        # ── LLM status ────────────────────────────────────────────────────────
        llm_status = _detect_llm()
        if llm_status:
            st.markdown(
                f'<div class="vha-llm-badge"><div class="dot-live"></div>{llm_status}</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="vha-llm-badge vha-llm-badge-none">⚡ Rule-based mode</div>',
                unsafe_allow_html=True,
            )
            st.caption(
                "Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or OLLAMA_BASE_URL in `.env` to enable LLM."
            )

        st.divider()

        st.caption("💾 Runs stored at:")
        st.code(str(RUNS_DIR.resolve()), language=None)

        st.divider()

        if st.button("🗂  View Past Runs", use_container_width=True):
            st.session_state["page"] = "history"
            st.rerun()

        page = st.session_state.get("page", "new_scan")
        if page == "history":
            if st.button("＋  New Scan", use_container_width=True):
                st.session_state["page"] = "new_scan"
                st.rerun()

        st.divider()

        # Quick-help accordion
        with st.expander("❓ Quick Help"):
            st.markdown(
                """
**Passive mode** (default):
- DNS enumeration
- HTTP header analysis
- TLS certificate inspection
- Technology fingerprinting

**Active mode** (opt-in):
- Port scanning (nmap)
- Directory fuzzing
- Configuration probes

All runs are saved locally for audit purposes.
"""
            )


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

# ══════════════════════════════════════════════════════════════════════════════
# Main page — New Scan
# ══════════════════════════════════════════════════════════════════════════════

def page_new_scan():
    # ── Hero banner ───────────────────────────────────────────────────────────
    st.markdown(
        """
<div class="vha-hero">
  <div class="badge">🛡️ Autonomous Red-Team Platform</div>
  <h1>Vibe Hacking Agent</h1>
  <p>Passive-first, authorization-gated, evidence-capturing security assessments — powered by multi-agent AI.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    # ── Safety notice ─────────────────────────────────────────────────────────
    st.markdown(
        """
<div class="vha-notice">
  <div class="notice-title">⚠️ Safety &amp; Legal Notice</div>
  <ul>
    <li>You must <strong>own</strong> the target system or hold <strong>written permission</strong> from its owner.</li>
    <li>Unauthorized scanning is <strong>illegal</strong> in most jurisdictions.</li>
    <li>Government, military, and critical-infrastructure targets are <strong>hard-blocked</strong>.</li>
    <li>All actions are <strong>logged with timestamps</strong> for accountability.</li>
  </ul>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("<div style='margin-top:1.5rem'></div>", unsafe_allow_html=True)

    # ── Section 1: Authorization & Scope ──────────────────────────────────────
    st.markdown(
        """
<div class="vha-section-header">
  <div class="step-badge">1</div>
  <h2>Authorization &amp; Scope</h2>
</div>
""",
        unsafe_allow_html=True,
    )

    authorized = st.checkbox(
        "✅  I own this system or have **written permission** to test it.",
        value=False,
        key="authorized",
    )

    col1, col2 = st.columns(2, gap="medium")

    with col1:
        target = st.text_input(
            "🎯 Primary target (domain or IP)",
            placeholder="example.com",
            key="target_input",
        )
        targets_raw = st.text_area(
            "📋 All in-scope targets (one per line)",
            placeholder="example.com\n192.168.1.0/24\napi.example.com",
            height=110,
            key="targets_raw",
        )
        excluded_raw = st.text_area(
            "🚫 Excluded targets (one per line, optional)",
            placeholder="legacy.example.com",
            height=85,
            key="excluded_raw",
        )

    with col2:
        authorization_note = st.text_area(
            "📝 Authorization note",
            placeholder="I am the system owner.  Company: Acme Corp.  Contact: security@acme.com",
            height=110,
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

    # ── Section 2: Active Testing ─────────────────────────────────────────────
    st.markdown(
        """
<div class="vha-section-header">
  <div class="step-badge">2</div>
  <h2>Active Testing <span style="font-weight:400;color:#8b949e">(optional)</span></h2>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown(
        """
<div style="background:rgba(0,217,255,0.05);border:1px solid rgba(0,217,255,0.18);
border-radius:8px;padding:0.85rem 1rem;margin-bottom:1rem;font-size:0.875rem;color:#8b949e;line-height:1.7">
  <strong style="color:#e6edf3">Default: Passive recon only</strong> — DNS, HTTP headers, TLS, robots.txt, tech fingerprinting.<br>
  Enable active testing for port scanning, directory fuzzing, and configuration probes.
  Requires <code>nmap</code> for port scanning.
</div>
""",
        unsafe_allow_html=True,
    )

    active_testing = st.checkbox(
        "🔓  Enable active testing (port scan, directory fuzz, config checks)",
        value=False,
        key="active_testing",
    )

    if active_testing:
        st.markdown(
            '<div style="background:rgba(255,211,42,0.07);border:1px solid rgba(255,211,42,0.3);'
            'border-radius:8px;padding:0.75rem 1rem;font-size:0.85rem;color:#ffd32a;margin-top:0.5rem">'
            '⚠️ Active testing sends probe packets to the target. Ensure you have explicit written authorization.</div>',
            unsafe_allow_html=True,
        )

    st.divider()

    # ── Blocklist preview ─────────────────────────────────────────────────────
    if target:
        blocked, reason = is_blocklisted(target)
        if blocked:
            st.markdown(
                f'<div class="vha-blocked">🚫 Target <code>{target}</code> is on the hard blocklist: {reason}</div>',
                unsafe_allow_html=True,
            )

    # ── Run button ────────────────────────────────────────────────────────────
    can_run = (
        authorized
        and bool(target)
        and not st.session_state.get("scan_running", False)
    )

    run_btn = st.button(
        "🚀  Launch Security Assessment",
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
        log_lines.append(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {stage}: {message}")
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
    st.markdown(
        '<div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.75rem">'
        '<div class="dot-live"></div>'
        '<span style="font-weight:600;color:#00d9ff">Assessment in progress — please wait…</span>'
        "</div>",
        unsafe_allow_html=True,
    )
    log = st.session_state.get("progress_log", [])
    if log:
        lines_html = ""
        for line in log[-20:]:
            # Format: [HH:MM:SS] STAGE: message
            parts = line.split("] ", 1)
            if len(parts) == 2:
                ts = parts[0].lstrip("[")
                rest = parts[1]
                stage_parts = rest.split(": ", 1)
                if len(stage_parts) == 2:
                    stage, msg = stage_parts
                    lines_html += (
                        f'<span class="ts">[{ts}]</span>'
                        f'<span class="stage">{stage}:</span>'
                        f'{msg}\n'
                    )
                else:
                    lines_html += f'<span class="ts">[{ts}]</span>{rest}\n'
            else:
                lines_html += f"{line}\n"
        st.markdown(
            f'<div class="vha-terminal">{lines_html}</div>',
            unsafe_allow_html=True,
        )


def _show_results(result: RunResult):
    st.divider()

    # Section header
    st.markdown(
        '<div class="vha-section-header" style="margin-top:0">'
        '<div class="step-badge">✓</div>'
        '<h2>Assessment Results</h2>'
        '</div>',
        unsafe_allow_html=True,
    )

    # Status / metrics row
    status_label = {
        ScanStatus.COMPLETED: "✅ Completed",
        ScanStatus.BLOCKED:   "🚫 Blocked",
        ScanStatus.FAILED:    "❌ Failed",
        ScanStatus.RUNNING:   "🔄 Running",
        ScanStatus.PENDING:   "⏳ Pending",
    }.get(result.status, "❓ Unknown")

    critical_high = sum(
        1 for f in result.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    duration = ""
    if result.completed_at and result.started_at:
        secs = int((result.completed_at - result.started_at).total_seconds())
        duration = f"{secs // 60}m {secs % 60}s"

    st.markdown(
        f"""
<div class="vha-stat-row">
  <div class="vha-stat">
    <div class="val" style="font-size:1.2rem">{status_label}</div>
    <div class="lbl">Status</div>
  </div>
  <div class="vha-stat">
    <div class="val">{len(result.findings)}</div>
    <div class="lbl">Total Findings</div>
  </div>
  <div class="vha-stat">
    <div class="val" style="color:{'#ff4757' if critical_high > 0 else '#2ed573'}">{critical_high}</div>
    <div class="lbl">Critical / High</div>
  </div>
  <div class="vha-stat">
    <div class="val">{len(result.asset_inventory.technologies)}</div>
    <div class="lbl">Technologies</div>
  </div>
  {f'<div class="vha-stat"><div class="val" style="font-size:1.3rem">{duration}</div><div class="lbl">Duration</div></div>' if duration else ''}
</div>
""",
        unsafe_allow_html=True,
    )

    if result.status == ScanStatus.BLOCKED:
        st.markdown(
            f'<div class="vha-blocked">🚫 Scan was blocked: {result.error}</div>',
            unsafe_allow_html=True,
        )
        return

    # Executive summary
    if result.executive_summary:
        st.markdown(
            '<p style="font-weight:600;font-size:0.85rem;text-transform:uppercase;'
            'letter-spacing:0.08em;color:#8b949e;margin-bottom:0.5rem">📝 Executive Summary</p>',
            unsafe_allow_html=True,
        )
        st.markdown(
            f'<div class="vha-summary-box">{result.executive_summary}</div>',
            unsafe_allow_html=True,
        )
        st.markdown("<div style='margin-top:1rem'></div>", unsafe_allow_html=True)

    # Findings
    if result.findings:
        st.markdown(
            '<p style="font-weight:700;font-size:1rem;margin-bottom:0.75rem">🔍 Security Findings</p>',
            unsafe_allow_html=True,
        )
        _show_findings_table(result)
    else:
        st.markdown(
            '<div style="background:rgba(0,255,136,0.07);border:1px solid rgba(0,255,136,0.25);'
            'border-radius:8px;padding:1rem 1.25rem;color:#00ff88;font-weight:600">'
            '✅ No security issues were identified during this assessment.</div>',
            unsafe_allow_html=True,
        )

    st.markdown("<div style='margin-top:1rem'></div>", unsafe_allow_html=True)

    # Asset inventory
    with st.expander("🗺  Asset Inventory"):
        inv = result.asset_inventory
        if inv.hosts:
            st.markdown(
                f"**Hosts:** {', '.join(f'`{h}`' for h in inv.hosts)}"
            )
        if inv.technologies:
            tech_badges = " ".join(
                f'<span style="background:#1a2133;border:1px solid #21262d;border-radius:999px;'
                f'padding:0.15rem 0.6rem;font-size:0.75rem;color:#8b949e;margin-right:0.2rem">{t}</span>'
                for t in inv.technologies
            )
            st.markdown("**Technologies:**", unsafe_allow_html=False)
            st.markdown(tech_badges, unsafe_allow_html=True)
        if inv.open_ports:
            st.markdown("**Open Ports:**")
            for host, ports in inv.open_ports.items():
                st.markdown(f"&nbsp;&nbsp;`{host}`: {', '.join(str(p) for p in ports)}")
        if inv.endpoints:
            st.markdown(f"**Endpoints discovered:** {len(inv.endpoints)}")
            with st.expander("Show endpoints"):
                for ep in inv.endpoints[:50]:
                    st.markdown(f"- `{ep}`")

    # Audit log
    with st.expander("📜  Audit Log"):
        for entry in result.audit_log:
            ts = entry.timestamp.strftime("%H:%M:%S")
            st.markdown(
                f'<div style="padding:0.4rem 0;border-bottom:1px solid #21262d">'
                f'<span style="color:#484f58;font-family:monospace;font-size:0.8rem">[{ts}]</span> '
                f'<span style="color:#00d9ff;font-weight:600;font-size:0.85rem">{entry.agent}</span>'
                f'<span style="color:#8b949e;font-size:0.85rem"> — {entry.action}</span></div>',
                unsafe_allow_html=True,
            )
            if entry.command:
                st.code(entry.command, language="bash")
            if entry.output:
                st.text(entry.output[:300] + ("…" if len(entry.output) > 300 else ""))

    # Downloads
    st.markdown(
        '<p style="font-weight:700;font-size:1rem;margin:1.25rem 0 0.75rem">💾 Export Report</p>',
        unsafe_allow_html=True,
    )
    dl_col1, dl_col2 = st.columns(2, gap="medium")
    report_path = result.report_path
    if report_path and Path(report_path).exists():
        md_text = Path(report_path).read_text(encoding="utf-8")
        dl_col1.download_button(
            label="⬇️  Download Markdown Report",
            data=md_text,
            file_name=f"vibe_hacking_report_{result.run_id[:8]}.md",
            mime="text/markdown",
            use_container_width=True,
        )

    json_data = result.model_dump_json(indent=2)
    dl_col2.download_button(
        label="⬇️  Download JSON Artefact",
        data=json_data,
        file_name=f"vibe_hacking_result_{result.run_id[:8]}.json",
        mime="application/json",
        use_container_width=True,
    )


def _show_findings_table(result: RunResult):
    """Render findings as styled expandable cards grouped by severity."""
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

    for sev in severity_order:
        group = [f for f in result.findings if f.severity == sev]
        if not group:
            continue
        hex_col = _SEV_HEX.get(sev.value, "#747d8c")
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:0.6rem;margin:1rem 0 0.5rem">'
            f'<span class="sev-badge sev-{sev.value}">{sev.value}</span>'
            f'<span style="color:#8b949e;font-size:0.85rem">{len(group)} finding{"s" if len(group) != 1 else ""}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )
        for finding in group:
            with st.expander(f"{finding.title}  ·  {finding.affected_asset}"):
                meta_col1, meta_col2 = st.columns(2)
                with meta_col1:
                    st.markdown(
                        f'<span class="sev-badge sev-{finding.severity.value}">{finding.severity.value}</span>'
                        f'&nbsp;&nbsp;<span style="color:#8b949e;font-size:0.82rem">Confidence: '
                        f'<strong style="color:#e6edf3">{finding.confidence.value}</strong></span>',
                        unsafe_allow_html=True,
                    )
                with meta_col2:
                    st.markdown(
                        f'<span style="color:#8b949e;font-size:0.82rem">Tool: '
                        f'<strong style="color:#e6edf3">{finding.tool}</strong></span>'
                        f'&nbsp; · &nbsp;'
                        f'<span style="color:#8b949e;font-size:0.82rem">Agent: '
                        f'<strong style="color:#e6edf3">{finding.agent}</strong></span>',
                        unsafe_allow_html=True,
                    )
                st.markdown(
                    '<p style="font-size:0.8rem;font-weight:600;text-transform:uppercase;'
                    'letter-spacing:0.07em;color:#8b949e;margin:0.75rem 0 0.25rem">Description</p>',
                    unsafe_allow_html=True,
                )
                st.write(finding.description)
                st.markdown(
                    '<p style="font-size:0.8rem;font-weight:600;text-transform:uppercase;'
                    'letter-spacing:0.07em;color:#8b949e;margin:0.75rem 0 0.25rem">Evidence</p>',
                    unsafe_allow_html=True,
                )
                st.code(finding.evidence)
                st.markdown(
                    '<p style="font-size:0.8rem;font-weight:600;text-transform:uppercase;'
                    'letter-spacing:0.07em;color:#8b949e;margin:0.75rem 0 0.25rem">Remediation</p>',
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f'<div style="background:rgba(0,217,255,0.05);border:1px solid rgba(0,217,255,0.18);'
                    f'border-radius:8px;padding:0.75rem 1rem;font-size:0.875rem;color:#e6edf3;line-height:1.7">'
                    f'{finding.remediation}</div>',
                    unsafe_allow_html=True,
                )


# ══════════════════════════════════════════════════════════════════════════════
# History page
# ══════════════════════════════════════════════════════════════════════════════

def page_history():
    st.markdown(
        """
<div class="vha-hero" style="padding:1.75rem 2rem 1.5rem">
  <div class="badge">📁 Run History</div>
  <h1 style="font-size:1.8rem!important">Past Assessments</h1>
  <p>Browse and export results from previous security assessment runs.</p>
</div>
""",
        unsafe_allow_html=True,
    )

    run_ids = list_runs()
    if not run_ids:
        st.markdown(
            '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;'
            'padding:2.5rem;text-align:center;color:#8b949e">'
            '<div style="font-size:2.5rem;margin-bottom:0.75rem">📭</div>'
            '<div style="font-weight:600;font-size:1rem;color:#e6edf3;margin-bottom:0.4rem">No past runs found</div>'
            '<div style="font-size:0.875rem">Start a new assessment to see results here.</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    for run_id in run_ids[:20]:
        try:
            r = load_run(run_id)
            has_critical = any(f.severity.value in ("CRITICAL", "HIGH") for f in r.findings)
            status_color = {
                "completed": "#2ed573",
                "failed":    "#ff4757",
                "blocked":   "#ff4757",
                "running":   "#00d9ff",
                "pending":   "#ffd32a",
            }.get(r.status.value, "#747d8c")

            label = (
                f"{'🔴' if has_critical else '✅'}  **{r.target}**"
                f" &nbsp;·&nbsp; {r.started_at.strftime('%Y-%m-%d %H:%M')} UTC"
                f" &nbsp;·&nbsp; {len(r.findings)} finding{'s' if len(r.findings) != 1 else ''}"
            )
            with st.expander(label):
                info_col1, info_col2, info_col3 = st.columns(3)
                info_col1.markdown(
                    f'<div style="font-size:0.78rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.07em">Run ID</div>'
                    f'<div style="font-family:monospace;font-size:0.8rem;color:#e6edf3">{r.run_id[:12]}…</div>',
                    unsafe_allow_html=True,
                )
                info_col2.markdown(
                    f'<div style="font-size:0.78rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.07em">Status</div>'
                    f'<div style="font-weight:600;color:{status_color}">{r.status.value.upper()}</div>',
                    unsafe_allow_html=True,
                )
                info_col3.markdown(
                    f'<div style="font-size:0.78rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.07em">Mode</div>'
                    f'<div style="font-size:0.875rem;color:#e6edf3">{"Active + Passive" if r.scope.active_testing else "Passive only"}</div>',
                    unsafe_allow_html=True,
                )

                if r.executive_summary:
                    st.markdown("<div style='margin-top:0.75rem'></div>", unsafe_allow_html=True)
                    st.markdown(
                        f'<div class="vha-summary-box" style="font-size:0.85rem">{r.executive_summary}</div>',
                        unsafe_allow_html=True,
                    )

                if r.findings:
                    st.markdown("<div style='margin-top:0.75rem'></div>", unsafe_allow_html=True)
                    sev_counts: Dict[str, int] = {}
                    for f in r.findings:
                        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
                    badges = " ".join(
                        f'<span class="sev-badge sev-{s}">{s}: {c}</span>'
                        for s, c in sev_counts.items()
                    )
                    st.markdown(badges, unsafe_allow_html=True)

                st.markdown("<div style='margin-top:0.75rem'></div>", unsafe_allow_html=True)
                btn_col1, btn_col2 = st.columns(2, gap="small")

                report_path = get_run_report_path(r.run_id)
                if report_path:
                    md_text = report_path.read_text(encoding="utf-8")
                    btn_col1.download_button(
                        "⬇️  Markdown Report",
                        data=md_text,
                        file_name=f"report_{run_id[:8]}.md",
                        mime="text/markdown",
                        key=f"dl_md_{run_id}",
                        use_container_width=True,
                    )
                btn_col2.download_button(
                    "⬇️  JSON Artefact",
                    data=r.model_dump_json(indent=2),
                    file_name=f"result_{run_id[:8]}.json",
                    mime="application/json",
                    key=f"dl_json_{run_id}",
                    use_container_width=True,
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
