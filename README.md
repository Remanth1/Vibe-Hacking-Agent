# Vibe Hacking Agent 🛡️

An **autonomous, multi-agent red-team testing service** that helps you evaluate
the security posture of a target **you own or are explicitly authorized to test**.

> **Legal notice:** This tool is for authorized testing only.  Unauthorized
> scanning is illegal.  A hard blocklist prevents scanning government, military,
> and critical-infrastructure targets regardless of what the user enters.

---

## Screenshots

![Vibe Hacking Agent – Main UI](https://github.com/user-attachments/assets/624ec8f2-cf24-4e18-8fb2-92931fa7bde0)

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   Streamlit Web UI                       │
└──────────────────────┬───────────────────────────────────┘
                       │
              LangGraph state machine
                       │
    ┌──────────────────▼──────────────────────────────┐
    │  [1] Scope & Policy Agent                       │
    │      • Validates targets / blocklist            │
    │      • Enforces passive-vs-active policy        │
    └──────────────────┬──────────────────────────────┘
                       │
    ┌──────────────────▼──────────────────────────────┐
    │  [2] Safety / Exploit-Blocker Agent             │
    │      • Re-checks blocklist                      │
    │      • Detects payload-like commands            │
    └──────────────────┬──────────────────────────────┘
                       │
    ┌──────────────────▼──────────────────────────────┐
    │  [3] Recon Agent                                │
    │      Passive: DNS · HTTP headers · TLS ·        │
    │               robots.txt · tech fingerprint     │
    │      Active*: nmap · dir fuzz · vuln checks     │
    └──────────────────┬──────────────────────────────┘
                       │
    ┌──────────────────▼──────────────────────────────┐
    │  [4] Vuln Triage Agent                          │
    │      • Rule-based finding generation            │
    │      • Severity & confidence assignment         │
    │      • Optional LLM remediation enrichment      │
    └──────────────────┬──────────────────────────────┘
                       │
    ┌──────────────────▼──────────────────────────────┐
    │  [5] Reporter Agent                             │
    │      • Executive summary (LLM or template)     │
    │      • Markdown + JSON report                   │
    │      • Audit log appendix                       │
    └─────────────────────────────────────────────────┘

*Active tools require the user to enable "Active testing" and confirm authorization.
```

---

## Features

| Category | Details |
|---|---|
| **Authorization gate** | Checkbox + scope form required before any scan; hard blocklist of gov/mil/critical-infra |
| **Passive recon** | DNS (A/AAAA/MX/TXT/NS/CNAME/SOA/rDNS), HTTP headers & security header analysis, TLS certificate inspection, robots.txt / sitemap.xml, technology fingerprinting |
| **Active recon** (opt-in) | nmap port scan (restricted flags), rate-limited directory fuzzing, CORS/HTTPS/debug-endpoint config checks |
| **Findings** | Severity (CRITICAL→INFO) + confidence, affected asset, description, evidence, remediation guidance |
| **Report** | Markdown + JSON; executive summary, findings table, asset inventory, full audit log |
| **LLM enhancement** | Works fully offline / rule-based; optionally enhanced by OpenAI, Anthropic, or local Ollama |
| **Persistence** | All runs saved to `runs/<run_id>/` with `result.json` and `report.md` |

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (Optional) Configure an LLM for richer summaries
cp .env.example .env
# Edit .env and set OPENAI_API_KEY or ANTHROPIC_API_KEY or OLLAMA_BASE_URL

# 3. Launch the UI
streamlit run app.py
```

Then open http://localhost:8501 in your browser.

### Active scanning prerequisites

Port scanning requires **nmap**:
```bash
# macOS
brew install nmap

# Debian / Ubuntu
sudo apt-get install nmap
```

---

## Project Layout

```
├── app.py                    # Streamlit UI (entry point)
├── requirements.txt
├── .env.example
├── agents/
│   ├── graph.py              # LangGraph state-machine orchestration
│   ├── scope_policy.py       # Agent 1 – scope & policy enforcement
│   ├── safety.py             # Agent 2 – exploit-blocker / safety gate
│   ├── recon.py              # Agent 3 – passive + active recon
│   ├── vuln_triage.py        # Agent 4 – vulnerability triage & scoring
│   └── reporter.py           # Agent 5 – report generation
├── tools/
│   ├── passive/              # dns_tools, http_tools, tls_tools, web_tools
│   └── active/               # port_scan, dir_fuzz, vuln_check
├── core/
│   ├── models.py             # Pydantic data models
│   ├── blocklist.py          # Hard blocklist (gov/mil/etc.)
│   ├── scope.py              # Scope validation
│   └── evidence.py           # Run persistence helpers
└── runs/                     # Artefacts – one sub-directory per run
```

---

## Safety & Ethics

* **Never** use this tool against systems you do not own or lack written permission to test.
* The hard blocklist cannot be bypassed from the UI.
* All actions are timestamped in an immutable audit log.
* Active tools send **no exploit payloads** – only safe configuration probes.
* The Safety Agent filters every planned action for payload-like content before execution.

