"""
Recon Agent.

Responsibilities:
- Run all allowed passive (and optionally active) recon tools
- Build the AssetInventory
- Log every command and its output to the audit trail
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from core.evidence import save_run
from core.models import AssetInventory, RunResult, ScanStatus
from tools.passive.dns_tools import lookup_dns
from tools.passive.http_tools import fetch_http_headers
from tools.passive.tls_tools import inspect_tls
from tools.passive.web_tools import fetch_robots_txt, fetch_sitemap, fingerprint_technologies

AGENT_NAME = "ReconAgent"


def run(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    LangGraph node: execute recon tools and populate asset inventory.
    """
    if state.get("current_stage") in ("blocked", "failed"):
        return state

    result: RunResult = state["run_result"]
    allowed_tools: List[str] = state.get("allowed_tools", [])
    result.add_audit(AGENT_NAME, "Starting reconnaissance")

    inventory = AssetInventory()

    for target in result.scope.targets:
        _recon_target(target, result, inventory, allowed_tools)

    result.asset_inventory = inventory

    # Active recon (only when authorized)
    if result.scope.active_testing:
        _active_recon(result, inventory, allowed_tools)

    result.add_audit(
        AGENT_NAME,
        "Reconnaissance complete",
        output=(
            f"Hosts: {len(inventory.hosts)}, "
            f"Technologies: {len(inventory.technologies)}, "
            f"Endpoints: {len(inventory.endpoints)}"
        ),
    )
    save_run(result)
    state["current_stage"] = "recon_complete"
    return state


def _recon_target(
    target: str,
    result: RunResult,
    inventory: AssetInventory,
    allowed_tools: List[str],
) -> None:
    """Run all passive recon tools against a single target."""

    # ── DNS ────────────────────────────────────────────────────────────────────
    if "dns_lookup" in allowed_tools:
        result.add_audit(AGENT_NAME, "DNS lookup", command=f"dns_lookup({target})")
        dns_data = lookup_dns(target)
        inventory.dns_records[target] = dns_data
        # Collect resolved IPs as hosts
        for addr in dns_data.get("A", []) + dns_data.get("AAAA", []):
            if addr not in inventory.hosts:
                inventory.hosts.append(addr)
        if target not in inventory.hosts:
            inventory.hosts.append(target)
        result.add_audit(
            AGENT_NAME,
            "DNS lookup complete",
            output=_safe_truncate(str(dns_data), 500),
        )

    # ── HTTP headers ──────────────────────────────────────────────────────────
    if "http_headers" in allowed_tools:
        result.add_audit(AGENT_NAME, "HTTP header fetch", command=f"fetch_http_headers({target})")
        http_data = fetch_http_headers(target)
        inventory.http_headers[target] = http_data
        result.add_audit(
            AGENT_NAME,
            "HTTP header fetch complete",
            output=_safe_truncate(str(http_data.get("headers", {})), 500),
        )

    # ── TLS inspection ────────────────────────────────────────────────────────
    if "tls_inspect" in allowed_tools:
        result.add_audit(AGENT_NAME, "TLS inspection", command=f"inspect_tls({target})")
        tls_data = inspect_tls(target)
        inventory.tls_info[target] = tls_data
        result.add_audit(
            AGENT_NAME,
            "TLS inspection complete",
            output=_safe_truncate(str(tls_data), 500),
        )

    # ── robots.txt ────────────────────────────────────────────────────────────
    if "robots_txt" in allowed_tools:
        result.add_audit(AGENT_NAME, "Fetching robots.txt", command=f"fetch_robots_txt({target})")
        robots = fetch_robots_txt(target)
        inventory.robots_txt[target] = robots.get("content", "")
        result.add_audit(
            AGENT_NAME,
            "robots.txt fetch complete",
            output=f"Found: {robots.get('found')}, "
                   f"Disallowed paths: {len(robots.get('disallowed', []))}",
        )

    # ── sitemap.xml ───────────────────────────────────────────────────────────
    if "sitemap" in allowed_tools:
        result.add_audit(AGENT_NAME, "Fetching sitemap.xml", command=f"fetch_sitemap({target})")
        sitemap = fetch_sitemap(target)
        urls = sitemap.get("urls", [])
        for url in urls:
            if url not in inventory.endpoints:
                inventory.endpoints.append(url)
        result.add_audit(
            AGENT_NAME,
            "Sitemap fetch complete",
            output=f"Found: {sitemap.get('found')}, URLs: {len(urls)}",
        )

    # ── Technology fingerprinting ─────────────────────────────────────────────
    if "tech_fingerprint" in allowed_tools:
        result.add_audit(
            AGENT_NAME, "Technology fingerprinting", command=f"fingerprint_technologies({target})"
        )
        tech = fingerprint_technologies(target)
        for t in tech.get("technologies", []):
            if t not in inventory.technologies:
                inventory.technologies.append(t)
        inventory.raw_data[f"{target}_tech"] = tech
        result.add_audit(
            AGENT_NAME,
            "Tech fingerprinting complete",
            output=f"Technologies: {', '.join(tech.get('technologies', []))}",
        )


def _active_recon(
    result: RunResult,
    inventory: AssetInventory,
    allowed_tools: List[str],
) -> None:
    """Run active recon tools (only when authorized)."""
    from tools.active.port_scan import run_port_scan
    from tools.active.dir_fuzz import run_dir_fuzz

    for target in result.scope.targets:
        if "port_scan" in allowed_tools:
            result.add_audit(
                AGENT_NAME,
                "Port scan (active)",
                command=f"nmap -sV --top-ports ... {target}",
            )
            scan_result = run_port_scan(target, intensity=result.scope.test_intensity)
            inventory.open_ports[target] = [
                p["port"] for p in scan_result.get("open_ports", [])
            ]
            inventory.raw_data[f"{target}_portscan"] = scan_result
            result.add_audit(
                AGENT_NAME,
                "Port scan complete",
                command=scan_result.get("command"),
                output=_safe_truncate(
                    scan_result.get("output", scan_result.get("error", "")), 1000
                ),
            )

        if "dir_fuzz" in allowed_tools:
            result.add_audit(
                AGENT_NAME,
                "Directory fuzzing (active)",
                command=f"dir_fuzz({target}, intensity={result.scope.test_intensity})",
            )
            fuzz_result = run_dir_fuzz(target, intensity=result.scope.test_intensity)
            inventory.raw_data[f"{target}_dirfuzz"] = fuzz_result
            for found in fuzz_result.get("found", []):
                url = found["url"]
                if url not in inventory.endpoints:
                    inventory.endpoints.append(url)
            result.add_audit(
                AGENT_NAME,
                "Directory fuzzing complete",
                output=f"Probed: {fuzz_result.get('probed')}, "
                       f"Found: {len(fuzz_result.get('found', []))}",
            )

        if "vuln_check" in allowed_tools:
            from tools.active.vuln_check import run_vuln_checks
            result.add_audit(
                AGENT_NAME,
                "Vulnerability config checks (active)",
                command=f"vuln_check({target})",
            )
            vc_result = run_vuln_checks(target)
            inventory.raw_data[f"{target}_vulncheck"] = vc_result
            result.add_audit(
                AGENT_NAME,
                "Vulnerability config checks complete",
                output=f"Checks run: {len(vc_result.get('checks_run', []))}, "
                       f"Issues: {len(vc_result.get('issues', []))}",
            )


def _safe_truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"
