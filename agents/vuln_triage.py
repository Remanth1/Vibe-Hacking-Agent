"""
Vulnerability Triage Agent.

Responsibilities:
- Analyse the asset inventory produced by the Recon Agent
- Apply rule-based checks to produce Finding objects
- Assign severity (CRITICAL/HIGH/MEDIUM/LOW/INFO) and confidence
- Optionally enhance findings with LLM reasoning if a provider is configured
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from core.evidence import save_run
from core.models import Confidence, Finding, RunResult, Severity

AGENT_NAME = "VulnTriageAgent"


def run(state: Dict[str, Any]) -> Dict[str, Any]:
    """LangGraph node: analyse recon data and produce findings."""
    if state.get("current_stage") in ("blocked", "failed"):
        return state

    result: RunResult = state["run_result"]
    result.add_audit(AGENT_NAME, "Starting vulnerability triage")

    inventory = result.asset_inventory

    findings: List[Finding] = []

    for target in result.scope.targets:
        findings.extend(_check_tls(target, inventory))
        findings.extend(_check_http_headers(target, inventory))
        findings.extend(_check_info_disclosure(target, inventory))
        findings.extend(_check_cookies(target, inventory))

    # Active vuln checks
    if result.scope.active_testing:
        for target in result.scope.targets:
            findings.extend(_check_active_results(target, inventory))

    # Run optional LLM enhancement
    findings = _maybe_enhance_with_llm(findings, result, state)

    for f in findings:
        result.add_finding(f)

    result.add_audit(
        AGENT_NAME,
        "Vulnerability triage complete",
        output=f"Total findings: {len(findings)} "
               f"(CRITICAL: {_count(findings, Severity.CRITICAL)}, "
               f"HIGH: {_count(findings, Severity.HIGH)}, "
               f"MEDIUM: {_count(findings, Severity.MEDIUM)}, "
               f"LOW: {_count(findings, Severity.LOW)}, "
               f"INFO: {_count(findings, Severity.INFO)})",
    )
    save_run(result)
    state["current_stage"] = "triage_complete"
    return state


# ── TLS checks ────────────────────────────────────────────────────────────────

def _check_tls(target: str, inventory: Any) -> List[Finding]:
    findings: List[Finding] = []
    tls = inventory.tls_info.get(target, {})
    if not tls:
        return findings

    if tls.get("error") and "verification failed" in str(tls.get("error", "")):
        findings.append(Finding(
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            affected_asset=target,
            title="TLS Certificate Verification Failed",
            description=(
                "The TLS certificate presented by the server could not be verified. "
                "This may indicate a self-signed certificate, an expired certificate, "
                "or a hostname mismatch."
            ),
            evidence=str(tls.get("error", "")),
            remediation=(
                "Obtain a valid TLS certificate from a trusted CA (e.g. Let's Encrypt). "
                "Ensure the certificate CN or SAN matches the target hostname."
            ),
            agent=AGENT_NAME,
            tool="tls_inspect",
            tags=["tls", "certificate"],
        ))

    if tls.get("is_expired"):
        findings.append(Finding(
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            affected_asset=target,
            title="TLS Certificate Expired",
            description=(
                f"The TLS certificate expired on {tls.get('not_after')}. "
                f"Browsers and clients will reject HTTPS connections."
            ),
            evidence=f"not_after={tls.get('not_after')}, days_until_expiry={tls.get('days_until_expiry')}",
            remediation="Renew the TLS certificate immediately. Use automated renewal (e.g. certbot) to prevent recurrence.",
            agent=AGENT_NAME,
            tool="tls_inspect",
            tags=["tls", "certificate", "expiry"],
        ))
    elif isinstance(tls.get("days_until_expiry"), int) and tls["days_until_expiry"] < 30:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            affected_asset=target,
            title="TLS Certificate Expiring Soon",
            description=f"The TLS certificate expires in {tls['days_until_expiry']} days.",
            evidence=f"not_after={tls.get('not_after')}",
            remediation="Renew the certificate before expiry. Set up automated renewal.",
            agent=AGENT_NAME,
            tool="tls_inspect",
            tags=["tls", "certificate", "expiry"],
        ))

    if tls.get("is_self_signed"):
        findings.append(Finding(
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            affected_asset=target,
            title="Self-Signed TLS Certificate",
            description="The server uses a self-signed certificate which is not trusted by browsers.",
            evidence=f"Subject: {tls.get('subject')}, Issuer: {tls.get('issuer')}",
            remediation="Replace with a certificate from a trusted CA.",
            agent=AGENT_NAME,
            tool="tls_inspect",
            tags=["tls", "certificate"],
        ))

    if tls.get("supports_tls10"):
        findings.append(Finding(
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            affected_asset=target,
            title="TLS 1.0 Supported (Deprecated Protocol)",
            description="The server accepts TLS 1.0 connections. TLS 1.0 is deprecated (RFC 8996) and has known weaknesses.",
            evidence="TLS 1.0 handshake succeeded",
            remediation="Disable TLS 1.0 in the server configuration. Support only TLS 1.2 and TLS 1.3.",
            agent=AGENT_NAME,
            tool="tls_inspect",
            tags=["tls", "weak-protocol"],
        ))

    if tls.get("supports_tls11"):
        findings.append(Finding(
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            affected_asset=target,
            title="TLS 1.1 Supported (Deprecated Protocol)",
            description="The server accepts TLS 1.1 connections. TLS 1.1 is deprecated (RFC 8996).",
            evidence="TLS 1.1 handshake succeeded",
            remediation="Disable TLS 1.1. Support only TLS 1.2 and TLS 1.3.",
            agent=AGENT_NAME,
            tool="tls_inspect",
            tags=["tls", "weak-protocol"],
        ))

    return findings


# ── HTTP header checks ────────────────────────────────────────────────────────

_MISSING_HEADER_DETAILS = {
    "Strict-Transport-Security": (
        Severity.HIGH,
        "Missing HSTS (HTTP Strict Transport Security)",
        "Without HSTS the browser may connect over HTTP, enabling downgrade attacks.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
    ),
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "Missing Content Security Policy (CSP)",
        "Without a CSP, the application is more susceptible to cross-site scripting (XSS) attacks.",
        "Define a strict Content-Security-Policy header. Start with 'default-src self' and refine.",
    ),
    "X-Frame-Options": (
        Severity.MEDIUM,
        "Missing X-Frame-Options Header",
        "Without X-Frame-Options (or CSP frame-ancestors), the page may be embedded in iframes (clickjacking).",
        "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP frame-ancestors.",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Missing X-Content-Type-Options Header",
        "Without this header, browsers may MIME-sniff responses, potentially executing unexpected content.",
        "Add 'X-Content-Type-Options: nosniff' to all responses.",
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Missing Referrer-Policy Header",
        "Without a Referrer-Policy, full URLs (including sensitive query parameters) may be sent to third parties.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    ),
    "Permissions-Policy": (
        Severity.INFO,
        "Missing Permissions-Policy Header",
        "A Permissions-Policy header allows restricting access to browser APIs (camera, microphone, etc.).",
        "Add a Permissions-Policy header tailored to the app's needs, e.g. 'Permissions-Policy: camera=(), microphone=()'.",
    ),
}


def _check_http_headers(target: str, inventory: Any) -> List[Finding]:
    findings: List[Finding] = []
    http_data = inventory.http_headers.get(target, {})
    if not http_data:
        return findings

    missing: List[str] = http_data.get("missing_security_headers", [])
    for header in missing:
        if header in _MISSING_HEADER_DETAILS:
            sev, title, desc, rem = _MISSING_HEADER_DETAILS[header]
            findings.append(Finding(
                severity=sev,
                confidence=Confidence.HIGH,
                affected_asset=target,
                title=title,
                description=desc,
                evidence=f"Header '{header}' was absent in the HTTP response from {http_data.get('url', target)}",
                remediation=rem,
                agent=AGENT_NAME,
                tool="http_headers",
                tags=["headers", header.lower().replace("-", "_")],
            ))

    return findings


# ── Information disclosure checks ─────────────────────────────────────────────

def _check_info_disclosure(target: str, inventory: Any) -> List[Finding]:
    findings: List[Finding] = []
    http_data = inventory.http_headers.get(target, {})
    disclosure = http_data.get("info_disclosure", {})

    if "Server" in disclosure:
        val = disclosure["Server"]
        # Flag if version number is present
        import re
        if re.search(r"\d+\.\d+", val):
            findings.append(Finding(
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                affected_asset=target,
                title="Server Version Disclosed in HTTP Header",
                description=(
                    f"The Server header reveals the software version: '{val}'. "
                    "Attackers can use version information to target known CVEs."
                ),
                evidence=f"Server: {val}",
                remediation=(
                    "Configure the server to return a generic Server header "
                    "(e.g. 'Server: Apache') or remove it entirely."
                ),
                agent=AGENT_NAME,
                tool="http_headers",
                tags=["headers", "information-disclosure"],
            ))

    if "X-Powered-By" in disclosure:
        findings.append(Finding(
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            affected_asset=target,
            title="Technology Disclosed via X-Powered-By Header",
            description=(
                f"The X-Powered-By header reveals: '{disclosure['X-Powered-By']}'. "
                "This assists attackers in fingerprinting the technology stack."
            ),
            evidence=f"X-Powered-By: {disclosure['X-Powered-By']}",
            remediation="Remove or suppress the X-Powered-By header in server/framework configuration.",
            agent=AGENT_NAME,
            tool="http_headers",
            tags=["headers", "information-disclosure"],
        ))

    # Debug headers
    for header in ("X-Debug-Token", "X-Debug-Token-Link"):
        if header in disclosure:
            findings.append(Finding(
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=target,
                title=f"Debug Header Exposed: {header}",
                description="A debug header is present in the production response, potentially exposing internal profiling data.",
                evidence=f"{header}: {disclosure[header]}",
                remediation="Disable debug mode in production and remove debug headers.",
                agent=AGENT_NAME,
                tool="http_headers",
                tags=["headers", "information-disclosure", "debug"],
            ))

    return findings


# ── Cookie checks ─────────────────────────────────────────────────────────────

def _check_cookies(target: str, inventory: Any) -> List[Finding]:
    findings: List[Finding] = []
    http_data = inventory.http_headers.get(target, {})
    cookies = http_data.get("cookies", [])

    for cookie in cookies:
        name = cookie.get("name", "unknown")

        if not cookie.get("secure"):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                affected_asset=target,
                title=f"Cookie Missing Secure Flag: {name}",
                description=f"Cookie '{name}' does not have the Secure flag, so it may be sent over unencrypted HTTP.",
                evidence=f"Cookie: {name}; Secure=False",
                remediation=f"Set the Secure flag on cookie '{name}'.",
                agent=AGENT_NAME,
                tool="http_headers",
                tags=["cookies", "session"],
            ))

        if not cookie.get("httponly"):
            findings.append(Finding(
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                affected_asset=target,
                title=f"Cookie Missing HttpOnly Flag: {name}",
                description=f"Cookie '{name}' does not have the HttpOnly flag, allowing JavaScript to access it (XSS risk).",
                evidence=f"Cookie: {name}; HttpOnly=False",
                remediation=f"Set the HttpOnly flag on cookie '{name}'.",
                agent=AGENT_NAME,
                tool="http_headers",
                tags=["cookies", "session"],
            ))

    return findings


# ── Active vuln results ───────────────────────────────────────────────────────

def _check_active_results(target: str, inventory: Any) -> List[Finding]:
    findings: List[Finding] = []
    allowed_tools: List[str] = []  # Active vuln checks may not have run

    # Process vuln_check results if present
    vuln_data = inventory.raw_data.get(f"{target}_vulncheck", {})
    for issue in vuln_data.get("issues", []):
        sev_map = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.INFO}
        findings.append(Finding(
            severity=sev_map.get(issue.get("severity", "LOW"), Severity.LOW),
            confidence=Confidence.MEDIUM,
            affected_asset=target,
            title=f"Active Check: {issue.get('check', 'unknown')}",
            description=issue.get("detail", ""),
            evidence=f"Check: {issue.get('check')}\nDetail: {issue.get('detail')}",
            remediation=_remediation_for_check(issue.get("check", "")),
            agent=AGENT_NAME,
            tool="vuln_check",
            tags=["active", issue.get("check", "")],
        ))

    # Exposed directories from dir fuzz
    fuzz_data = inventory.raw_data.get(f"{target}_dirfuzz", {})
    for found in fuzz_data.get("found", []):
        url = found.get("url", "")
        status = found.get("status_code", 0)
        # Flag potentially sensitive paths
        sensitive_keywords = [".env", ".git", "config", "admin", "debug", "backup", "phpinfo"]
        if any(kw in url.lower() for kw in sensitive_keywords):
            findings.append(Finding(
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                affected_asset=url,
                title=f"Potentially Sensitive Path Accessible: {url}",
                description=f"A potentially sensitive URL returned HTTP {status}.",
                evidence=f"URL: {url}, Status: {status}, Size: {found.get('content_length')} bytes",
                remediation="Restrict access to this resource using authentication or server configuration.",
                agent=AGENT_NAME,
                tool="dir_fuzz",
                tags=["active", "exposure"],
            ))

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _count(findings: List[Finding], severity: Severity) -> int:
    return sum(1 for f in findings if f.severity == severity)


def _remediation_for_check(check_name: str) -> str:
    remediations = {
        "cors_wildcard": "Restrict CORS to known, trusted origins. Do not use wildcard with credentials.",
        "http_methods": "Disable unused HTTP methods (TRACE, TRACK, PUT, DELETE) unless required by the application.",
        "debug_endpoints": "Disable or restrict access to debug/diagnostic endpoints in production.",
        "clickjacking": "Set X-Frame-Options or CSP frame-ancestors to prevent clickjacking.",
        "http_to_https_redirect": "Configure the server to redirect all HTTP traffic to HTTPS.",
    }
    return remediations.get(check_name, "Review and remediate the identified issue.")


def _maybe_enhance_with_llm(
    findings: List[Finding], result: RunResult, state: Dict[str, Any]
) -> List[Finding]:
    """
    If an LLM is configured, enrich finding descriptions with additional context.
    Falls back gracefully when no LLM is available.
    """
    llm = state.get("llm")
    if llm is None:
        return findings
    try:
        for finding in findings:
            prompt = (
                f"You are a senior security engineer providing concise remediation advice. "
                f"Finding: {finding.title}. "
                f"Description: {finding.description}. "
                f"Improve the remediation guidance in 2-3 sentences, referencing applicable standards (OWASP, CIS, NIST)."
            )
            response = llm.invoke(prompt)
            if hasattr(response, "content"):
                finding.remediation = response.content.strip()
            elif isinstance(response, str):
                finding.remediation = response.strip()
    except Exception:
        pass  # LLM enhancement is best-effort
    return findings
