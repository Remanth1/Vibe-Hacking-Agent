"""
Basic vulnerability template checks (active tool).
These are lightweight, non-exploitative HTTP probes that validate
known-bad configurations.  They send no attack payloads.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

import requests

_UA = "VibeScan/1.0 (security-assessment; authorized)"
_TIMEOUT = 10


# ── Public API ────────────────────────────────────────────────────────────────

def run_vuln_checks(target: str) -> Dict[str, Any]:
    """
    Run a battery of lightweight config-validation probes.

    Returns::

        {
            "checks_run": ["cors_wildcard", ...],
            "issues": [{"check": "...", "detail": "...", "severity": "HIGH"}],
            "error": None | "...",
        }
    """
    base_url = _base_url(target)
    issues: List[Dict[str, str]] = []
    checks_run: List[str] = []

    runners = [
        _check_cors_wildcard,
        _check_http_methods,
        _check_debug_endpoints,
        _check_clickjacking,
        _check_mixed_content_redirect,
    ]

    for runner in runners:
        try:
            name, found = runner(base_url)
            checks_run.append(name)
            issues.extend(found)
        except Exception as exc:
            checks_run.append(getattr(runner, "__name__", "unknown"))
            issues.append(
                {"check": getattr(runner, "__name__", "unknown"), "detail": str(exc), "severity": "INFO"}
            )

    return {"checks_run": checks_run, "issues": issues, "error": None}


# ── Individual checks ─────────────────────────────────────────────────────────

def _check_cors_wildcard(base_url: str) -> tuple[str, List[Dict[str, str]]]:
    """Detect Access-Control-Allow-Origin: * on endpoints that set cookies."""
    name = "cors_wildcard"
    issues: List[Dict[str, str]] = []
    try:
        resp = requests.get(
            base_url,
            headers={"Origin": "https://evil.example.com", "User-Agent": _UA},
            timeout=_TIMEOUT,
            verify=False,
        )
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*" and acac.lower() == "true":
            issues.append(
                {
                    "check": name,
                    "detail": "CORS wildcard origin combined with credentials=true",
                    "severity": "HIGH",
                }
            )
        elif acao == "*":
            issues.append(
                {
                    "check": name,
                    "detail": f"CORS wildcard origin ({acao}) may expose data to any site",
                    "severity": "MEDIUM",
                }
            )
    except Exception:
        pass
    return name, issues


def _check_http_methods(base_url: str) -> tuple[str, List[Dict[str, str]]]:
    """Send OPTIONS to discover dangerous HTTP methods."""
    name = "http_methods"
    issues: List[Dict[str, str]] = []
    dangerous = {"TRACE", "TRACK", "PUT", "DELETE", "PATCH", "CONNECT"}
    try:
        resp = requests.options(
            base_url,
            headers={"User-Agent": _UA},
            timeout=_TIMEOUT,
            verify=False,
        )
        allow = resp.headers.get("Allow", "") + resp.headers.get("Public", "")
        methods = {m.strip().upper() for m in allow.split(",")}
        found_dangerous = methods & dangerous
        if found_dangerous:
            issues.append(
                {
                    "check": name,
                    "detail": f"Server advertises potentially dangerous HTTP methods: {', '.join(sorted(found_dangerous))}",
                    "severity": "MEDIUM",
                }
            )
    except Exception:
        pass
    return name, issues


def _check_debug_endpoints(base_url: str) -> tuple[str, List[Dict[str, str]]]:
    """Check for exposed debug/diagnostic endpoints."""
    name = "debug_endpoints"
    issues: List[Dict[str, str]] = []
    targets = [
        ("/phpinfo.php", 200, "PHP info page exposed"),
        ("/server-status", 200, "Apache server-status exposed"),
        ("/server-info", 200, "Apache server-info exposed"),
        ("/.git/HEAD", 200, "Git repository exposed"),
        ("/.env", 200, ".env file potentially exposed"),
        ("/web.config", 200, "web.config potentially exposed"),
        ("/actuator", 200, "Spring Boot Actuator exposed"),
        ("/actuator/health", 200, "Spring Boot Actuator health exposed"),
    ]
    try:
        session = requests.Session()
        session.headers["User-Agent"] = _UA
        for path, expected_status, detail in targets:
            url = base_url.rstrip("/") + path
            try:
                resp = session.get(url, timeout=_TIMEOUT, verify=False, allow_redirects=False)
                if resp.status_code == expected_status:
                    issues.append({"check": name, "detail": f"{detail}: {url}", "severity": "HIGH"})
            except Exception:
                pass
    except Exception:
        pass
    return name, issues


def _check_clickjacking(base_url: str) -> tuple[str, List[Dict[str, str]]]:
    """Verify X-Frame-Options or CSP frame-ancestors are set."""
    name = "clickjacking"
    issues: List[Dict[str, str]] = []
    try:
        resp = requests.get(base_url, headers={"User-Agent": _UA}, timeout=_TIMEOUT, verify=False)
        xfo = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get("Content-Security-Policy", "")
        if not xfo and "frame-ancestors" not in csp.lower():
            issues.append(
                {
                    "check": name,
                    "detail": "No X-Frame-Options or CSP frame-ancestors – page may be embeddable in iframes (clickjacking risk)",
                    "severity": "MEDIUM",
                }
            )
    except Exception:
        pass
    return name, issues


def _check_mixed_content_redirect(base_url: str) -> tuple[str, List[Dict[str, str]]]:
    """Check whether HTTP redirects to HTTPS."""
    name = "http_to_https_redirect"
    issues: List[Dict[str, str]] = []
    if base_url.startswith("https://"):
        http_url = "http://" + base_url[8:]
    else:
        http_url = base_url
    try:
        resp = requests.get(
            http_url,
            headers={"User-Agent": _UA},
            timeout=_TIMEOUT,
            allow_redirects=False,
            verify=False,
        )
        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("Location", "")
            if not location.startswith("https://"):
                issues.append(
                    {
                        "check": name,
                        "detail": f"HTTP redirect target is not HTTPS: {location}",
                        "severity": "MEDIUM",
                    }
                )
        elif resp.status_code == 200:
            issues.append(
                {
                    "check": name,
                    "detail": "Site accessible over plain HTTP without redirect to HTTPS",
                    "severity": "MEDIUM",
                }
            )
    except Exception:
        pass
    return name, issues


# ── Helpers ───────────────────────────────────────────────────────────────────

def _base_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    return f"https://{target}"
