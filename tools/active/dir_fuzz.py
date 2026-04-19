"""
Rate-limited directory fuzzer (active tool).
Uses a built-in minimal wordlist and rate-limits all requests.
No exploit payloads – only enumeration of common paths.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

import requests

_UA = "VibeScan/1.0 (security-assessment; authorized)"
_TIMEOUT = 8

# ── Built-in wordlist ─────────────────────────────────────────────────────────
# Common paths worth enumerating.  Intentionally short to stay non-aggressive.
COMMON_PATHS = [
    ".env", ".git/HEAD", ".htaccess", "admin", "admin/login", "administrator",
    "api", "api/v1", "api/v2", "backup", "config", "console", "dashboard",
    "debug", "docs", "healthz", "info", "login", "logout", "manage",
    "metrics", "phpinfo.php", "phpmyadmin", "readme.txt", "README.md",
    "robots.txt", "server-status", "server-info", "sitemap.xml",
    "swagger", "swagger-ui", "swagger.json", "openapi.json",
    "test", "tmp", "upload", "uploads", "web.config", "wp-admin",
    "wp-login.php", "xmlrpc.php",
]

# Paths per intensity level
_INTENSITY_PATHS = {
    "low": COMMON_PATHS[:20],
    "medium": COMMON_PATHS[:35],
    "high": COMMON_PATHS,
}

# Requests per second caps
_INTENSITY_RPS = {"low": 2, "medium": 5, "high": 10}


def run_dir_fuzz(
    target: str,
    intensity: str = "low",
    custom_paths: List[str] | None = None,
) -> Dict[str, Any]:
    """
    Probe common paths on *target* and report which ones return HTTP 2xx/3xx.

    Returns::

        {
            "base_url": "https://...",
            "probed": 20,
            "found": [{"url": "...", "status_code": 200, "content_length": 1234}],
            "error": None | "...",
        }
    """
    base_url = _base_url(target)
    paths = custom_paths if custom_paths is not None else _INTENSITY_PATHS.get(intensity, COMMON_PATHS[:20])
    rps = _INTENSITY_RPS.get(intensity, 2)
    delay = 1.0 / rps

    result: Dict[str, Any] = {
        "base_url": base_url,
        "probed": 0,
        "found": [],
        "error": None,
    }

    session = requests.Session()
    session.headers.update({"User-Agent": _UA})

    for path in paths:
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            resp = session.get(
                url,
                timeout=_TIMEOUT,
                allow_redirects=False,
                verify=False,
            )
            result["probed"] += 1
            if resp.status_code < 404:
                result["found"].append(
                    {
                        "url": url,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                    }
                )
        except Exception:
            result["probed"] += 1  # Count as probed even on error
        time.sleep(delay)

    return result


def _base_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    return f"https://{target}"
