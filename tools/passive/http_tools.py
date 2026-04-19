"""
HTTP header analysis tool.
Fetches headers from http:// and https:// endpoints and extracts
security-relevant information.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

# Timeout for HTTP requests (seconds)
_TIMEOUT = 10

# Security headers we specifically look for
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

# Headers that may disclose sensitive information
INFO_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-Generator",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Drupal-Cache",
    "X-Varnish",
    "Via",
    "X-Backend-Server",
    "X-Debug-Token",
    "X-Debug-Token-Link",
]


def fetch_http_headers(target: str) -> Dict[str, Any]:
    """
    Fetch HTTP headers for *target* (tries HTTPS first, then HTTP).

    Returns a structured dict with:
    - ``url``: final URL after redirects
    - ``status_code``: integer
    - ``headers``: dict of all response headers
    - ``security_headers``: present security headers
    - ``missing_security_headers``: list of absent security headers
    - ``info_disclosure``: dict of disclosure headers found
    - ``redirect_chain``: list of redirect URLs
    - ``cookies``: list of cookie analysis dicts
    - ``error``: error message if request failed
    """
    result: Dict[str, Any] = {
        "url": "",
        "status_code": None,
        "headers": {},
        "security_headers": {},
        "missing_security_headers": [],
        "info_disclosure": {},
        "redirect_chain": [],
        "cookies": [],
        "error": None,
    }

    url = _normalise_url(target)

    try:
        session = requests.Session()
        session.max_redirects = 10
        resp = session.get(
            url,
            timeout=_TIMEOUT,
            verify=True,
            allow_redirects=True,
            headers={"User-Agent": "VibeScan/1.0 (security-assessment; authorized)"},
        )
        result["url"] = resp.url
        result["status_code"] = resp.status_code
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        result["headers"] = dict(resp.headers)

        # Redirect chain
        result["redirect_chain"] = [r.url for r in resp.history]

        # Security headers
        present: Dict[str, str] = {}
        missing: List[str] = []
        for sh in SECURITY_HEADERS:
            if sh.lower() in headers_lower:
                present[sh] = headers_lower[sh.lower()]
            else:
                missing.append(sh)
        result["security_headers"] = present
        result["missing_security_headers"] = missing

        # Info disclosure
        for ih in INFO_DISCLOSURE_HEADERS:
            if ih.lower() in headers_lower:
                result["info_disclosure"][ih] = headers_lower[ih.lower()]

        # Cookie analysis
        for cookie in resp.cookies:
            result["cookies"].append(_analyse_cookie(cookie))

        # Also check Set-Cookie header directly for flags
        raw_set_cookie = resp.headers.get("Set-Cookie", "")
        if raw_set_cookie and not result["cookies"]:
            result["cookies"].append(_analyse_raw_set_cookie(raw_set_cookie))

    except requests.exceptions.SSLError as exc:
        # Retry without TLS verification to still get headers
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                resp = requests.get(
                    url,
                    timeout=_TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                    headers={
                        "User-Agent": "VibeScan/1.0 (security-assessment; authorized)"
                    },
                )
            result["url"] = resp.url
            result["status_code"] = resp.status_code
            result["headers"] = dict(resp.headers)
            result["error"] = f"SSL verification failed: {exc}"
        except Exception as inner_exc:
            result["error"] = str(inner_exc)
    except requests.exceptions.ConnectionError as exc:
        # Try plain HTTP if HTTPS failed
        if url.startswith("https://"):
            http_url = url.replace("https://", "http://", 1)
            try:
                resp = requests.get(
                    http_url,
                    timeout=_TIMEOUT,
                    allow_redirects=True,
                    headers={
                        "User-Agent": "VibeScan/1.0 (security-assessment; authorized)"
                    },
                )
                result["url"] = resp.url
                result["status_code"] = resp.status_code
                result["headers"] = dict(resp.headers)
                result["error"] = f"HTTPS failed, used HTTP: {exc}"
            except Exception as inner_exc:
                result["error"] = str(inner_exc)
        else:
            result["error"] = str(exc)
    except Exception as exc:
        result["error"] = str(exc)

    return result


def _normalise_url(target: str) -> str:
    """Ensure target has a scheme."""
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"


def _analyse_cookie(cookie: Any) -> Dict[str, Any]:
    return {
        "name": cookie.name,
        "secure": cookie.secure,
        "httponly": bool(getattr(cookie, "_rest", {}).get("HttpOnly")),
        "samesite": getattr(cookie, "_rest", {}).get("SameSite", None),
        "domain": cookie.domain,
        "path": cookie.path,
    }


def _analyse_raw_set_cookie(header_value: str) -> Dict[str, Any]:
    """Basic parsing of a raw Set-Cookie header value."""
    parts = [p.strip() for p in header_value.split(";")]
    name = parts[0].split("=")[0] if parts else "unknown"
    flags = [p.lower() for p in parts[1:]]
    return {
        "name": name,
        "secure": "secure" in flags,
        "httponly": "httponly" in flags,
        "samesite": next(
            (p.split("=")[1] for p in flags if p.startswith("samesite=")), None
        ),
    }
