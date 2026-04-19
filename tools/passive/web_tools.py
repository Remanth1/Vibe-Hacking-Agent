"""
Web content tools: robots.txt, sitemap.xml, and technology fingerprinting
from HTTP headers and page content.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

_TIMEOUT = 10
_UA = "VibeScan/1.0 (security-assessment; authorized)"


# ── robots.txt ────────────────────────────────────────────────────────────────

def fetch_robots_txt(target: str) -> Dict[str, Any]:
    """Fetch and parse robots.txt.  Returns disallowed paths and interesting hints."""
    base_url = _base_url(target)
    url = urljoin(base_url, "/robots.txt")
    result: Dict[str, Any] = {
        "url": url,
        "found": False,
        "content": "",
        "disallowed": [],
        "sitemap_urls": [],
        "error": None,
    }
    try:
        resp = requests.get(url, timeout=_TIMEOUT, headers={"User-Agent": _UA})
        if resp.status_code == 200:
            result["found"] = True
            result["content"] = resp.text[:4096]   # cap stored content
            lines = resp.text.splitlines()
            for line in lines:
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        result["disallowed"].append(path)
                elif line.lower().startswith("sitemap:"):
                    result["sitemap_urls"].append(line.split(":", 1)[1].strip())
    except Exception as exc:
        result["error"] = str(exc)
    return result


# ── sitemap.xml ───────────────────────────────────────────────────────────────

def fetch_sitemap(target: str) -> Dict[str, Any]:
    """Fetch sitemap.xml and extract URLs (first 100)."""
    base_url = _base_url(target)
    url = urljoin(base_url, "/sitemap.xml")
    result: Dict[str, Any] = {
        "url": url,
        "found": False,
        "urls": [],
        "error": None,
    }
    try:
        resp = requests.get(url, timeout=_TIMEOUT, headers={"User-Agent": _UA})
        if resp.status_code == 200 and (
            "xml" in resp.headers.get("Content-Type", "") or resp.text.startswith("<?xml")
        ):
            result["found"] = True
            # Extract <loc> tags
            locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", resp.text, re.IGNORECASE)
            result["urls"] = locs[:100]
    except Exception as exc:
        result["error"] = str(exc)
    return result


# ── Technology fingerprinting ─────────────────────────────────────────────────

# Signature map: (header_name, regex_pattern) -> technology name
_HEADER_SIGS: List[tuple[str, str, str]] = [
    # (header_name_lower, regex, technology)
    ("server", r"apache", "Apache HTTP Server"),
    ("server", r"nginx", "Nginx"),
    ("server", r"iis", "Microsoft IIS"),
    ("server", r"litespeed", "LiteSpeed"),
    ("server", r"cloudflare", "Cloudflare"),
    ("server", r"openresty", "OpenResty"),
    ("x-powered-by", r"php", "PHP"),
    ("x-powered-by", r"asp\.net", "ASP.NET"),
    ("x-powered-by", r"express", "Express.js"),
    ("x-powered-by", r"next\.js", "Next.js"),
    ("x-generator", r"wordpress", "WordPress"),
    ("x-generator", r"drupal", "Drupal"),
    ("x-generator", r"joomla", "Joomla"),
    ("set-cookie", r"phpsessid", "PHP"),
    ("set-cookie", r"jsessionid", "Java (Servlet)"),
    ("set-cookie", r"asp\.net_sessionid", "ASP.NET"),
    ("set-cookie", r"wp-settings", "WordPress"),
    ("set-cookie", r"django", "Django"),
    ("x-drupal-cache", r".*", "Drupal"),
    ("x-varnish", r".*", "Varnish Cache"),
]

# Body content signatures
_BODY_SIGS: List[tuple[str, str]] = [
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress', "WordPress"),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla', "Joomla"),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal', "Drupal"),
    (r'/wp-content/|/wp-includes/', "WordPress"),
    (r'Powered by <a[^>]+>vBulletin', "vBulletin"),
    (r'__VIEWSTATE', "ASP.NET WebForms"),
    (r'ng-version=|angular\.min\.js', "Angular"),
    (r'react\.production\.min\.js|__react', "React"),
    (r'vue\.min\.js|Vue\.component', "Vue.js"),
    (r'<link[^>]+bootstrap', "Bootstrap"),
    (r'jquery\.min\.js|jquery-', "jQuery"),
]


def fingerprint_technologies(target: str) -> Dict[str, Any]:
    """
    Identify web technologies in use.

    Returns ``{"technologies": [...], "details": {...}, "error": ...}``.
    """
    result: Dict[str, Any] = {
        "technologies": [],
        "details": {},
        "error": None,
    }
    url = _base_url(target)
    try:
        resp = requests.get(
            url,
            timeout=_TIMEOUT,
            headers={"User-Agent": _UA},
            allow_redirects=True,
        )
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:50_000]  # cap body to 50 kB

        found: set[str] = set()

        # Header-based detection
        for header, pattern, tech in _HEADER_SIGS:
            val = headers_lower.get(header, "")
            if val and re.search(pattern, val, re.IGNORECASE):
                found.add(tech)
                result["details"].setdefault(header, []).append(
                    {"tech": tech, "value": val}
                )

        # Body-based detection
        for pattern, tech in _BODY_SIGS:
            if re.search(pattern, body, re.IGNORECASE):
                found.add(tech)

        result["technologies"] = sorted(found)
    except Exception as exc:
        result["error"] = str(exc)
    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _base_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"
    return f"https://{target}"
