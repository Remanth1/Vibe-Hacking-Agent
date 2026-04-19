"""
Hard blocklist of targets that may never be scanned, regardless of
authorization claims.  Patterns are matched case-insensitively against
the normalized target string (domain or IP).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Tuple

# ── Domain / hostname patterns ────────────────────────────────────────────────
# Each entry is a compiled regex that matches the *full* normalized hostname.
_DOMAIN_PATTERNS: list[re.Pattern[str]] = [re.compile(p, re.IGNORECASE) for p in [
    # US Government
    r"(^|\.)gov$",
    r"(^|\.)gov\.",
    # US Military
    r"(^|\.)mil$",
    r"(^|\.)mil\.",
    # Other government TLDs
    r"(^|\.)gov\.uk$",
    r"(^|\.)gov\.au$",
    r"(^|\.)gov\.nz$",
    r"(^|\.)gc\.ca$",
    r"(^|\.)gouv\.fr$",
    r"(^|\.)gob\.",
    # Known critical US infrastructure hostnames
    r"whitehouse\.gov",
    r"cia\.gov",
    r"nsa\.gov",
    r"fbi\.gov",
    r"dhs\.gov",
    r"dod\.gov",
    r"pentagon\.gov",
    r"federalreserve\.gov",
    r"treasury\.gov",
    r"cdc\.gov",
    r"irs\.gov",
    # Cloud provider management planes (not user workloads)
    r"(^|\.)amazonaws\.com$",
    r"(^|\.)azure\.com$",
    r"(^|\.)googleapis\.com$",
    r"(^|\.)cloudflare\.com$",
    # Payment card networks
    r"(^|\.)visa\.com$",
    r"(^|\.)mastercard\.com$",
    r"(^|\.)swift\.com$",
]]

# ── IP ranges that are hard-blocked ──────────────────────────────────────────
# (RFC 1918 private ranges are intentionally NOT blocked – users test their
# own internal infrastructure regularly.)
_BLOCKED_IP_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # IANA special-purpose ranges that should never be scanned
    ipaddress.ip_network("0.0.0.0/8"),           # "This" network
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved (future use)
]


def is_blocklisted(target: str) -> Tuple[bool, str]:
    """
    Return ``(True, reason)`` if *target* is on the hard blocklist,
    otherwise ``(False, "")`` .
    """
    normalized = target.strip().lower()

    # ── IP address / network check ───────────────────────────────────────────
    try:
        addr = ipaddress.ip_address(normalized)
        for net in _BLOCKED_IP_NETWORKS:
            if addr in net:
                return True, f"IP {addr} falls inside blocked network {net}"
        return False, ""
    except ValueError:
        pass

    # CIDR notation
    try:
        net = ipaddress.ip_network(normalized, strict=False)
        for blocked in _BLOCKED_IP_NETWORKS:
            if net.subnet_of(blocked) or blocked.subnet_of(net):  # type: ignore[arg-type]
                return True, f"Network {net} overlaps blocked network {blocked}"
        return False, ""
    except ValueError:
        pass

    # ── Domain pattern check ─────────────────────────────────────────────────
    for pattern in _DOMAIN_PATTERNS:
        if pattern.search(normalized):
            return True, f"Target matches blocked pattern ({pattern.pattern!r})"

    return False, ""
