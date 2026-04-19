"""
Scope validation helpers.
"""
from __future__ import annotations

import ipaddress
import re
from typing import List, Tuple

from .blocklist import is_blocklisted
from .models import ScopeConfig


def _is_valid_target(target: str) -> bool:
    """Return True if *target* is a valid hostname, IP address, or CIDR block."""
    t = target.strip()

    # Plain IP
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        pass

    # CIDR
    try:
        ipaddress.ip_network(t, strict=False)
        return True
    except ValueError:
        pass

    # Wildcard domain (e.g. *.example.com)
    if t.startswith("*."):
        t = t[2:]

    # Hostname / domain
    hostname_re = re.compile(
        r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(hostname_re.match(t))


def validate_scope(scope: ScopeConfig) -> Tuple[bool, List[str]]:
    """
    Validate a ``ScopeConfig``.

    Returns ``(is_valid, list_of_issues)``.  The list is empty when valid.
    """
    issues: List[str] = []

    if not scope.targets:
        issues.append("No targets specified – add at least one domain or IP address.")
        return False, issues

    for target in scope.targets:
        if not _is_valid_target(target):
            issues.append(
                f"'{target}' is not a valid hostname, IP address, or CIDR block."
            )
            continue

        blocked, reason = is_blocklisted(target)
        if blocked:
            issues.append(f"Target '{target}' is on the hard blocklist: {reason}")

    for target in scope.excluded_targets:
        if not _is_valid_target(target):
            issues.append(
                f"Excluded target '{target}' is not a valid hostname/IP/CIDR."
            )

    if scope.test_intensity not in ("low", "medium", "high"):
        issues.append(
            f"Test intensity must be 'low', 'medium', or 'high'; "
            f"got '{scope.test_intensity}'."
        )

    return len(issues) == 0, issues


def target_is_in_scope(target: str, scope: ScopeConfig) -> bool:
    """Return True if *target* is within the defined scope and not excluded."""
    for excluded in scope.excluded_targets:
        # Simple substring / suffix match
        if target.endswith(excluded) or target == excluded:
            return False
    # If any scope target matches as a suffix or equals the target, it's in scope
    for allowed in scope.targets:
        allowed_clean = allowed.lstrip("*.")
        if target == allowed or target.endswith(f".{allowed_clean}"):
            return True
    return False
