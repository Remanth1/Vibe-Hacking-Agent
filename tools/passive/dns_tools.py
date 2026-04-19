"""
DNS recon tool: resolves A, AAAA, MX, TXT, NS, CNAME, SOA records and
performs a reverse-DNS lookup.  Uses dnspython; falls back to the stdlib
``socket`` module when dnspython is unavailable.
"""
from __future__ import annotations

import socket
from typing import Any, Dict, List

try:
    import dns.resolver
    import dns.reversename
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False

RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA")


def lookup_dns(target: str) -> Dict[str, Any]:
    """
    Return a dict of DNS records for *target*.

    ``{"A": [...], "MX": [...], ...}``
    """
    results: Dict[str, Any] = {}

    if _HAS_DNSPYTHON:
        results = _dns_python_lookup(target)
    else:
        results = _socket_fallback(target)

    # Always include a reverse-DNS attempt on each A/AAAA address
    reverse: Dict[str, str] = {}
    for addr in results.get("A", []) + results.get("AAAA", []):
        try:
            host, _, _ = socket.gethostbyaddr(addr)
            reverse[addr] = host
        except Exception:
            reverse[addr] = ""
    results["reverse_dns"] = reverse

    return results


def _dns_python_lookup(target: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(target, rtype, raise_on_no_answer=False)
            records: List[str] = []
            for rdata in answers:
                records.append(str(rdata))
            if records:
                results[rtype] = records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, Exception):
            pass  # silently skip unavailable record types

    return results


def _socket_fallback(target: str) -> Dict[str, Any]:
    """Minimal fallback using only stdlib socket."""
    results: Dict[str, Any] = {}
    try:
        infos = socket.getaddrinfo(target, None)
        a_records: List[str] = []
        aaaa_records: List[str] = []
        for info in infos:
            addr = info[4][0]
            if ":" in addr:
                if addr not in aaaa_records:
                    aaaa_records.append(addr)
            else:
                if addr not in a_records:
                    a_records.append(addr)
        if a_records:
            results["A"] = a_records
        if aaaa_records:
            results["AAAA"] = aaaa_records
    except socket.gaierror:
        pass
    return results
