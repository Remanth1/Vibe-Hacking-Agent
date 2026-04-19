"""
TLS / certificate inspection tool.
Connects to the target on port 443 (or a supplied port) and extracts
certificate metadata without requiring any third-party scanner.

Public API
----------
``inspect_tls``         – passive cert/protocol inspection (no weak-protocol negotiation)
``probe_legacy_tls``    – separate, explicitly-named function that tests for deprecated
                          TLS versions (called only when active testing is enabled)
"""
from __future__ import annotations

import datetime
import socket
import ssl
from typing import Any, Dict, List, Optional


def inspect_tls(target: str, port: int = 443, timeout: int = 10) -> Dict[str, Any]:
    """
    Passively inspect the TLS certificate and negotiated connection for *target*:port.

    This function only opens a single, *secure* TLS connection (using the system
    default context which enforces TLS 1.2+).  Weak-protocol detection is handled
    separately by ``probe_legacy_tls``.

    Keys in the returned dict:
    - ``subject``: dict of certificate subject fields
    - ``issuer``: dict of issuer fields
    - ``san``: list of Subject Alternative Names
    - ``not_before``: ISO-8601 string
    - ``not_after``: ISO-8601 string
    - ``days_until_expiry``: int (negative = already expired)
    - ``is_expired``: bool
    - ``is_self_signed``: bool
    - ``protocol``: negotiated TLS protocol version string
    - ``cipher``: negotiated cipher suite name
    - ``error``: error message if connection failed
    """
    result: Dict[str, Any] = {
        "subject": {},
        "issuer": {},
        "san": [],
        "not_before": None,
        "not_after": None,
        "days_until_expiry": None,
        "is_expired": False,
        "is_self_signed": False,
        "protocol": None,
        "cipher": None,
        "error": None,
    }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                result["protocol"] = ssock.version()
                cipher_info = ssock.cipher()
                result["cipher"] = cipher_info[0] if cipher_info else None

                if cert:
                    result["subject"] = _rdn_to_dict(cert.get("subject", ()))
                    result["issuer"] = _rdn_to_dict(cert.get("issuer", ()))
                    result["san"] = _extract_san(cert)

                    not_after_str = cert.get("notAfter", "")
                    not_before_str = cert.get("notBefore", "")
                    not_after = _parse_cert_date(not_after_str)
                    not_before = _parse_cert_date(not_before_str)

                    if not_after:
                        result["not_after"] = not_after.isoformat()
                        delta = not_after - datetime.datetime.now(datetime.timezone.utc)
                        result["days_until_expiry"] = delta.days
                        result["is_expired"] = delta.days < 0
                    if not_before:
                        result["not_before"] = not_before.isoformat()

                    # Self-signed: subject == issuer
                    result["is_self_signed"] = (
                        result["subject"] == result["issuer"]
                        and bool(result["subject"])
                    )
    except ssl.SSLCertVerificationError as exc:
        result["error"] = f"Certificate verification failed: {exc}"
        # Still try to get the cert without verification
        _try_get_cert_no_verify(target, port, timeout, result)
    except Exception as exc:
        result["error"] = str(exc)

    return result


def probe_legacy_tls(target: str, port: int = 443, timeout: int = 10) -> Dict[str, bool]:
    """
    **Active probe** – detect whether *target*:port accepts deprecated TLS versions.

    This function is intentionally kept separate from ``inspect_tls`` because it
    negotiates weak protocol versions (TLS 1.0, TLS 1.1) that should never be used
    in production connections.  Call this only when active testing has been
    explicitly authorized.

    Returns ``{"supports_tls10": bool, "supports_tls11": bool}``.
    """
    return {
        "supports_tls10": _probe_one_legacy_version(target, port, timeout, ssl.TLSVersion.TLSv1),
        "supports_tls11": _probe_one_legacy_version(target, port, timeout, ssl.TLSVersion.TLSv1_1),
    }


def _try_get_cert_no_verify(
    target: str, port: int, timeout: int, result: Dict[str, Any]
) -> None:
    """Attempt to fetch cert metadata without verification (for reporting only)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    result.setdefault("subject", _rdn_to_dict(cert.get("subject", ())))
                    result.setdefault("issuer", _rdn_to_dict(cert.get("issuer", ())))
                    result.setdefault("san", _extract_san(cert))
    except Exception:
        pass


def _probe_one_legacy_version(
    target: str, port: int, timeout: int, version: "ssl.TLSVersion"
) -> bool:
    """
    Internal helper: attempt a TLS handshake restricted to *version*.

    This is a **security detection probe** only – it tests whether the server
    accepts a deprecated protocol version so the issue can be reported to the user.
    No application data is sent; the connection is closed immediately after the
    handshake succeeds (or fails).
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target):
                return True
    except Exception:
        return False


def _rdn_to_dict(rdn_sequence: Any) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for rdn in rdn_sequence:
        for attr in rdn:
            result[attr[0]] = attr[1]
    return result


def _extract_san(cert: Dict[str, Any]) -> List[str]:
    san_list: List[str] = []
    for entry in cert.get("subjectAltName", []):
        san_list.append(f"{entry[0]}:{entry[1]}")
    return san_list


def _parse_cert_date(date_str: str) -> Optional[datetime.datetime]:
    if not date_str:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            # Cert dates use UTC but strptime with %Z may return naive; normalize to UTC
            dt = datetime.datetime.strptime(date_str, fmt)
            return dt.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    return None

