"""
TLS / certificate inspection tool.
Connects to the target on port 443 (or a supplied port) and extracts
certificate metadata without requiring any third-party scanner.
"""
from __future__ import annotations

import datetime
import socket
import ssl
from typing import Any, Dict, List, Optional


def inspect_tls(target: str, port: int = 443, timeout: int = 10) -> Dict[str, Any]:
    """
    Return TLS metadata for *target*:port.

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
    - ``supports_tls10``: bool (weak)
    - ``supports_tls11``: bool (weak)
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
        "supports_tls10": False,
        "supports_tls11": False,
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
                        delta = not_after - datetime.datetime.utcnow()
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

    # Check for legacy protocol support
    result["supports_tls10"] = _probe_tls_version(
        target, port, timeout, ssl.TLSVersion.TLSv1
    )
    result["supports_tls11"] = _probe_tls_version(
        target, port, timeout, ssl.TLSVersion.TLSv1_1
    )

    return result


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


def _probe_tls_version(
    target: str, port: int, timeout: int, version: "ssl.TLSVersion"
) -> bool:
    """Return True if the server accepts *version*."""
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
            return datetime.datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None
