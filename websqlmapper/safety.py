from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit


class SafetyError(ValueError):
    pass


def require_authorization(authorized: bool) -> None:
    if not authorized:
        raise SafetyError(
            "Authorization acknowledgement required. Use --authorized only for systems you own or are explicitly permitted to test."
        )


def validate_http_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise SafetyError("Only http:// and https:// targets are supported.")
    if not parts.hostname:
        raise SafetyError("Target URL must include a hostname.")


def private_target_addresses(url: str) -> frozenset[str]:
    """Resolve a target and return its private/loopback addresses, or an empty set.

    The mapper keeps the initial set and revalidates it during long runs so a
    hostname cannot silently change from a private lab address to a public one.
    """
    validate_http_url(url)
    host = urlsplit(url).hostname
    if host is None:
        return frozenset()
    if host.lower() == "localhost":
        return frozenset({"127.0.0.1", "::1"})
    try:
        direct = ipaddress.ip_address(host)
    except ValueError:
        direct = None
    if direct is not None:
        return frozenset({str(direct)}) if (direct.is_private or direct.is_loopback or direct.is_link_local) else frozenset()
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return frozenset()
    addresses = frozenset(info[4][0] for info in infos)
    if not addresses:
        return frozenset()
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            return frozenset()
    return addresses


def is_private_or_loopback_target(url: str) -> bool:
    return bool(private_target_addresses(url))


def require_private_mapping_target(url: str, *, expected_addresses: frozenset[str] | None = None) -> frozenset[str]:
    addresses = private_target_addresses(url)
    if not addresses:
        raise SafetyError(
            "Blind database mapping is intentionally restricted to localhost/private lab targets. "
            "Remote targets can be scanned for indicators, but automated data reconstruction is disabled."
        )
    if expected_addresses is not None and addresses != expected_addresses:
        raise SafetyError(
            "Private mapping target resolution changed during the run; mapping stopped to prevent DNS rebinding."
        )
    return addresses

