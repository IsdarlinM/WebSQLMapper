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


def is_private_or_loopback_target(url: str) -> bool:
    validate_http_url(url)
    host = urlsplit(url).hostname
    if host is None:  # validate_http_url above should make this unreachable.
        return False
    if host.lower() == "localhost":
        return True
    try:
        direct = ipaddress.ip_address(host)
        return direct.is_private or direct.is_loopback or direct.is_link_local
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False

    addresses = {info[4][0] for info in infos}
    if not addresses:
        return False
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            return False
    return True


def require_private_mapping_target(url: str) -> None:
    if not is_private_or_loopback_target(url):
        raise SafetyError(
            "Blind database mapping is intentionally restricted to localhost/private lab targets. "
            "Remote targets can be scanned for indicators, but automated data reconstruction is disabled."
        )
