from __future__ import annotations

import copy
import json
import random
import re
import threading
import time
import uuid
from pathlib import Path
from dataclasses import replace
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException

from .importers import parse_nested_path, split_index
from .models import RequestConfig, ResponseSnapshot
from .safety import validate_http_url


_RETRY_STATUS = {429, 502, 503, 504}
_SECRET_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key"}


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key: ("<redacted>" if key.lower() in _SECRET_HEADERS else value) for key, value in headers.items()}




def redact_text_secrets(text: str) -> str:
    if not text:
        return text
    masked = re.sub(r'(?i)(["\']?(?:password|passwd|secret|token|access_token|api_key|authorization)["\']?\s*[:=]\s*["\']?)([^"\'&\s,}]+)', r'\1<redacted>', text)
    masked = re.sub(
        r'(?is)(<(?:password|passwd|secret|token|access_token|api_key|authorization)\b[^>]*>)(.*?)(</(?:password|passwd|secret|token|access_token|api_key|authorization)>)',
        r'\1<redacted>\3',
        masked,
    )
    return masked

def _set_nested(data: Any, path: str, value: Any) -> Any:
    result = copy.deepcopy(data)
    tokens = parse_nested_path(path)
    current = result
    for token in tokens[:-1]:
        if isinstance(token, int):
            if not isinstance(current, list) or token < 0 or token >= len(current):
                raise ValueError(f"JSON path does not exist: {path}")
            current = current[token]
        else:
            if not isinstance(current, dict) or token not in current:
                raise ValueError(f"JSON path does not exist: {path}")
            current = current[token]
    final = tokens[-1]
    if isinstance(final, int):
        if not isinstance(current, list) or final < 0 or final >= len(current):
            raise ValueError(f"JSON path does not exist: {path}")
        current[final] = value
    else:
        if not isinstance(current, dict):
            raise ValueError(f"JSON path parent is not an object: {path}")
        current[final] = value
    return result


def _replace_header(headers: dict[str, str], name: str, value: str) -> None:
    existing = next((key for key in headers if key.lower() == name.lower()), None)
    if existing:
        headers[existing] = value
    else:
        headers[name] = value


def _multipart_encode(data: dict[str, Any], inject_name: str, inject_value: str) -> tuple[bytes, str]:
    boundary = "----WebSQLMapper" + uuid.uuid4().hex
    chunks: list[bytes] = []
    fields = dict(data)
    fields[inject_name] = inject_value
    for name, raw_value in fields.items():
        chunks.append(f"--{boundary}\r\n".encode())
        if isinstance(raw_value, dict) and "filename" in raw_value:
            filename = str(raw_value.get("filename", "upload.bin"))
            content_type = str(raw_value.get("content_type", "application/octet-stream"))
            content = raw_value.get("content", "")
            content_bytes = content if isinstance(content, bytes) else str(content).encode("utf-8")
            chunks.append(
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
            )
            chunks.append(f"Content-Type: {content_type}\r\n\r\n".encode())
            chunks.append(content_bytes + b"\r\n")
        else:
            chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
            chunks.append(str(raw_value).encode("utf-8") + b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _inject_query(url: str, parameter: str, value: str) -> str:
    parts = urlsplit(url)
    name, requested_index = split_index(parameter)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    matching_seen = 0
    replaced = False
    new_pairs: list[tuple[str, str]] = []
    for key, current in pairs:
        if key == name and matching_seen == requested_index:
            new_pairs.append((key, value))
            replaced = True
            matching_seen += 1
        else:
            new_pairs.append((key, current))
            if key == name:
                matching_seen += 1
    if not replaced:
        if requested_index > 0:
            raise ValueError(f"query parameter occurrence does not exist: {parameter}")
        new_pairs.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(new_pairs, doseq=True), parts.fragment))


def _inject_path(url: str, parameter: str, value: str) -> str:
    parts = urlsplit(url)
    segments = parts.path.split("/")
    nonempty_indexes = [i for i, segment in enumerate(segments) if segment]
    try:
        requested = int(parameter)
    except ValueError as exc:
        raise ValueError("path injection parameter must be a 1-based segment number") from exc
    if requested < 1 or requested > len(nonempty_indexes):
        raise ValueError(f"path segment {requested} does not exist")
    segments[nonempty_indexes[requested - 1]] = quote(value, safe="")
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segments) or "/", parts.query, parts.fragment))


def _auto_location(config: RequestConfig) -> str:
    if config.location != "auto":
        return config.location
    method = config.method.upper()
    if config.body_mode == "query":
        return "query"
    if config.body_mode in {"json", "graphql"}:
        return "json"
    if config.body_mode in {"form", "multipart"}:
        return "form"
    if config.body_mode in {"raw", "xml"}:
        return "raw"
    return "query" if method in {"GET", "HEAD", "DELETE", "OPTIONS"} else "form"


class HTTPClient:
    """Session-aware HTTP transport with bounded retry/rate controls."""

    @staticmethod
    def validate_config(config: RequestConfig, value: str = "1") -> None:
        """Reject deterministic request configuration errors before a scan starts.

        ``request()`` still converts per-request failures into ``ResponseSnapshot``
        objects so network faults never crash an active scan. This preflight is for
        static user/configuration mistakes that should be surfaced as a 4xx/CLI
        error instead of being mistaken for target behavior.
        """
        method = config.method.upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ValueError(f"unsupported HTTP method: {method}")
        if not config.parameter:
            raise ValueError("injection parameter cannot be empty")
        HTTPClient.inject(config, value)
        if config.auth_type not in {None, "", "basic"}:
            raise ValueError(f"unsupported auth_type: {config.auth_type}")
        if config.ca_bundle and not Path(config.ca_bundle).is_file():
            raise ValueError(f"CA bundle not found: {config.ca_bundle}")
        if config.proxy:
            proxy = urlsplit(config.proxy)
            allowed = {"http", "https", "socks4", "socks4a", "socks5", "socks5h"}
            if proxy.scheme.lower() not in allowed or not proxy.hostname:
                raise ValueError("proxy must be a valid HTTP/HTTPS/SOCKS URL")
            if proxy.scheme.lower().startswith("socks"):
                try:
                    import socks  # type: ignore  # noqa: F401
                except ImportError as exc:
                    raise ValueError(
                        "SOCKS proxy support requires PySocks; rerun the installer or install websqlmapper[socks]"
                    ) from exc

    def __init__(self) -> None:
        self.session = requests.Session()
        self._lock = threading.Lock()
        self._last_request_started = 0.0

    @staticmethod
    def inject(config: RequestConfig, value: str) -> tuple[str, bytes | None, dict[str, str]]:
        validate_http_url(config.url)
        if config.timeout <= 0 or config.timeout > 120:
            raise ValueError("timeout must be greater than 0 and at most 120 seconds")
        if config.retries < 0 or config.retries > 5:
            raise ValueError("retries must be between 0 and 5")
        if config.rate < 0 or config.rate > 100:
            raise ValueError("rate must be between 0 and 100 requests/second")
        if config.delay_ms < 0 or config.delay_ms > 60_000:
            raise ValueError("delay_ms must be between 0 and 60000")
        if config.jitter_ms < 0 or config.jitter_ms > 60_000:
            raise ValueError("jitter_ms must be between 0 and 60000")

        location = _auto_location(config)
        allowed_locations = {"query", "form", "json", "graphql", "cookie", "header", "path", "raw"}
        if location not in allowed_locations:
            raise ValueError(f"location must be one of: {', '.join(sorted(allowed_locations))}, auto")

        headers = dict(config.headers)
        cookies = dict(config.cookies)
        url = config.url
        body: bytes | None = None

        if config.bearer_token:
            _replace_header(headers, "Authorization", f"Bearer {config.bearer_token}")

        if location == "query":
            url = _inject_query(url, config.parameter, value)
        elif location == "path":
            url = _inject_path(url, config.parameter, value)
        elif location == "cookie":
            cookies[config.parameter] = value
        elif location == "header":
            _replace_header(headers, config.parameter, value)
        elif location == "json" or location == "graphql":
            data = _set_nested(config.data, config.parameter, value)
            body = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif location == "form":
            if config.body_mode == "multipart":
                if not isinstance(config.data, dict):
                    raise ValueError("multipart data must be a JSON object")
                body, content_type = _multipart_encode(config.data, config.parameter, value)
                headers["Content-Type"] = content_type
            else:
                if not isinstance(config.data, dict):
                    raise ValueError("form data must be a JSON object")
                data = dict(config.data)
                data[config.parameter] = value
                body = urlencode(data, doseq=True).encode("utf-8")
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif location == "raw":
            template = config.raw_body
            if template is None:
                raise ValueError("raw/XML injection requires raw_body with a {{INJECT}} placeholder")
            if "{{INJECT}}" not in template:
                raise ValueError("raw/XML injection requires a {{INJECT}} placeholder")
            body = template.replace("{{INJECT}}", value, 1).encode("utf-8")
            if config.body_mode == "xml":
                headers.setdefault("Content-Type", "application/xml")

        if cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        return url, body, headers

    def _pace(self, config: RequestConfig) -> None:
        base_delay = config.delay_ms / 1000.0
        jitter = random.uniform(0, config.jitter_ms / 1000.0) if config.jitter_ms else 0.0
        with self._lock:
            now = time.monotonic()
            rate_wait = 0.0
            if config.rate > 0 and self._last_request_started:
                rate_wait = max(0.0, (1.0 / config.rate) - (now - self._last_request_started))
            wait_for = max(rate_wait, base_delay + jitter)
            if wait_for:
                time.sleep(wait_for)
            self._last_request_started = time.monotonic()

    def request(self, config: RequestConfig, value: str) -> ResponseSnapshot:
        try:
            url, body, headers = self.inject(config, value)
        except (ValueError, TypeError) as exc:
            return ResponseSnapshot(
                status=0,
                body="",
                elapsed=0.0,
                final_url=config.url,
                headers={},
                error=f"request configuration error: {exc}",
                request_method=config.method.upper(),
                request_url=config.url,
            )

        auth = None
        if config.auth_type:
            if config.auth_type != "basic":
                return ResponseSnapshot(
                    status=0, body="", elapsed=0.0, final_url=url, headers={},
                    error=f"unsupported auth_type: {config.auth_type}", request_method=config.method.upper(), request_url=url,
                )
            auth = HTTPBasicAuth(config.auth_username or "", config.auth_password or "")

        proxies = None
        if config.proxy:
            if config.proxy.lower().startswith(("socks4://", "socks4a://", "socks5://", "socks5h://")):
                try:
                    import socks  # type: ignore  # noqa: F401
                except ImportError:
                    return ResponseSnapshot(
                        status=0, body="", elapsed=0.0, final_url=url, headers={},
                        error="SOCKS proxy support requires PySocks; rerun the installer or install websqlmapper[socks]",
                        request_method=config.method.upper(), request_url=url, request_headers=redact_headers(headers),
                    )
            proxies = {"http": config.proxy, "https": config.proxy}

        attempts = max(1, config.retries + 1)
        last_error: str | None = None
        started_total = time.perf_counter()
        for attempt in range(1, attempts + 1):
            self._pace(config)
            started = time.perf_counter()
            try:
                verify_value: bool | str = config.verify_tls
                if config.ca_bundle:
                    if not Path(config.ca_bundle).is_file():
                        return ResponseSnapshot(status=0, body="", elapsed=0.0, final_url=url, headers={}, error=f"CA bundle not found: {config.ca_bundle}", request_method=config.method.upper(), request_url=url, request_headers=redact_headers(headers))
                    verify_value = config.ca_bundle
                response = self.session.request(
                    method=config.method.upper(),
                    url=url,
                    data=body,
                    headers=headers,
                    timeout=config.timeout,
                    allow_redirects=config.follow_redirects,
                    verify=verify_value,
                    proxies=proxies,
                    auth=auth,
                )
                elapsed = time.perf_counter() - started
                text = response.text[:1_500_000]
                if response.status_code in _RETRY_STATUS and attempt < attempts:
                    last_error = f"transient HTTP {response.status_code}"
                    time.sleep(min(1.0, 0.15 * (2 ** (attempt - 1))))
                    continue
                return ResponseSnapshot(
                    status=response.status_code,
                    body=text,
                    elapsed=elapsed,
                    final_url=str(response.url),
                    headers=dict(response.headers),
                    error=None,
                    request_method=config.method.upper(),
                    request_url=url,
                    request_headers=redact_headers(headers),
                    request_body=(redact_text_secrets(body.decode("utf-8", errors="replace")[:200_000]) if body is not None else None),
                    attempt=attempt,
                )
            except RequestException as exc:
                last_error = f"{exc.__class__.__name__}: {exc}"
                if attempt < attempts:
                    time.sleep(min(1.0, 0.15 * (2 ** (attempt - 1))))
                    continue
                elapsed = time.perf_counter() - started_total
                return ResponseSnapshot(
                    status=0,
                    body="",
                    elapsed=elapsed,
                    final_url=url,
                    headers={},
                    error=last_error,
                    request_method=config.method.upper(),
                    request_url=url,
                    request_headers=redact_headers(headers),
                    request_body=(redact_text_secrets(body.decode("utf-8", errors="replace")[:200_000]) if body is not None else None),
                    attempt=attempt,
                )

        return ResponseSnapshot(
            status=0, body="", elapsed=time.perf_counter() - started_total, final_url=url, headers={},
            error=last_error or "request failed", request_method=config.method.upper(), request_url=url,
        )


def with_timeout(config: RequestConfig, timeout: float) -> RequestConfig:
    return replace(config, timeout=timeout)
