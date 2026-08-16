from __future__ import annotations

import base64
import copy
import json
import random
import re
import threading
import time
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException

from .importers import parse_nested_path, split_index
from .models import RedirectHop, RequestConfig, ResponseSnapshot
from .safety import validate_http_url

_RETRY_STATUS = {429, 502, 503, 504}
_REDIRECT_STATUS = {301, 302, 303, 307, 308}
_SECRET_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key"}
_SAFE_RETRY_METHODS = {"GET", "HEAD", "OPTIONS"}


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key: ("<redacted>" if key.lower() in _SECRET_HEADERS else value) for key, value in headers.items()}


def redact_text_secrets(text: str) -> str:
    if not text:
        return text
    masked = re.sub(r'(?i)(["\']?(?:password|passwd|secret|token|access_token|api_key|authorization)["\']?\s*[:=]\s*["\']?)([^"\'&\s,}]+)', r'\1<redacted>', text)
    return re.sub(
        r'(?is)(<(?:password|passwd|secret|token|access_token|api_key|authorization)\b[^>]*>)(.*?)(</(?:password|passwd|secret|token|access_token|api_key|authorization)>)',
        r'\1<redacted>\3', masked,
    )


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


def _remove_header(headers: dict[str, str], name: str) -> None:
    existing = next((key for key in headers if key.lower() == name.lower()), None)
    if existing:
        headers.pop(existing, None)


def _multipart_encode(data: Any, inject_name: str, inject_value: str) -> tuple[bytes, str]:
    boundary = "----WebSQLMapper" + uuid.uuid4().hex
    if isinstance(data, dict):
        pairs: list[tuple[str, Any]] = [(str(k), v) for k, v in data.items()]
    elif isinstance(data, list) and all(isinstance(item, (list, tuple)) and len(item) == 2 for item in data):
        pairs = [(str(item[0]), item[1]) for item in data]
    else:
        raise ValueError("multipart data must be a JSON object or ordered [name, value] pairs")
    name, requested_index = split_index(inject_name)
    seen = 0
    replaced = False
    fields: list[tuple[str, Any]] = []
    for field_name, raw_value in pairs:
        if field_name == name and seen == requested_index:
            fields.append((field_name, inject_value)); replaced = True; seen += 1
        else:
            fields.append((field_name, raw_value))
            if field_name == name:
                seen += 1
    if not replaced:
        if requested_index > 0:
            raise ValueError(f"multipart parameter occurrence does not exist: {inject_name}")
        fields.append((name, inject_value))
    chunks: list[bytes] = []
    for field_name, raw_value in fields:
        chunks.append(f"--{boundary}\r\n".encode())
        if isinstance(raw_value, dict) and "filename" in raw_value:
            filename = str(raw_value.get("filename", "upload.bin"))
            content_type = str(raw_value.get("content_type", "application/octet-stream"))
            if "content_base64" in raw_value:
                try:
                    content_bytes = base64.b64decode(str(raw_value["content_base64"]), validate=True)
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"invalid base64 content for multipart field {field_name}") from exc
            else:
                content = raw_value.get("content", "")
                content_bytes = content if isinstance(content, bytes) else str(content).encode("utf-8")
            chunks.append(f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode())
            chunks.append(f"Content-Type: {content_type}\r\n\r\n".encode())
            chunks.append(content_bytes + b"\r\n")
        else:
            chunks.append(f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n'.encode())
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
            new_pairs.append((key, value)); replaced = True; matching_seen += 1
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
    if config.body_mode == "query": return "query"
    if config.body_mode in {"json", "graphql"}: return "json"
    if config.body_mode in {"form", "multipart"}: return "form"
    if config.body_mode in {"raw", "xml"}: return "raw"
    return "query" if method in {"GET", "HEAD", "DELETE", "OPTIONS"} else "form"


def _origin(url: str) -> tuple[str, str, int | None]:
    parts = urlsplit(url)
    port = parts.port
    if port is None:
        port = 443 if parts.scheme.lower() == "https" else 80 if parts.scheme.lower() == "http" else None
    return parts.scheme.lower(), (parts.hostname or "").lower(), port


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _redirect_allowed(policy: str, source: str, target: str) -> bool:
    if policy == "any": return True
    if policy == "same-host": return _host(source) == _host(target)
    if policy == "same-origin": return _origin(source) == _origin(target)
    return False


def _redirect_method(method: str, status: int) -> str:
    method = method.upper()
    if status == 303 and method != "HEAD": return "GET"
    if status in {301, 302} and method == "POST": return "GET"
    return method


def _retry_after_seconds(value: str | None) -> float | None:
    if not value: return None
    value = value.strip()
    try:
        return max(0.0, min(30.0, float(value)))
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None: when = when.replace(tzinfo=timezone.utc)
            return max(0.0, min(30.0, (when - datetime.now(timezone.utc)).total_seconds()))
        except (TypeError, ValueError, OverflowError):
            return None


class HTTPClient:
    """Session-aware HTTP transport with bounded redirects, retries, streaming, and rate controls."""

    def __init__(self) -> None:
        self._local = threading.local()
        self._pace_lock = threading.Lock()
        self._last_request_started = 0.0
        self.sleep_callback: Callable[[float], None] | None = None

    def _sleep(self, seconds: float) -> None:
        if seconds <= 0: return
        if self.sleep_callback:
            self.sleep_callback(seconds)
        else:
            time.sleep(seconds)

    def _session(self, config: RequestConfig) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            self._local.session = session
            self._local.seeded_cookie_signature = None
        if config.cookie_mode in {"session", "merge"}:
            signature = tuple(sorted(config.cookies.items()))
            if self._local.seeded_cookie_signature != signature:
                session.cookies.update(config.cookies)
                self._local.seeded_cookie_signature = signature
        elif config.cookie_mode == "static":
            session.cookies.clear()
            self._local.seeded_cookie_signature = None
        return session

    @staticmethod
    def validate_config(config: RequestConfig, value: str = "1") -> None:
        method = config.method.upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ValueError(f"unsupported HTTP method: {method}")
        if not config.parameter: raise ValueError("injection parameter cannot be empty")
        HTTPClient.inject(config, value)
        if config.auth_type not in {None, "", "basic"}: raise ValueError(f"unsupported auth_type: {config.auth_type}")
        if config.ca_bundle and not Path(config.ca_bundle).is_file(): raise ValueError(f"CA bundle not found: {config.ca_bundle}")
        if config.client_cert and not Path(config.client_cert).is_file(): raise ValueError(f"client certificate not found: {config.client_cert}")
        if config.client_key and not Path(config.client_key).is_file(): raise ValueError(f"client key not found: {config.client_key}")
        if config.client_key and not config.client_cert: raise ValueError("client_key requires client_cert")
        if config.effective_redirect_policy not in {"never", "same-origin", "same-host", "any"}: raise ValueError("redirect_policy must be never, same-origin, same-host, or any")
        if config.max_redirects < 0 or config.max_redirects > 20: raise ValueError("max_redirects must be between 0 and 20")
        if config.retry_policy not in {"safe", "all", "none"}: raise ValueError("retry_policy must be safe, all, or none")
        if config.cookie_mode not in {"static", "session", "merge"}: raise ValueError("cookie_mode must be static, session, or merge")
        if config.max_body_bytes < 1024 or config.max_body_bytes > 50_000_000: raise ValueError("max_body_bytes must be between 1024 and 50000000")
        if config.concurrency < 1 or config.concurrency > 8: raise ValueError("concurrency must be between 1 and 8")
        if config.cookie_mode != "static" and config.concurrency > 1: raise ValueError("concurrency > 1 requires cookie_mode=static to avoid session-state races")
        connect, read = config.effective_timeout
        if connect <= 0 or connect > 120 or read <= 0 or read > 120: raise ValueError("connect/read timeouts must be greater than 0 and at most 120 seconds")
        if config.max_duration <= 0 or config.max_duration > 86_400: raise ValueError("max_duration must be greater than 0 and at most 86400 seconds")
        if config.proxy:
            proxy = urlsplit(config.proxy)
            allowed = {"http", "https", "socks4", "socks4a", "socks5", "socks5h"}
            if proxy.scheme.lower() not in allowed or not proxy.hostname: raise ValueError("proxy must be a valid HTTP/HTTPS/SOCKS URL")
            if proxy.scheme.lower().startswith("socks"):
                try: import socks  # type: ignore  # noqa: F401
                except ImportError as exc: raise ValueError("SOCKS proxy support requires PySocks; rerun the installer or install websqlmapper[socks]") from exc

    @staticmethod
    def inject(config: RequestConfig, value: str) -> tuple[str, bytes | None, dict[str, str]]:
        validate_http_url(config.url)
        if config.timeout <= 0 or config.timeout > 120: raise ValueError("timeout must be greater than 0 and at most 120 seconds")
        if config.retries < 0 or config.retries > 5: raise ValueError("retries must be between 0 and 5")
        if config.rate < 0 or config.rate > 100: raise ValueError("rate must be between 0 and 100 requests/second")
        if config.delay_ms < 0 or config.delay_ms > 60_000: raise ValueError("delay_ms must be between 0 and 60000")
        if config.jitter_ms < 0 or config.jitter_ms > 60_000: raise ValueError("jitter_ms must be between 0 and 60000")
        location = _auto_location(config)
        allowed_locations = {"query", "form", "json", "graphql", "cookie", "header", "path", "raw"}
        if location not in allowed_locations: raise ValueError(f"location must be one of: {', '.join(sorted(allowed_locations))}, auto")
        headers = dict(config.headers); cookies = dict(config.cookies); url = config.url; body: bytes | None = None
        if config.bearer_token: _replace_header(headers, "Authorization", f"Bearer {config.bearer_token}")
        if location == "query": url = _inject_query(url, config.parameter, value)
        elif location == "path": url = _inject_path(url, config.parameter, value)
        elif location == "cookie": cookies[config.parameter] = value
        elif location == "header": _replace_header(headers, config.parameter, value)
        elif location in {"json", "graphql"}:
            data = _set_nested(config.data, config.parameter, value)
            body = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif location == "form":
            if config.body_mode == "multipart":
                body, content_type = _multipart_encode(config.data, config.parameter, value); headers["Content-Type"] = content_type
            else:
                name, requested_index = split_index(config.parameter)
                if isinstance(config.data, dict):
                    pairs = [(str(k), str(v)) for k, v in config.data.items()]
                elif isinstance(config.data, list) and all(isinstance(item, (list, tuple)) and len(item) == 2 for item in config.data):
                    pairs = [(str(item[0]), str(item[1])) for item in config.data]
                else:
                    raise ValueError("form data must be a JSON object or ordered [name, value] pairs")
                seen = 0; replaced = False; out_pairs: list[tuple[str, str]] = []
                for key, current in pairs:
                    if key == name and seen == requested_index:
                        out_pairs.append((key, value)); replaced = True; seen += 1
                    else:
                        out_pairs.append((key, current))
                        if key == name: seen += 1
                if not replaced:
                    if requested_index > 0: raise ValueError(f"form parameter occurrence does not exist: {config.parameter}")
                    out_pairs.append((name, value))
                body = urlencode(out_pairs, doseq=True).encode("utf-8"); headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif location == "raw":
            template = config.raw_body
            if template is None or "{{INJECT}}" not in template: raise ValueError("raw/XML injection requires raw_body with a {{INJECT}} placeholder")
            body = template.replace("{{INJECT}}", value, 1).encode("utf-8")
            if config.body_mode == "xml": headers.setdefault("Content-Type", "application/xml")
        if cookies and config.cookie_mode == "static": headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        return url, body, headers

    def _pace(self, config: RequestConfig) -> None:
        base_delay = config.delay_ms / 1000.0
        jitter = random.uniform(0, config.jitter_ms / 1000.0) if config.jitter_ms else 0.0
        with self._pace_lock:
            now = time.monotonic(); rate_wait = 0.0
            if config.rate > 0 and self._last_request_started: rate_wait = max(0.0, (1.0 / config.rate) - (now - self._last_request_started))
            wait_for = max(rate_wait, base_delay + jitter)
            if wait_for: self._sleep(wait_for)
            self._last_request_started = time.monotonic()

    def _read_limited(self, response: requests.Response, limit: int) -> tuple[str, bool]:
        chunks: list[bytes] = []; total = 0; truncated = False
        for chunk in response.iter_content(chunk_size=32_768):
            if not chunk: continue
            remaining = limit - total
            if remaining <= 0: truncated = True; break
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining]); total += remaining; truncated = True; break
            chunks.append(chunk); total += len(chunk)
        raw = b"".join(chunks)
        encoding = response.encoding or "utf-8"
        try: return raw.decode(encoding, errors="replace"), truncated
        except LookupError: return raw.decode("utf-8", errors="replace"), truncated

    def _can_retry(self, config: RequestConfig, method: str) -> bool:
        if config.retry_policy == "none": return False
        if config.retry_policy == "all": return True
        return method.upper() in _SAFE_RETRY_METHODS

    def request(self, config: RequestConfig, value: str) -> ResponseSnapshot:
        try: url, body, headers = self.inject(config, value)
        except (ValueError, TypeError) as exc:
            return ResponseSnapshot(status=0, body="", elapsed=0.0, final_url=config.url, headers={}, error=f"request configuration error: {exc}", request_method=config.method.upper(), request_url=config.url)
        auth: HTTPBasicAuth | None = None
        if config.auth_type:
            if config.auth_type != "basic": return ResponseSnapshot(status=0, body="", elapsed=0.0, final_url=url, headers={}, error=f"unsupported auth_type: {config.auth_type}", request_method=config.method.upper(), request_url=url)
            auth = HTTPBasicAuth(config.auth_username or "", config.auth_password or "")
        proxies = {"http": config.proxy, "https": config.proxy} if config.proxy else None
        verify_value: bool | str = config.ca_bundle or config.verify_tls
        session = self._session(config)
        redirect_policy = config.effective_redirect_policy
        method = config.method.upper(); current_url = url; current_body = body; current_headers = dict(headers); current_auth = auth
        redirects: list[RedirectHop] = []; visited = {current_url}; started_total = time.perf_counter(); attempt_total = 0
        while True:
            attempts = max(1, config.retries + 1) if self._can_retry(config, method) else 1
            response: requests.Response | None = None; last_error: str | None = None
            for attempt in range(1, attempts + 1):
                attempt_total += 1; self._pace(config); started = time.perf_counter()
                try:
                    cert_value = (config.client_cert, config.client_key) if config.client_cert and config.client_key else config.client_cert
                    response = session.request(method=method, url=current_url, data=current_body, headers=current_headers,
                        timeout=config.effective_timeout, allow_redirects=False, verify=verify_value, proxies=proxies,
                        auth=current_auth, cert=cert_value, stream=True)
                    if response.status_code in _RETRY_STATUS and attempt < attempts:
                        retry_after = _retry_after_seconds(response.headers.get("Retry-After"))
                        response.close(); self._sleep(retry_after if retry_after is not None else min(2.0, 0.15 * (2 ** (attempt - 1)))); continue
                    break
                except RequestException as exc:
                    last_error = f"{exc.__class__.__name__}: {exc}"
                    if attempt < attempts:
                        self._sleep(min(2.0, 0.15 * (2 ** (attempt - 1)))); continue
                    return ResponseSnapshot(status=0, body="", elapsed=time.perf_counter()-started_total, final_url=current_url, headers={}, error=last_error,
                        request_method=method, request_url=current_url, request_headers=redact_headers(current_headers),
                        request_body=(redact_text_secrets((current_body or b"").decode("utf-8", errors="replace")[:200_000]) if current_body is not None else None), attempt=attempt_total, redirects=redirects)
            if response is None:
                return ResponseSnapshot(status=0, body="", elapsed=time.perf_counter()-started_total, final_url=current_url, headers={}, error=last_error or "request failed", request_method=method, request_url=current_url, redirects=redirects)
            body_text, truncated = self._read_limited(response, config.max_body_bytes)
            elapsed = time.perf_counter() - started_total
            status = response.status_code; content_type = response.headers.get("Content-Type", "")
            location = response.headers.get("Location")
            if status not in _REDIRECT_STATUS or not location:
                response.close()
                return ResponseSnapshot(status=status, body=body_text, elapsed=elapsed, final_url=str(response.url), headers=dict(response.headers), error=None,
                    request_method=config.method.upper(), request_url=url, request_headers=redact_headers(headers),
                    request_body=(redact_text_secrets((body or b"").decode("utf-8", errors="replace")[:200_000]) if body is not None else None),
                    attempt=attempt_total, content_type=content_type, body_truncated=truncated, redirects=redirects,
                    redirect_outcome="followed" if redirects else None)
            target = urljoin(str(response.url), location)
            source_origin = _origin(str(response.url)); target_origin = _origin(target)
            hop = RedirectHop(index=len(redirects)+1, status=status, method=method, url=str(response.url), location=target,
                elapsed_ms=round((time.perf_counter()-started_total)*1000,2), cross_host=source_origin[1]!=target_origin[1],
                cross_origin=source_origin!=target_origin, https_downgrade=source_origin[0]=="https" and target_origin[0]=="http")
            redirects.append(hop); response.close()
            if redirect_policy == "never" or not _redirect_allowed(redirect_policy, str(response.url), target):
                return ResponseSnapshot(status=status, body=body_text, elapsed=elapsed, final_url=str(response.url), headers=dict(response.headers), error=None,
                    request_method=config.method.upper(), request_url=url, request_headers=redact_headers(headers), request_body=(redact_text_secrets((body or b"").decode("utf-8", errors="replace")[:200_000]) if body is not None else None),
                    attempt=attempt_total, content_type=content_type, body_truncated=truncated, redirects=redirects, redirect_outcome="blocked-policy")
            if len(redirects) > config.max_redirects:
                return ResponseSnapshot(status=status, body=body_text, elapsed=elapsed, final_url=str(response.url), headers=dict(response.headers), error="maximum redirects reached",
                    request_method=config.method.upper(), request_url=url, request_headers=redact_headers(headers), attempt=attempt_total, content_type=content_type, body_truncated=truncated, redirects=redirects, redirect_outcome="max-redirects")
            if target in visited:
                return ResponseSnapshot(status=status, body=body_text, elapsed=elapsed, final_url=str(response.url), headers=dict(response.headers), error="redirect loop detected",
                    request_method=config.method.upper(), request_url=url, request_headers=redact_headers(headers), attempt=attempt_total, content_type=content_type, body_truncated=truncated, redirects=redirects, redirect_outcome="loop")
            visited.add(target)
            new_method = _redirect_method(method, status)
            if new_method != method:
                current_body = None; _remove_header(current_headers, "Content-Type"); _remove_header(current_headers, "Content-Length")
            method = new_method
            if hop.cross_host:
                _remove_header(current_headers, "Authorization"); _remove_header(current_headers, "Cookie"); current_auth = None
            current_url = target


def with_timeout(config: RequestConfig, timeout: float) -> RequestConfig:
    return replace(config, timeout=timeout, connect_timeout=timeout, read_timeout=timeout)
