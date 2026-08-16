from __future__ import annotations

import base64
import json
import re
import shlex
from email import policy
from email.parser import BytesParser
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from .models import InjectionPoint, RequestConfig


class RequestParseError(ValueError):
    pass


@dataclass(slots=True)
class ImportedRequest:
    config: RequestConfig
    source: str
    raw: str

    def to_dict(self, *, redact: bool = True) -> dict[str, Any]:
        data = self.config.clone_dict()
        if redact:
            # Import/parse output should not expose credentials by default.
            if data.get("auth_password"):
                data["auth_password"] = "<redacted>"
            if data.get("bearer_token"):
                data["bearer_token"] = "<redacted>"
            if "Authorization" in data.get("headers", {}):
                data["headers"]["Authorization"] = "<redacted>"
            if data.get("cookies"):
                data["cookies"] = {key: "<redacted>" for key in data["cookies"]}
        return {"source": self.source, "request": data}


def read_text_input(value: str) -> str:
    if value == "-":
        import sys
        return sys.stdin.read()
    path = Path(value)
    if path.is_file():
        return path.read_text(encoding="utf-8", errors="replace")
    return value


def _parse_cookie_header(value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in value.split(";"):
        if "=" not in part:
            continue
        key, val = part.split("=", 1)
        if key.strip():
            cookies[key.strip()] = val.strip()
    return cookies


def _body_from_content_type(content_type: str, body: str) -> tuple[str, Any, str | None]:
    lowered = content_type.lower()
    if "application/json" in lowered or "application/graphql+json" in lowered:
        if not body.strip():
            return "json", {}, None
        try:
            return "json", json.loads(body), None
        except json.JSONDecodeError as exc:
            raise RequestParseError(f"invalid JSON request body: {exc.msg}") from exc
    if "application/x-www-form-urlencoded" in lowered:
        pairs = parse_qsl(body, keep_blank_values=True)
        names = [name for name, _ in pairs]
        data: Any = pairs if len(names) != len(set(names)) else dict(pairs)
        return "form", data, None
    if "multipart/form-data" in lowered:
        try:
            message = BytesParser(policy=policy.default).parsebytes(
                (f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n").encode("utf-8")
                + body.replace("\n", "\r\n").encode("utf-8", errors="replace")
            )
        except (ValueError, TypeError) as exc:
            raise RequestParseError(f"invalid multipart request body: {exc}") from exc
        if not message.is_multipart():
            raise RequestParseError("multipart/form-data body does not match its boundary")
        pairs: list[list[object]] = []
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if not name:
                continue
            payload = part.get_payload(decode=True) or b""
            filename = part.get_filename()
            if filename:
                value: object = {
                    "filename": filename,
                    "content_type": part.get_content_type() or "application/octet-stream",
                    "content_base64": base64.b64encode(payload).decode("ascii"),
                }
            else:
                charset = part.get_content_charset() or "utf-8"
                try:
                    value = payload.decode(charset, errors="replace")
                except LookupError:
                    value = payload.decode("utf-8", errors="replace")
            pairs.append([str(name), value])
        names = [str(item[0]) for item in pairs]
        data: Any = pairs if len(names) != len(set(names)) else {str(k): v for k, v in pairs}
        return "multipart", data, None
    if "xml" in lowered:
        return "xml", {}, body
    if body:
        return "raw", {}, body
    return "auto", {}, None


def parse_raw_request(text: str, *, scheme: str = "https") -> ImportedRequest:
    if not isinstance(text, str) or not text.strip():
        raise RequestParseError("raw HTTP request is empty")
    normalized = text.replace("\r\n", "\n")
    head, sep, body = normalized.partition("\n\n")
    lines = head.split("\n")
    request_line = lines[0].strip() if lines else ""
    match = re.fullmatch(r"([A-Za-z]+)\s+(\S+)\s+HTTP/\d(?:\.\d)?", request_line)
    if not match:
        raise RequestParseError("first line must look like: GET /path HTTP/1.1")
    method, target = match.group(1).upper(), match.group(2)
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise RequestParseError(f"unsupported HTTP method: {method}")

    headers: dict[str, str] = {}
    seen_headers: set[str] = set()
    host = ""
    for line in lines[1:]:
        if not line.strip():
            continue
        if line[:1].isspace():
            raise RequestParseError("folded HTTP headers are not supported")
        if ":" not in line:
            raise RequestParseError(f"malformed header line: {line!r}")
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            raise RequestParseError("HTTP header name cannot be empty")
        lowered_name = name.lower()
        if lowered_name in seen_headers and lowered_name not in {"cookie"}:
            raise RequestParseError(f"duplicate HTTP header is not losslessly supported: {name}")
        seen_headers.add(lowered_name)
        if lowered_name == "host":
            host = value
        elif lowered_name not in {"content-length", "cookie"}:
            headers[name] = value

    if target.startswith(("http://", "https://")):
        url = target
    else:
        if not host:
            raise RequestParseError("relative request target requires a Host header")
        if not target.startswith("/"):
            target = "/" + target
        if scheme not in {"http", "https"}:
            raise RequestParseError("scheme must be http or https")
        url = f"{scheme}://{host}{target}"

    cookie_value = ""
    for line in lines[1:]:
        if line.lower().startswith("cookie:"):
            cookie_value = line.split(":", 1)[1].strip()
            break
    cookies = _parse_cookie_header(cookie_value)
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    body_mode, data, raw_body = _body_from_content_type(content_type, body if sep else "")

    return ImportedRequest(
        config=RequestConfig(
            url=url,
            method=method,
            data=data,
            headers=headers,
            cookies=cookies,
            body_mode=body_mode,
            raw_body=raw_body,
        ),
        source="raw-http",
        raw=text,
    )


def _normalize_curl_text(text: str) -> str:
    text = text.strip()
    text = re.sub(r"\\\r?\n\s*", " ", text)
    text = re.sub(r"\^\r?\n\s*", " ", text)
    return text


def parse_curl(text: str) -> ImportedRequest:
    text = _normalize_curl_text(text)
    if not text:
        raise RequestParseError("cURL input is empty")
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError as exc:
        raise RequestParseError(f"invalid cURL quoting: {exc}") from exc
    if not tokens or Path(tokens[0]).name.lower() not in {"curl", "curl.exe"}:
        raise RequestParseError("cURL input must start with curl")

    method: str | None = None
    url: str | None = None
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    data_parts: list[str] = []
    form_parts: list[list[object]] = []
    proxy: str | None = None
    verify_tls = True
    ca_bundle: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    connect_timeout: float | None = None
    max_duration: float = 300.0
    max_redirects: int = 5
    retries: int = 1
    follow_redirects = False
    auth_type: str | None = None
    auth_username: str | None = None
    auth_password: str | None = None

    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token in {"-X", "--request"}:
            i += 1
            if i >= len(tokens):
                raise RequestParseError(f"{token} requires a method")
            method = tokens[i].upper()
        elif token in {"-H", "--header"}:
            i += 1
            if i >= len(tokens) or ":" not in tokens[i]:
                raise RequestParseError(f"{token} requires 'Name: value'")
            name, value = tokens[i].split(":", 1)
            name = name.strip()
            if name.lower() == "cookie":
                cookies.update(_parse_cookie_header(value))
            else:
                if any(existing.lower() == name.lower() for existing in headers):
                    raise RequestParseError(f"duplicate cURL header is not losslessly supported: {name}")
                headers[name] = value.strip()
        elif token in {"-b", "--cookie"}:
            i += 1
            if i >= len(tokens):
                raise RequestParseError(f"{token} requires cookie data")
            cookies.update(_parse_cookie_header(tokens[i]))
        elif token in {"-F", "--form"}:
            i += 1
            if i >= len(tokens) or "=" not in tokens[i]:
                raise RequestParseError(f"{token} requires NAME=VALUE")
            name, form_value = tokens[i].split("=", 1)
            if not name:
                raise RequestParseError(f"{token} form name cannot be empty")
            if form_value.startswith("@") or form_value.startswith("<"):
                raise RequestParseError("cURL multipart file references are not read automatically; import a captured raw HTTP request instead")
            form_parts.append([name, form_value])
            method = method or "POST"
        elif token in {"-d", "--data", "--data-raw", "--data-binary", "--data-ascii"}:
            i += 1
            if i >= len(tokens):
                raise RequestParseError(f"{token} requires data")
            data_parts.append(tokens[i])
            method = method or "POST"
        elif token == "--data-urlencode":
            i += 1
            if i >= len(tokens):
                raise RequestParseError("--data-urlencode requires data")
            data_parts.append(tokens[i])
            method = method or "POST"
        elif token == "--json":
            i += 1
            if i >= len(tokens):
                raise RequestParseError("--json requires a JSON value")
            data_parts.append(tokens[i])
            headers.setdefault("Content-Type", "application/json")
            headers.setdefault("Accept", "application/json")
            method = method or "POST"
        elif token in {"-x", "--proxy"}:
            i += 1
            if i >= len(tokens):
                raise RequestParseError(f"{token} requires a proxy URL")
            proxy = tokens[i]
        elif token in {"-k", "--insecure"}:
            verify_tls = False
        elif token == "--cacert":
            i += 1
            if i >= len(tokens):
                raise RequestParseError("--cacert requires a file path")
            ca_bundle = tokens[i]
        elif token == "--cert":
            i += 1
            if i >= len(tokens):
                raise RequestParseError("--cert requires a certificate path")
            client_cert = tokens[i]
        elif token == "--key":
            i += 1
            if i >= len(tokens):
                raise RequestParseError("--key requires a private-key path")
            client_key = tokens[i]
        elif token in {"--connect-timeout", "--max-time"}:
            i += 1
            if i >= len(tokens):
                raise RequestParseError(f"{token} requires seconds")
            try:
                seconds = float(tokens[i])
            except ValueError as exc:
                raise RequestParseError(f"{token} requires a numeric value") from exc
            if token == "--connect-timeout": connect_timeout = seconds
            else: max_duration = seconds
        elif token == "--max-redirs":
            i += 1
            if i >= len(tokens): raise RequestParseError("--max-redirs requires an integer")
            try: max_redirects = int(tokens[i])
            except ValueError as exc: raise RequestParseError("--max-redirs requires an integer") from exc
        elif token == "--retry":
            i += 1
            if i >= len(tokens): raise RequestParseError("--retry requires an integer")
            try: retries = int(tokens[i])
            except ValueError as exc: raise RequestParseError("--retry requires an integer") from exc
        elif token in {"-A", "--user-agent"}:
            i += 1
            if i >= len(tokens): raise RequestParseError(f"{token} requires a value")
            headers["User-Agent"] = tokens[i]
        elif token in {"-L", "--location"}:
            follow_redirects = True
        elif token in {"-u", "--user"}:
            i += 1
            if i >= len(tokens):
                raise RequestParseError(f"{token} requires USER:PASSWORD")
            userpass = tokens[i]
            auth_username, _, auth_password = userpass.partition(":")
            auth_type = "basic"
        elif token == "--url":
            i += 1
            if i >= len(tokens):
                raise RequestParseError("--url requires a URL")
            url = tokens[i]
        elif token.startswith("-"):
            if token in {"-s", "--silent", "-S", "--show-error", "--compressed", "--fail", "--fail-with-body"}:
                pass
            else:
                raise RequestParseError(f"unsupported cURL option: {token}")
        else:
            if url is None and token.startswith(("http://", "https://")):
                url = token
            elif url is None:
                raise RequestParseError(f"unexpected cURL token: {token!r}")
        i += 1

    if not url:
        raise RequestParseError("cURL command does not contain a URL")
    method = method or "GET"
    if form_parts and data_parts:
        raise RequestParseError("cannot combine cURL multipart --form and --data options in one imported request")
    body = "&".join(data_parts)
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    if form_parts:
        names = [str(item[0]) for item in form_parts]
        data = form_parts if len(names) != len(set(names)) else {str(k): v for k, v in form_parts}
        body_mode, raw_body = "multipart", None
        headers.pop(next((k for k in headers if k.lower() == "content-type"), ""), None)
    else:
        body_mode, data, raw_body = _body_from_content_type(content_type, body)
    if body and not content_type and not form_parts:
        body_mode, data, raw_body = "form", dict(parse_qsl(body, keep_blank_values=True)), None
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    config = RequestConfig(
        url=url,
        method=method,
        data=data,
        headers=headers,
        cookies=cookies,
        body_mode=body_mode,
        raw_body=raw_body,
        proxy=proxy,
        verify_tls=verify_tls,
        ca_bundle=ca_bundle,
        client_cert=client_cert,
        client_key=client_key,
        connect_timeout=connect_timeout,
        max_duration=max_duration,
        follow_redirects=follow_redirects,
        redirect_policy="any" if follow_redirects else "never",
        max_redirects=max_redirects,
        retries=retries,
        auth_type=auth_type,
        auth_username=auth_username,
        auth_password=auth_password,
    )
    return ImportedRequest(config=config, source="curl", raw=text)


def infer_original_value(config: RequestConfig, location: str, parameter: str, fallback: str = "1") -> str:
    """Best-effort extraction of the current value at an injection point."""
    try:
        if location == "query":
            name, index = split_index(parameter)
            values = [value for key, value in parse_qsl(urlsplit(config.url).query, keep_blank_values=True) if key == name]
            return values[index] if values else fallback
        if location == "form":
            name, index = split_index(parameter)
            if isinstance(config.data, dict):
                return str(config.data.get(name, fallback))
            if isinstance(config.data, list):
                values = [str(item[1]) for item in config.data if isinstance(item, (list, tuple)) and len(item) == 2 and str(item[0]) == name]
                return values[index] if index < len(values) else fallback
        if location in {"json", "graphql"}:
            value = get_nested(config.data, parameter)
            return fallback if value is None else str(value)
        if location == "cookie":
            return config.cookies.get(parameter, fallback)
        if location == "header":
            return next((v for k, v in config.headers.items() if k.lower() == parameter.lower()), fallback)
        if location == "path":
            segments = [unquote_plus(x) for x in urlsplit(config.url).path.split("/") if x]
            idx = int(parameter) - 1
            return segments[idx] if 0 <= idx < len(segments) else fallback
    except (ValueError, IndexError, KeyError, TypeError):
        return fallback
    return fallback


def split_index(parameter: str) -> tuple[str, int]:
    match = re.fullmatch(r"(.+?)\[(\d+)]", parameter)
    if not match:
        return parameter, 0
    return match.group(1), int(match.group(2))


def parse_nested_path(path: str) -> list[str | int]:
    if not path:
        raise ValueError("nested path cannot be empty")
    tokens: list[str | int] = []
    for name, index in re.findall(r"([^.\[\]]+)|\[(\d+)]", path):
        tokens.append(name if name else int(index))
    if not tokens:
        raise ValueError(f"invalid nested path: {path!r}")
    return tokens


def get_nested(data: Any, path: str) -> Any:
    current = data
    for token in parse_nested_path(path):
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current):
                raise KeyError(path)
            current = current[token]
        else:
            if not isinstance(current, dict) or token not in current:
                raise KeyError(path)
            current = current[token]
    return current


_SENSITIVE_POINT = re.compile(r"(?i)(?:pass|secret|token|auth|session|cookie|api[_-]?key|csrf|xsrf)")

def _walk_json_points(value: Any, prefix: str = "") -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(item, (dict, list)):
                points.extend(_walk_json_points(item, path))
            else:
                points.append(InjectionPoint("json", path, "" if item is None else str(item), bool(_SENSITIVE_POINT.search(path)), path))
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            path = f"{prefix}[{idx}]"
            if isinstance(item, (dict, list)):
                points.extend(_walk_json_points(item, path))
            else:
                points.append(InjectionPoint("json", path, "" if item is None else str(item), bool(_SENSITIVE_POINT.search(path)), path))
    return points

def discover_injection_points(config: RequestConfig) -> list[InjectionPoint]:
    """Enumerate existing request-controlled values without sending traffic."""
    points: list[InjectionPoint] = []
    query_pairs = parse_qsl(urlsplit(config.url).query, keep_blank_values=True)
    counts: dict[str, int] = {}
    totals: dict[str, int] = {}
    for name, _ in query_pairs: totals[name] = totals.get(name, 0) + 1
    for name, value in query_pairs:
        idx = counts.get(name, 0); counts[name] = idx + 1
        parameter = f"{name}[{idx}]" if totals[name] > 1 else name
        points.append(InjectionPoint("query", parameter, value, bool(_SENSITIVE_POINT.search(name)), parameter))
    if config.body_mode in {"json", "graphql"}:
        for point in _walk_json_points(config.data):
            point.location = "graphql" if config.body_mode == "graphql" else "json"
            points.append(point)
    elif config.body_mode in {"form", "multipart"}:
        if isinstance(config.data, dict):
            pairs = [(str(k), v) for k, v in config.data.items()]
        elif isinstance(config.data, list):
            pairs = [(str(item[0]), item[1]) for item in config.data if isinstance(item, (list, tuple)) and len(item) == 2]
        else: pairs = []
        totals = {}; counts = {}
        for name, _ in pairs: totals[name] = totals.get(name, 0) + 1
        for name, value in pairs:
            idx = counts.get(name, 0); counts[name] = idx + 1
            parameter = f"{name}[{idx}]" if totals[name] > 1 else name
            if isinstance(value, dict) and "filename" in value:
                continue
            points.append(InjectionPoint("form", parameter, str(value), bool(_SENSITIVE_POINT.search(name)), parameter))
    for name, value in config.cookies.items():
        points.append(InjectionPoint("cookie", name, "<redacted>" if _SENSITIVE_POINT.search(name) else value, bool(_SENSITIVE_POINT.search(name)), name))
    ignored_headers = {"host", "content-length", "content-type", "accept", "accept-encoding", "connection"}
    for name, value in config.headers.items():
        if name.lower() in ignored_headers: continue
        sensitive = bool(_SENSITIVE_POINT.search(name))
        points.append(InjectionPoint("header", name, "<redacted>" if sensitive else value, sensitive, name))
    segments = [unquote_plus(x) for x in urlsplit(config.url).path.split("/") if x]
    for idx, value in enumerate(segments, 1):
        if value and (value.isdigit() or re.fullmatch(r"[A-Za-z0-9._~-]{1,80}", value)):
            points.append(InjectionPoint("path", str(idx), value, False, f"segment {idx}: {value}"))
    if config.raw_body and "{{INJECT}}" in config.raw_body:
        points.append(InjectionPoint("raw", "body", "{{INJECT}}", False, "raw body placeholder"))
    return points
