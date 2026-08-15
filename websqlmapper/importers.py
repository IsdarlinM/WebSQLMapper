from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from .models import RequestConfig


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
        return "form", dict(parse_qsl(body, keep_blank_values=True)), None
    if "multipart/form-data" in lowered:
        # Preserve raw multipart exactly. Injection can still target a placeholder
        # in raw bodies; structured multipart generation is supported separately.
        return "raw", {}, body
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
        if name.lower() == "host":
            host = value
        elif name.lower() not in {"content-length", "cookie"}:
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
    proxy: str | None = None
    verify_tls = True
    ca_bundle: str | None = None
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
            if name.lower() == "cookie":
                cookies.update(_parse_cookie_header(value))
            else:
                headers[name.strip()] = value.strip()
        elif token in {"-b", "--cookie"}:
            i += 1
            if i >= len(tokens):
                raise RequestParseError(f"{token} requires cookie data")
            cookies.update(_parse_cookie_header(tokens[i]))
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
            # Ignore transport-only curl switches that do not change semantic
            # request content. Unknown switches with values are intentionally not
            # guessed because that can silently misparse a request.
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
    body = "&".join(data_parts)
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    body_mode, data, raw_body = _body_from_content_type(content_type, body)
    if body and not content_type:
        # curl -d defaults to application/x-www-form-urlencoded.
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
        follow_redirects=follow_redirects,
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
        if location == "form" and isinstance(config.data, dict):
            return str(config.data.get(parameter, fallback))
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
