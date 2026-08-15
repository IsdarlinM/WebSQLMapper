from __future__ import annotations

import json
import time
from dataclasses import replace
from http.cookiejar import CookieJar
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, Request, build_opener

from .models import RequestConfig, ResponseSnapshot
from .safety import validate_http_url


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class HTTPClient:
    def __init__(self) -> None:
        self._cookies = CookieJar()
        self._opener = build_opener(HTTPCookieProcessor(self._cookies), _NoRedirect())

    @staticmethod
    def _cookie_header(cookies: dict[str, str]) -> str:
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    @staticmethod
    def inject(config: RequestConfig, value: str) -> tuple[str, bytes | None, dict[str, str]]:
        validate_http_url(config.url)
        method = config.method.upper()
        headers = dict(config.headers)
        if config.cookies:
            headers["Cookie"] = HTTPClient._cookie_header(config.cookies)

        parts = urlsplit(config.url)
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        data = dict(config.data)
        body_mode = config.body_mode
        if body_mode == "auto":
            body_mode = "query" if method in {"GET", "HEAD", "DELETE"} else "form"

        body: bytes | None = None
        if body_mode == "query":
            replaced = False
            new_pairs: list[tuple[str, str]] = []
            for key, current in query_pairs:
                if key == config.parameter:
                    new_pairs.append((key, value))
                    replaced = True
                else:
                    new_pairs.append((key, current))
            if not replaced:
                new_pairs.append((config.parameter, value))
            url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(new_pairs), parts.fragment))
        elif body_mode == "form":
            data[config.parameter] = value
            body = urlencode(data, doseq=True).encode("utf-8")
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            url = config.url
        elif body_mode == "json":
            data[config.parameter] = value
            body = json.dumps(data, separators=(",", ":")).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
            url = config.url
        else:
            raise ValueError("body_mode must be one of: auto, query, form, json")
        return url, body, headers

    def request(self, config: RequestConfig, value: str) -> ResponseSnapshot:
        url, body, headers = self.inject(config, value)
        req = Request(url=url, data=body, headers=headers, method=config.method.upper())
        started = time.perf_counter()
        try:
            with self._opener.open(req, timeout=config.timeout) as response:
                raw = response.read(1_500_000)
                elapsed = time.perf_counter() - started
                charset = response.headers.get_content_charset() or "utf-8"
                text = raw.decode(charset, errors="replace")
                return ResponseSnapshot(
                    status=response.status,
                    body=text,
                    elapsed=elapsed,
                    final_url=response.geturl(),
                    headers=dict(response.headers.items()),
                )
        except HTTPError as exc:
            raw = exc.read(1_500_000)
            elapsed = time.perf_counter() - started
            charset = exc.headers.get_content_charset() if exc.headers else None
            text = raw.decode(charset or "utf-8", errors="replace")
            return ResponseSnapshot(
                status=exc.code,
                body=text,
                elapsed=elapsed,
                final_url=exc.geturl(),
                headers=dict(exc.headers.items()) if exc.headers else {},
                error=str(exc),
            )
        except (URLError, TimeoutError, OSError) as exc:
            elapsed = time.perf_counter() - started
            return ResponseSnapshot(
                status=0, body="", elapsed=elapsed, final_url=url, headers={}, error=str(exc)
            )


def with_timeout(config: RequestConfig, timeout: float) -> RequestConfig:
    return replace(config, timeout=timeout)
