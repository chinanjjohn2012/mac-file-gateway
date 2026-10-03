"""Realtime table scope checks for Local Skill ClickHouse queries."""
from __future__ import annotations

from datetime import datetime

from gateway.core import GatewayError
from .sql_lexer import Token

_CLAUSE_END = {"WHERE", "PREWHERE", "GROUP", "ORDER", "HAVING", "LIMIT", "SETTINGS", "FORMAT", "UNION"}


def _fail(code: str, message: str) -> GatewayError:
    return GatewayError(code, message)


def _table_names(tokens: list[Token]) -> list[str]:
    names: list[str] = []
    for i, token in enumerate(tokens):
        if token.kind != "IDENT" or token.upper not in {"FROM", "JOIN"}:
            continue
        j = i + 1
        if j >= len(tokens) or tokens[j].kind != "IDENT":
            continue
        parts = [tokens[j].value]
        j += 1
        while j + 1 < len(tokens) and tokens[j].kind == "DOT" and tokens[j + 1].kind == "IDENT":
            parts.append(tokens[j + 1].value)
            j += 2
        names.append(parts[-1])
    return names


def _has_top_level_comma_join(tokens: list[Token]) -> bool:
    start = None
    for i, token in enumerate(tokens):
        if token.kind == "IDENT" and token.depth == 0 and token.upper == "FROM":
            start = i + 1
            break
    if start is None:
        return False
    for token in tokens[start:]:
        if token.kind == "IDENT" and token.depth == 0 and token.upper in _CLAUSE_END:
            break
        if token.kind == "COMMA" and token.depth == 0:
            return True
    return False


def _and_or_end(tokens: list[Token], index: int) -> bool:
    if index >= len(tokens):
        return True
    token = tokens[index]
    return token.kind == "IDENT" and token.depth == 0 and token.upper == "AND"


def _where_region(tokens: list[Token]) -> tuple[int, int] | None:
    start = None
    for i, token in enumerate(tokens):
        if token.kind == "IDENT" and token.depth == 0 and token.upper in {"WHERE", "PREWHERE"}:
            start = i + 1
            break
    if start is None:
        return None
    end = len(tokens)
    for i in range(start, len(tokens)):
        token = tokens[i]
        if token.kind == "IDENT" and token.depth == 0 and token.upper in _CLAUSE_END - {"WHERE", "PREWHERE"}:
            end = i
            break
    return start, end


def _parse_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _duration(seconds: float) -> None:
    if seconds < 0:
        raise _fail("skill_query_scope_unknown", "Time range is not provable.")
    if seconds > 7200:
        raise _fail("skill_query_scope_exceeded", "Realtime query exceeds the 2 hour limit.")


class QueryScopeGate:
    def __init__(self, realtime_columns: dict[str, str], small_schema_count: int):
        self.realtime_columns = {k.casefold(): v.casefold() for k, v in realtime_columns.items()}
        self.small_schema_count = small_schema_count

    def _realtime(self, tokens: list[Token], table: str, instance: str) -> None:
        if tokens and tokens[0].upper == "WITH":
            raise _fail("skill_query_scope_unknown", "Realtime CTE queries are not allowed.")
        if any(t.kind == "IDENT" and t.upper in {"JOIN", "UNION"} for t in tokens):
            raise _fail("skill_query_scope_unknown", "Realtime JOIN/UNION queries are not allowed.")
        if _has_top_level_comma_join(tokens):
            raise _fail("skill_query_scope_unknown", "Realtime comma-join queries are not allowed.")
        if any(t.kind == "IDENT" and t.upper == "SELECT" and t.depth > 0 for t in tokens):
            raise _fail("skill_query_scope_unknown", "Realtime subqueries are not allowed.")

        time_column = self.realtime_columns.get(f"{instance}/{table}".casefold())
        if time_column is None:
            raise _fail("skill_query_scope_unknown", "Realtime table lacks an audited time-column mapping.")

        region = _where_region(tokens)
        if region is None:
            raise _fail("skill_query_scope_unknown", "Realtime query requires a provable time predicate.")
        start, end = region
        section = tokens[start:end]
        if any(t.kind == "IDENT" and t.upper == "OR" for t in section):
            raise _fail("skill_query_scope_unknown", "OR is not allowed in realtime scope predicates.")

        for i, token in enumerate(section):
            if token.kind != "IDENT" or token.depth != 0 or token.value.casefold() != time_column:
                continue
            tail = section[i + 1:]
            if tail and tail[0].kind == "OP" and tail[0].value == ">=":
                if (
                    len(tail) >= 8
                    and tail[1].kind == "IDENT" and tail[1].upper == "NOW"
                    and tail[2].kind == "LPAREN" and tail[3].kind == "RPAREN"
                    and tail[4].kind == "OP" and tail[4].value == "-"
                    and tail[5].kind == "IDENT" and tail[5].upper == "INTERVAL"
                    and tail[6].kind == "NUMBER" and tail[7].kind == "IDENT"
                ):
                    amount = int(tail[6].value)
                    factor = {"MINUTE": 60, "HOUR": 3600, "DAY": 86400}.get(tail[7].upper)
                    if factor is None:
                        raise _fail("skill_query_scope_unknown", "Unsupported realtime interval unit.")
                    if not _and_or_end(tail, 8):
                        raise _fail("skill_query_scope_unknown", "Realtime relative time expression is not a simple bound.")
                    _duration(amount * factor)
                    return
                if len(tail) >= 2 and tail[1].kind == "STRING":
                    lower = _parse_time(tail[1].value)
                    if lower is None:
                        raise _fail("skill_query_scope_unknown", "Invalid absolute time bound.")
                    if len(tail) > 2 and not (
                        tail[2].kind == "IDENT" and tail[2].depth == 0 and tail[2].upper == "AND"
                    ):
                        raise _fail("skill_query_scope_unknown", "Absolute lower bound must be a simple constant predicate.")
                    for j, other in enumerate(section):
                        if (
                            other.kind == "IDENT" and other.depth == 0 and other.value.casefold() == time_column
                            and j + 2 < len(section)
                            and section[j + 1].kind == "OP" and section[j + 1].value in {"<", "<="}
                            and section[j + 2].kind == "STRING"
                        ):
                            upper = _parse_time(section[j + 2].value)
                            if upper is None:
                                raise _fail("skill_query_scope_unknown", "Invalid absolute time bound.")
                            if not _and_or_end(section, j + 3):
                                raise _fail("skill_query_scope_unknown", "Absolute upper bound must be a simple constant predicate.")
                            try:
                                _duration((upper - lower).total_seconds())
                            except TypeError:
                                raise _fail("skill_query_scope_unknown", "Absolute time zones are inconsistent.") from None
                            return
                    raise _fail("skill_query_scope_unknown", "Absolute lower bound requires an upper bound.")
            if (
                len(tail) >= 4
                and tail[0].kind == "IDENT" and tail[0].upper == "BETWEEN"
                and tail[1].kind == "STRING"
                and tail[2].kind == "IDENT" and tail[2].upper == "AND"
                and tail[3].kind == "STRING"
            ):
                if not _and_or_end(tail, 4):
                    raise _fail("skill_query_scope_unknown", "BETWEEN time bound must be a simple constant predicate.")
                lower = _parse_time(tail[1].value)
                upper = _parse_time(tail[3].value)
                if lower is None or upper is None:
                    raise _fail("skill_query_scope_unknown", "Invalid BETWEEN time bound.")
                try:
                    _duration((upper - lower).total_seconds())
                except TypeError:
                    raise _fail("skill_query_scope_unknown", "Absolute time zones are inconsistent.") from None
                return
        raise _fail("skill_query_scope_unknown", "Realtime time predicate is not provable.")

    def check(self, tokens: list[Token], instance: str) -> None:
        tables = _table_names(tokens)
        small = [name for name in tables if name.casefold().endswith("_small")]
        if small:
            raise _fail("skill_query_scope_unknown", "No audited _small schema mapping is available in v1.")
        realtime = [name for name in tables if name.casefold().endswith("_realtime")]
        if not realtime:
            return
        if len({name.casefold() for name in realtime}) != 1:
            raise _fail("skill_query_scope_unknown", "Realtime query must reference one audited table.")
        self._realtime(tokens, realtime[0], instance)


__all__ = ["QueryScopeGate"]
