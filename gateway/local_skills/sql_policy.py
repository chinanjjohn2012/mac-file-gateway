"""Read-only SQL policy gates for Local Skill database scripts."""
from __future__ import annotations

from gateway.core import GatewayError
from .config import AuditPolicy
from .sql_lexer import Token, lex_sql, single_statement
from .sql_scope import QueryScopeGate

_ALLOWED = {"SELECT", "WITH", "SHOW", "DESC", "DESCRIBE"}
_NONREAD = {
    "INSERT", "UPDATE", "DELETE", "REPLACE", "MERGE", "UPSERT", "DROP",
    "ALTER", "CREATE", "TRUNCATE", "RENAME", "GRANT", "REVOKE", "OPTIMIZE",
    "SYSTEM", "KILL", "ATTACH", "DETACH", "SET", "CALL", "LOAD", "LOCK",
}
_TABLE_FUNCTIONS = {
    "url", "s3", "file", "remote", "remotesecure", "mysql", "postgresql",
    "hdfs", "jdbc", "odbc", "merge", "cluster", "clusterallreplicas",
}


def _fail(code: str, message: str) -> GatewayError:
    return GatewayError(code, message)


def _statement(tokens: list[Token]) -> tuple[str, list[Token]]:
    if not tokens:
        raise _fail("skill_sql_not_readonly", "SQL statement is empty.")
    working = tokens
    if working[0].upper == "EXPLAIN":
        if len(working) > 1 and working[1].upper == "ANALYZE":
            raise _fail("skill_explain_analyze_not_allowed", "EXPLAIN ANALYZE is not allowed.")
        working = working[1:]
        if not working:
            raise _fail("skill_sql_not_readonly", "EXPLAIN requires a statement.")

    first = working[0].upper
    if first != "WITH":
        if first not in _ALLOWED:
            raise _fail("skill_sql_not_readonly", "Only read-only SQL statement classes are allowed.")
        return first, working

    main = None
    for token in working[1:]:
        if token.depth == 0 and token.kind == "IDENT" and (token.upper in _ALLOWED or token.upper in _NONREAD):
            main = token.upper
            break
    if main is None or main in _NONREAD or main not in _ALLOWED - {"WITH"}:
        raise _fail("skill_sql_not_readonly", "WITH must end in a read-only statement.")
    return "WITH", working


def _side_effects(tokens: list[Token]) -> None:
    for i, token in enumerate(tokens):
        if token.depth != 0:
            continue
        if token.upper == "INTO" and i + 1 < len(tokens) and tokens[i + 1].upper in {"OUTFILE", "DUMPFILE"}:
            raise _fail("skill_sql_not_readonly", "SQL file output is not allowed.")
        if token.upper == "FOR" and i + 1 < len(tokens) and tokens[i + 1].upper == "UPDATE":
            raise _fail("skill_sql_not_readonly", "SELECT FOR UPDATE is not allowed.")
        if token.upper == "LOCK":
            raise _fail("skill_sql_not_readonly", "Locking SQL is not allowed.")


def _show(statement: str, tokens: list[Token]) -> None:
    if statement != "SHOW":
        return
    words = [t.upper for t in tokens if t.kind == "IDENT" and t.depth == 0]
    allowed = (
        len(words) >= 2 and words[:2] == ["SHOW", "TABLES"]
        or len(words) >= 3 and words[:3] == ["SHOW", "CREATE", "TABLE"]
        or len(words) >= 2 and words[:2] == ["SHOW", "COLUMNS"]
    )
    if not allowed:
        raise _fail("skill_show_not_allowed", "SHOW form is not allowed.")


def _system_schema(dialect: str, tokens: list[Token], statement: str) -> None:
    denied = (
        {"information_schema", "performance_schema", "mysql", "sys"}
        if dialect == "mysql"
        else {"system", "information_schema"}
    )
    for i in range(len(tokens) - 2):
        if (
            tokens[i].kind in {"IDENT", "STRING"}
            and tokens[i + 1].kind == "DOT"
            and tokens[i].value.casefold() in denied
        ):
            raise _fail("skill_system_schema_not_allowed", "System schema access is not allowed.")
    if statement == "SHOW":
        for i in range(len(tokens) - 1):
            if (
                tokens[i].kind == "IDENT"
                and tokens[i].upper in {"FROM", "IN"}
                and tokens[i + 1].kind in {"IDENT", "STRING"}
                and tokens[i + 1].value.casefold() in denied
            ):
                raise _fail("skill_system_schema_not_allowed", "System schema access is not allowed.")


def _table_functions(tokens: list[Token]) -> None:
    for i in range(len(tokens) - 1):
        if (
            tokens[i].kind == "IDENT"
            and tokens[i + 1].kind == "LPAREN"
            and tokens[i].value.casefold() in _TABLE_FUNCTIONS
        ):
            raise _fail("skill_table_function_not_allowed", "External or dynamic table function is not allowed.")


class SqlPolicyGate:
    def __init__(self, policy: AuditPolicy):
        self.records = policy.compatibility["skills"]
        self.scopes: dict[str, QueryScopeGate] = {}
        for name, raw in self.records.items():
            if raw.get("kind") != "clickhouse":
                continue
            columns: dict[str, str] = {}
            for key, value in raw.get("realtime_time_columns", {}).items():
                if isinstance(value, str):
                    columns[key] = value
                elif isinstance(value, dict) and isinstance(value.get("column"), str):
                    columns[key] = value["column"]
            self.scopes[name] = QueryScopeGate(columns, int(raw.get("small_schema_count", 0)))

    def validate(self, skill: str, sql: str, *, instance: str | None = None) -> None:
        record = self.records.get(skill, {})
        dialect = record.get("kind")
        if dialect not in {"mysql", "clickhouse"}:
            raise _fail("skill_sql_not_readonly", "Skill has no audited SQL dialect.")
        if instance is None and dialect == "clickhouse":
            defaults = [rule.get("default") for rules in record.get("argv", {}).values() for rule in rules if rule.get("name") == "instance"]
            instance = defaults[0] if len(defaults) == 1 else ""
        tokens = single_statement(lex_sql(sql))
        statement, working = _statement(tokens)
        _side_effects(working)
        _show(statement, working)
        _system_schema(dialect, working, statement)
        _table_functions(working)
        if dialect == "clickhouse":
            self.scopes[skill].check(working, instance or "")


__all__ = ["SqlPolicyGate"]
