"""Small conservative SQL lexer used by Local Skill policy gates."""
from __future__ import annotations

from dataclasses import dataclass

from gateway.core import GatewayError


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    depth: int

    @property
    def upper(self) -> str:
        return self.value.upper()


def _fail(message: str) -> GatewayError:
    return GatewayError("skill_sql_not_readonly", message)


def lex_sql(sql: str) -> list[Token]:
    if not isinstance(sql, str) or not sql.strip() or len(sql) > 65_536 or "\x00" in sql:
        raise _fail("SQL must be a non-empty bounded text statement.")

    out: list[Token] = []
    i = 0
    depth = 0
    n = len(sql)

    def add(kind: str, value: str, token_depth: int | None = None) -> None:
        out.append(Token(kind, value, depth if token_depth is None else token_depth))

    while i < n:
        ch = sql[i]
        if ch.isspace():
            i += 1
            continue
        if sql.startswith("--", i):
            end = sql.find("\n", i + 2)
            i = n if end < 0 else end + 1
            continue
        if ch == "#":
            end = sql.find("\n", i + 1)
            i = n if end < 0 else end + 1
            continue
        if sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            if end < 0:
                raise _fail("Unterminated SQL comment.")
            i = end + 2
            continue
        if ch in {"'", '"'}:
            quote = ch
            chars: list[str] = []
            i += 1
            closed = False
            while i < n:
                if sql[i] == quote:
                    if i + 1 < n and sql[i + 1] == quote:
                        chars.append(quote)
                        i += 2
                        continue
                    i += 1
                    closed = True
                    break
                if sql[i] == "\\" and i + 1 < n:
                    chars.append(sql[i + 1])
                    i += 2
                    continue
                chars.append(sql[i])
                i += 1
            if not closed:
                raise _fail("Unterminated SQL quoted value.")
            add("STRING", "".join(chars))
            continue
        if ch == "`":
            chars = []
            i += 1
            closed = False
            while i < n:
                if sql[i] == "`":
                    if i + 1 < n and sql[i + 1] == "`":
                        chars.append("`")
                        i += 2
                        continue
                    i += 1
                    closed = True
                    break
                chars.append(sql[i])
                i += 1
            if not closed:
                raise _fail("Unterminated SQL identifier.")
            add("IDENT", "".join(chars))
            continue
        if ch.isalpha() or ch == "_":
            start = i
            i += 1
            while i < n and (sql[i].isalnum() or sql[i] in "_$"):
                i += 1
            add("IDENT", sql[start:i])
            continue
        if ch.isdigit():
            start = i
            i += 1
            while i < n and sql[i].isdigit():
                i += 1
            add("NUMBER", sql[start:i])
            continue
        two = sql[i:i + 2]
        if two in {">=", "<=", "<>", "!="}:
            add("OP", two)
            i += 2
            continue
        if ch in "=><+-*/":
            add("OP", ch)
            i += 1
            continue
        if ch == "(":
            add("LPAREN", ch, depth)
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth -= 1
            if depth < 0:
                raise _fail("Unbalanced SQL parentheses.")
            add("RPAREN", ch, depth)
            i += 1
            continue
        if ch == ",":
            add("COMMA", ch)
            i += 1
            continue
        if ch == ".":
            add("DOT", ch)
            i += 1
            continue
        if ch == ";":
            add("SEMI", ch)
            i += 1
            continue
        raise _fail("SQL contains unsupported syntax.")

    if depth != 0:
        raise _fail("Unbalanced SQL parentheses.")
    return out


def single_statement(tokens: list[Token]) -> list[Token]:
    semis = [i for i, token in enumerate(tokens) if token.kind == "SEMI"]
    if not semis:
        return tokens
    if len(semis) != 1 or semis[0] != len(tokens) - 1:
        raise _fail("Multiple SQL statements are not allowed.")
    return tokens[:-1]


__all__ = ["Token", "lex_sql", "single_statement"]
