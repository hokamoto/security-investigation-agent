"""SQL processing pipeline built on sqlglot AST transforms."""

from __future__ import annotations

import sqlglot
from sqlglot import exp

CLICKHOUSE = "clickhouse"

# LLM-generated non-ClickHouse function names -> ClickHouse equivalents.
_FUNCTION_RENAMES = {
    "arraylength": "length",
    "arraysize": "length",
    "arraylen": "length",
    "size": "length",
    "length": "length",
    "arrayagg": "groupArray",
    "collect": "groupArray",
    "collectset": "groupUniqArray",
    "collect_set": "groupUniqArray",
}

# Map-typed columns that require mapContains instead of has/hasKey.
_MAP_COLUMNS = {"requestHeaders"}

# Known CDN column renames for WAF->CDN confusion.
_CDN_COLUMN_FIXES = {
    "clientIP": "cliIP",
}


def process_sql(
    sql: str,
    database_name: str,
    siem_table: str,
    cdn_table: str,
    session_timestamp: str,
) -> tuple[str, bool, str | None]:
    """Parse, transform, validate, and emit SQL.

    Returns:
        (processed_sql, is_valid, error_message)
        For invalid SQL, processed_sql is the original SQL.
    """
    try:
        ast = sqlglot.parse_one(sql, dialect=CLICKHOUSE)
    except (sqlglot.errors.ParseError, ValueError) as e:
        return sql, False, f"SQL syntax error: {e}"

    ast = _fix_functions(ast)
    ast = _fix_map_functions(ast)
    ast = _fix_cdn_columns(ast, cdn_table)
    ast = _fix_join_on_predicates(ast)
    ast = _fix_window_in_where(ast)
    ast = _fix_hdx_join(ast, database_name, siem_table, cdn_table)
    ast = _replace_now(ast, session_timestamp)

    is_valid, error = _validate(ast, database_name, siem_table, cdn_table)
    if not is_valid:
        return sql, False, error

    # Keep trailing whitespace so regex-based test helpers can capture
    # end-of-query ON/WHERE clauses.
    return f"{ast.sql(dialect=CLICKHOUSE)} ", True, None


def _fix_functions(ast: exp.Expression) -> exp.Expression:
    """Normalize wrong function names to ClickHouse equivalents."""

    def _transform(node: exp.Expression) -> exp.Expression:
        replacement = None
        if isinstance(node, exp.Anonymous):
            replacement = _FUNCTION_RENAMES.get(node.name.lower())
        elif isinstance(node, exp.Func):
            replacement = _FUNCTION_RENAMES.get(node.key.lower())

        if replacement:
            return exp.Anonymous(this=replacement, expressions=[arg.copy() for arg in _function_args(node)])
        return node

    return ast.transform(_transform)


def _fix_map_functions(ast: exp.Expression) -> exp.Expression:
    """Rewrite has/hasKey to mapContains only for known Map columns."""

    def _transform(node: exp.Expression) -> exp.Expression:
        is_has = isinstance(node, exp.ArrayContains) or (isinstance(node, exp.Anonymous) and node.name.lower() in {"has", "haskey"})
        if is_has:
            args = _function_args(node)
            if args and isinstance(args[0], exp.Column) and args[0].name in _MAP_COLUMNS:
                return exp.Anonymous(this="mapContains", expressions=[arg.copy() for arg in args])
        return node

    return ast.transform(_transform)


def _fix_cdn_columns(ast: exp.Expression, cdn_table: str) -> exp.Expression:
    """Fix known column mismatches only for CDN table references."""
    cdn_aliases: set[str] = set()

    for table in ast.find_all(exp.Table):
        if table.name == cdn_table:
            cdn_aliases.add(table.alias_or_name)
            cdn_aliases.add(table.name)

    if not cdn_aliases:
        return ast

    def _transform(node: exp.Expression) -> exp.Expression:
        if isinstance(node, exp.Column) and node.name in _CDN_COLUMN_FIXES:
            if node.table and node.table in cdn_aliases:
                return exp.Column(
                    this=exp.to_identifier(_CDN_COLUMN_FIXES[node.name]),
                    table=exp.to_identifier(node.table),
                )
        return node

    return ast.transform(_transform)


def _fix_join_on_predicates(ast: exp.Expression) -> exp.Expression:
    """Move non-equality INNER JOIN ON predicates into WHERE clause."""
    for join in ast.find_all(exp.Join):
        join_side = (join.side or "").upper()
        join_kind = (join.kind or "").upper()

        if join_side in {"LEFT", "RIGHT", "FULL"}:
            continue
        if join_kind not in {"", "INNER"}:
            continue

        on_expr = join.args.get("on")
        if not on_expr:
            continue

        equi: list[exp.Expression] = []
        non_equi: list[exp.Expression] = []

        for pred in _split_and_conditions(on_expr):
            if isinstance(pred, exp.EQ):
                equi.append(pred)
            else:
                non_equi.append(pred)

        if not equi or not non_equi:
            continue

        join.set("on", _and_join(equi))

        select = join.find_ancestor(exp.Select)
        if not select:
            continue

        where = select.args.get("where")
        moved = _and_join(non_equi)
        if where:
            select.set("where", exp.Where(this=exp.and_(where.this, moved)))
        else:
            select.set("where", exp.Where(this=moved))

    return ast


def _fix_window_in_where(ast: exp.Expression) -> exp.Expression:
    """Wrap query in subquery when WHERE contains window functions."""
    if not isinstance(ast, exp.Select):
        return ast

    where = ast.args.get("where")
    if not where:
        return ast

    conditions = _split_and_conditions(where.this)
    regular: list[exp.Expression] = []
    window_conds: list[tuple[exp.Expression, list[exp.Window]]] = []

    for cond in conditions:
        windows = list(cond.find_all(exp.Window))
        if windows:
            window_conds.append((cond, windows))
        else:
            regular.append(cond)

    if not window_conds:
        return ast

    # Assign synthetic aliases for each window expression and add to SELECT.
    counter = 0
    outer_filters: list[exp.Expression] = []
    for cond, windows in window_conds:
        cond_copy = cond.copy()
        for win in cond_copy.find_all(exp.Window):
            counter += 1
            alias_name = f"_w{counter}"
            # Add window expression to inner SELECT list.
            win_copy = win.copy()
            ast.args["expressions"].append(exp.Alias(this=win_copy, alias=exp.to_identifier(alias_name)))
            # Replace window node in the condition with a column reference.
            win.replace(exp.column(alias_name))
        outer_filters.append(cond_copy)

    # Set inner WHERE to regular conditions only.
    if regular:
        ast.set("where", exp.Where(this=_and_join(regular)))
    else:
        ast.set("where", None)

    # Wrap: SELECT * FROM (inner) AS _t WHERE <outer_filters>
    outer_where = _and_join(outer_filters)
    return exp.Select(expressions=[exp.Star()]).from_(
        exp.Subquery(this=ast, alias=exp.TableAlias(this=exp.to_identifier("_t")))
    ).where(outer_where)


def _fix_hdx_join(
    ast: exp.Expression,
    database_name: str,
    siem_table: str,
    cdn_table: str,
) -> exp.Expression:
    """Wrap right-side JOIN table in subquery when its time filter is in WHERE."""
    time_columns = {
        siem_table: "timestamp",
        cdn_table: "reqTimeSec",
    }

    for join in ast.find_all(exp.Join):
        if not isinstance(join.this, exp.Table):
            continue

        table = join.this
        if table.name not in time_columns:
            continue

        time_col = time_columns[table.name]
        alias_name = table.alias_or_name
        full_table = f"{table.db or database_name}.{table.name}"
        alias_candidates = {alias_name, table.name}

        select = join.find_ancestor(exp.Select)
        if not select:
            continue

        between_pred = None
        remaining = None
        from_on = False

        # First, try to extract BETWEEN from WHERE clause.
        where = select.args.get("where")
        if where:
            between_pred, remaining = _extract_between_for_alias(where.this, alias_candidates, time_col)

        # If not found in WHERE, check the JOIN ON clause (e.g. LEFT JOINs).
        if not between_pred:
            on_expr = join.args.get("on")
            if on_expr:
                between_pred, on_remaining = _extract_between_for_alias(on_expr, alias_candidates, time_col)
                if between_pred:
                    from_on = True
                    if on_remaining:
                        join.set("on", on_remaining)
                    else:
                        join.set("on", None)

        if not between_pred:
            continue

        subquery_where = between_pred.copy()
        for col in subquery_where.find_all(exp.Column):
            if col.table in alias_candidates:
                col.set("table", None)
                col.set("db", None)

        subquery = exp.Select(expressions=[exp.Star()]).from_(full_table).where(subquery_where)

        # Move ARRAY JOINs that reference the wrapped table into the subquery.
        outer_joins = select.args.get("joins", [])
        to_move = []
        for i, oj in enumerate(outer_joins):
            if (oj.kind or "").upper() != "ARRAY":
                continue
            # Check if ARRAY JOIN references the table being wrapped.
            refs_table = False
            for col in oj.find_all(exp.Column):
                if col.table in alias_candidates:
                    refs_table = True
                    break
            if refs_table:
                to_move.append(i)

        for idx in reversed(to_move):
            array_join = outer_joins.pop(idx)
            # Strip table qualifiers so columns resolve inside the subquery.
            for col in array_join.find_all(exp.Column):
                if col.table in alias_candidates:
                    col.set("table", None)
            subquery.set("joins", subquery.args.get("joins", []) + [array_join])

        join.this.replace(exp.Subquery(this=subquery, alias=exp.TableAlias(this=exp.to_identifier(alias_name))))

        # Only update outer WHERE when the BETWEEN came from WHERE (not ON).
        if not from_on:
            if remaining:
                select.set("where", exp.Where(this=remaining))
            else:
                select.set("where", None)

    return ast


def _replace_now(ast: exp.Expression, session_timestamp: str) -> exp.Expression:
    """Replace now()/CURRENT_TIMESTAMP with deterministic session timestamp."""
    replacement = sqlglot.parse_one(
        f"parseDateTimeBestEffort('{session_timestamp}')",
        dialect=CLICKHOUSE,
    )

    def _transform(node: exp.Expression) -> exp.Expression:
        if isinstance(node, exp.CurrentTimestamp):
            return replacement.copy()
        if isinstance(node, exp.Column) and not node.table and node.name.upper() == "CURRENT_TIMESTAMP":
            return replacement.copy()
        if isinstance(node, exp.Anonymous) and node.name.lower() == "now" and not node.expressions:
            return replacement.copy()
        return node

    return ast.transform(_transform)


def _validate(
    ast: exp.Expression,
    database_name: str,
    siem_table: str,
    cdn_table: str,
) -> tuple[bool, str | None]:
    """Validate SELECT-only and table whitelist constraints using AST."""
    if not isinstance(ast, exp.Select):
        return False, f"Only SELECT statements are allowed. Got: {type(ast).__name__}"

    allowed = {
        siem_table.lower(),
        cdn_table.lower(),
        f"{database_name}.{siem_table}".lower(),
        f"{database_name}.{cdn_table}".lower(),
    }

    cte_names = set()
    with_clause = ast.args.get("with_")
    if isinstance(with_clause, exp.With):
        for cte in with_clause.expressions:
            if isinstance(cte, exp.CTE):
                cte_names.add(cte.alias_or_name.lower())

    tables = list(ast.find_all(exp.Table))
    if not tables:
        return False, (f"Query must reference an allowed table ({database_name}.{siem_table} or {database_name}.{cdn_table}).")

    for table in tables:
        ref = f"{table.db}.{table.name}".lower() if table.db else table.name.lower()
        if ref in allowed:
            continue
        if table.name.lower() in cte_names:
            continue
        return False, (
            f"Table not allowed: {table.db + '.' + table.name if table.db else table.name}. "
            f"Only {database_name}.{siem_table} and {database_name}.{cdn_table} are permitted."
        )

    return True, None


def _split_and_conditions(expr: exp.Expression) -> list[exp.Expression]:
    """Split an expression tree on AND into a flat list."""
    if isinstance(expr, exp.Where):
        return _split_and_conditions(expr.this)
    if isinstance(expr, exp.Paren):
        return _split_and_conditions(expr.this)
    if isinstance(expr, exp.And):
        return _split_and_conditions(expr.this) + _split_and_conditions(expr.expression)
    return [expr]


def _and_join(conditions: list[exp.Expression]) -> exp.Expression:
    """Join predicates with AND."""
    if not conditions:
        raise ValueError("conditions must not be empty")

    result = conditions[0]
    for cond in conditions[1:]:
        result = exp.and_(result, cond)
    return result


def _extract_between_for_alias(
    where_expr: exp.Expression,
    aliases: set[str],
    column: str,
) -> tuple[exp.Between | None, exp.Expression | None]:
    """Extract time BETWEEN predicate and return remainder.

    Accepts both qualified (`alias.column`) and unqualified (`column`) forms.
    """
    conditions = _split_and_conditions(where_expr)
    target: exp.Between | None = None
    remaining: list[exp.Expression] = []

    for cond in conditions:
        if target is None and isinstance(cond, exp.Between) and isinstance(cond.this, exp.Column) and cond.this.name == column:
            if cond.this.table in aliases or not cond.this.table:
                target = cond
                continue
        remaining.append(cond)

    return target, (_and_join(remaining) if remaining else None)


def _function_args(node: exp.Expression) -> list[exp.Expression]:
    """Extract positional args across sqlglot function node variants."""
    if isinstance(node, exp.Anonymous):
        return list(node.expressions)

    args: list[exp.Expression] = []
    this = getattr(node, "this", None)
    if isinstance(this, exp.Expression):
        args.append(this)

    expression = getattr(node, "expression", None)
    if isinstance(expression, exp.Expression):
        args.append(expression)

    expressions = getattr(node, "expressions", None)
    if expressions:
        args.extend(expressions)

    return args
