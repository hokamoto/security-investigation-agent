"""Utilities for SQL query normalization and transformation."""

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from siem_agent.agent_state import AgentState


def normalize_clickhouse_array_functions(sql: str) -> str:
    """Replace non-existent ClickHouse array functions with correct equivalents.

    Args:
        sql: SQL query string potentially containing incorrect array functions

    Returns:
        SQL query with all incorrect array functions replaced with correct equivalents
    """
    # Replace arrayLength with length (case-insensitive, handles optional whitespace before '(')
    sql = re.sub(r'\barrayLength\s*\(', 'length(', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\barraySize\s*\(', 'length(', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\barrayLen\s*\(', 'length(', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\bsize\s*\(', 'length(', sql, flags=re.IGNORECASE)

    sql = re.sub(r'\barrayAgg\s*\(', 'groupArray(', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\bcollect\s*\(', 'groupArray(', sql, flags=re.IGNORECASE)

    sql = re.sub(r'\bcollectSet\s*\(', 'groupUniqArray(', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\bcollect_set\s*\(', 'groupUniqArray(', sql, flags=re.IGNORECASE)

    sql = re.sub(r'\barrayFirst\s*\((?!\s*x\s*->\s*true)', r'arrayFirst(x -> true, ', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\barrayLast\s*\((?!\s*x\s*->\s*true)', r'arrayLast(x -> true, ', sql, flags=re.IGNORECASE)

    return sql


def apply_hdx_join_workaround(sql: str, database_name: str, siem_table: str, cdn_table: str) -> str:
    """
    Apply HDX time range bug workaround by wrapping right-side JOIN tables in subqueries.

    HDX bug: When hdx_query_timerange_required is enabled, JOIN queries fail even with
    valid time range filters in WHERE clause. The parser cannot detect time range predicates
    for the right-side table of a JOIN.

    Workaround: Wrap the right-side table in a subquery that contains its time filter.

    Example transformation:
        FROM logs AS cdn JOIN siem AS waf ON cdn.reqId = waf.requestId
        WHERE cdn.reqTimeSec BETWEEN ... AND ... AND waf.timestamp BETWEEN ... AND ...

    Becomes:
        FROM logs AS cdn JOIN (SELECT * FROM siem WHERE timestamp BETWEEN ... AND ...) AS waf
        ON cdn.reqId = waf.requestId WHERE cdn.reqTimeSec BETWEEN ... AND ...

    Args:
        sql: Original SQL query
        database_name: Database name (e.g., "akamai_jp")
        siem_table: SIEM/WAF table name (e.g., "siem")
        cdn_table: CDN table name (e.g., "logs")

    Returns:
        Transformed SQL with subquery workaround applied (if JOIN detected)
    """
    # Normalize whitespace for easier parsing
    sql = ' '.join(sql.split())

    # Check if this is a JOIN query
    if not re.search(r'\bJOIN\b', sql, re.IGNORECASE):
        return sql

    # Pattern to match JOIN clause with table and alias
    # Matches: JOIN [database.]table AS alias
    # Also matches: JOIN [database.]table (without AS keyword)
    join_pattern = r'\bJOIN\s+(?:(\w+)\.)?(\w+)(?:\s+AS)?\s+(\w+)\s+ON\b'
    join_match = re.search(join_pattern, sql, re.IGNORECASE)

    if not join_match:
        return sql  # No recognizable JOIN pattern

    join_db = join_match.group(1) or database_name  # Use provided db if not specified
    join_table = join_match.group(2)
    join_alias = join_match.group(3)

    # Determine the time column based on table name
    if join_table == siem_table:
        time_column = 'timestamp'
    elif join_table == cdn_table:
        time_column = 'reqTimeSec'
    else:
        # Unknown table, skip transformation
        return sql

    # Extract time filter for the right-side table from WHERE clause
    # Pattern: alias.time_column BETWEEN function(...) AND function(...)
    # Matches function calls like parseDateTimeBestEffort('...')
    time_filter_pattern = rf'\b{re.escape(join_alias)}\.{time_column}\s+BETWEEN\s+(\w+\([^)]+\))\s+AND\s+(\w+\([^)]+\))'
    time_match = re.search(time_filter_pattern, sql, re.IGNORECASE)

    if not time_match:
        # Try fully qualified name: db.table.time_column BETWEEN ...
        fq_pattern = rf'\b{re.escape(join_db)}\.{re.escape(join_table)}\.{time_column}\s+BETWEEN\s+(\w+\([^)]+\))\s+AND\s+(\w+\([^)]+\))'
        time_match = re.search(fq_pattern, sql, re.IGNORECASE)

        if not time_match:
            # No time filter for right-side table, no transformation needed
            return sql

    time_start = time_match.group(1).strip()
    time_end = time_match.group(2).strip()

    # Build the subquery
    full_table_name = f"{join_db}.{join_table}"
    subquery = f"(SELECT * FROM {full_table_name} WHERE {time_column} BETWEEN {time_start} AND {time_end})"

    # Replace the JOIN table with subquery
    # Find the exact JOIN clause to replace
    original_join = join_match.group(0)  # e.g., "JOIN akamai_jp.siem AS waf ON"

    # Construct replacement: JOIN (subquery) AS alias ON
    new_join = f"JOIN {subquery} AS {join_alias} ON"

    # Replace in SQL
    sql = sql[:join_match.start()] + new_join + sql[join_match.end():]

    # Remove the time filter from WHERE clause (now in subquery)
    # Need to handle both alias.column and db.table.column formats
    sql = re.sub(
        rf'\s+AND\s+{re.escape(join_alias)}\.{time_column}\s+BETWEEN\s+\w+\([^)]+\)\s+AND\s+\w+\([^)]+\)',
        '',
        sql,
        flags=re.IGNORECASE
    )
    sql = re.sub(
        rf'\s+AND\s+{re.escape(join_db)}\.{re.escape(join_table)}\.{time_column}\s+BETWEEN\s+\w+\([^)]+\)\s+AND\s+\w+\([^)]+\)',
        '',
        sql,
        flags=re.IGNORECASE
    )

    return sql


def apply_sql_transformations(sql: str, state: "AgentState") -> str:
    """
    Apply all SQL transformations needed for HDX compatibility.

    This is the main entry point for SQL transformations. Currently applies:
    - HDX JOIN time range bug workaround

    Args:
        sql: Original SQL query
        state: Agent state containing database configuration

    Returns:
        Transformed SQL query
    """
    sql = apply_hdx_join_workaround(
        sql=sql,
        database_name=state.database_name,
        siem_table=state.siem_log_table_name,
        cdn_table=state.cdn_log_table_name,
    )
    return sql
