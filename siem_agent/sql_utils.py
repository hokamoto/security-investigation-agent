"""Utilities for SQL query normalization and transformation."""

import re


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

    return sql
