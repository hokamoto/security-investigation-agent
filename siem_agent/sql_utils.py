"""
SQL utilities: validation and error handling for SIEM Agent
"""

import re
import json
from typing import Any, Iterable


def extract_clickhouse_error(error: Any) -> str:
    """
    Extract concise error message from ClickHouse exception.
    Accepts exception objects or strings and always returns a string.
    """
    error_str = str(error)

    # Quick check if it's a ClickHouse error
    markers = ['ClickHouse exception', 'DB::Exception', 'code:']
    if not any(marker in error_str for marker in markers):
        return error_str

    # Try to extract JSON error field
    json_match = re.search(r'server response:\s*(\{[^}]+\})', error_str, re.DOTALL)
    if json_match:
        try:
            error_data = json.loads(json_match.group(1))
            return error_data.get('error', error_str)
        except json.JSONDecodeError:
            pass

    return error_str


def validate_sql(sql: str, _db_name: str, _allowed_tables: Iterable[str]) -> str:
    """
    Minimal SQL validation for safety
    - Ensures only SELECT/WITH queries (read-only)
    - Prevents dangerous keywords (write operations)
    - All other validation (tables, timestamps, syntax) handled by ClickHouse + LLM repair

    Note: db_name and allowed_tables parameters are kept for backward compatibility
    but not used (validation simplified to rely on ClickHouse + LLM repair)
    """
    s = sql.strip()
    sl = s.lower()

    # Only allow read-only queries
    if not re.match(r"^\s*(select|with)\b", sl):
        raise ValueError(f"Only SELECT/WITH queries allowed: {sql}")

    # Block dangerous write/admin operations
    if re.search(r"\b(insert|update|delete|drop|alter|create|truncate|attach|detach|optimize|system|kill|grant|revoke|rename|set)\b", sl):
        raise ValueError(f"Disallowed keyword present: {sql}")

    # Return query as-is (no table qualification, no timestamp validation)
    # ClickHouse will return errors for invalid syntax/tables, which triggers LLM repair
    return s
