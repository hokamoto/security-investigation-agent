"""ClickHouse query utilities for BAML-based SIEM Agent."""

import json
import re
from datetime import datetime, UTC
from typing import Any

import clickhouse_connect


class ClickHouseClient:
    """Reusable ClickHouse client for SIEM Agent.

    Provides methods for:
    - Executing read-only SQL queries with safety settings
    - Discovering available hosts and ruleTags
    - SQL transformation utilities (timestamp replacement, settings clause)

    Designed for use as an LLM tool.
    """

    def __init__(
        self,
        config: dict,
        session_timestamp: str | None = None,
    ):
        """Initialize ClickHouse client.

        Args:
            config: Configuration dictionary containing 'clickhouse' section.
            session_timestamp: Fixed ISO timestamp for session (prevents now() drift).
                               If None, uses current UTC time.
        """
        self.config = config
        self.session_timestamp = session_timestamp or datetime.now(UTC).isoformat().replace("+00:00", "Z")

        # Extract commonly used config values
        self._ch_config = self.config["clickhouse"]
        self.database_name = self._ch_config["database"]
        self.siem_log_table_name = self._ch_config["siem_log_table_name"]
        self.cdn_log_table_name = self._ch_config["cdn_log_table_name"]
        self.max_result_rows = self._ch_config.get("max_result_rows", 100)
        self.excluded_rule_tag_prefixes = [
            prefix.strip() for prefix in self.config.get("agent", {}).get("excluded_rule_tag_prefixes", []) if isinstance(prefix, str) and prefix.strip()
        ]

        self._client = None

    def _get_client(self):
        """Get or create ClickHouse client connection."""
        if self._client is None:
            self._client = clickhouse_connect.get_client(
                host=self._ch_config["host"],
                port=self._ch_config["port"],
                interface="https",
                database=self.database_name,
                username=self._ch_config["user"],
                password=self._ch_config["password"],
            )
        return self._client

    def close(self):
        """Close the ClickHouse client connection."""
        if self._client is not None and hasattr(self._client, "close"):
            self._client.close()
            self._client = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False

    def prepare_sql(
        self,
        sql: str,
        readonly: int = 2,
        max_result_rows: int | None = None,
    ) -> str:
        """Prepare SQL for execution by applying transformations.

        Args:
            sql: Raw SQL query string
            readonly: Read-only mode for SETTINGS (2 = read-only, disallow temp tables)
            max_result_rows: Max rows (uses instance default if None)

        Returns:
            Prepared SQL string
        """
        effective_max_rows = max_result_rows if max_result_rows is not None else self.max_result_rows

        # Replace now() with fixed timestamp
        replacement = f"parseDateTimeBestEffort('{self.session_timestamp}')"
        pattern = r"\bnow\s*\(\s*\)"
        sql = re.sub(pattern, replacement, sql, flags=re.IGNORECASE)

        # Append SETTINGS clause if not present
        sql = sql.rstrip().rstrip(";")
        if not re.search(r"\bSETTINGS\b", sql, re.IGNORECASE):
            sql += f"""
SETTINGS readonly = {readonly}, max_execution_time = 20, max_result_rows = {effective_max_rows}, result_overflow_mode = 'throw'"""

        return sql

    def execute_query(
        self,
        sql: str,
        prepare: bool = True,
    ) -> dict[str, Any]:
        """Execute a SQL query and return results.

        Designed for use as an LLM tool.

        Args:
            sql: SQL query to execute
            prepare: If True, apply prepare_sql() transformations

        Returns:
            Dictionary with:
                - success: bool
                - columns: list of column names (if success)
                - rows: list of dicts, each dict maps column name to value (if success)
                - row_count: number of rows returned (if success)
                - error: error message (if not success)
                - sql: the original SQL before any transformations
        """
        try:
            executed_sql = self.prepare_sql(sql) if prepare else sql
            client = self._get_client()
            result = client.query(executed_sql)

            # Convert rows to list of dicts with column names as keys
            rows_as_dicts = [dict(zip(result.column_names, row)) for row in result.result_rows]

            return {
                "success": True,
                "columns": result.column_names,
                "rows": rows_as_dicts,
                "row_count": len(rows_as_dicts),
                "sql": sql,
            }
        except Exception as e:
            error_str = str(e)
            error_code = None
            error_message = error_str  # Default to full error string

            # Try to extract structured error information from JSON response
            if "server response:" in error_str:
                try:
                    # Extract JSON part
                    json_start = error_str.find("server response:") + len("server response:")
                    json_end = error_str.rfind("(for url")
                    if json_end == -1:
                        json_end = len(error_str)

                    json_str = error_str[json_start:json_end].strip()
                    parsed = json.loads(json_str)

                    # Extract error code and message
                    if "error" in parsed:
                        full_error = parsed["error"]
                        # Extract code: "Code: 62. DB::Exception: ..."
                        import re

                        code_match = re.match(r"^Code:\s*(\d+)\.", full_error)
                        if code_match:
                            error_code = int(code_match.group(1))

                        # Extract message after "DB::Exception:"
                        if "DB::Exception:" in full_error:
                            error_message = full_error.split("DB::Exception:", 1)[1].strip()
                            # Remove "FORMAT Native" and everything after
                            error_message = re.sub(
                                r"\n FORMAT Native.*",
                                "",
                                error_message,
                                flags=re.DOTALL,
                            )
                        else:
                            error_message = full_error

                except (json.JSONDecodeError, KeyError, ValueError):
                    # Fall back to full error string if parsing fails
                    pass

            return {
                "success": False,
                "error": error_str,  # Full error string for logging
                "error_code": error_code,  # Structured: ClickHouse error code
                "error_message": error_message,  # Structured: concise error message
                "sql": sql,
            }

    @classmethod
    def format_query_result_as_table(cls, columns: list[str], rows: list[dict]) -> str:
        """Format query result as a plain-text table.

        Args:
            columns: List of column names
            rows: List of row dicts (column name -> value)

        Returns:
            Formatted table string
        """
        if not rows:
            return "No rows returned"

        # Convert to string rows using column order
        headers = columns or list(rows[0].keys())
        str_rows = [[str(row[col]) if row.get(col) is not None else "NULL" for col in headers] for row in rows]

        # Compute column widths
        col_widths = [len(h) for h in headers]
        for row in str_rows:
            for idx, val in enumerate(row):
                col_widths[idx] = max(col_widths[idx], len(val))

        def _fmt_row(row: list[str]) -> str:
            return " | ".join(val.ljust(col_widths[idx]) for idx, val in enumerate(row))

        # Format table
        header_line = _fmt_row(headers)
        separator = "-+-".join("-" * width for width in col_widths)
        data_lines = [_fmt_row(row) for row in str_rows]

        return "\n".join([header_line, separator] + data_lines)

    def discover_hosts_and_tags(self) -> tuple[list[str], list[str]]:
        """Query ClickHouse for available hosts and ruleTags.

        Returns:
            Tuple of (available_hosts, available_rule_tags)
        """
        available_hosts = []
        available_rule_tags = []

        # Discover hosts (last 7 days)
        hosts_sql = f"""
        SELECT DISTINCT host
        FROM {self.database_name}.{self.siem_log_table_name}
        WHERE now() >= timestamp AND timestamp >= now() - INTERVAL 7 DAY
        ORDER BY host
        LIMIT 100
        """
        result = self.execute_query(hosts_sql)
        if result["success"]:
            available_hosts = [row["host"] for row in result["rows"]]

        # Discover ruleTags (last 90 days)
        tags_sql = f"""
        SELECT DISTINCT arrayJoin(ruleTags) as ruleTag
        FROM {self.database_name}.{self.siem_log_table_name}
        WHERE now() >= timestamp AND timestamp >= now() - INTERVAL 90 DAY
        ORDER BY ruleTag ASC
        """
        result = self.execute_query(tags_sql)
        if result["success"]:
            available_rule_tags = [
                rule_tag
                for row in result["rows"]
                if (rule_tag := row["ruleTag"]) and not any(rule_tag.startswith(prefix) for prefix in self.excluded_rule_tag_prefixes)
            ]

        return available_hosts, available_rule_tags
