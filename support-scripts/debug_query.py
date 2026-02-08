#!/usr/bin/env python3
"""
Debug script to run arbitrary SQL queries against ClickHouse.
Useful for testing queries during development.
"""

import yaml
import clickhouse_connect
import argparse
import csv
import sys
import re

# ============================================================
# EDIT THESE QUERIES FOR YOUR DEBUGGING NEEDS
# Note: Use {database_name}.{siem_log_table_name} or {database_name}.{cdn_log_table_name} format
# Add multiple queries as list items - they will be executed sequentially
# ============================================================
QUERIES = [
    """
    SELECT * FROM system.columns WHERE table = '{siem_log_table_name}' AND database = '{database_name}'
    """
]
# ============================================================


def _append_settings_clause(sql: str, max_result_rows: int, readonly: int = 2) -> str:
    """
    Append SETTINGS clause to SQL query if not already present.

    Args:
        sql: SQL query string
        max_result_rows: max_result_rows setting value
        readonly: readonly setting value (default: 2 for debug script)

    Returns:
        SQL string with SETTINGS clause appended
    """
    # Strip trailing whitespace and semicolons
    sql = sql.rstrip().rstrip(";")

    # Check if query already has SETTINGS clause
    if re.search(r"\bSETTINGS\b", sql, re.IGNORECASE):
        # SETTINGS clause already exists, return as-is
        return sql

    # Check if this is a SET command (skip SETTINGS clause for SET commands)
    if re.match(r"^\s*SET\b", sql, re.IGNORECASE):
        # SET command, return as-is
        return sql

    return sql


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Run SQL queries against ClickHouse")
    parser.add_argument(
        "query",
        nargs="?",
        help="SQL query to execute (if not provided, uses QUERIES constant)",
    )
    parser.add_argument("--csv", action="store_true", help="Output results in CSV format")
    args = parser.parse_args()

    # Load configuration
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)

    ch_config = config["clickhouse"]

    if not args.csv:
        print(f"Connecting to ClickHouse at {ch_config['host']}:{ch_config['port']}")
        print(f"Database: {ch_config['database']}\n")

    # Connect to ClickHouse
    client = clickhouse_connect.get_client(
        host=ch_config["host"],
        port=ch_config["port"],
        interface="https",
        username=ch_config["user"],
        password=ch_config["password"],
        database=ch_config["database"],
        send_receive_timeout=300,
        connect_timeout=30,
    )

    # Determine which queries to execute
    if args.query:
        # Use query from command-line argument
        queries_to_execute = [args.query]
    else:
        # Use queries from QUERIES constant
        queries_to_execute = QUERIES

    # Format queries with database and table name
    formatted_queries = [
        _append_settings_clause(
            query.format(
                database_name=ch_config["database"],
                siem_log_table_name=ch_config["siem_log_table_name"],
                cdn_log_table_name=ch_config["cdn_log_table_name"],
            ),
            max_result_rows=ch_config["max_result_rows"],
            readonly=2,
        )
        for query in queries_to_execute
    ]

    try:
        # CSV output setup
        csv_writer = None
        csv_header_written = False

        if args.csv:
            csv_writer = csv.writer(sys.stdout, quoting=csv.QUOTE_NONNUMERIC, lineterminator="\n")

        # Execute queries sequentially
        for idx, formatted_query in enumerate(formatted_queries, 1):
            if not args.csv:
                print(f"Executing query {idx}/{len(formatted_queries)}:")
                print("-" * 60)
                print(formatted_query)
                print("-" * 60)
                print()

            # Execute query
            result = client.query(formatted_query)

            # Display results
            if result.row_count > 0:
                col_names = result.column_names

                if args.csv:
                    # CSV output - write header only once (for first query)
                    if not csv_header_written:
                        csv_writer.writerow(col_names)
                        csv_header_written = True

                    # Write all rows
                    for row in result.result_rows:
                        # Clean up data: replace actual newlines with escaped versions
                        cleaned_row = []
                        for val in row:
                            if isinstance(val, str):
                                # Replace actual newlines with space to prevent CSV breaking
                                cleaned_val = val.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
                                cleaned_row.append(cleaned_val)
                            else:
                                cleaned_row.append(val)
                        csv_writer.writerow(cleaned_row)
                else:
                    # Text output
                    print(f"Results ({result.row_count} rows):\n")
                    print(" | ".join(col_names))
                    print("-" * 60)
                    for row in result.result_rows:
                        print(" | ".join(str(val) for val in row))
                    print()  # Add blank line between query results
            else:
                if not args.csv:
                    print("No results returned.")
                    print()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    finally:
        client.close()

    return 0


if __name__ == "__main__":
    exit(main())
