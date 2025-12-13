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

# ============================================================
# EDIT THESE QUERIES FOR YOUR DEBUGGING NEEDS
# Note: Use {database_name}.{siem_log_table_name} or {database_name}.{cdn_log_table_name} format
# Add multiple queries as list items - they will be executed sequentially
# ============================================================
QUERIES = [
    """
    SELECT * FROM akamai_jp.siem WHERE has(attackTypes, 'Bot') LIMIT 3
    """
]
# ============================================================


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Run SQL queries against ClickHouse")
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
        settings={
            "readonly": 2,
            "max_result_rows": 300,
            "max_result_bytes": 100000000,
            "result_overflow_mode": "break",
        }
    )

    # Format queries with database and table name
    formatted_queries = [
        query.format(
            database_name=ch_config["database"],
            siem_log_table_name=ch_config["siem_log_table_name"],
            cdn_log_table_name=ch_config["cdn_log_table_name"]
        )
        for query in QUERIES
    ]

    try:
        # CSV output setup
        csv_writer = None
        csv_header_written = False

        if args.csv:
            csv_writer = csv.writer(
                sys.stdout,
                quoting=csv.QUOTE_NONNUMERIC,
                lineterminator='\n'
            )

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
                                cleaned_val = val.replace('\r\n', ' ').replace('\n', ' ').replace('\r', ' ')
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
