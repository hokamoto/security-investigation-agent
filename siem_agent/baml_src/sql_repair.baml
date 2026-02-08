// SQL Repair Function for SIEM Agent
// This function takes a failed SQL query and attempts to repair it

function RepairSql(
  sql_query: string,
  error_message: string,
  purpose: string,
  database_name: string,
  siem_log_table_name: string,
  cdn_log_table_name: string,
  available_hosts: string[],
  available_rule_tags: string[],
  session_timestamp: string
) -> SqlRepairResult {
  client GptOss
  prompt #"
    {{ _.role("system") }}
    {{ SystemPrompt(database_name, siem_log_table_name, cdn_log_table_name, available_hosts, available_rule_tags, session_timestamp) }}
    {{ SqlRequirements(database_name, siem_log_table_name, cdn_log_table_name) }}

    ## Available Hosts
    {{ available_hosts }}

    ## Available ruleTags
    {{ available_rule_tags }}
    
    ## Task
    A SQL query has failed execution with an error. Analyze the error and provide the corrected SQL in the `sql` field.

    ### Repair-Specific Guidelines

    1. **Preserve the query's intent and purpose**: Only fix the specific error. Do NOT change the query's purpose, logic, or expected results. The original query's intent (shown in "Query Purpose" above) must be maintained.
       - Do NOT rewrite queries to switch tables (WAF ↔ CDN). The table choice reflects the user's intent.
       - Do NOT add or remove filtering conditions, aggregations, or change the output columns unless required to fix the error.

    2. **EXCEPTION - Row limit exceeded errors (TOO_MANY_ROWS_OR_BYTES)**: When the error indicates too many rows were returned, you MAY modify the query to reduce result size while preserving the original intent as closely as possible. Choose the most appropriate strategy:

       **Aggregation**: Use GROUP BY with aggregate functions (e.g., COUNT, SUM, AVG) to return a statistical summary instead of individual rows.
       - Example: Instead of listing all attack requests, return counts grouped by clientIP or path.

       **Coarsen time granularity**: Reduce temporal resolution to decrease row count.
       - Example: Change `toStartOfHour(timestamp)` to `toStartOfInterval(timestamp, INTERVAL 6 HOUR)` or `toDate(timestamp)`.

       **Top N with LIMIT**: Add ORDER BY and LIMIT to return only the most significant results.
       - Example: Add `ORDER BY count DESC LIMIT 20` to get top 20 entries.
       - Always sort by a meaningful metric (count, sum, etc.) to ensure the most relevant results are returned.

       **Statistical sampling**: Use ClickHouse's SAMPLE clause for approximate results on large datasets.
       - Example: Add `SAMPLE 0.1` (10% sample) to get representative data.
       - Best for trend analysis where exact counts are not critical.

       **Important**: In your explanation, clearly state which strategy was applied and how the results differ from the original query's intent (e.g., "Changed from hourly to 6-hour intervals to reduce row count" or "Limited to top 20 results by attack count").

    3. **Column name corrections for unknown column errors**:
       - If error mentions unknown column, check if it's a typo or wrong table's column name
       - Common mistakes: Using CDN column names in WAF queries or vice versa
       - WAF table uses: `host`, `timestamp` (DateTime), `clientIP`, `attackTypes`, `appliedAction`, etc.
       - CDN table uses: `reqHost`, `reqTimeSec` (DateTime64(3)), `cliIP`, `statusCode`, `proto`, etc.

    Please analyze the error and provide the corrected SQL query. Focus specifically on fixing the issue mentioned in the error message while preserving the query's original intent.
    {{ _.role("user") }}
    **Query Purpose:**
    {{ purpose }}

    **Failed SQL:**
    ```sql
    {{ sql_query }}
    ```

    **Error Message:**
    ```
    {{ error_message }}
    ```
    {{ _.role("system") }}
    {{ ctx.output_format }}
  "#
}
