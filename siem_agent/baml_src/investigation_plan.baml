// Investigation Planning Function for SIEM Agent
// This function first evaluates answerability, then generates queries if answerable

function GenerateInvestigationPlan(
  user_question: string,
  available_hosts: string[],
  available_rule_tags: string[],
  database_name: string,
  siem_log_table_name: string,
  cdn_log_table_name: string,
  current_replanning_round: int,
  max_replanning_rounds: int,
  session_timestamp: string
) -> InvestigationPlan {
  client GptOss
  prompt #"
    {{ _.role("system") }}
    {{ SystemPrompt(database_name, siem_log_table_name, cdn_log_table_name, available_hosts, available_rule_tags, session_timestamp) }}
    {{ SqlRequirements(database_name, siem_log_table_name, cdn_log_table_name) }}

    ## Available Hosts
    {{ available_hosts }}

    ## Available ruleTags
    {{ available_rule_tags }}

    **CURRENT WORKFLOW PHASE: PLANNING**
    You are in the **plan** phase of the investigation workflow.
    **Current Planning Round**: {{ current_replanning_round }} of {{ max_replanning_rounds }}

    ## Task
    Your task has two steps:
    1. **Evaluate Answerability**: Determine whether the user's question can be answered with WAF/CDN logs
    2. **Generate Queries** (only if answerable): Create SQL queries to gather the required data

    ---

    ## Step 1: Answerability Evaluation

    Before generating any queries, evaluate whether the question can be answered.

    ### Query Completeness Requirements (check FIRST)

    1. **Explicit Time Period Required:**
       - The user question MUST specify a time range explicitly
       - Valid examples: "last 7 days", "yesterday", "between 2025-01-01 and 2025-01-05", "in December 2025", "past 24 hours"
       - If NO time period is specified: set `is_answerable=false`
       - DO NOT assume a default time period - always require explicit specification

    2. **Explicit Target Host Required:**
       - The user question MUST specify EITHER:
         a) A specific host name (e.g., "www.example.com")
         b) Explicit "all hosts" intent (e.g., "across all hosts", "for all available hosts", "on any host")
       - If NO host is specified AND no "all hosts" intent is expressed: set `is_answerable=false`
       - DO NOT assume a default host - always require explicit specification

    ### Data Availability Requirements

    - The databases do NOT contain: business KPIs, user identities, full request bodies, performance/SLA metrics, or external intelligence
    - Questions requiring these are unanswerable: "total conversions or revenue", "unique users/sessions", "app latency/availability", "user credentials"

    ### Data Uncertainty Handling

    - If the question requires information that MIGHT be present in request headers or query strings but is NOT guaranteed (e.g., usernames, session IDs):
      - **If the question explicitly specifies WHERE the information exists** (e.g., "check `X-User-ID` header"): `is_answerable=true`
      - **If the question does NOT specify the location**: `is_answerable=false` (explain that the location is not specified)

    ### When Unanswerable

    If `is_answerable=false`, set:
    - `unanswerable_reason`: Explain which requirement failed and why
    - `investigation_strategy`: null
    - `queries`: null

    ---

    ## Step 2: Query Planning (only if answerable)

    If `is_answerable=true`, generate SQL queries with the following approach:

    ### Incremental Planning Philosophy
    - **This system supports multi-round investigation**: You can see query results and generate follow-up queries based on those results
    - **Prefer simple queries over complex queries** - let multiple rounds handle complexity
    - **Common pattern**: "Find the top X" in round 1 → "Get details about X" in round 2 using the actual value from round 1
    - Avoid complex JOINs, nested subqueries, or trying to answer everything at once
    - When a question asks for "most attacked X and details about it", plan to identify X first, then get details in a follow-up round
    - If any required host/ruleTag is missing from discovery, adjust scope accordingly

    ### Technical Requirements
    - Each query MUST specify which table it uses: WAF (`{{ database_name }}.{{ siem_log_table_name }}`), CDN (`{{ database_name }}.{{ cdn_log_table_name }}`), or both
    - Respect schema differences: WAF uses host/timestamp, CDN uses reqHost/reqTimeSec. Do NOT mix columns across tables
    - Avoid redundant queries. Each query should add new information
    - **CRITICAL**: When questions ask for "most", "top", "highest", or similar superlatives, ALWAYS include `count()` or the relevant metric in the SELECT clause, not just in ORDER BY. Example: `SELECT path, count() AS total FROM ... GROUP BY path ORDER BY total DESC LIMIT 1` (NOT just `SELECT path FROM ... ORDER BY count() DESC LIMIT 1`)
    ### Multi-Round Investigation Strategy

    **This architecture enables powerful incremental investigation**: You can execute simple queries, examine their results, and generate follow-up queries based on what you learned.

    **When Query B depends on Query A's result**:
    - Round 1: Execute Query A to identify the target (e.g., find the top attacking IP)
    - Round 2: Execute Query B using the actual value from Query A (e.g., analyze that specific IP's behavior)

    **Queries within a single round must be independent** (they execute in parallel):
    - Each query must have all literal values specified
    - DO NOT use placeholders like `REPLACE_WITH_...`, `<VALUE_FROM_QUERY_1>`, `{result}`, or `TBD`
    - Placeholders are treated as literal strings and will return 0 rows

    **Example: "Which IP attacked most and what paths did it target?"**
    - Round 1 → Query 1: `SELECT clientIP, count() AS cnt FROM siem ... GROUP BY clientIP ORDER BY cnt DESC LIMIT 1`
    - Round 1 Result: `clientIP='192.168.1.1', cnt=15234`
    - Round 2 → Query 2: `SELECT path, count() AS cnt FROM siem WHERE clientIP = '192.168.1.1' ... GROUP BY path ORDER BY cnt DESC`

    **This is a FEATURE, not a limitation**: Multi-round investigation allows flexible, adaptive analysis based on discovered patterns.

    ### Output for Answerable Questions
    - `is_answerable`: true
    - `unanswerable_reason`: null
    - `investigation_strategy`: Detailed explanation of the investigation approach
    - `queries`: Array of SQL query objects

    {{ _.role("user") }}
    User Question: {{ user_question }}
    {{ _.role("system") }}
    {{ ctx.output_format }}
  "#
}
