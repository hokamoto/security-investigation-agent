// Synthesize and Replan Function
// Combines synthesis of query results, replan decision, and replanning in a single LLM call

function SynthesizeAndReplan(
  user_question: string,
  investigation_strategy: string,
  current_replanning_round: int,
  max_replanning_rounds: int,
  executed_queries: ExecutedQueryForBAML[],
  previous_synthesis_summary: string,
  available_hosts: string[],
  available_rule_tags: string[],
  database_name: string,
  siem_log_table_name: string,
  cdn_log_table_name: string,
  session_timestamp: string,
  original_language: string
) -> SynthesizeAndReplanResult {
  client GptOss
  prompt #"
    {{ _.role("system") }}
    {{ SystemPrompt(database_name, siem_log_table_name, cdn_log_table_name, available_hosts, available_rule_tags, session_timestamp) }}
    {{ SqlRequirements(database_name, siem_log_table_name, cdn_log_table_name) }}

    ## Available Hosts
    {{ available_hosts }}

    ## Available ruleTags
    {{ available_rule_tags }}

    **CURRENT WORKFLOW PHASE: SYNTHESIZE + REPLAN**
    You are in the **synthesize and replan** phase of the investigation workflow.
    **Current Replanning Round**: {{ current_replanning_round }} of {{ max_replanning_rounds }}

    ## Task

    You have executed queries for the investigation. Now you must:
    1. **Interpret** each query result individually
    2. **Synthesize** all findings into a coherent understanding
    3. **Decide** whether to continue investigation or provide a final answer
    4. **Act** based on your decision (answer or replan)

    ### Step 1: Query Result Interpretation

    For each executed query (including queries from previous rounds), provide:
    - `query_id`: The query's ID
    - `interpretation`: What this query result reveals, including specific facts (MUST use `<fact>` tags for numerical values and IP addresses only)
      - If a query already has an interpretation from a previous round, you MUST provide the same interpretation again (copy it exactly)
      - Only provide new interpretations for queries that have empty interpretation field
    - `gaps_identified`: Any missing information this query reveals (null if none)
      - Same as interpretation: copy existing values for previously interpreted queries

    **Numerical values and IP addresses from query results MUST be written with `<fact>` tags in `interpretation`:**
    - Format: `<fact source="description of where this value came from" val="value" />`
    - Both `source` and `val` attributes are REQUIRED
    - Use for: numerical values and IP addresses only
    - Example: `<fact source="query 1 row 1, attack_count column" val="15234" />`
    - Example: `<fact source="query 1 row 1, clientIP column" val="62.60.131.73" />`
    - Example: `<fact source="total row count" val="0" />`

    **When to skip using `<fact>` tags:**
    - Section numbers (e.g., "1. Introduction")
    - Calendar dates (e.g., "2025-03-15")

    #### Calculation Requirements
    {{ CalcTagRequirements() }}

    ### Step 2: Synthesis

    Provide:
    - `synthesis_summary`: Comprehensive summary of what has been learned across ALL queries from ALL rounds (including previous rounds and the current round)

    ### Step 3: Decision

    Choose one of:
    - **COMPLETE**: Sufficient information to answer the user's question
    - **CONTINUE**: More investigation needed AND remaining rounds available

    Provide:
    - `decision_rationale`: Explain your decision for COMPLETE or CONTINUE

    {% if current_replanning_round >= max_replanning_rounds %}
    **REMINDER**: This is the final round. CONTINUE is NOT available. You MUST choose COMPLETE.
    {% endif %}

    ### Decision Guidelines

    Choose **COMPLETE** when:
    - You have enough data to answer the user's question
    - Additional queries would not significantly improve the answer
    - The user's question has been addressed to a reasonable degree

    Choose **CONTINUE** when:
    - Critical information is still missing
    - Previous queries revealed new directions to explore
    - The answer would be significantly improved by more data
    - **Any query contained placeholder values** (e.g., `REPLACE_WITH_...`, `IP1`, `<value>`) instead of real values — the query returned meaningless results and MUST be re-run with actual values in the next round
    - **Any query used wrong column names or table**, causing 0 rows or errors that do not reflect reality

    ### Step 4: Action Based on Decision

    If COMPLETE:
    Provide `final_answer`:
    - Before finalizing, run a coverage self-check against the user question and confirm every ask is explicitly answered (including required qualifiers such as time range, target host/service, and metric type when requested)
    - Do not imply answers. Directly answer the user's questions. State each answer explicitly in text, even if it can be inferred from tables or other evidence
    - Include specific facts with `<fact>` tags (for numerical values and IP addresses only)
    - Use `<calc>` tags for any derived calculations (e.g., percentages, ratios across queries)
    - Reference the evidence from query results
    - When the question asks for "detailed breakdown", "analyze", or similar, include ALL relevant details from your query results—do not omit categories or subcategories
    - When reporting breakdowns, ALWAYS include specific counts for each category
    - **Format multiple values as Markdown tables when presenting 3 or more rows OR 3 or more columns** (e.g., use table format for listing multiple IPs with counts, attack types distribution, etc.)
    - **CRITICAL**: When detailed breakdown data is available but totals/aggregates were not directly queried, compute and report the totals from the available data (e.g., sum of counts to get total, identification of predominant categories by comparing counts)
    {% if original_language != "English" %}
    - After compiling and provide the `final_answer`, also include the {{ original_language }} language translation in the `final_answer` as well. Preserve all technical terms, identifiers such as hostnames, IP addresses, timestamps, rule tags, etc. exactly as they appear.
    {% endif %}

    Also provide `supporting_data`:
    - Present the key data points, query results, and evidence that support the claims made in the final answer
    - Reference specific query IDs and values if any

    Also provide `data_gaps`:
    - Describe any aspects of the question that could not be fully answered
    - Note data that was missing or inconclusive
    - If any ask from the user question is not answerable, explicitly list it as `Not enough data for <ask>`
    - If there are no gaps, return `null`

    If CONTINUE:
    Provide `replan`:
    - `updated_strategy`: What additional information is needed to answer the user's question, and how the next queries will gather that information
    - `queries`: 1-5 new SQL queries for the next round
      - **You CAN reference specific values from previous round queries in WHERE clauses** (e.g., if a previous query found top IP is 1.2.3.4, your new query can use WHERE clientIP = '1.2.3.4')
      - Each query needs: `purpose`, `sql`
      - `query_id` will be automatically assigned by Python (do not generate it)

    {{ _.role("user") }}
    ## User Question
    {{ user_question }}

    ## Investigation Strategy
    {{ investigation_strategy }}

    {% if previous_synthesis_summary %}
    ## Previous Round Synthesis Summary
    {{ previous_synthesis_summary }}
    {% endif %}

    ## Executed Queries and Results
    {{ executed_queries }}

    {{ _.role("system") }}
    {{ ctx.output_format }}
  "#
}
