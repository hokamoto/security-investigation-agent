// BAML Types for SIEM Agent Investigation Planning

class PlannedQuery {
  purpose string @description("What this query discovers - succinct, action-oriented")
  sql string @description("Single-line ClickHouse SQL")
}

class InvestigationPlan {
  is_answerable bool @description("Whether the question can be answered with WAF/CDN logs")
  unanswerable_reason string? @description("Explanation if not answerable (required when is_answerable=false)")
  investigation_strategy string? @description("Detailed explanation of the investigation approach (null when is_answerable=false)")
  queries PlannedQuery[]? @description("SQL queries (null when is_answerable=false)")
}

// SQL repair result from RepairSql BAML function
class SqlRepairResult {
  explanation string @description("Detailed explanation of what was fixed and why it was fixed that way.")
  sql string @description("Corrected ClickHouse-compatible SQL query. Must be single-line with no newline characters.")
}

// ============================================================
// Synthesize and Replan Types
// ============================================================

// Each query result interpretation
class QueryResultInterpretation {
  query_id int @description("Corresponding query_id")
  interpretation string @description("What this query result reveals, including specific facts with <fact> tags for numerical values and IP addresses only")
  gaps_identified string? @description("Missing information revealed by this query")
}

// Replan decision enum
enum ReplanDecisionType {
  CONTINUE @description("Additional investigation needed")
  COMPLETE @description("Sufficient data to answer the question")
}

// Replan result (when decision is CONTINUE)
class ReplanResult {
  updated_strategy string @description("Updated investigation strategy based on findings")
  queries PlannedQuery[] @description("Next round queries (1-5)")
}

// Query information formatted for BAML type system (all values stringified)
class ExecutedQueryForBAML {
  query_id int
  purpose string
  sql string
  row_count int
  result map<string, string>[]
  interpretation string @description("Interpretation of the query result (populated after synthesis, empty before)")
  gaps_identified string? @description("Missing information revealed by this query (null if none or not yet synthesized)")
}

// SynthesizeAndReplan function output
class SynthesizeAndReplanResult {
  // Step 1: Individual query result interpretations
  query_interpretations QueryResultInterpretation[]

  // Step 2: Overall synthesis
  synthesis_summary string @description("Summary of what has been learned so far")

  // Step 3: Decision
  decision ReplanDecisionType
  decision_rationale string @description("Reasoning for the decision")

  // Step 4a: COMPLETE - final answer
  final_answer string? @description("Answer to the user question (use <fact> tags for numerical values and IP addresses only). Required when decision=COMPLETE")

  // Step 4b: CONTINUE - replan
  replan ReplanResult? @description("Follow-up queries. Required when decision=CONTINUE")
}

// Result of executing a single query (for Python execution tracking)
class QueryExecutionResult {
  query_id int @description("Query ID from PlannedQuery")
  status string @description("Execution status: 'ok', 'validation_failed', 'execution_failed', 'result_overflow'")
  sql string @description("The SQL that was executed (may be repaired version)")
  row_count int? @description("Number of rows returned (null if failed)")
  error_message string? @description("Error message if status != 'ok'")
  formatted_result string? @description("Table-formatted result text (null if failed)")
}
