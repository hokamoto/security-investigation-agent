# Test Failure Analysis Guide

This document helps LLMs (Claude, ChatGPT, etc.) efficiently analyze test failures from the SIEM agent's LLM-as-a-judge regression harness. It provides structured commands, failure taxonomy, and a step-by-step analysis checklist optimized for context-window efficiency. Do not fix any tests, just analyze them.

## Key File Paths

| Purpose | Path |
|---------|------|
| Test case definitions | `test_runner/test/test_cases.yaml` |
| Test results | `test_runner/test_results/test_results_*.jsonl` |
| Session logs | `logs/session_*.jsonl` |
| BAML prompts | `siem_agent/baml_src/` (`fragments.baml`, `investigation_plan.baml`, `synthesize_and_replan.baml`, `sql_repair.baml`) |
| Agent source | `siem_agent/main.py`, `siem_agent/execute.py`, `siem_agent/synthesize.py` |

### Test Results Structure

Each line in a test results JSONL file contains:
- `record_type`: always `"test_result"`
- `test_name`: matches the `name` field in `test_cases.yaml`
- `run_number`: which run (tests are typically run multiple times for reliability)
- `question`, `answer`: the agent's input and output
- `acceptance_criteria`: list of criteria strings the judge evaluates
- `result`: `"PASS"` or `"FAIL"`
- `reason`: the judge's explanation
- `agent_log_file`: path to the full session log for this run

### Session Log Structure

Each line is a JSON event with `event_type`, `timestamp`, `message`, and `data`. Event types:
- `session_start` — question and config
- `discovery` — host/ruleTag discovery results
- `llm_call` — LLM prompts and responses (planning, synthesis, repair)
- `sql_query` — SQL queries with results, errors, repair attempts
- `round_start` / `round_end` — iteration boundaries
- `session_end` — final answer and summary

The `sql_query` data includes: `purpose`, `sql_original`, `sql_executed`, `success`, `row_count`, `columns`, `rows`, `error_code`, `error_message`, `is_repair_attempt`, `repair_attempt_number`.

## Efficient Log Analysis with `jq`

### Extract Only Failures from Test Results

```bash
# All failures from a specific results file
cat test_runner/test_results/test_results_*.jsonl | jq -c 'select(.result == "FAIL")'

# Failures with readable summary
cat test_runner/test_results/test_results_*.jsonl | jq -r 'select(.result == "FAIL") | "\(.test_name) run \(.run_number): \(.reason)"'

# Count pass/fail per test
cat test_runner/test_results/test_results_*.jsonl | jq -r '[.test_name, .result] | @tsv' | sort | uniq -c
```

### Find the Session Log for a Failed Test

```bash
# Get the session log path for a specific failed test (Replace `[TEST_NAME]` with the real test name)
cat test_runner/test_results/test_results_*.jsonl | jq -r 'select(.result == "FAIL" and .test_name == "[TEST_NAME]") | .agent_log_file'
```

### Extract Human-Readable Messages from a Session Log

```bash
# Full readable trace (best first step for understanding a failure)
cat logs/session_TIMESTAMP.jsonl | jq -r '.message'
```

### Extract LLM Prompts and Responses

```bash
# All LLM calls (planning, synthesis, repair)
cat logs/session_TIMESTAMP.jsonl | jq 'select(.event_type == "llm_call")'

# Just the message summaries
cat logs/session_TIMESTAMP.jsonl | jq -r 'select(.event_type == "llm_call") | .message'
```

### Extract SQL Queries and Results

```bash
# All SQL queries with purpose, SQL, and outcome
cat logs/session_TIMESTAMP.jsonl | jq 'select(.event_type == "sql_query") | {purpose: .data.purpose, sql: .data.sql_executed, success: .data.success, rows: .data.row_count, error: .data.error_message}'

# Only failed SQL queries
cat logs/session_TIMESTAMP.jsonl | jq 'select(.event_type == "sql_query" and .data.success == false) | {purpose: .data.purpose, sql: .data.sql_executed, error: .data.error_message, is_repair: .data.is_repair_attempt}'

# SQL queries with their full result data
cat logs/session_TIMESTAMP.jsonl | jq 'select(.event_type == "sql_query" and .data.success == true) | {purpose: .data.purpose, sql: .data.sql_executed, columns: .data.columns, rows: .data.rows}'
```

### Extract Session Summary

```bash
# Final answer and session metadata
cat logs/session_TIMESTAMP.jsonl | jq 'select(.event_type == "session_end")'
```

### Full Investigation Trace for a Failed Test (Combined)

```bash
# 1. Find session log for a failed test
LOG=$(cat test_runner/test_results/test_results_*.jsonl | jq -r 'select(.result == "FAIL" and .test_name == "TEST_NAME" and .run_number == 1) | .agent_log_file')

# 2. Get the full readable trace
cat "$LOG" | jq -r '.message'

# 3. Or get a compact summary: round markers + SQL outcomes + final answer
cat "$LOG" | jq -r 'select(.event_type == "round_start" or .event_type == "round_end" or .event_type == "sql_query" or .event_type == "session_end") | .message'
```

## Failure Classification Taxonomy

When analyzing a failure, classify it into one of these categories to guide remediation:

### 1. Agent Analysis Error
The agent produced wrong numbers or conclusions despite having correct SQL results. The data was there, but the synthesis or final answer misinterpreted it.

**Indicators**: SQL query results contain the correct data, but the final answer states incorrect values.

### 2. Incomplete Answer
Correct data was retrieved and mostly reported, but the final answer omitted a required detail (e.g., missing a total count, not stating an explicit number).

**Indicators**: Judge says "does not explicitly state X" even though X is derivable from the answer.

### 3. SQL Generation Error
The LLM generated incorrect SQL that returned wrong data. The query succeeded but produced incorrect results (wrong filters, wrong aggregation, wrong joins).

**Indicators**: SQL queries succeed but return unexpected values; final answer is wrong because the underlying data was wrong.

### 4. SQL Repair Failure
A query failed with a ClickHouse error and the auto-repair mechanism (via `RepairSql`) could not fix it within the allowed retries.

**Indicators**: `sql_query` events with `success: false` and `is_repair_attempt: true`; error messages in the log.

### 5. Arithmetic/Calculation Error
The agent made arithmetic mistakes, either in `<calc>` tag evaluation or in LLM-generated arithmetic within the synthesis step.

**Indicators**: SQL results are correct, individual numbers in the answer are correct, but derived values (percentages, differences, totals) are wrong.

### 6. Synthesis Omission
The synthesis step dropped relevant facts that were present in query results. Data was retrieved correctly but not carried through to the final answer.

**Indicators**: Query results contain the needed data (visible in `sql_query` events), but the synthesis LLM call output omits it.

### 7. Premature Completion
The agent decided `COMPLETE` too early in the replan step without having gathered sufficient data to answer the question fully.

**Indicators**: Few rounds executed; `session_end` shows the agent chose to stop; missing data that required additional queries.

### 8. Forced Completion
The agent hit the maximum number of rounds (`max_iterations` or `max_replanning_rounds`) without fully answering.

**Indicators**: Many rounds in the session log; the last round shows max iteration reached.

### 9. Test Case Ambiguity
The acceptance criteria contain implicit assumptions not directly stated in the question, or the criteria are ambiguous.

**Indicators**: The agent's answer is reasonable and factually correct but doesn't match the specific phrasing expected by the criteria.

### 10. Judge Error
The LLM judge made an incorrect pass/fail determination — either passing a wrong answer or failing a correct one.

**Indicators**: Manual review shows the answer meets all criteria but the judge said FAIL (or vice versa).

### 11. Unanswerable Misclassification
The agent incorrectly classified a question as unanswerable (when data exists) or as answerable (when data doesn't exist).

**Indicators**: Session log shows the agent concluded "cannot be determined" when queries could have answered it, or the agent fabricated an answer without data support.

## Debugging Tools

```bash
# Replay a SQL query against ClickHouse to verify results
uv run python support-scripts/debug_query.py "SELECT ..."
```

## Analysis Checklist for LLMs

Follow these steps when analyzing a test failure:

### Step 1: Identify the Failure
```bash
cat test_runner/test_results/test_results_*.jsonl | jq -r 'select(.result == "FAIL") | "[\(.test_name) run \(.run_number)] \(.reason)"'
```
Note the `test_name`, `run_number`, and the judge's `reason`.

### Step 2: Compare Answer vs Criteria
Read the failed test result entry. Compare the `answer` field against each item in `acceptance_criteria`. Identify exactly which criterion was not met.

### Step 3: Get the Session Log
```bash
LOG=$(cat test_runner/test_results/test_results_*.jsonl | jq -r 'select(.result == "FAIL" and .test_name == "TEST_NAME" and .run_number == RUN) | .agent_log_file')
```

### Step 4: Read the Human-Readable Trace
```bash
cat "$LOG" | jq -r '.message'
```
This gives the fastest overview of what happened during the investigation.

### Step 5: Check SQL Results
```bash
cat "$LOG" | jq 'select(.event_type == "sql_query") | {round: .data.round_number, purpose: .data.purpose, success: .data.success, rows: .data.row_count, error: .data.error_message}'
```
Determine if queries returned the right data. If a query should have returned data for the missing criterion, check whether:
- The query was never planned (planning issue)
- The query was planned but failed (SQL/repair issue)
- The query succeeded but returned wrong data (SQL generation issue)
- The query returned correct data but it was lost in synthesis

### Step 6: Classify the Failure
Using the taxonomy above, assign a category. This determines where to focus remediation.
