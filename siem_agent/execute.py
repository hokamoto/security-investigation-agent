"""Query execution module for BAML-based SIEM Agent."""

from typing import List, Optional

from baml_py.baml_py import BamlError
import requests

from siem_agent.agent_state import AgentState, ExecutedQuery
from siem_agent.baml_client import b
from siem_agent.baml_client.types import InvestigationPlan, SqlRepairResult
from siem_agent.clickhouse import ClickHouseClient
from siem_agent.sql_utils import normalize_clickhouse_array_functions


# Python dataclass to track execution results (not BAML-generated)
class QueryExecutionResult:
    """Result of executing a single query."""

    def __init__(
        self,
        query_id: int,
        status: str,
        sql: str,
        row_count: Optional[int] = None,
        error_message: Optional[str] = None,
        formatted_result: Optional[str] = None,
    ):
        self.query_id = query_id
        self.status = status
        self.sql = sql
        self.row_count = row_count
        self.error_message = error_message
        self.formatted_result = formatted_result


def repair_sql_with_baml(
    sql_query: str,
    error_message: str,
    purpose: str,
    state: AgentState,
    parent_query_id: int,
) -> Optional[SqlRepairResult]:
    """Call BAML RepairSql function and return repair result.

    Args:
        sql_query: The failed SQL query
        error_message: The error message from validation/execution
        purpose: The intended purpose of the query (from PlannedQuery)
        state: Agent state containing configuration and database metadata
        parent_query_id: The query ID of the original query being repaired

    Returns:
        SqlRepairResult with repaired sql and explanation, None if repair call failed
    """
    try:
        # Create the BAML request
        req = b.request.RepairSql(
            sql_query=sql_query,
            error_message=error_message,
            purpose=purpose,
            database_name=state.database_name,
            siem_log_table_name=state.siem_log_table_name,
            cdn_log_table_name=state.cdn_log_table_name,
            available_hosts=state.available_hosts,
            available_rule_tags=state.available_rule_tags,
            session_timestamp=state.session_timestamp,
        )

        # Make the HTTP call with timing
        with state.session_logger.timed_event() as timer:
            res = requests.post(url=req.url, headers=req.headers, json=req.body.json())
            response_json = res.json()

        # Parse the response
        raw_content = response_json["choices"][0]["message"]["content"]
        if raw_content is None:
            raise ValueError(
                f"LLM returned None content. Response: {response_json}"
            )
        try:
            parsed: SqlRepairResult = b.parse.RepairSql(raw_content)
        except BamlError as e:
            # Log BAML validation error details
            error_details = {
                "error_type": "BAML_ValidationError",
                "function": "RepairSql",
                "raw_output": getattr(e, "raw_output", str(e)),
                "message": getattr(e, "message", str(e)),
                "prompt": getattr(e, "prompt", "N/A"),
                "detailed_message": getattr(e, "detailed_message", str(e)),
            }
            state.session_logger.log_error(
                e, context=f"BAML validation error in RepairSql: {error_details}"
            )
            # Re-raise to crash the program as requested
            raise

        # Normalize array functions in repaired SQL
        if parsed.sql:
            parsed.sql = normalize_clickhouse_array_functions(parsed.sql)

        # Extract prompt for logging
        prompt_full = _extract_prompt_from_request(req)

        # Log the repair LLM call
        state.session_logger.log_llm_call(
            call_type="repair",
            prompt_full=prompt_full,
            raw_response=raw_content,
            parsed_response=parsed,
            response_json=response_json,
            duration=timer.duration,
            parent_id=f"{state.current_replanning_round}_sql_{parent_query_id}",
        )

        return parsed

    except Exception:
        return None


def _extract_prompt_from_request(req) -> str:
    """Extract the prompt text from a BAML request.

    Args:
        req: BAML request object

    Returns:
        Prompt string
    """
    try:
        body = req.body.json()
        messages = body.get("messages", [])
        if messages:
            parts = []
            for msg in messages:
                role = msg.get("role", "")
                content = msg.get("content", "")
                parts.append(f"[{role}]\n{content}")
            return "\n\n".join(parts)
    except Exception:
        pass
    return str(req)


def execute_investigation_plan(
    investigation_plan: InvestigationPlan,
    state: AgentState,
) -> List[QueryExecutionResult]:
    """Execute all queries in investigation plan sequentially.

    Args:
        investigation_plan: BAML InvestigationPlan with queries to execute
        state: Agent state containing configuration and database client

    Returns:
        List of QueryExecutionResult objects (one per query)
    """
    if not investigation_plan.queries:
        return []

    results: List[QueryExecutionResult] = []

    for query in investigation_plan.queries:
        # Assign global query_id from state (LLM does not generate query_id)
        assigned_query_id = state.next_query_id
        state.next_query_id += 1

        original_sql = query.sql
        current_sql = query.sql
        repair_attempt = 0
        query_completed = False

        # Retry loop for repair attempts
        while not query_completed and repair_attempt <= state.max_sql_repair_retries:
            # Execute query with timing
            with state.session_logger.timed_event() as timer:
                exec_result = state.ch_client.execute_query(
                    sql=current_sql, prepare=True
                )

            if exec_result["success"]:
                row_count = exec_result["row_count"]

                # Log the successful SQL query
                state.session_logger.log_sql_query(
                    query_id=assigned_query_id,
                    purpose=query.purpose,
                    sql_original=original_sql,
                    sql_executed=exec_result["sql"],
                    success=True,
                    duration=timer.duration,
                    row_count=row_count,
                    columns=exec_result.get("columns"),
                    rows=exec_result.get("rows"),
                    is_repair_attempt=repair_attempt > 0,
                    repair_attempt_number=repair_attempt if repair_attempt > 0 else 0,
                    parent_query_id=assigned_query_id if repair_attempt > 0 else None,
                )

                # Format result (handle 0 rows as well)
                if row_count == 0:
                    formatted = "No rows returned"
                else:
                    formatted = ClickHouseClient.format_query_result_as_table(
                        exec_result["columns"],
                        exec_result["rows"],
                    )

                results.append(
                    QueryExecutionResult(
                        query_id=assigned_query_id,
                        status="ok",
                        sql=exec_result["sql"],
                        row_count=row_count,
                        formatted_result=formatted,
                    )
                )

                # Store successfully executed query in state
                state.executed_queries.append(
                    ExecutedQuery(
                        query_id=assigned_query_id,
                        sql=exec_result["sql"],
                        purpose=query.purpose,
                        result=exec_result,
                    )
                )
                query_completed = True
            else:
                # Execution failed
                concise_error = exec_result.get("error_message", exec_result["error"])

                # Log the failed SQL query
                state.session_logger.log_sql_query(
                    query_id=assigned_query_id,
                    purpose=query.purpose,
                    sql_original=original_sql,
                    sql_executed=exec_result.get("sql", current_sql),
                    success=False,
                    duration=timer.duration,
                    error_message=concise_error,
                    is_repair_attempt=repair_attempt > 0,
                    repair_attempt_number=repair_attempt if repair_attempt > 0 else 0,
                    parent_query_id=assigned_query_id if repair_attempt > 0 else None,
                )

                if repair_attempt >= state.max_sql_repair_retries:
                    # Max retries exhausted
                    error_msg = f"Execution failed after {repair_attempt} repair attempts: {concise_error}"
                    results.append(
                        QueryExecutionResult(
                            query_id=assigned_query_id,
                            status="execution_failed",
                            sql=exec_result["sql"],
                            error_message=error_msg,
                        )
                    )
                    # Failed queries are NOT stored in state.executed_queries
                    query_completed = True
                else:
                    # Attempt repair
                    repair_result = repair_sql_with_baml(
                        sql_query=current_sql,
                        error_message=concise_error,
                        purpose=query.purpose,
                        state=state,
                        parent_query_id=assigned_query_id,
                    )

                    if repair_result and repair_result.sql:
                        # Update SQL and retry
                        current_sql = repair_result.sql
                        repair_attempt += 1
                        continue  # Retry with repaired SQL
                    else:
                        # Repair failed
                        results.append(
                            QueryExecutionResult(
                                query_id=assigned_query_id,
                                status="execution_failed",
                                sql=exec_result["sql"],
                                error_message=concise_error,
                            )
                        )
                        # Failed queries are NOT stored in state.executed_queries
                        query_completed = True

    return results
