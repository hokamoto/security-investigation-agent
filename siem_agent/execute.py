"""Query execution module for BAML-based SIEM Agent."""

from dataclasses import dataclass
from typing import Dict, List, Optional

from baml_py.baml_py import BamlError
import requests

from siem_agent.agent_state import AgentState, ExecutedQuery
from siem_agent.baml_client import b
from siem_agent.baml_client.types import (
    BatchSqlRepairItem,
    FailedQueryForRepair,
    InvestigationPlan,
)
from siem_agent.clickhouse import ClickHouseClient
from siem_agent.sql_utils import (
    normalize_clickhouse_array_functions,
    apply_sql_transformations,
)


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


@dataclass
class _FailedQueryInfo:
    """Tracks a failed query pending batch repair."""

    query_index: int  # 1-based index within this batch
    entry_index: int  # index into query_entries list
    query_id: int
    purpose: str
    current_sql: str
    error_message: str


def repair_sql_batch_with_baml(
    failed_queries: List[_FailedQueryInfo],
    state: AgentState,
) -> Dict[int, BatchSqlRepairItem]:
    """Call BAML RepairSqlBatch to repair failed queries in one LLM call.

    Args:
        failed_queries: List of failed query info to repair
        state: Agent state containing configuration and database metadata

    Returns:
        Dict mapping query_index -> BatchSqlRepairItem. Empty dict if call failed.
    """
    baml_inputs = [
        FailedQueryForRepair(
            query_index=fq.query_index,
            purpose=fq.purpose,
            sql=fq.current_sql,
            error_message=fq.error_message,
        )
        for fq in failed_queries
    ]

    try:
        req = b.request.RepairSqlBatch(
            failed_queries=baml_inputs,
            database_name=state.database_name,
            siem_log_table_name=state.siem_log_table_name,
            cdn_log_table_name=state.cdn_log_table_name,
            available_hosts=state.available_hosts,
            available_rule_tags=state.available_rule_tags,
            session_timestamp=state.session_timestamp,
        )

        with state.session_logger.timed_event() as timer:
            res = requests.post(url=req.url, headers=req.headers, json=req.body.json())
            response_json = res.json()

        raw_content = response_json["choices"][0]["message"]["content"]
        if raw_content is None:
            raise ValueError(f"LLM returned None content. Response: {response_json}")
        try:
            parsed_list: List[BatchSqlRepairItem] = b.parse.RepairSqlBatch(raw_content)
        except BamlError as e:
            error_details = {
                "error_type": "BAML_ValidationError",
                "function": "RepairSqlBatch",
                "raw_output": getattr(e, "raw_output", str(e)),
                "message": getattr(e, "message", str(e)),
                "prompt": getattr(e, "prompt", "N/A"),
                "detailed_message": getattr(e, "detailed_message", str(e)),
            }
            state.session_logger.log_error(
                e,
                context=f"BAML validation error in RepairSqlBatch: {error_details}",
            )
            raise

        # Normalize array functions and apply SQL transformations in all repaired SQL
        for item in parsed_list:
            if item.sql:
                item.sql = normalize_clickhouse_array_functions(item.sql)
                item.sql = apply_sql_transformations(item.sql, state)

        # Build result dict keyed by query_index
        result_map: Dict[int, BatchSqlRepairItem] = {}
        for item in parsed_list:
            result_map[item.query_index] = item

        # Log the batch repair LLM call
        prompt_full = _extract_prompt_from_request(req)
        parent_ids = [f"{state.current_replanning_round}_sql_{fq.query_id}" for fq in failed_queries]
        state.session_logger.log_llm_call(
            call_type="batch_repair",
            prompt_full=prompt_full,
            raw_response=raw_content,
            parsed_response=parsed_list,
            response_json=response_json,
            duration=timer.duration,
            parent_id=",".join(parent_ids),
        )

        return result_map

    except Exception:
        return {}


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
    """Execute all queries in investigation plan with batch repair for failures.

    Uses a two-phase approach per repair round:
    - Phase 1: Execute all incomplete queries, collecting successes and failures
    - Phase 2: Batch repair all failures in one LLM call
    - Phase 3: Apply repairs and loop back

    Args:
        investigation_plan: BAML InvestigationPlan with queries to execute
        state: Agent state containing configuration and database client

    Returns:
        List of QueryExecutionResult objects (one per query)
    """
    if not investigation_plan.queries:
        return []

    results: List[QueryExecutionResult] = []

    # Assign query IDs upfront and build mutable tracking entries
    query_entries: List[dict] = []
    for query in investigation_plan.queries:
        assigned_query_id = state.next_query_id
        state.next_query_id += 1

        # Apply SQL transformations (including HDX JOIN workaround)
        transformed_sql = apply_sql_transformations(query.sql, state)

        query_entries.append(
            {
                "query_id": assigned_query_id,
                "purpose": query.purpose,
                "original_sql": query.sql,
                "current_sql": transformed_sql,
                "completed": False,
                "repair_attempt": 0,
            }
        )

    for repair_round in range(state.max_sql_repair_retries + 1):
        # Phase 1: Execute all incomplete queries
        pending_failures: List[_FailedQueryInfo] = []

        for idx, entry in enumerate(query_entries):
            if entry["completed"]:
                continue

            with state.session_logger.timed_event() as timer:
                exec_result = state.ch_client.execute_query(sql=entry["current_sql"], prepare=True)

            is_repair = entry["repair_attempt"] > 0

            if exec_result["success"]:
                row_count = exec_result["row_count"]

                state.session_logger.log_sql_query(
                    query_id=entry["query_id"],
                    purpose=entry["purpose"],
                    sql_original=entry["original_sql"],
                    sql_executed=exec_result["sql"],
                    success=True,
                    duration=timer.duration,
                    row_count=row_count,
                    columns=exec_result.get("columns"),
                    rows=exec_result.get("rows"),
                    is_repair_attempt=is_repair,
                    repair_attempt_number=(entry["repair_attempt"] if is_repair else 0),
                    parent_query_id=(entry["query_id"] if is_repair else None),
                )

                if row_count == 0:
                    formatted = "No rows returned"
                else:
                    formatted = ClickHouseClient.format_query_result_as_table(
                        exec_result["columns"],
                        exec_result["rows"],
                    )

                results.append(
                    QueryExecutionResult(
                        query_id=entry["query_id"],
                        status="ok",
                        sql=exec_result["sql"],
                        row_count=row_count,
                        formatted_result=formatted,
                    )
                )

                state.executed_queries.append(
                    ExecutedQuery(
                        query_id=entry["query_id"],
                        sql=exec_result["sql"],
                        purpose=entry["purpose"],
                        result=exec_result,
                    )
                )
                entry["completed"] = True
            else:
                concise_error = exec_result.get("error_message", exec_result["error"])

                state.session_logger.log_sql_query(
                    query_id=entry["query_id"],
                    purpose=entry["purpose"],
                    sql_original=entry["original_sql"],
                    sql_executed=exec_result.get("sql", entry["current_sql"]),
                    success=False,
                    duration=timer.duration,
                    error_message=concise_error,
                    is_repair_attempt=is_repair,
                    repair_attempt_number=(entry["repair_attempt"] if is_repair else 0),
                    parent_query_id=(entry["query_id"] if is_repair else None),
                )

                if repair_round >= state.max_sql_repair_retries:
                    # Max retries exhausted
                    error_msg = f"Execution failed after {entry['repair_attempt']} repair attempts: {concise_error}"
                    results.append(
                        QueryExecutionResult(
                            query_id=entry["query_id"],
                            status="execution_failed",
                            sql=exec_result["sql"],
                            error_message=error_msg,
                        )
                    )
                    entry["completed"] = True
                else:
                    pending_failures.append(
                        _FailedQueryInfo(
                            query_index=len(pending_failures) + 1,
                            entry_index=idx,
                            query_id=entry["query_id"],
                            purpose=entry["purpose"],
                            current_sql=entry["current_sql"],
                            error_message=concise_error,
                        )
                    )

        # Phase 2: Batch repair all failures
        if not pending_failures:
            break

        repair_map = repair_sql_batch_with_baml(
            failed_queries=pending_failures,
            state=state,
        )

        # Phase 3: Apply repairs to query entries
        any_repaired = False
        for fq in pending_failures:
            repair = repair_map.get(fq.query_index)
            if repair and repair.sql:
                entry = query_entries[fq.entry_index]
                entry["current_sql"] = repair.sql
                entry["repair_attempt"] += 1
                any_repaired = True
            else:
                # Repair failed or missing for this query
                entry = query_entries[fq.entry_index]
                results.append(
                    QueryExecutionResult(
                        query_id=entry["query_id"],
                        status="execution_failed",
                        sql=entry["current_sql"],
                        error_message=fq.error_message,
                    )
                )
                entry["completed"] = True

        if not any_repaired:
            break

    return results
