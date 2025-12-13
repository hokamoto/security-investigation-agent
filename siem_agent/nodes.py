"""
LangGraph node implementations for SIEM Agent (multi-node workflow)
"""

import time
from datetime import datetime, date, time as dt_time
from decimal import Decimal
from typing import Any, Dict, List, Optional

from langgraph.graph import END

from .config import (
    AgentState,
    CONFIG,
    PROMPTS,
    InvestigationPlan,
    PlannedQuery,
    SynthesisResponse,
    ReplanDecision,
    StatisticalSummaryQueries,
    SummaryQuery,
)
from .llm_utils import llm_invoke_structured, retry_sql_with_repair
from .sql_utils import validate_sql, extract_clickhouse_error
from . import config


def _serialize_value(value: Any):
    """Convert query result values into JSON/checkpoint safe types."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime, date, dt_time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    return str(value)


def _serialize_rows(rows: List[List[Any]]) -> List[List[Any]]:
    """Serialize rows to ensure checkpoint compatibility."""
    return [[_serialize_value(v) for v in row] for row in rows]


def _format_rows_as_table(column_names: List[str], rows: List[List[Any]]) -> str:
    """Render query rows as a plain-text table for logging/LLM consumption."""
    if not rows:
        return "No results"

    headers = column_names or [f"Column_{i + 1}" for i in range(len(rows[0]))]
    str_rows = [[str(val) if val is not None else "NULL" for val in row] for row in rows]

    # Compute column widths
    col_widths = [len(h) for h in headers]
    for row in str_rows:
        for idx, val in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(val))

    def _fmt_row(row: List[str]) -> str:
        return " | ".join(val.ljust(col_widths[idx]) for idx, val in enumerate(row))

    header_line = _fmt_row(headers)
    separator = "-+-".join("-" * width for width in col_widths)
    data_lines = [_fmt_row(row) for row in str_rows]

    return "\n".join([header_line, separator, *data_lines])


def _retry_with_statistical_summary(
    original_query: PlannedQuery,
    original_result: dict,
    state: AgentState
) -> Optional[dict]:
    """
    When a query exceeds max_result_rows, ask LLM to rewrite it as statistical summary queries.

    Args:
        original_query: The PlannedQuery that caused overflow
        original_result: The result dict with status="result_overflow"
        state: Current agent state

    Returns:
        Combined result dict from summary queries, or None if rewrite fails
    """
    print("  Generating statistical summary queries...")

    max_result_rows = CONFIG['clickhouse']['max_result_rows']

    prompt = PROMPTS['rewrite_as_summary_prompt'].format(
        original_purpose=original_query.purpose,
        original_sql=original_result['sql'],
        original_table=original_query.table,
        expected_result_type=original_query.expected_result_type,
        max_result_rows=max_result_rows,
        statistical_insight_framework=PROMPTS['statistical_insight_framework'],
        sql_requirements=PROMPTS['sql_requirements']
    )

    try:
        response = llm_invoke_structured(
            prompt=prompt,
            response_model=StatisticalSummaryQueries,
            available_hosts=state.get("available_hosts", []),
            available_rule_tags=state.get("available_rule_tags", []),
            database_name=state["database_name"],
            siem_log_table_name=state["siem_log_table_name"],
            cdn_log_table_name=state.get("cdn_log_table_name"),
            state=state
        )

        print(f"  Generated {len(response.queries)} summary queries")
        config.session_logger.log("INFO", "agent", "statistical_summary_generated", {
            "original_query_id": original_query.query_id,
            "rationale": response.rationale,
            "summary_query_count": len(response.queries)
        })

        # Execute summary queries sequentially
        all_results = []
        total_rows = 0

        for idx, summary_query in enumerate(response.queries, 1):
            print(f"    Summary {idx}/{len(response.queries)} ({summary_query.query_type}): {summary_query.purpose}")

            result = _validate_and_execute_sql(
                sql_query=summary_query.sql,
                description=f"Summary {idx}: {summary_query.purpose}",
                database_name=state["database_name"],
                siem_log_table_name=state["siem_log_table_name"],
                cdn_log_table_name=state.get("cdn_log_table_name"),
                available_hosts=state.get("available_hosts", []),
                state=state,
                log_event_prefix=f"summary_query_{idx}"
            )

            if result.get("status") == "ok":
                all_results.append({
                    "query_type": summary_query.query_type,
                    "purpose": summary_query.purpose,
                    "sql": summary_query.sql,
                    "row_count": result["row_count"],
                    "rows": result["rows"],
                    "column_names": result["column_names"]
                })
                total_rows += result["row_count"]
                print(f"      Rows: {result['row_count']}")
            elif result.get("status") == "result_overflow":
                # Even summary query overflowed - this shouldn't happen but handle gracefully
                print(f"      Summary query still overflowed (this should not happen)")
                config.session_logger.log("ERROR", "agent", "summary_query_overflow", {
                    "summary_query": summary_query.sql,
                    "query_type": summary_query.query_type
                })
                return None
            else:
                # Summary query failed
                print(f"      Summary query failed: {result.get('error', 'Unknown error')}")
                config.session_logger.log("ERROR", "agent", "summary_query_failed", {
                    "summary_query": summary_query.sql,
                    "error": result.get('error')
                })
                # Continue with other queries - partial results are still useful

        if not all_results:
            print("  All summary queries failed")
            return None

        # Combine results into a single formatted output
        combined_text = _format_summary_results(all_results, response.rationale)

        print(f"  Statistical summary complete: {total_rows} total rows across {len(all_results)} queries")

        return {
            "status": "ok",
            "sql": original_result['sql'],  # Keep original SQL for reference
            "row_count": total_rows,
            "column_names": ["summary_results"],
            "rows": [[combined_text]],  # Single row with combined summary
            "formatted_result": combined_text,
            "purpose": original_query.purpose,
            "is_statistical_summary": True,
            "summary_rationale": response.rationale,
            "summary_query_count": len(all_results)
        }

    except Exception as e:
        print(f"  Failed to generate statistical summary: {e}")
        config.session_logger.log("ERROR", "agent", "statistical_summary_failed", {
            "error": str(e),
            "original_query": original_result['sql']
        })
        return None


def _format_summary_results(results: List[Dict[str, Any]], rationale: str) -> str:
    """Format multiple summary query results into a single text block."""
    parts = [
        f"Statistical Summary (generated due to large result set)",
        f"Rationale: {rationale}",
        ""
    ]

    for idx, result in enumerate(results, 1):
        parts.append(f"## Summary Query {idx}: {result['purpose']} ({result['query_type']})")
        parts.append(f"SQL: {result['sql']}")
        parts.append(f"Rows: {result['row_count']}")

        if result['row_count'] > 0:
            table_text = _format_rows_as_table(result['column_names'], result['rows'])
            parts.append("Data:")
            parts.append(table_text)

        parts.append("")

    return "\n".join(parts)


def _validate_and_execute_sql(
    sql_query: str,
    description: str,
    database_name: str,
    siem_log_table_name: str,
    cdn_log_table_name: Optional[str],
    available_hosts: List[str],
    state: AgentState,
    log_event_prefix: str = "query"
) -> dict:
    """Validate and execute SQL with one repair attempt."""
    allowed_tables = [siem_log_table_name]
    if cdn_log_table_name:
        allowed_tables.append(cdn_log_table_name)

    try:
        safe_sql = validate_sql(sql_query, database_name, allowed_tables)
    except Exception as ve:
        print(f"  Invalid SQL for '{description}': {ve}")
        config.session_logger.log("WARNING", "agent", f"{log_event_prefix}_validation_failed", {
            "query": sql_query,
            "error": str(ve)
        })

        repaired_sql = retry_sql_with_repair(
            sql_query=sql_query,
            error=ve,
            repair_prompt_template=PROMPTS['repair_prompt_sql'],
            prompt_context={
                'database_name': database_name,
                'siem_log_table_name': siem_log_table_name,
                'cdn_log_table_name': cdn_log_table_name,
                'sql_query': sql_query,
                'error': ve
            },
            available_hosts=available_hosts,
            available_rule_tags=state.get("available_rule_tags", []),
            state=state
        )

        if repaired_sql is None:
            return {
                "status": "validation_failed",
                "error": str(ve),
                "sql": sql_query,
                "purpose": description
            }

        try:
            safe_sql = validate_sql(repaired_sql, database_name, allowed_tables)
            sql_query = repaired_sql
            print("  Repaired SQL accepted")
        except Exception as ve2:
            return {
                "status": "validation_failed",
                "error": f"{ve}; Repair failed: {ve2}",
                "sql": sql_query,
                "purpose": description
            }

    try:
        query_start = time.time()
        # Client already configured with max_result_rows, no need to pass settings
        result = config.client.query(safe_sql)
        result_rows = result.result_rows
        column_names = result.column_names
        query_elapsed = time.time() - query_start

        serialized_rows = _serialize_rows(result_rows)
        result_table_text = _format_rows_as_table(column_names, serialized_rows)

        config.session_logger.log("INFO", "clickhouse", f"{log_event_prefix}_query_executed", {
            "query": safe_sql,
            "row_count": len(result_rows),
            "result_table": result_table_text
        }, elapsed_time=query_elapsed)

        return {
            "status": "ok",
            "sql": safe_sql,
            "row_count": len(result_rows),
            "column_names": column_names,
            "rows": serialized_rows,
            "formatted_result": result_table_text,
            "purpose": description
        }
    except Exception as e:
        error_message = extract_clickhouse_error(e)

        # Check if this is a max_result_rows overflow exception
        overflow_keywords = ['too many rows', 'result rows', 'max_result_rows', 'overflow']
        is_overflow = any(keyword.lower() in error_message.lower() for keyword in overflow_keywords)

        if is_overflow:
            # Return special status for overflow - will trigger statistical summary retry
            config.session_logger.log("WARNING", "clickhouse", f"{log_event_prefix}_result_overflow", {
                "query": sql_query,
                "error": error_message,
                "max_result_rows": CONFIG['clickhouse']['max_result_rows']
            })
            print(f"  Result overflow: Query would return more than {CONFIG['clickhouse']['max_result_rows']} rows")
            return {
                "status": "result_overflow",
                "error": error_message,
                "sql": safe_sql,
                "purpose": description,
                "max_result_rows": CONFIG['clickhouse']['max_result_rows']
            }

        # Normal error - attempt SQL repair
        config.session_logger.log("ERROR", "clickhouse", f"{log_event_prefix}_query_failed", {
            "query": sql_query,
            "error": error_message
        })
        print("  Query failed, attempting repair")

        repaired_sql = retry_sql_with_repair(
            sql_query=sql_query,
            error=error_message,
            repair_prompt_template=PROMPTS['repair_prompt_sql'],
            prompt_context={
                'database_name': database_name,
                'siem_log_table_name': siem_log_table_name,
                'cdn_log_table_name': cdn_log_table_name,
                'sql_query': sql_query,
                'error': error_message
            },
            available_hosts=available_hosts,
            available_rule_tags=state.get("available_rule_tags", []),
            state=state
        )

        if not repaired_sql:
            return {
                "status": "execution_failed",
                "error": error_message,
                "sql": sql_query,
                "purpose": description
            }

        # Validate and retry execution once with repaired SQL
        try:
            safe_sql = validate_sql(repaired_sql, database_name, allowed_tables)
            sql_query = repaired_sql
        except Exception as ve:
            return {
                "status": "execution_failed",
                "error": f"{error_message}; Repair failed validation: {ve}",
                "sql": sql_query,
                "purpose": description
            }

        try:
            query_start = time.time()
            # Client already configured with max_result_rows
            result = config.client.query(safe_sql)
            result_rows = result.result_rows
            column_names = result.column_names
            query_elapsed = time.time() - query_start

            serialized_rows = _serialize_rows(result_rows)
            result_table_text = _format_rows_as_table(column_names, serialized_rows)

            config.session_logger.log("INFO", "clickhouse", f"{log_event_prefix}_query_executed", {
                "query": safe_sql,
                "row_count": len(result_rows),
                "result_table": result_table_text
            }, elapsed_time=query_elapsed)

            return {
                "status": "ok",
                "sql": safe_sql,
                "row_count": len(result_rows),
                "column_names": column_names,
                "rows": serialized_rows,
                "formatted_result": result_table_text,
                "purpose": description
            }
        except Exception as retry_error:
            retry_error_msg = extract_clickhouse_error(retry_error)

            # Check if retry also hit overflow
            overflow_keywords = ['too many rows', 'result rows', 'max_result_rows', 'overflow']
            is_overflow = any(keyword.lower() in retry_error_msg.lower() for keyword in overflow_keywords)

            if is_overflow:
                config.session_logger.log("WARNING", "clickhouse", f"{log_event_prefix}_result_overflow_after_repair", {
                    "query": sql_query,
                    "error": retry_error_msg,
                    "max_result_rows": CONFIG['clickhouse']['max_result_rows']
                })
                print(f"  Result overflow after repair: Query still exceeds {CONFIG['clickhouse']['max_result_rows']} rows")
                return {
                    "status": "result_overflow",
                    "error": retry_error_msg,
                    "sql": safe_sql,
                    "purpose": description,
                    "max_result_rows": CONFIG['clickhouse']['max_result_rows']
                }

            config.session_logger.log("ERROR", "clickhouse", f"{log_event_prefix}_query_failed_after_repair", {
                "query": sql_query,
                "error": retry_error_msg
            })
            return {
                "status": "execution_failed",
                "error": f"{error_message}; Repair attempt failed: {retry_error_msg}",
                "sql": sql_query,
                "purpose": description
            }


def _render_query_block(entry: Dict[str, Any]) -> str:
    """Format a single query execution record for synthesis prompt."""
    header = f"## Query {entry.get('query_id', '?')}: {entry.get('purpose', '')}"
    details = [
        header,
        f"Table: {entry.get('table', 'unknown')} | Expected: {entry.get('expected_result_type', 'unknown')}",
        f"SQL: {entry.get('sql', '')}",
        f"Status: {entry.get('status', 'unknown')}",
    ]

    if entry.get("status") == "ok":
        details.append(f"Rows: {entry.get('row_count', 0)}")
        table_text = entry.get("formatted_result")
        if not table_text:
            table_text = _format_rows_as_table(entry.get("column_names", []), entry.get("rows", []))
        if table_text:
            details.append("Data:")
            details.append(table_text)
    else:
        if entry.get("error"):
            details.append(f"Error: {entry['error']}")

    return "\n".join(details)


def _render_all_query_results(history: List[Dict[str, Any]]) -> str:
    """Combine all query execution records into a single text block."""
    if not history:
        return "No queries were executed."
    return "\n\n".join(_render_query_block(entry) for entry in history)


def discover(state: AgentState) -> AgentState:
    """Enumerate available hosts and ruleTags before planning."""
    print("\n[DISCOVER] Enumerating hosts and ruleTags")
    state["next_node"] = "plan"

    discovery_sql = f"""
    SELECT DISTINCT host
    FROM {state['database_name']}.{state['siem_log_table_name']}
    WHERE timestamp >= now() - INTERVAL 7 DAY
    ORDER BY host
    LIMIT 100
    """

    try:
        result = config.client.query(discovery_sql)
        hosts = [row[0] for row in result.result_rows]
        state["available_hosts"] = hosts

        print(f"  Discovered {len(hosts)} hosts")
        if not hosts:
            state["is_answerable"] = False
            state["unanswerable_reason"] = "No hosts found in the last 7 days."
            state["answer"] = state["unanswerable_reason"]
            state["next_node"] = "end"
            return state
    except Exception as e:
        state["is_answerable"] = False
        state["unanswerable_reason"] = f"Host discovery failed: {e}"
        state["answer"] = state["unanswerable_reason"]
        state["next_node"] = "end"
        config.session_logger.log("ERROR", "agent", "host_discovery_failed", {"error": str(e)})
        return state

    rule_tag_discovery_sql = f"""
    SELECT DISTINCT arrayJoin(ruleTags) as ruleTag
    FROM {state['database_name']}.{state['siem_log_table_name']}
    WHERE timestamp >= now() - INTERVAL 90 DAY
    ORDER BY ruleTag ASC
    """

    try:
        rule_tag_result = config.client.query(rule_tag_discovery_sql)
        rule_tags = [row[0] for row in rule_tag_result.result_rows]
        state["available_rule_tags"] = rule_tags
        config.session_logger.log("INFO", "agent", "ruletag_discovery_success", {
            "rule_tag_count": len(rule_tags)
        })
    except Exception as rt_error:
        state["available_rule_tags"] = []
        print(f"  RuleTag discovery failed: {rt_error}")
        config.session_logger.log("ERROR", "agent", "ruletag_discovery_failed", {
            "error": str(rt_error)
        })

    return state


def plan(state: AgentState) -> AgentState:
    """LLM generates full investigation plan."""
    print("\n[PLAN] Generating investigation plan")
    hosts_display = ", ".join(state.get("available_hosts", [])[:10])
    rule_tag_display = ", ".join(state.get("available_rule_tags", [])[:20]) or "(none found)"

    prompt = PROMPTS['planning_prompt'].format(
        user_question=state["user_question"],
        current_replanning_round=state.get("current_replanning_round", 0),
        max_replanning_rounds=state.get("max_replanning_rounds", 3),
        available_hosts=hosts_display or "(none found)",
        available_rule_tags=rule_tag_display,
        database_name=state["database_name"],
        siem_log_table_name=state["siem_log_table_name"],
        cdn_log_table_name=state.get("cdn_log_table_name", "(not configured)"),
        sql_requirements=PROMPTS["sql_requirements"],
        anti_hallucination_rules=PROMPTS["anti_hallucination_rules"],
        answerability_rules=PROMPTS["answerability_rules"]
    )

    response = llm_invoke_structured(
        prompt=prompt,
        response_model=InvestigationPlan,
        available_hosts=state.get("available_hosts", []),
        available_rule_tags=state.get("available_rule_tags", []),
        database_name=state["database_name"],
        siem_log_table_name=state["siem_log_table_name"],
        cdn_log_table_name=state.get("cdn_log_table_name"),
        state=state
    )

    state["investigation_plan"] = response.model_dump()
    state["plan_rationale"] = response.rationale
    state["is_answerable"] = response.is_answerable
    state["unanswerable_reason"] = response.unanswerable_reason
    state["current_query_index"] = 0
    state["query_execution_history"] = []
    state["execution_errors"] = []

    config.session_logger.log("INFO", "agent", "plan_generated", {
        "is_answerable": response.is_answerable,
        "query_count": len(response.queries),
        "estimated_complexity": response.estimated_complexity
    })

    if not response.is_answerable or not response.queries:
        state["answer"] = response.unanswerable_reason or "Question cannot be answered with available data."
        state["next_node"] = "end"
    else:
        state["next_node"] = "execute"

    return state


def execute(state: AgentState) -> AgentState:
    """Execute one query from the investigation plan."""
    plan_data = state.get("investigation_plan")
    if not plan_data:
        state["answer"] = "No investigation plan available."
        state["next_node"] = "end"
        return state

    plan_model = InvestigationPlan.model_validate(plan_data)
    queries = plan_model.queries
    idx = state.get("current_query_index", 0)

    if idx >= len(queries):
        state["next_node"] = "synthesize"
        return state

    planned_query: PlannedQuery = queries[idx]
    current_round = state.get("current_replanning_round", 0)
    current_position_in_plan = idx + 1
    print(f"\n[EXECUTE] [Round {current_round}] Query {current_position_in_plan}/{len(queries)} - {planned_query.purpose}")

    result = _validate_and_execute_sql(
        sql_query=planned_query.sql,
        description=f"Query {planned_query.query_id}: {planned_query.purpose}",
        database_name=state["database_name"],
        siem_log_table_name=state["siem_log_table_name"],
        cdn_log_table_name=state.get("cdn_log_table_name"),
        available_hosts=state.get("available_hosts", []),
        state=state,
        log_event_prefix="plan_execution"
    )

    # Check if query exceeded max_result_rows - if so, retry with statistical summary
    if result.get("status") == "result_overflow":
        summary_result = _retry_with_statistical_summary(
            original_query=planned_query,
            original_result=result,
            state=state
        )

        if summary_result:
            # Successfully generated statistical summary
            result = summary_result
        else:
            # Summary generation failed - keep the overflow result for error tracking
            print("  Failed to generate statistical summary, query will be marked as failed")

    record = {
        "query_id": planned_query.query_id,
        "purpose": planned_query.purpose,
        "sql": result.get("sql", planned_query.sql),
        "table": planned_query.table,
        "expected_result_type": planned_query.expected_result_type,
        "status": result.get("status", "unknown"),
        "row_count": result.get("row_count", 0),
        "column_names": result.get("column_names", []),
        "rows": result.get("rows", []),
        "formatted_result": result.get("formatted_result", ""),
        "error": result.get("error")
    }

    state["query_execution_history"].append(record)

    if result.get("status") != "ok":
        error_msg = result.get("error", "Unknown error")
        state["execution_errors"].append(f"Query {planned_query.query_id}: {error_msg}")
        print(f"  Query failed: {error_msg}")
    else:
        print(f"  Rows returned: {record['row_count']}")

    state["current_query_index"] = idx + 1
    state["next_node"] = "execute" if state["current_query_index"] < len(queries) else "synthesize"

    return state


def synthesize(state: AgentState) -> AgentState:
    """LLM synthesizes all query results into final answer."""
    print("\n[SYNTHESIZE] Analyzing results and generating answer")
    plan_rationale = state.get("plan_rationale", "")
    history = state.get("query_execution_history", [])
    execution_errors = state.get("execution_errors", [])

    all_query_results = _render_all_query_results(history)
    execution_errors_block = "\n".join(f"- {err}" for err in execution_errors) if execution_errors else "None"

    prompt = PROMPTS['synthesis_prompt'].format(
        user_question=state["user_question"],
        plan_rationale=plan_rationale or "(none provided)",
        all_query_results=all_query_results,
        execution_errors=execution_errors_block,
        tag_formatting=PROMPTS["tag_formatting"],
        anti_hallucination_rules=PROMPTS["anti_hallucination_rules"]
    )

    response = llm_invoke_structured(
        prompt=prompt,
        response_model=SynthesisResponse,
        available_hosts=state.get("available_hosts", []),
        available_rule_tags=state.get("available_rule_tags", []),
        database_name=state["database_name"],
        siem_log_table_name=state["siem_log_table_name"],
        cdn_log_table_name=state.get("cdn_log_table_name"),
        state=state
    )

    state["answer"] = response.answer

    # Store synthesis results for potential re-planning decision
    state["synthesis_confidence"] = response.confidence
    state["synthesis_data_gaps"] = response.data_gaps

    # Route to replan_decision to check if more investigation is needed
    state["next_node"] = "replan_decision"

    config.session_logger.log("INFO", "agent", "synthesis_complete", {
        "confidence": response.confidence,
        "data_gaps": response.data_gaps
    })

    return state


def replan_decision(state: AgentState) -> AgentState:
    """LLM decides if additional investigation is needed based on synthesis results."""
    current_round = state.get("current_replanning_round", 0)
    max_rounds = state.get("max_replanning_rounds", 3)

    print(f"\n[REPLAN_DECISION] Evaluating need for additional investigation (Round {current_round}/{max_rounds})")

    # If we've reached max rounds, stop
    if current_round >= max_rounds:
        print(f"[REPLAN_DECISION] Max replanning rounds ({max_rounds}) reached. Stopping.")
        state["needs_replanning"] = False
        state["replan_rationale"] = f"Maximum replanning rounds ({max_rounds}) reached."
        state["next_node"] = "end"
        config.session_logger.log("INFO", "agent", "replan_decision_max_rounds", {
            "current_round": current_round,
            "max_rounds": max_rounds
        })
        return state

    # Prepare context for LLM decision
    history = state.get("query_execution_history", [])
    all_query_results = _render_all_query_results(history)

    prompt = PROMPTS['replan_decision_prompt'].format(
        user_question=state["user_question"],
        current_replanning_round=current_round,
        max_replanning_rounds=max_rounds,
        current_answer=state.get("answer", ""),
        current_confidence=state.get("synthesis_confidence", "unknown"),
        data_gaps="\n".join(f"- {gap}" for gap in state.get("synthesis_data_gaps", [])) or "None",
        all_query_results=all_query_results
    )

    response = llm_invoke_structured(
        prompt=prompt,
        response_model=ReplanDecision,
        available_hosts=state.get("available_hosts", []),
        available_rule_tags=state.get("available_rule_tags", []),
        database_name=state["database_name"],
        siem_log_table_name=state["siem_log_table_name"],
        cdn_log_table_name=state.get("cdn_log_table_name"),
        state=state
    )

    state["needs_replanning"] = response.needs_replanning
    state["replan_rationale"] = response.rationale

    config.session_logger.log("INFO", "agent", "replan_decision_made", {
        "needs_replanning": response.needs_replanning,
        "rationale": response.rationale,
        "suggested_next_steps": response.suggested_next_steps,
        "estimated_additional_queries": response.estimated_additional_queries
    })

    if response.needs_replanning:
        print(f"[REPLAN_DECISION] Additional investigation needed: {response.rationale}")
        # Store decision context for replan node
        state["replan_suggested_steps"] = response.suggested_next_steps
        state["replan_estimated_queries"] = response.estimated_additional_queries
        state["next_node"] = "replan"
    else:
        print(f"[REPLAN_DECISION] Investigation complete: {response.rationale}")
        print(f"[REPLAN_DECISION] Final answer ready")
        state["next_node"] = "end"

    return state


def replan(state: AgentState) -> AgentState:
    """LLM generates additional queries based on previous results."""
    current_round = state.get("current_replanning_round", 0)
    max_rounds = state.get("max_replanning_rounds", 3)

    print(f"\n[REPLAN] Generating additional investigation plan (Round {current_round + 1}/{max_rounds})")

    # Increment replanning round
    state["current_replanning_round"] = current_round + 1

    # Save current plan to history
    if state.get("investigation_plan"):
        state["replanning_history"].append({
            "round": current_round,
            "plan": state["investigation_plan"],
            "rationale": state.get("plan_rationale", ""),
            "query_count": len(state.get("query_execution_history", []))
        })

    # Prepare context for LLM
    history = state.get("query_execution_history", [])
    all_previous_results = _render_all_query_results(history)

    prompt = PROMPTS['replanning_prompt'].format(
        user_question=state["user_question"],
        current_replanning_round=state["current_replanning_round"],
        max_replanning_rounds=max_rounds,
        previous_answer=state.get("answer", ""),
        replan_rationale=state.get("replan_rationale", ""),
        suggested_next_steps="\n".join(f"- {step}" for step in state.get("replan_suggested_steps", [])) or "None",
        all_previous_results=all_previous_results,
        database_name=state["database_name"],
        siem_log_table_name=state["siem_log_table_name"],
        cdn_log_table_name=state.get("cdn_log_table_name", "(not configured)"),
        sql_requirements=PROMPTS["sql_requirements"],
        anti_hallucination_rules=PROMPTS["anti_hallucination_rules"]
    )

    response = llm_invoke_structured(
        prompt=prompt,
        response_model=InvestigationPlan,
        available_hosts=state.get("available_hosts", []),
        available_rule_tags=state.get("available_rule_tags", []),
        database_name=state["database_name"],
        siem_log_table_name=state["siem_log_table_name"],
        cdn_log_table_name=state.get("cdn_log_table_name"),
        state=state
    )

    # Update state with new plan
    state["investigation_plan"] = response.model_dump()
    state["plan_rationale"] = response.rationale
    state["is_answerable"] = response.is_answerable
    state["unanswerable_reason"] = response.unanswerable_reason

    # Reset execution state for new queries
    # Note: We keep query_execution_history to maintain full context
    state["current_query_index"] = 0

    config.session_logger.log("INFO", "agent", "replan_generated", {
        "round": state["current_replanning_round"],
        "is_answerable": response.is_answerable,
        "query_count": len(response.queries),
        "estimated_complexity": response.estimated_complexity
    })

    if not response.is_answerable or not response.queries:
        state["answer"] = response.unanswerable_reason or "Additional investigation cannot proceed with available data."
        state["next_node"] = "end"
    else:
        state["next_node"] = "execute"

    return state


def route(state: AgentState) -> str:
    """Route to the next node based on state['next_node']."""
    next_node = state.get("next_node", "end")
    if next_node == "plan":
        return "plan"
    if next_node == "execute":
        return "execute"
    if next_node == "synthesize":
        return "synthesize"
    if next_node == "replan_decision":
        return "replan_decision"
    if next_node == "replan":
        return "replan"
    return END
