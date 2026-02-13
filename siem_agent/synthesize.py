"""Synthesize and replan module for BAML-based SIEM Agent."""

from typing import List

from baml_py.baml_py import BamlError
import requests

from siem_agent.agent_state import AgentState, ExecutedQuery
from siem_agent.baml_client import b
from siem_agent.baml_client.types import (
    ExecutedQueryForBAML,
    SynthesizeAndReplanResult,
)
from siem_agent.sql_utils import normalize_clickhouse_array_functions
from siem_agent.tag_processor import process_output_tags


def _update_executed_queries_with_interpretations(
    executed_queries: List[ExecutedQuery],
    query_interpretations: list,
) -> None:
    """Update ExecutedQuery objects with interpretations from synthesis.

    Args:
        executed_queries: List of ExecutedQuery objects to update (modified in-place)
        query_interpretations: List of QueryResultInterpretation from BAML
    """
    # Create a mapping from query_id to interpretation
    interp_map = {qi.query_id: qi for qi in query_interpretations}

    # Update each executed query with its interpretation
    for eq in executed_queries:
        if eq.query_id in interp_map:
            qi = interp_map[eq.query_id]
            eq.interpretation = qi.interpretation
            eq.gaps_identified = qi.gaps_identified


def prepare_executed_queries_for_baml(
    executed_queries: List[ExecutedQuery],
) -> List[ExecutedQueryForBAML]:
    """Convert ExecutedQuery list to BAML-compatible format.

    Args:
        executed_queries: List of successfully executed queries from agent state

    Returns:
        List of ExecutedQueryForBAML objects for BAML function
    """
    baml_queries: List[ExecutedQueryForBAML] = []

    for eq in executed_queries:
        result = eq.result
        # Convert row values to strings for BAML map<string, string>[] type
        rows = result.get("rows", [])
        result_rows: List[dict[str, str]] = [{k: str(v) if v is not None else "NULL" for k, v in row.items()} for row in rows]

        baml_queries.append(
            ExecutedQueryForBAML(
                query_id=eq.query_id,
                purpose=eq.purpose,
                sql=eq.sql,
                row_count=result.get("row_count", 0),
                result=result_rows,
                interpretation=eq.interpretation,
                gaps_identified=eq.gaps_identified,
            )
        )

    return baml_queries


def synthesize_and_replan(state: AgentState) -> SynthesizeAndReplanResult:
    """Call BAML SynthesizeAndReplan function.

    Combines synthesis of query results, replan decision, and replanning
    in a single LLM call.

    Args:
        state: Agent state containing executed queries and configuration

    Returns:
        SynthesizeAndReplanResult with decision and appropriate action
    """
    # Prepare executed queries for BAML
    baml_queries = prepare_executed_queries_for_baml(state.executed_queries)

    # Create the BAML request
    req = b.request.SynthesizeAndReplan(
        user_question=state.user_question,
        investigation_strategy=state.investigation_strategy,
        current_replanning_round=state.current_replanning_round,
        max_replanning_rounds=state.max_replanning_rounds,
        executed_queries=baml_queries,
        previous_synthesis_summary=state.synthesis_summary,
        available_hosts=state.available_hosts,
        available_rule_tags=state.available_rule_tags,
        database_name=state.database_name,
        siem_log_table_name=state.siem_log_table_name,
        cdn_log_table_name=state.cdn_log_table_name,
        session_timestamp=state.session_timestamp,
        original_language=state.original_language,
    )

    # Make the HTTP call with timing
    with state.session_logger.timed_event() as timer:
        res = requests.post(url=req.url, headers=req.headers, json=req.body.json())
        response_json = res.json()

    # Parse the response
    raw_content = response_json["choices"][0]["message"]["content"]
    if raw_content is None:
        raise ValueError(f"LLM returned None content. Response: {response_json}")
    try:
        parsed: SynthesizeAndReplanResult = b.parse.SynthesizeAndReplan(raw_content)
    except BamlError as e:
        # Log BAML validation error details
        error_details = {
            "error_type": "BAML_ValidationError",
            "function": "SynthesizeAndReplan",
            "raw_output": getattr(e, "raw_output", str(e)),
            "message": getattr(e, "message", str(e)),
            "prompt": getattr(e, "prompt", "N/A"),
            "detailed_message": getattr(e, "detailed_message", str(e)),
        }
        state.session_logger.log_error(e, context=f"BAML validation error in SynthesizeAndReplan: {error_details}")
        # Re-raise to crash the program as requested
        raise

    # Normalize array functions in replan queries
    if parsed.replan and parsed.replan.queries:
        for query in parsed.replan.queries:
            query.sql = normalize_clickhouse_array_functions(query.sql)

    # Extract prompt for logging
    prompt_full = _extract_prompt_from_request(req)

    # Log the synthesize LLM call
    state.session_logger.log_llm_call(
        call_type="synthesize",
        prompt_full=prompt_full,
        raw_response=raw_content,
        parsed_response=parsed,
        response_json=response_json,
        duration=timer.duration,
    )

    # Process <calc> and <fact> tags immediately after parsing
    for qi in parsed.query_interpretations:
        if qi.interpretation:
            qi.interpretation = process_output_tags(qi.interpretation)
    if parsed.synthesis_summary:
        parsed.synthesis_summary = process_output_tags(parsed.synthesis_summary)
    if parsed.final_answer:
        parsed.final_answer = process_output_tags(parsed.final_answer)
    if parsed.supporting_data:
        parsed.supporting_data = process_output_tags(parsed.supporting_data)
    if parsed.data_gaps:
        parsed.data_gaps = process_output_tags(parsed.data_gaps)

    # Update ExecutedQuery objects with interpretations and gaps
    _update_executed_queries_with_interpretations(state.executed_queries, parsed.query_interpretations)

    # Save synthesis_summary to state for next round
    state.synthesis_summary = parsed.synthesis_summary

    return parsed


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
