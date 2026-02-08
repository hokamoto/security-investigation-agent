"""SIEM Agent - Investigate security questions using Akamai SIEM/CDN logs"""

import argparse
import json
import sys
from datetime import datetime, UTC
from pathlib import Path

from baml_py.baml_py import BamlError
import requests
import yaml

from siem_agent.agent_state import AgentState
from siem_agent.baml_client import b
from siem_agent.baml_client.types import InvestigationPlan, ReplanDecisionType
from siem_agent.clickhouse import ClickHouseClient
from siem_agent.execute import QueryExecutionResult, execute_investigation_plan
from siem_agent.session_logger import create_session_logger
from siem_agent.sql_utils import normalize_clickhouse_array_functions
from siem_agent.synthesize import synthesize_and_replan


def load_config() -> dict:
    """Load configuration from config.yaml."""
    config_path = Path(__file__).parent.parent / "config.yaml"
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def generate_investigation_plan(state: AgentState) -> InvestigationPlan:
    """Generate an investigation plan using BAML.

    Args:
        state: Agent state containing configuration and database metadata

    Returns:
        InvestigationPlan with queries to execute
    """
    # Create the request
    req = b.request.GenerateInvestigationPlan(
        user_question=state.user_question,
        available_hosts=state.available_hosts,
        available_rule_tags=state.available_rule_tags,
        database_name=state.database_name,
        siem_log_table_name=state.siem_log_table_name,
        cdn_log_table_name=state.cdn_log_table_name,
        current_replanning_round=state.current_replanning_round,
        max_replanning_rounds=state.max_replanning_rounds,
        session_timestamp=state.session_timestamp,
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
        parsed = b.parse.GenerateInvestigationPlan(raw_content)
    except BamlError as e:
        # Log BAML validation error details
        error_details = {
            "error_type": "BAML_ValidationError",
            "function": "GenerateInvestigationPlan",
            "raw_output": getattr(e, "raw_output", str(e)),
            "message": getattr(e, "message", str(e)),
            "prompt": getattr(e, "prompt", "N/A"),
            "detailed_message": getattr(e, "detailed_message", str(e)),
        }
        state.session_logger.log_error(
            e,
            context=f"BAML validation error in GenerateInvestigationPlan: {error_details}",
        )
        # Re-raise to crash the program as requested
        raise

    # Extract prompt from request for logging (needed for both success and unanswerable cases)
    prompt_full = _extract_prompt_from_request(req)

    # Check if the question is answerable
    if not parsed.is_answerable:
        # Log the LLM call first (for debugging - includes raw_response)
        state.session_logger.log_llm_call(
            call_type="plan",
            prompt_full=prompt_full,
            raw_response=raw_content,
            parsed_response=parsed,
            response_json=response_json,
            duration=timer.duration,
        )

        # Log detailed error information for post-mortem analysis
        error_context = {
            "is_answerable": False,
            "unanswerable_reason": parsed.unanswerable_reason,
            "user_question": state.user_question,
            "available_hosts": state.available_hosts,
            "available_rule_tags_count": len(state.available_rule_tags),
            "current_replanning_round": state.current_replanning_round,
            "max_replanning_rounds": state.max_replanning_rounds,
        }
        error_msg = (
            f"LLM determined the question is unanswerable.\n"
            f"  Reason: {parsed.unanswerable_reason}\n"
            f"  User question: {state.user_question}"
        )
        state.session_logger.log_error(
            ValueError(error_msg),
            context=f"Question deemed unanswerable: {error_context}",
        )

        # Raise exception to stop execution
        raise ValueError(error_msg)

    # Normalize array functions in all generated queries
    if parsed.queries:  # Add None check for safety
        for query in parsed.queries:
            query.sql = normalize_clickhouse_array_functions(query.sql)

    # Log the LLM call (normal success case)
    state.session_logger.log_llm_call(
        call_type="plan",
        prompt_full=prompt_full,
        raw_response=raw_content,
        parsed_response=parsed,
        response_json=response_json,
        duration=timer.duration,
    )

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
            # Concatenate all message contents
            parts = []
            for msg in messages:
                role = msg.get("role", "")
                content = msg.get("content", "")
                parts.append(f"[{role}]\n{content}")
            return "\n\n".join(parts)
    except Exception:
        pass
    return str(req)


def _build_round_dict(
    round_number: int,
    strategy: str,
    plan: InvestigationPlan,
    execution_results: list[QueryExecutionResult],
    state: AgentState,
    synthesis_summary: str,
    decision: str,
) -> dict:
    """Build a dict describing one investigation round for the log.

    Args:
        round_number: 0-indexed round number
        strategy: Investigation strategy text for this round
        plan: The InvestigationPlan used in this round
        execution_results: List of QueryExecutionResult from execute_investigation_plan
        state: Agent state (used to look up full result data for successful queries)
        synthesis_summary: Synthesis summary produced after this round
        decision: "COMPLETE" or "CONTINUE"

    Returns:
        Dict with round metadata, planned/executed queries, synthesis, and decision
    """
    planned_queries = [
        {"purpose": q.purpose, "sql": q.sql} for q in (plan.queries or [])
    ]

    executed_queries = []
    for i, er in enumerate(execution_results):
        entry = {
            "query_id": er.query_id,
            "purpose": plan.queries[i].purpose
            if plan.queries and i < len(plan.queries)
            else "",
            "sql": er.sql,
            "success": er.status == "ok",
            "row_count": er.row_count,
            "columns": [],
            "rows": [],
            "error_message": er.error_message,
        }

        if er.status == "ok":
            # Look up the ExecutedQuery in state for columns/rows
            for eq in state.executed_queries:
                if eq.query_id == er.query_id:
                    result = eq.result
                    entry["columns"] = result.get("columns", [])
                    raw_rows = result.get("rows", [])
                    entry["rows"] = [[str(v) for v in row.values()] for row in raw_rows]
                    break

        executed_queries.append(entry)

    return {
        "round": round_number,
        "strategy": strategy,
        "planned_queries": planned_queries,
        "executed_queries": executed_queries,
        "synthesis_summary": synthesis_summary,
        "decision": decision,
    }


def run_investigation_loop(state: AgentState, json_mode: bool = False) -> str:
    """Run the full investigation loop: PLAN → EXECUTE → SYNTHESIZE+REPLAN → ...

    This function orchestrates the multi-round investigation workflow:
    1. Generate initial investigation plan
    2. Execute queries
    3. Synthesize results and decide on next action
    4. If CONTINUE: replan and loop back to step 2
    5. If COMPLETE or BLOCKED: return result

    Args:
        state: Agent state containing configuration and database metadata
        json_mode: If True, suppress console output (for JSON response mode)

    Returns:
        Final answer string (for COMPLETE) or blocked/unanswerable reason
    """
    # Step 1: Generate initial investigation plan
    plan = generate_investigation_plan(state)

    if not plan.is_answerable:
        reason = plan.unanswerable_reason or "Unknown reason"
        return f"UNANSWERABLE: {reason}"

    # Store investigation strategy
    state.investigation_strategy = plan.investigation_strategy or ""

    if not plan.queries:
        return "UNANSWERABLE: No queries generated for this question."

    # Main investigation loop
    while True:
        # Log round start
        state.session_logger.log_round_start(
            planned_queries=plan.queries,
            strategy=state.investigation_strategy,
        )

        with state.session_logger.timed_event() as round_timer:
            queries_before = len(state.executed_queries)

            # Step 2: Execute queries
            execution_results = execute_investigation_plan(
                investigation_plan=plan,
                state=state,
            )

            queries_executed_this_round = len(state.executed_queries) - queries_before

            # Step 3: Synthesize and decide
            result = synthesize_and_replan(state)

        # Determine decision string for logging
        decision_str = (
            result.decision.value
            if hasattr(result.decision, "value")
            else str(result.decision)
        )

        # Log round end
        state.session_logger.log_round_end(
            queries_executed=queries_executed_this_round,
            decision=decision_str,
            duration=round_timer.duration,
        )

        # Build investigation log entry for this round
        state.investigation_log.append(
            _build_round_dict(
                round_number=state.current_replanning_round,
                strategy=state.investigation_strategy,
                plan=plan,
                execution_results=execution_results,
                state=state,
                synthesis_summary=result.synthesis_summary,
                decision=decision_str,
            )
        )

        # Step 4: Act based on decision
        if result.decision == ReplanDecisionType.COMPLETE:
            final_answer = result.final_answer or "No final answer provided."
            if not json_mode:
                print("Questions:")
                print(state.user_question)
                print("Answer:")
                print(final_answer)
            return final_answer

        elif result.decision == ReplanDecisionType.CONTINUE:
            # Check if we can continue
            if state.current_replanning_round >= state.max_replanning_rounds:
                # Safety fallback: should not happen if LLM follows instructions
                if result.final_answer:
                    return result.final_answer

                # Output forced completion information
                if not json_mode:
                    print("\n" + "=" * 80)
                    print(
                        "WARNING: Investigation terminated - maximum replanning rounds reached"
                    )
                    print("=" * 80)
                    print(f"\nMaximum rounds: {state.max_replanning_rounds}")
                    print(f"Rounds executed: {state.current_replanning_round}")

                    print("\n--- What Has Been Discovered ---")
                    print(result.synthesis_summary)

                    print("\n--- Unresolved Issues (Why Continuation Was Needed) ---")
                    print(result.decision_rationale)

                    if result.replan and result.replan.updated_strategy:
                        print("\n--- Planned Next Steps (Interrupted) ---")
                        print(result.replan.updated_strategy)

                    print("\n" + "=" * 80 + "\n")

                return f"FORCED_COMPLETE: Max replanning rounds ({state.max_replanning_rounds}) reached. Summary: {result.synthesis_summary}"

            # Update state for next round
            state.current_replanning_round += 1
            state.session_logger.set_round(state.current_replanning_round)

            if result.replan and result.replan.queries:
                # Update strategy
                state.investigation_strategy = result.replan.updated_strategy

                # Create new InvestigationPlan from replan queries
                plan = InvestigationPlan(
                    is_answerable=True,
                    unanswerable_reason=None,
                    investigation_strategy=result.replan.updated_strategy,
                    queries=result.replan.queries,
                )
            else:
                # No queries provided despite CONTINUE - force completion
                if not json_mode:
                    print("\n" + "=" * 80)
                    print(
                        "WARNING: Investigation terminated - no replan queries generated"
                    )
                    print("=" * 80)

                    print("\n--- What Has Been Discovered ---")
                    print(result.synthesis_summary)

                    print("\n--- Unresolved Issues (Why Continuation Was Needed) ---")
                    print(result.decision_rationale)
                    print(
                        "\n(Note: LLM selected CONTINUE but failed to generate follow-up queries)"
                    )

                    print("\n" + "=" * 80 + "\n")

                return f"FORCED_COMPLETE: No replan queries provided. Summary: {result.synthesis_summary}"
        else:
            # Unknown decision - should not happen
            return f"ERROR: Unknown decision type: {result.decision}"


def main():
    """Run the SIEM Agent investigation workflow."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="SIEM Agent - Investigate security questions using Akamai SIEM/CDN logs"
    )
    parser.add_argument(
        "question", type=str, help="Security investigation question to answer"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_mode",
        help="Output result in structured JSON format for programmatic consumption",
    )
    args = parser.parse_args()
    user_question = args.question
    json_mode = args.json_mode

    # Load config
    config = load_config()

    # Get current timestamp for session
    session_timestamp = (
        datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    )

    # Initialize session logger
    session_logger = create_session_logger(config, session_timestamp)

    # Initialize ClickHouse client
    ch_client = ClickHouseClient(config=config, session_timestamp=session_timestamp)

    outcome = "error"
    final_answer = None
    json_output_mode = json_mode  # Store for access in finally block

    try:
        # Log session start
        session_logger.log_session_start(user_question, config)

        # Discover hosts and ruleTags from ClickHouse with timing
        with session_logger.timed_event() as discovery_timer:
            available_hosts, available_rule_tags = ch_client.discover_hosts_and_tags()

        session_logger.log_discovery(
            available_hosts, available_rule_tags, discovery_timer.duration
        )

        if not available_hosts:
            outcome = "error"
            return

        # Initialize agent state with session logger
        state = AgentState(
            ch_client=ch_client,
            config=config,
            available_hosts=available_hosts,
            available_rule_tags=available_rule_tags,
            session_timestamp=session_timestamp,
            user_question=user_question,
            current_replanning_round=0,
            debug=False,
            session_logger=session_logger,
        )

        # Run the investigation loop
        final_answer = run_investigation_loop(state, json_mode=json_mode)

        # Determine outcome based on result
        if final_answer.startswith("UNANSWERABLE:"):
            outcome = "unanswerable"
        elif final_answer.startswith("FORCED_COMPLETE:"):
            outcome = "forced_complete"
        elif final_answer.startswith("ERROR:"):
            outcome = "error"
        else:
            outcome = "complete"

    except ValueError as e:
        # Handle "unanswerable" ValueError cleanly (no stack trace)
        if "LLM determined the question is unanswerable" in str(e):
            session_logger.log_error(e, context="main()")
            outcome = "unanswerable"

            # Extract unanswerable reason from error message
            error_str = str(e)
            if "Reason:" in error_str:
                # Extract the reason line
                reason = error_str.split("Reason:")[1].split("\n")[0].strip()
                final_answer = f"UNANSWERABLE: {reason}"
            else:
                # Fallback to full error message
                final_answer = f"UNANSWERABLE: {error_str}"

            # Print clean error message without stack trace
            if not json_mode:
                print(f"\nERROR: {e}", file=sys.stderr)
            # Don't re-raise - exit will be handled by finally block
        else:
            # Other ValueErrors - re-raise with stack trace
            session_logger.log_error(e, context="main()")
            outcome = "error"
            raise

    except Exception as e:
        session_logger.log_error(e, context="main()")
        outcome = "error"
        raise

    finally:
        ch_client.close()
        session_logger.close(outcome=outcome, final_answer=final_answer)

        # Output JSON response if requested
        if json_output_mode:
            try:
                investigation_log = state.investigation_log
            except NameError:
                investigation_log = []
            json_response = {
                "session_start_timestamp": session_timestamp,
                "user_question": user_question,
                "final_answer": final_answer,
                "investigation_log": investigation_log,
                "duration": session_logger.get_total_duration(),
                "total_rounds": session_logger.get_total_rounds(),
                "total_prompt_tokens": session_logger.get_total_prompt_tokens(),
                "total_completion_tokens": session_logger.get_total_completion_tokens(),
                "log_file_name": session_logger.get_log_file_path(),
            }
            print(json.dumps(json_response, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
