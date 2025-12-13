#!/usr/bin/env python3
"""
SIEM Agent - Multi-node planning/execution workflow for Akamai WAF SIEM data

Usage:
    # Interactive mode
    uv run -m siem_agent

    # CLI argument mode
    uv run -m siem_agent "How many SQL injection attacks occurred yesterday?"

    # CLI with JSON output
    uv run -m siem_agent --json results/output.json "How many SQL injection attacks occurred yesterday?"
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
import clickhouse_connect
from datetime import datetime
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END

from .config import AgentState, CONFIG, InvestigationPlan
from .logging_utils import StructuredLogger, LOG_DIR
from .nodes import discover, plan, execute, synthesize, replan_decision, replan, route
from . import config


# Build workflow
workflow = StateGraph(AgentState)

workflow.add_node("discover", discover)
workflow.add_node("plan", plan)
workflow.add_node("execute", execute)
workflow.add_node("synthesize", synthesize)
workflow.add_node("replan_decision", replan_decision)
workflow.add_node("replan", replan)

workflow.set_entry_point("discover")

workflow.add_conditional_edges(
    "discover",
    route,
    {
        "plan": "plan",
        END: END,
    },
)

workflow.add_conditional_edges(
    "plan",
    route,
    {
        "execute": "execute",
        END: END,
    },
)

workflow.add_conditional_edges(
    "execute",
    route,
    {
        "execute": "execute",
        "synthesize": "synthesize",
        END: END,
    },
)

workflow.add_conditional_edges(
    "synthesize",
    route,
    {
        "replan_decision": "replan_decision",
        END: END,
    },
)

workflow.add_conditional_edges(
    "replan_decision",
    route,
    {
        "replan": "replan",
        END: END,
    },
)

workflow.add_conditional_edges(
    "replan",
    route,
    {
        "execute": "execute",
        END: END,
    },
)


def build_app():
    """Compile LangGraph app (no checkpointing)"""
    return workflow.compile()


def _parse_cli_args(argv):
    """Parse CLI arguments including optional JSON output path."""
    parser = argparse.ArgumentParser(
        description="Run the SIEM investigation agent",
        add_help=True,
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        metavar="FILE",
        help="Write the final result as JSON to FILE (in addition to stdout)",
    )
    parser.add_argument(
        "question",
        nargs="*",
        help="Security investigation question to answer",
    )
    return parser.parse_args(argv)


def _build_json_payload(final_state, user_question, processed_answer, elapsed):
    """Prepare a JSON-serializable payload with key session outputs."""
    total_tokens = final_state.get('total_input_tokens', 0) + final_state.get('total_output_tokens', 0)
    planning_rounds = final_state.get("current_replanning_round", 0) + 1
    # Remove table field from queries in JSON output
    sanitized_queries = []
    for entry in final_state.get("query_execution_history", []):
        if isinstance(entry, dict):
            sanitized_queries.append({k: v for k, v in entry.items() if k != "table"})
        else:
            sanitized_queries.append(entry)
    payload = {
        "session": {
            "elapsed_seconds": elapsed,
        },
        "question": user_question,
        "answer": {
            "text": processed_answer,
            "confidence": final_state.get("synthesis_confidence", ""),
            "data_gaps": final_state.get("synthesis_data_gaps", []),
        },
        "queries": sanitized_queries,
        "execution_errors": final_state.get("execution_errors", []),
        "investigation_plan": final_state.get("investigation_plan"),
        "stats": {
            "queries_run": final_state.get("current_query_index", 0),
            "planning_rounds": planning_rounds,
            "llm_calls": final_state.get("llm_call_count", 0),
            "input_tokens": final_state.get("total_input_tokens", 0),
            "output_tokens": final_state.get("total_output_tokens", 0),
            "total_tokens": total_tokens,
        },
    }
    return payload


def _write_json_output(json_path, payload):
    """Write the JSON payload to disk, creating parent directories if needed."""
    path = Path(json_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"JSON output saved to {path}")
        config.session_logger.log("INFO", "agent", "json_output_saved", {"path": str(path)})
    except Exception as e:
        print(f"Failed to write JSON output to {path}: {e}")
        config.session_logger.log("ERROR", "agent", "json_output_failed", {"path": str(path), "error": str(e)})


def main():
    """Run the SIEM analysis agent"""
    args = _parse_cli_args(sys.argv[1:])
    json_output_path = args.json_path

    # 1. Get user question (CLI arg or interactive)
    if args.question:
        user_question = " ".join(args.question).strip()
    else:
        user_question = input("\nEnter your question about WAF logs: ").strip()
        if not user_question:
            print("No question provided. Exiting.")
            return None

    print(f"\n{'='*80}")
    print(f" USER QUESTION")
    print(f"{'='*80}")
    print(f"\n{user_question}\n")

    # 2. Initialize session
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(LOG_DIR, exist_ok=True)
    session_timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    session_dir = LOG_DIR / f"{session_timestamp}_{session_id}"
    config.session_logger = StructuredLogger(session_dir)

    config.session_logger.log("INFO", "agent", "session_start", {
        "session_id": session_id,
        "user_question": user_question,
        "config": {
            "clickhouse_host": CONFIG['clickhouse']['host'],
            "llm_model": CONFIG['vllm']['model'],
            "max_iterations": CONFIG['agent']['max_iterations'],
        }
    })

    print(f"Session ID: {session_id}")
    print(f"Target: {CONFIG['clickhouse']['host']}:{CONFIG['clickhouse']['port']}/{CONFIG['clickhouse']['database']}")
    print(f"LLM: {CONFIG['vllm']['model']} @ {CONFIG['vllm']['base_url']}")
    print(f"Max Iterations: {CONFIG['agent']['max_iterations']}")
    print(f"Session logs: {session_dir}\n")

    # 3. Initialize ClickHouse
    try:
        config.client = clickhouse_connect.get_client(
            host=CONFIG['clickhouse']['host'],
            port=CONFIG['clickhouse']['port'],
            interface='https',
            database=CONFIG['clickhouse']['database'],
            username=CONFIG['clickhouse']['user'],
            password=CONFIG['clickhouse']['password'],
            settings={
                "readonly": 1,
                "max_execution_time": 10,
                "max_result_rows": CONFIG['clickhouse']['max_result_rows'],
                "result_overflow_mode": "throw",
                "max_result_bytes": 5_000_000,
            },
        )
        # Connectivity check
        config.client.query("SELECT 1")
        print("ClickHouse connection: OK")
    except Exception as e:
        print(f"Failed to initialize ClickHouse client: {e}")
        print("Hint: verify host/port/db/user/password and network access.")
        config.session_logger.log("ERROR", "agent", "clickhouse_init_failed", {"error": str(e)})
        return None

    # 4. Initialize vLLM
    try:
        config.llm = ChatOpenAI(
            base_url=CONFIG['vllm']['base_url'] + "/v1",
            model=CONFIG['vllm']['model'],
            temperature=CONFIG['vllm'].get('temperature', 0.2),
            top_p=CONFIG['vllm'].get('top_p', 1.0),
            timeout=CONFIG['vllm'].get('timeout', 300),
            max_tokens=CONFIG['vllm'].get('max_tokens', 4096),
            reasoning={"effort": CONFIG['vllm'].get('reasoning_effort', "medium")},
            api_key=CONFIG['vllm'].get('api_key', "EMPTY"),
            use_responses_api=True
        )
        # Quick sanity check
        _ = config.llm.invoke("ping")
        print("vLLM connection: OK\n")
    except Exception as e:
        print(f"Failed to initialize vLLM client: {e}")
        print("Hint: ensure vLLM server is running at the configured base_url.")
        config.session_logger.log("ERROR", "agent", "vllm_init_failed", {"error": str(e)})
        return None

    # 5. Build workflow
    app = build_app()

    # 6. Initialize state
    initial_state = {
        "user_question": user_question,
        "database_name": CONFIG['clickhouse']['database'],
        "siem_log_table_name": CONFIG['clickhouse']['siem_log_table_name'],
        "cdn_log_table_name": CONFIG['clickhouse']['cdn_log_table_name'],
        "available_hosts": [],
        "available_rule_tags": [],
        "investigation_plan": None,
        "plan_rationale": "",
        "is_answerable": True,
        "unanswerable_reason": "",
        "query_execution_history": [],
        "current_query_index": 0,
        "execution_errors": [],
        "next_node": "discover",
        "answer": "",
        # Re-planning tracking
        "current_replanning_round": 0,
        "max_replanning_rounds": CONFIG['agent'].get('max_replanning_rounds', 3),
        "needs_replanning": False,
        "replan_rationale": "",
        "replanning_history": [],
        "synthesis_confidence": "",
        "synthesis_data_gaps": [],
        "replan_suggested_steps": [],
        "replan_estimated_queries": 0,
        # Metadata
        "total_input_tokens": 0,
        "total_output_tokens": 0,
        "llm_call_count": 0,
    }

    # 7. Run workflow
    try:
        start_time = time.time()
        final_state = app.invoke(
            initial_state,
            {"recursion_limit": CONFIG['agent']['max_iterations'] + 10}
        )
        elapsed = time.time() - start_time

        # 8. Format output to stdout
        print(f"\n{'='*80}")
        print(f" INVESTIGATION PLAN")
        print(f"{'='*80}\n")

        plan_data = final_state.get("investigation_plan")
        plan_obj = None
        if plan_data:
            plan_obj = InvestigationPlan.model_validate(plan_data)
            print(f"Answerable: {plan_obj.is_answerable} | Complexity: {plan_obj.estimated_complexity}")
            print(f"Rationale: {plan_obj.rationale}\n")
            for q in plan_obj.queries:
                print(f"- Query {q.query_id} [{q.table}] - {q.purpose}")
                print(f"  Expected: {q.expected_result_type}")
                print(f"  SQL: {q.sql}\n")
        else:
            print("No plan generated.\n")

        print(f"{'='*80}")
        print(f" SUPPORTING DATA")
        print(f"{'='*80}\n")

        if final_state.get("query_execution_history"):
            for entry in final_state["query_execution_history"]:
                print(f"Query {entry.get('query_id', '?')}: {entry.get('purpose', '')}")
                print(f"Table: {entry.get('table', 'unknown')} | Expected: {entry.get('expected_result_type', '')}")
                print(f"SQL: {entry.get('sql', '')}")
                status = entry.get("status", "unknown")
                print(f"Status: {status}")
                if status == "ok":
                    print(f"Rows: {entry.get('row_count', 0)}")
                    if entry.get("formatted_result"):
                        print(f"{entry['formatted_result']}")
                else:
                    print(f"Error: {entry.get('error', 'Unknown error')}")
                print()
        else:
            print("No queries executed.\n")

        if final_state.get("execution_errors"):
            print("Execution errors:")
            for err in final_state["execution_errors"]:
                print(f"- {err}")
            print()

        print(f"{'='*80}")
        print(f" ANSWER")
        print(f"{'='*80}\n")

        answer = final_state.get("answer", "Investigation incomplete")
        from .llm_utils import evaluate_num_tags
        processed_answer = evaluate_num_tags(answer)
        print(f"{processed_answer}\n")

        print(f"{'='*80}")
        print(f" SESSION STATISTICS")
        print(f"{'='*80}\n")
        print(f"Session ID:           {session_id}")
        print(f"Planning Rounds:      {final_state.get('current_replanning_round', 0) + 1}")
        print(f"Queries run:          {final_state.get('current_query_index', 0)}")
        print(f"LLM Calls:            {final_state.get('llm_call_count', 0):,}")
        print(f"Input Tokens:         {final_state.get('total_input_tokens', 0):,}")
        print(f"Output Tokens:        {final_state.get('total_output_tokens', 0):,}")
        total_tokens = final_state.get('total_input_tokens', 0) + final_state.get('total_output_tokens', 0)
        print(f"Total Tokens:         {total_tokens:,}")
        print(f"Elapsed Time:         {elapsed:.1f}s")
        print(f"Session Log:          {session_dir}/session.log\n")

        config.session_logger.log("INFO", "agent", "session_end", {
            "session_id": session_id,
            "queries_run": final_state.get('current_query_index', 0),
            "llm_calls": final_state.get('llm_call_count', 0),
            "total_tokens": total_tokens,
            "elapsed_seconds": elapsed,
            "answer_complete": final_state.get("next_node") == "end"
        })

        if json_output_path:
            json_payload = _build_json_payload(
                final_state=final_state,
                user_question=user_question,
                processed_answer=processed_answer,
                elapsed=elapsed,
            )
            _write_json_output(json_output_path, json_payload)

        return final_state

    except Exception as e:
        config.session_logger.log("ERROR", "agent", "session_failed", {
            "error": str(e)
        })
        print(f"\nERROR: Investigation failed - {str(e)}\n")
        raise


if __name__ == "__main__":
    main()
