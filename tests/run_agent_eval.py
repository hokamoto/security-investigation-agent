#!/usr/bin/env python3
"""
Simple regression harness that runs the SIEM agent against dated test cases and
checks answers for regressions. Each case is a YAML file in tests/cases/*.yaml.
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "tests" / "cases"
ARTIFACTS_DIR = REPO_ROOT / "tests" / "artifacts"

# Ensure local package imports work when running as a script (uv run tests/run_agent_eval.py).
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@dataclass
class Case:
    name: str
    question: str
    expected_answer: str
    expected_methods: List[str]
    raw: Dict[str, Any]


def _write_json(path: Path, data: Any) -> None:
    """Write JSON to disk with a safe fallback for non-serializable values."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        text = json.dumps(data, ensure_ascii=False, indent=2)
    except TypeError:
        text = json.dumps(data, ensure_ascii=False, indent=2, default=str)
    path.write_text(text, encoding="utf-8")


def load_cases(cases_dir: Path, selected_names: Optional[List[str]]) -> List[Case]:
    cases: List[Case] = []
    for path in sorted(cases_dir.glob("*.yaml")):
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if selected_names and data.get("name") not in selected_names:
            continue
        cases.append(
            Case(
                name=data["name"],
                question=data["question"],
                expected_answer=data.get("expected_answer", ""),
                expected_methods=[str(item) for item in data.get("expected_methods", [])],
                raw=data,
            )
        )
    return cases


def _normalize_content(content: Any) -> str:
    """Coerce LLM response content into a plain string for grading."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # LangChain Responses API may return a list payload; flatten to text.
        try:
            return " ".join(_normalize_content(item) for item in content)
        except Exception:
            return json.dumps(content, ensure_ascii=False)
    if isinstance(content, dict):
        return json.dumps(content, ensure_ascii=False)
    return str(content)


def _extract_user_facing_text(content: Any) -> str:
    """
    Extract only the user-facing text from an LLM response, ignoring reasoning streams.
    This avoids PASS/FAIL detection being influenced by internal reasoning output.
    """
    if isinstance(content, list):
        user_parts: List[str] = []
        reasoning_parts: List[str] = []  # Collect reasoning as fallback
        for item in content:
            if isinstance(item, dict):
                part_type = (item.get("type") or "").lower()
                # Handle nested content structure (e.g., reasoning blocks with content arrays)
                if "content" in item and isinstance(item["content"], list):
                    # Recursively extract from nested content
                    nested_text = _extract_user_facing_text(item["content"])
                    if part_type.startswith("reasoning"):
                        reasoning_parts.append(nested_text)
                    else:
                        user_parts.append(nested_text)
                else:
                    text = item.get("text") or ""
                    if part_type.startswith("reasoning"):
                        if text:
                            reasoning_parts.append(_normalize_content(text))
                    elif text:
                        user_parts.append(_normalize_content(text))
            else:
                user_parts.append(_normalize_content(item))
        if user_parts:
            return " ".join(user_parts)
        # Fallback: if no user-facing parts, use reasoning parts
        # (happens when LLM only outputs reasoning without final answer)
        if reasoning_parts:
            return " ".join(reasoning_parts)
    return _normalize_content(content)


def run_agent(question: str, artifacts_dir: Path) -> Dict[str, Any]:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    json_path = artifacts_dir / "agent.json"
    cmd = [
        "uv",
        "run",
        "-m",
        "siem_agent",
        "--json",
        str(json_path),
        question,
    ]
    completed = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    (artifacts_dir / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (artifacts_dir / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    result: Dict[str, Any] = {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "json_path": str(json_path),
    }
    if json_path.exists():
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            result["payload"] = payload
            result["answer_text"] = payload.get("answer", {}).get("text", "")
            result["investigation_plan"] = payload.get("investigation_plan")
            result["queries"] = payload.get("queries", [])
            result["planning_rounds"] = payload.get("stats", {}).get("planning_rounds")
        except Exception as exc:  # pragma: no cover - defensive
            result["payload_error"] = str(exc)
    else:
        result["payload_error"] = "JSON output missing"
    return result


def grade_with_llm(
    case: Case,
    answer_text: str,
    plan: Any,
    queries: List[Any],
    planning_rounds: Optional[int],
    artifacts_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    grader_log: Dict[str, Any] = {
        "case": case.name,
        "question": case.question,
        "expected_answer": case.expected_answer,
        "expected_methods": case.expected_methods,
        "agent_answer_text": answer_text,
        "investigation_plan": plan,
        "queries": queries,
        "planning_rounds": planning_rounds,
    }
    try:
        from langchain_core.messages import HumanMessage, SystemMessage
        from langchain_openai import ChatOpenAI
        from siem_agent.config import CONFIG
    except Exception as exc:  # pragma: no cover - optional path
        error_payload = {"status": "error", "reason": f"LLM grader unavailable: {exc}"}
        grader_log.update(error_payload)
        if artifacts_dir:
            _write_json(artifacts_dir / "grader.json", grader_log)
        return error_payload

    system_prompt = (
        "You are a strict grader. Evaluate TWO dimensions separately:\n"
        "1) ANSWER: Does the answer align with the expected summary and the fixed time range?\n"
        "2) METHOD: Do the investigation steps (planning rounds, SQL queries) satisfy the grading notes about process/SQL? "
        "Use investigation plan + executed queries + planning_rounds to judge METHOD. If expected_methods lack method constraints, METHOD = PASS unless steps clearly conflict."
    )
    methods = "\n".join(f"- {note}" for note in case.expected_methods) if case.expected_methods else "None"
    plan_text = json.dumps(plan, ensure_ascii=False, indent=2) if plan is not None else "None"
    queries_text = json.dumps(queries, ensure_ascii=False, indent=2) if queries else "None"
    planning_rounds_text = "unknown" if planning_rounds is None else str(planning_rounds)
    user_prompt = (
        f"Question: {case.question}\n"
        f"Expected answer: {case.expected_answer}\n"
        f"Expected methods:\n{methods}\n"
        f"Answer from the agent:\n{answer_text}\n"
        f"Planning rounds used (discover + replans): {planning_rounds_text}\n"
        f"Investigation plan (initial):\n{plan_text}\n"
        f"Executed queries (with SQL):\n{queries_text}\n"
        "Respond ONLY in this format:\n"
        "answer_result: PASS or FAIL\n"
        "method_result: PASS or FAIL\n"
        "justification: <one short line>\n"
        "Use FAIL if unsure."
    )
    grader_log.update(
        {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
        }
    )
    try:
        llm = ChatOpenAI(
            base_url=CONFIG["vllm"]["base_url"] + "/v1",
            model=CONFIG["vllm"]["model"],
            temperature=CONFIG["vllm"].get("temperature", 0.2),
            top_p=CONFIG["vllm"].get("top_p", 1.0),
            timeout=CONFIG["vllm"].get("timeout", 120),
            max_tokens=10000,
            reasoning={"effort": CONFIG["vllm"].get("reasoning_effort", "medium")},
            api_key=CONFIG["vllm"].get("api_key", "EMPTY"),
            use_responses_api=True,
        )
        response = llm.invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt),
            ]
        )
        raw_content = response.content if hasattr(response, "content") else response

        # Check if raw_content is a JSON string and parse it
        if isinstance(raw_content, str):
            try:
                parsed = json.loads(raw_content)
                raw_content = parsed
            except json.JSONDecodeError:
                pass  # Keep as string if not valid JSON

        content_text = _extract_user_facing_text(raw_content)
        lower_text = content_text.lower()
        answer_verdict = "fail"
        method_verdict = "fail"
        grader_log.update(
            {
                "raw_response": raw_content,
                "extracted_text": content_text,
            }
        )

        # Try strict format first: "answer_result: PASS/FAIL"
        answer_match = re.search(r"answer_result\s*:\s*(pass|fail)", lower_text)
        method_match = re.search(r"method_result\s*:\s*(pass|fail)", lower_text)

        # Fallback: look for "ANSWER PASS" or "ANSWER: PASS" in reasoning text
        if not answer_match:
            answer_match = re.search(r"answer[:\s]+(pass|fail)", lower_text)
        if not method_match:
            method_match = re.search(r"method[:\s]+(pass|fail)", lower_text)

        if answer_match:
            answer_verdict = answer_match.group(1)
        else:
            answer_verdict = "unknown"

        if method_match:
            method_verdict = method_match.group(1)
        else:
            method_verdict = "unknown"
        grade_result = {
            "answer_result": answer_verdict,
            "method_result": method_verdict,
            "llm_response": content_text,
        }
        grader_log.update(grade_result)
        if artifacts_dir:
            _write_json(artifacts_dir / "grader.json", grader_log)
        return grade_result
    except Exception as exc:  # pragma: no cover - defensive
        error_payload = {"status": "error", "reason": str(exc)}
        grader_log.update(error_payload)
        if artifacts_dir:
            _write_json(artifacts_dir / "grader.json", grader_log)
        return error_payload


def evaluate_case(case: Case, artifacts_root: Path) -> Dict[str, Any]:
    artifacts_dir = artifacts_root / case.name
    agent_result = run_agent(case.question, artifacts_dir)
    answer_text = agent_result.get("answer_text", "")
    llm_grade = grade_with_llm(
        case,
        answer_text,
        plan=agent_result.get("investigation_plan"),
        queries=agent_result.get("queries", []),
        planning_rounds=agent_result.get("planning_rounds"),
        artifacts_dir=artifacts_dir,
    )

    answer_status = llm_grade.get("answer_result", llm_grade.get("status", "unknown"))
    method_status = llm_grade.get("method_result", "unknown")
    overall = "unknown"
    if agent_result.get("returncode", 1) != 0 or agent_result.get("payload_error"):
        answer_status = "fail"
        method_status = "fail"
        overall = "fail"
    else:
        if answer_status == "pass" and method_status == "pass":
            overall = "pass"
        elif "fail" in (answer_status, method_status):
            overall = "fail"

    summary = {
        "case": case.name,
        "overall": overall,
        "answer_result": answer_status,
        "method_result": method_status,
        "llm_response": llm_grade.get("llm_response", ""),
        "agent": {
            "returncode": agent_result.get("returncode"),
            "payload_error": agent_result.get("payload_error"),
            "json_path": agent_result.get("json_path"),
        },
    }
    (artifacts_dir / "result.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run regression checks against the SIEM agent.")
    parser.add_argument(
        "--cases-dir",
        default=str(CASES_DIR),
        help="Directory containing YAML test cases.",
    )
    parser.add_argument(
        "--case",
        action="append",
        help="Run a specific case name (can be repeated). Defaults to all cases.",
    )
    parser.add_argument(
        "--artifacts-dir",
        default=str(ARTIFACTS_DIR),
        help="Where to write per-case artifacts.",
    )
    args = parser.parse_args(argv)

    cases = load_cases(Path(args.cases_dir), args.case)
    if not cases:
        print("No test cases found.", file=sys.stderr)
        return 1

    artifacts_root = Path(args.artifacts_dir)
    results = []
    for case in cases:
        print(f"Running case: {case.name}")
        result = evaluate_case(case, artifacts_root)
        results.append(result)
        print(
            f"  -> ANSWER={result['answer_result'].upper()} "
            f"METHOD={result['method_result'].upper()} "
            f"OVERALL={result['overall'].upper()}"
        )

    failures = [r for r in results if r["overall"] != "pass"]
    print("\nSummary:")
    for res in results:
        print(
            f"{res['case']}: ANSWER={res['answer_result'].upper()} "
            f"METHOD={res['method_result'].upper()} "
            f"OVERALL={res['overall'].upper()}"
        )
    return 0 if not failures else 2


if __name__ == "__main__":
    sys.exit(main())
