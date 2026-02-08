"""LLM agent test runner using LLM-as-a-judge via BAML."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, TextIO

import baml_py
import requests
import yaml

from test_runner.baml_client import b
from test_runner.baml_client.types import JudgeResult


TEST_RUNNER_DIR = Path(__file__).resolve().parent
TEST_CASES_PATH = TEST_RUNNER_DIR / "test" / "test_cases.yaml"
TEST_RESULTS_DIR = TEST_RUNNER_DIR / "test_results"


class TestLogger:
    """Logs test results to stdout (human-readable) and JSONL file (structured)."""

    def __init__(self, results_dir: Path) -> None:
        results_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        self.log_file_path = results_dir / f"test_results_{timestamp}.jsonl"
        self.file: TextIO = self.log_file_path.open("w", encoding="utf-8")
        self.log_console(f"Test log started: {timestamp}")
        self.log_console(f"Log file: {self.log_file_path}\n")

    def log_console(self, message: str) -> None:
        """Write message to stdout only, with immediate flush."""
        print(message, flush=True)

    def log_result(self, result_data: dict[str, Any]) -> None:
        """Write structured test result to JSONL file."""
        record = {"record_type": "test_result", **result_data}
        self.file.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.file.flush()

    def log_summary(self, summary_data: dict[str, Any]) -> None:
        """Write summary record as the last line of the JSONL file."""
        record = {"record_type": "summary", **summary_data}
        self.file.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.file.flush()

    def close(self) -> None:
        """Close the log file."""
        self.log_console(
            f"\nTest log ended: {datetime.now().strftime('%Y-%m-%dT%H-%M-%S')}"
        )
        self.file.close()


@dataclass(frozen=True)
class TestCase:
    name: str
    question: str
    acceptance_criteria: tuple[str, ...]


@dataclass
class TestStats:
    runs: int = 0
    passes: int = 0
    durations: list[float] = field(default_factory=list)


def load_test_cases(path: Path) -> list[TestCase]:
    data = yaml.safe_load(path.read_text())
    if not data or "tests" not in data:
        raise ValueError(f"Invalid test cases file: {path}")
    cases = []
    for entry in data["tests"]:
        criteria = entry.get("acceptance_criteria", [])
        cases.append(
            TestCase(
                name=str(entry["name"]),
                question=str(entry["question"]),
                acceptance_criteria=tuple(str(c) for c in criteria),
            )
        )
    return cases


def filter_test_cases(
    cases: Iterable[TestCase], names: list[str] | None
) -> list[TestCase]:
    if not names:
        return list(cases)
    selected = [case for case in cases if case.name in names]
    missing = sorted(set(names) - {case.name for case in selected})
    if missing:
        raise ValueError(f"Unknown test case(s): {', '.join(missing)}")
    return selected


@dataclass
class AgentResult:
    """Result from running the analysis agent with --json flag."""

    final_answer: str
    log_file_name: str | None
    stderr: str
    returncode: int
    duration: float


def run_agent(question: str) -> AgentResult:
    """Run the analysis agent with --json flag and parse the response."""
    start = time.perf_counter()
    result = subprocess.run(
        [sys.executable, "-m", "siem_agent", "--json", question],
        text=True,
        capture_output=True,
    )
    duration = time.perf_counter() - start
    stdout = result.stdout or ""
    stderr = result.stderr or ""

    if result.returncode != 0:
        return AgentResult(
            final_answer="",
            log_file_name=None,
            stderr=stderr,
            returncode=result.returncode,
            duration=duration,
        )

    try:
        response = json.loads(stdout)
        return AgentResult(
            final_answer=response.get("final_answer", ""),
            log_file_name=response.get("log_file_name"),
            stderr=stderr,
            returncode=result.returncode,
            duration=duration,
        )
    except json.JSONDecodeError as exc:
        return AgentResult(
            final_answer="",
            log_file_name=None,
            stderr=f"JSON parse error: {exc}\nRaw stdout: {stdout}",
            returncode=1,
            duration=duration,
        )


def judge_answer(
    question: str,
    acceptance_criteria: tuple[str, ...],
    actual_answer: str,
    actual_unanswerable: bool,
) -> JudgeResult:
    criteria_text = "\n".join(f"- {c}" for c in acceptance_criteria)
    req = b.request.JudgeAnswer(
        question=question,
        acceptance_criteria=criteria_text,
        actual_answer=actual_answer,
        actual_unanswerable=actual_unanswerable,
    )
    res = requests.post(url=req.url, headers=req.headers, json=req.body.json())
    raw_content = res.json()["choices"][0]["message"]["content"]
    try:
        return b.parse.JudgeAnswer(raw_content)
    except baml_py.BamlError as exc:
        raise RuntimeError(f"BAML judge parse failed: {exc}") from exc


def is_unanswerable_text(text: str) -> bool:
    prefix = text.strip().lower()
    return (
        prefix.startswith("unanswerable:")
        or prefix.startswith("forced_complete:")
        or prefix.startswith("error:")
    )


def summarize_stats(name: str, stats: TestStats) -> str:
    if not stats.durations:
        avg = 0.0
        max_time = 0.0
    else:
        avg = sum(stats.durations) / len(stats.durations)
        max_time = max(stats.durations)
    pass_rate = (stats.passes / stats.runs) if stats.runs else 0.0
    return (
        f"{name}: pass_rate={pass_rate:.2%}, "
        f"avg_time={avg:.2f}s, max_time={max_time:.2f}s"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test runner for SIEM agent using LLM-as-a-judge."
    )
    parser.add_argument(
        "--tests",
        nargs="+",
        help="Test case names to run (default: all).",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Number of runs per test case (default: 1).",
    )
    parser.add_argument(
        "--cases-file",
        type=Path,
        default=TEST_CASES_PATH,
        help="Path to consolidated test cases YAML.",
    )
    args = parser.parse_args()

    if args.runs < 1:
        raise ValueError("--runs must be >= 1")

    all_cases = load_test_cases(args.cases_file)
    selected_cases = filter_test_cases(all_cases, args.tests)

    logger = TestLogger(TEST_RESULTS_DIR)

    try:
        stats_by_name: dict[str, TestStats] = {
            case.name: TestStats() for case in selected_cases
        }

        for case in selected_cases:
            for run_idx in range(args.runs):
                agent_result = run_agent(case.question)

                if agent_result.returncode != 0:
                    reason = (
                        f"FAIL {case.name} (run {run_idx + 1}/{args.runs}): "
                        f"agent_error returncode={agent_result.returncode}, "
                        f"stderr={agent_result.stderr.strip()}"
                    )
                    logger.log_console(reason)
                    logger.log_result(
                        {
                            "test_name": case.name,
                            "run_number": run_idx + 1,
                            "question": case.question,
                            "answer": "",
                            "acceptance_criteria": list(case.acceptance_criteria),
                            "result": "FAIL",
                            "reason": (
                                f"agent_error returncode={agent_result.returncode}, "
                                f"stderr={agent_result.stderr.strip()}"
                            ),
                            "agent_duration": agent_result.duration,
                            "judge_duration": None,
                            "total_duration": agent_result.duration,
                            "agent_log_file": agent_result.log_file_name,
                        }
                    )
                    stats = stats_by_name[case.name]
                    stats.runs += 1
                    stats.durations.append(agent_result.duration)
                    continue

                actual_answer = agent_result.final_answer
                if not actual_answer:
                    reason = (
                        f"FAIL {case.name} (run {run_idx + 1}/{args.runs}): "
                        "empty answer from agent"
                    )
                    logger.log_console(reason)
                    logger.log_result(
                        {
                            "test_name": case.name,
                            "run_number": run_idx + 1,
                            "question": case.question,
                            "answer": "",
                            "acceptance_criteria": list(case.acceptance_criteria),
                            "result": "FAIL",
                            "reason": "empty answer from agent",
                            "agent_duration": agent_result.duration,
                            "judge_duration": None,
                            "total_duration": agent_result.duration,
                            "agent_log_file": agent_result.log_file_name,
                        }
                    )
                    stats = stats_by_name[case.name]
                    stats.runs += 1
                    stats.durations.append(agent_result.duration)
                    continue

                actual_unanswerable = is_unanswerable_text(actual_answer)

                judge_start = time.perf_counter()
                try:
                    result = judge_answer(
                        question=case.question,
                        acceptance_criteria=case.acceptance_criteria,
                        actual_answer=actual_answer,
                        actual_unanswerable=actual_unanswerable,
                    )
                    judge_duration = time.perf_counter() - judge_start
                    total_duration = agent_result.duration + judge_duration

                    stats = stats_by_name[case.name]
                    stats.runs += 1
                    stats.durations.append(total_duration)

                    if result.is_pass:
                        stats.passes += 1
                        logger.log_result(
                            {
                                "test_name": case.name,
                                "run_number": run_idx + 1,
                                "question": case.question,
                                "answer": actual_answer,
                                "acceptance_criteria": list(case.acceptance_criteria),
                                "result": "PASS",
                                "reason": result.reason,
                                "agent_duration": agent_result.duration,
                                "judge_duration": judge_duration,
                                "total_duration": total_duration,
                                "agent_log_file": agent_result.log_file_name,
                            }
                        )
                    else:
                        reason = (
                            f"FAIL {case.name} (run {run_idx + 1}/{args.runs}): "
                            f"{result.reason}"
                        )
                        logger.log_console(reason)
                        logger.log_result(
                            {
                                "test_name": case.name,
                                "run_number": run_idx + 1,
                                "question": case.question,
                                "answer": actual_answer,
                                "acceptance_criteria": list(case.acceptance_criteria),
                                "result": "FAIL",
                                "reason": result.reason,
                                "agent_duration": agent_result.duration,
                                "judge_duration": judge_duration,
                                "total_duration": total_duration,
                                "agent_log_file": agent_result.log_file_name,
                            }
                        )
                except Exception as exc:
                    judge_duration = time.perf_counter() - judge_start
                    total_duration = agent_result.duration + judge_duration
                    stats = stats_by_name[case.name]
                    stats.runs += 1
                    stats.durations.append(total_duration)
                    reason = (
                        f"FAIL {case.name} (run {run_idx + 1}/{args.runs}): "
                        f"judge_error {exc}"
                    )
                    logger.log_console(reason)
                    logger.log_result(
                        {
                            "test_name": case.name,
                            "run_number": run_idx + 1,
                            "question": case.question,
                            "answer": actual_answer,
                            "acceptance_criteria": list(case.acceptance_criteria),
                            "result": "FAIL",
                            "reason": f"judge_error {exc}",
                            "agent_duration": agent_result.duration,
                            "judge_duration": judge_duration,
                            "total_duration": total_duration,
                            "agent_log_file": agent_result.log_file_name,
                        }
                    )

        logger.log_console("\nTest Results:")
        total_runs = 0
        total_passes = 0
        all_durations: list[float] = []
        per_test_stats: list[dict[str, Any]] = []
        for case in selected_cases:
            stats = stats_by_name[case.name]
            logger.log_console(summarize_stats(case.name, stats))
            total_runs += stats.runs
            total_passes += stats.passes
            all_durations.extend(stats.durations)
            pass_rate = (stats.passes / stats.runs) if stats.runs else 0.0
            per_test_stats.append({
                "test_name": case.name,
                "runs": stats.runs,
                "passes": stats.passes,
                "pass_rate": pass_rate,
                "avg_duration": (sum(stats.durations) / len(stats.durations)) if stats.durations else 0.0,
                "max_duration": max(stats.durations) if stats.durations else 0.0,
            })

        overall_pass_rate = (total_passes / total_runs) if total_runs else 0.0
        logger.log_summary({
            "total_runs": total_runs,
            "total_passes": total_passes,
            "total_failures": total_runs - total_passes,
            "overall_pass_rate": overall_pass_rate,
            "avg_duration": (sum(all_durations) / len(all_durations)) if all_durations else 0.0,
            "max_duration": max(all_durations) if all_durations else 0.0,
            "per_test": per_test_stats,
        })
    finally:
        logger.close()


if __name__ == "__main__":
    main()
