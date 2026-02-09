"""Session logging module for SIEM Agent.

Creates one JSONL file per session (one user question) with structured logging
of all events including LLM calls, SQL queries, and session lifecycle.
"""

import json
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, UTC
from enum import Enum
from pathlib import Path
from time import perf_counter
from typing import Any, Optional


class EventType(str, Enum):
    """Types of events that can be logged."""

    SESSION_START = "session_start"
    SESSION_END = "session_end"
    DISCOVERY = "discovery"
    LLM_CALL = "llm_call"
    SQL_QUERY = "sql_query"
    ROUND_START = "round_start"
    ROUND_END = "round_end"
    ERROR = "error"


class Timer:
    """Simple timer for measuring durations."""

    def __init__(self):
        self.start_time: float = 0
        self.end_time: float = 0

    def start(self):
        self.start_time = perf_counter()

    def stop(self):
        self.end_time = perf_counter()

    @property
    def duration(self) -> float:
        """Duration in seconds."""
        return self.end_time - self.start_time


@dataclass
class BaseEvent:
    """Base event with common fields."""

    event_type: str
    timestamp: str
    round_number: int = 0
    duration: float = 0.0


def _format_session_start_message(data: dict) -> str:
    """Format message for session_start event."""
    lines = ["Session started"]
    lines.append(f"  Session ID: {data.get('session_id', 'N/A')}")
    lines.append(f"  Question: {data.get('user_question', 'N/A')}")
    return "\n".join(lines)


def _format_session_end_message(data: dict) -> str:
    """Format message for session_end event."""
    outcome = data.get("outcome", "unknown")
    lines = [f"Session ended ({outcome})"]
    lines.append(f"  Rounds: {data.get('total_rounds', 0)}")
    prompt_tokens = data.get("total_prompt_tokens", 0)
    completion_tokens = data.get("total_completion_tokens", 0)
    lines.append(
        f"  LLM calls: {data.get('total_llm_calls', 0)} "
        f"({prompt_tokens} prompt + {completion_tokens} completion tokens)"
    )
    lines.append(f"  SQL queries: {data.get('total_sql_queries', 0)}")
    duration = data.get("total_duration", 0)
    lines.append(f"  Duration: {duration:.2f}s")
    final_answer = data.get("final_answer")
    lines.append(f"  Final answer: {final_answer if final_answer else 'N/A'}")
    sql_errors = data.get("sql_errors", [])
    if sql_errors:
        lines.append(f"  SQL errors ({len(sql_errors)}):")
        for err in sql_errors:
            repair_info = ""
            if err.get("is_repair_attempt"):
                repair_info = f" [repair #{err.get('repair_attempt_number', 0)}]"
            lines.append(
                f"    #{err.get('query_id')} round={err.get('round_number')}{repair_info}: {err.get('error_message')}"
            )
    return "\n".join(lines)


def _format_discovery_message(data: dict) -> str:
    """Format message for discovery event."""
    duration = data.get("duration", 0)
    hosts_count = data.get("hosts_count", 0)
    rule_tags_count = data.get("rule_tags_count", 0)
    hosts = data.get("hosts", [])

    lines = [f"Discovery completed in {duration:.2f}s"]
    hosts_str = ", ".join(hosts) if hosts else "none"
    lines.append(f"  Hosts ({hosts_count}): {hosts_str}")
    lines.append(f"  Rule tags: {rule_tags_count} tags found")
    return "\n".join(lines)


def _format_llm_call_message(data: dict) -> str:
    """Format message for llm_call event."""
    call_type = data.get("call_type", "unknown")
    round_number = data.get("round_number", 0)
    prompt_tokens = data.get("prompt_tokens", 0)
    completion_tokens = data.get("completion_tokens", 0)
    duration = data.get("duration", 0)

    lines = [f"LLM call: {call_type} (round {round_number})"]
    lines.append(f"  Tokens: {prompt_tokens} prompt → {completion_tokens} completion")
    lines.append(f"  Duration: {duration:.2f}s")

    parsed = data.get("parsed_response")
    if call_type == "plan" and parsed:
        if isinstance(parsed, dict):
            if "investigation_strategy" in parsed:
                lines.append(f"  Strategy: {parsed['investigation_strategy']}")
            if "queries" in parsed and parsed["queries"] is not None:
                lines.append(f"  Queries planned: {len(parsed['queries'])}")
        else:
            if hasattr(parsed, "investigation_strategy"):
                lines.append(f"  Strategy: {parsed.investigation_strategy}")
            if hasattr(parsed, "queries") and parsed.queries is not None:
                lines.append(f"  Queries planned: {len(parsed.queries)}")
    elif call_type == "batch_repair":
        parent_id = data.get("parent_id")
        if parent_id:
            lines.append(f"  Parent queries: {parent_id}")
        if parsed and isinstance(parsed, list):
            lines.append(f"  Queries repaired: {len(parsed)}")
            for item in parsed:
                idx = getattr(item, "query_index", None)
                expl = getattr(item, "explanation", None)
                if idx is None and isinstance(item, dict):
                    idx = item.get("query_index")
                    expl = item.get("explanation")
                if idx is not None and expl:
                    lines.append(f"    [{idx}] {expl}")

    return "\n".join(lines)


def _format_sql_query_message(data: dict) -> str:
    """Format message for sql_query event."""
    query_id = data.get("query_id", 0)
    round_number = data.get("round_number", 0)
    success = data.get("success", False)
    is_repair = data.get("is_repair_attempt", False)
    repair_num = data.get("repair_attempt_number", 0)
    purpose = data.get("purpose", "N/A")
    sql = data.get("sql_executed", "N/A")
    duration = data.get("duration", 0)

    if is_repair:
        status = "succeeded" if success else "failed"
        lines = [
            f"SQL query #{query_id} repair attempt #{repair_num} {status} (round {round_number})"
        ]
    else:
        status = "succeeded" if success else "failed"
        lines = [f"SQL query #{query_id} {status} (round {round_number})"]

    lines.append(f"  Purpose: {purpose}")
    lines.append(f"  SQL: {sql}")

    if success:
        row_count = data.get("row_count", 0)
        columns = data.get("columns", [])
        lines.append(f"  Result: {row_count} rows in {duration:.2f}s")
        if columns:
            lines.append(f"  Columns: {', '.join(str(c) for c in columns)}")
    else:
        error_message = data.get("error_message", "Unknown error")
        lines.append(f"  Error: {error_message}")
        lines.append(f"  Duration: {duration:.2f}s")

    return "\n".join(lines)


def _format_round_start_message(data: dict) -> str:
    """Format message for round_start event."""
    round_number = data.get("round_number", 0)
    strategy = data.get("strategy", "N/A")
    planned_queries = data.get("planned_queries", [])
    count = data.get("planned_query_count", len(planned_queries))

    lines = [f"Round {round_number} started"]
    lines.append(f"  Strategy: {strategy}")
    lines.append(f"  Planned queries ({count}):")
    for i, q in enumerate(planned_queries, 1):
        purpose = (
            q.get("purpose", "N/A")
            if isinstance(q, dict)
            else getattr(q, "purpose", "N/A")
        )
        lines.append(f"    {i}. {purpose}")
    return "\n".join(lines)


def _format_round_end_message(data: dict) -> str:
    """Format message for round_end event."""
    round_number = data.get("round_number", 0)
    queries_executed = data.get("queries_executed", 0)
    decision = data.get("decision", "N/A")
    duration = data.get("duration", 0)

    lines = [f"Round {round_number} ended"]
    lines.append(f"  Queries executed: {queries_executed}")
    lines.append(f"  Decision: {decision}")
    lines.append(f"  Duration: {duration:.2f}s")
    return "\n".join(lines)


def _format_error_message(data: dict) -> str:
    """Format message for error event."""
    context = data.get("context", "unknown")
    error_type = data.get("error_type", "Unknown")
    error_message = data.get("error_message", "No message")

    lines = [f"ERROR in {context}"]
    lines.append(f"  Type: {error_type}")
    lines.append(f"  Message: {error_message}")
    return "\n".join(lines)


# Message formatters by event type
_MESSAGE_FORMATTERS = {
    "session_start": _format_session_start_message,
    "session_end": _format_session_end_message,
    "discovery": _format_discovery_message,
    "llm_call": _format_llm_call_message,
    "sql_query": _format_sql_query_message,
    "round_start": _format_round_start_message,
    "round_end": _format_round_end_message,
    "error": _format_error_message,
}


def _serialize_for_json(obj: Any) -> Any:
    """Convert objects to JSON-serializable format.

    Recursively converts complex objects to JSON-serializable types.
    Falls back to string representation for objects that can't be serialized.
    """
    # Handle None, primitives (str, int, float, bool)
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    # Handle Enums
    if isinstance(obj, Enum):
        return obj.value

    # Handle lists and tuples
    if isinstance(obj, (list, tuple)):
        return [_serialize_for_json(item) for item in obj]

    # Handle dictionaries
    if isinstance(obj, dict):
        return {str(k): _serialize_for_json(v) for k, v in obj.items()}

    # Handle objects with __dict__ (dataclasses, Pydantic models, etc.)
    if hasattr(obj, "__dict__"):
        try:
            return {k: _serialize_for_json(v) for k, v in obj.__dict__.items()}
        except Exception:
            # Fallback to string representation if __dict__ fails
            return str(obj)

    # Fallback: convert to string for any other type
    try:
        return str(obj)
    except Exception:
        return f"<unserializable: {type(obj).__name__}>"


class SessionLogger:
    """Logger for a single investigation session.

    Creates one JSONL file per session with all events.
    Thread-safe with immediate flush after each write.
    """

    def __init__(self, config: dict, session_id: str):
        """Initialize the session logger.

        Args:
            config: Configuration dictionary with logging settings
            session_id: Unique session identifier (e.g., "2026-02-01T12-34-56Z")
        """
        self._config = config
        self._session_id = session_id
        self._lock = threading.Lock()
        self._file = None
        self._closed = False

        # Logging configuration
        logging_config = config.get("logging", {})
        self._enabled = logging_config.get("enabled", True)
        self._logs_directory = logging_config.get("logs_directory", "logs")

        # Session state
        self._round_number = 0
        self._llm_call_seq = 0

        # Aggregated statistics
        self._total_llm_calls = 0
        self._total_sql_queries = 0
        self._total_prompt_tokens = 0
        self._total_completion_tokens = 0
        self._session_start_time: Optional[float] = None

        # SQL errors accumulated during the session
        self._sql_errors: list[dict] = []

        if self._enabled:
            self._init_log_file()

    def _init_log_file(self):
        """Initialize the log file."""
        logs_dir = Path(self._logs_directory)
        logs_dir.mkdir(parents=True, exist_ok=True)

        # Convert session_id to safe filename (replace colons)
        safe_session_id = self._session_id.replace(":", "-")
        log_path = logs_dir / f"session_{safe_session_id}.jsonl"

        try:
            self._file = open(log_path, "w", encoding="utf-8")
        except Exception as e:
            print(
                f"WARNING: Failed to create log file {log_path}: {e}", file=sys.stderr
            )
            self._enabled = False

    def _write_event(self, event: dict):
        """Write an event to the log file.

        Restructures the event into the standard format:
        - event_type: Type of event
        - timestamp: ISO timestamp
        - message: Human-readable description
        - data: All other fields

        Args:
            event: Event dictionary to write
        """
        if not self._enabled or self._file is None or self._closed:
            return

        with self._lock:
            try:
                # Extract top-level fields
                event_type = event.get("event_type", "unknown")
                timestamp = event.get("timestamp", "")

                # Build data dict with remaining fields
                data = {
                    k: v
                    for k, v in event.items()
                    if k not in ("event_type", "timestamp")
                }

                # Generate human-readable message
                formatter = _MESSAGE_FORMATTERS.get(event_type)
                if formatter:
                    message = formatter(data)
                else:
                    message = f"Event: {event_type}"

                # Build restructured event
                restructured = {
                    "event_type": event_type,
                    "timestamp": timestamp,
                    "message": message,
                    "data": data,
                }

                # Recursively serialize complex objects to JSON-compatible types
                serialized = _serialize_for_json(restructured)

                # Convert to JSON with explicit settings for safety
                # - ensure_ascii=False: preserve Unicode characters
                # - default=str: fallback to string for any remaining unserializable objects
                # - separators: compact output without extra spaces
                json_line = json.dumps(
                    serialized,
                    ensure_ascii=False,
                    default=str,
                    separators=(",", ":"),
                )

                # Validate: ensure no literal newlines in output (they should be escaped as \n)
                if "\n" in json_line:
                    # This should never happen if json.dumps works correctly
                    print(
                        f"WARNING: Unescaped newline detected in JSON output for event type {event.get('event_type')}",
                        file=sys.stderr,
                    )
                    # Replace literal newlines with escaped version as safety measure
                    json_line = json_line.replace("\n", "\\n")

                self._file.write(json_line + "\n")
                self._file.flush()

            except (TypeError, ValueError) as e:
                # JSON encoding errors
                event_type = event.get("event_type", "unknown")
                print(
                    f"WARNING: JSON encoding failed for {event_type} event: {e}",
                    file=sys.stderr,
                )
            except Exception as e:
                # Other errors (I/O, etc.)
                print(f"WARNING: Failed to write log event: {e}", file=sys.stderr)

    def _current_timestamp(self) -> str:
        """Get current ISO timestamp."""
        return datetime.now(UTC).isoformat(timespec="milliseconds")

    @contextmanager
    def timed_event(self):
        """Context manager for timing events.

        Yields:
            Timer object with duration property after context exits
        """
        timer = Timer()
        timer.start()
        try:
            yield timer
        finally:
            timer.stop()

    def set_round(self, round_number: int):
        """Set the current round number.

        Args:
            round_number: Current investigation round (0-indexed)
        """
        self._round_number = round_number
        self._llm_call_seq = 0  # Reset sequence for new round

    def log_session_start(self, user_question: str, config: dict):
        """Log session start event.

        Args:
            user_question: The user's investigation question
            config: Configuration snapshot (sensitive values will be redacted)
        """
        self._session_start_time = perf_counter()

        # Redact sensitive config values
        config_snapshot = self._redact_config(config)

        event = {
            "event_type": EventType.SESSION_START.value,
            "timestamp": self._current_timestamp(),
            "session_id": self._session_id,
            "user_question": user_question,
            "config_snapshot": config_snapshot,
        }
        self._write_event(event)

    def _redact_config(self, config: dict) -> dict:
        """Redact sensitive values from config.

        Args:
            config: Original config dictionary

        Returns:
            Config with sensitive values redacted
        """
        redacted = {}
        for key, value in config.items():
            if isinstance(value, dict):
                redacted[key] = self._redact_config(value)
            elif key.lower() in ("password", "api_key", "secret", "token"):
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = value
        return redacted

    def close(self, outcome: str, final_answer: Optional[str] = None):
        """Log session end and close the log file.

        Args:
            outcome: Session outcome ("complete", "unanswerable", "forced_complete", "error")
            final_answer: Final answer if outcome is "complete"
        """
        if self._closed:
            return

        total_duration = 0.0
        if self._session_start_time is not None:
            total_duration = perf_counter() - self._session_start_time

        event = {
            "event_type": EventType.SESSION_END.value,
            "timestamp": self._current_timestamp(),
            "outcome": outcome,
            "final_answer": final_answer,
            "total_rounds": self._round_number + 1,
            "total_llm_calls": self._total_llm_calls,
            "total_sql_queries": self._total_sql_queries,
            "total_prompt_tokens": self._total_prompt_tokens,
            "total_completion_tokens": self._total_completion_tokens,
            "total_duration": total_duration,
            "sql_errors": self._sql_errors,
        }
        self._write_event(event)

        self._closed = True
        if self._file is not None:
            try:
                self._file.close()
            except Exception:
                pass

    def log_discovery(
        self,
        hosts: list,
        rule_tags: list,
        duration: float,
    ):
        """Log discovery event.

        Args:
            hosts: List of discovered hosts
            rule_tags: List of discovered rule tags
            duration: Time taken for discovery
        """
        event = {
            "event_type": EventType.DISCOVERY.value,
            "timestamp": self._current_timestamp(),
            "round_number": self._round_number,
            "duration": duration,
            "hosts_count": len(hosts),
            "rule_tags_count": len(rule_tags),
            "hosts": hosts,
            "rule_tags": rule_tags,
        }
        self._write_event(event)

    def log_llm_call(
        self,
        call_type: str,
        prompt_full: str,
        raw_response: str,
        parsed_response: Any,
        response_json: dict,
        duration: float,
        parent_id: Optional[str] = None,
    ) -> str:
        """Log an LLM call event.

        Args:
            call_type: Type of call ("plan", "repair", "synthesize")
            prompt_full: Full prompt text
            raw_response: Raw LLM response content
            parsed_response: Parsed response object
            response_json: Full response JSON from vLLM
            duration: Time taken for the call
            parent_id: For repair calls, the parent query ID

        Returns:
            call_id: Unique identifier for this call
        """
        self._llm_call_seq += 1
        call_id = f"{self._round_number}_{call_type}_{self._llm_call_seq}"

        # Extract token usage from response
        usage = response_json.get("usage", {})
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)

        # Update aggregated statistics
        self._total_llm_calls += 1
        self._total_prompt_tokens += prompt_tokens
        self._total_completion_tokens += completion_tokens

        # Get finish reason
        choices = response_json.get("choices", [{}])
        finish_reason = choices[0].get("finish_reason") if choices else None

        # Get model info
        model_name = response_json.get("model", "unknown")

        event = {
            "event_type": EventType.LLM_CALL.value,
            "timestamp": self._current_timestamp(),
            "round_number": self._round_number,
            "duration": duration,
            "call_id": call_id,
            "call_type": call_type,
            "parent_id": parent_id,
            "prompt": prompt_full,
            "raw_response": raw_response,
            "parsed_response": parsed_response,
            "finish_reason": finish_reason,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "model_name": model_name,
        }
        self._write_event(event)

        return call_id

    def log_sql_query(
        self,
        query_id: int,
        purpose: str,
        sql_original: str,
        sql_executed: str,
        success: bool,
        duration: float,
        row_count: Optional[int] = None,
        columns: Optional[list] = None,
        rows: Optional[list] = None,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
        is_repair_attempt: bool = False,
        repair_attempt_number: int = 0,
        parent_query_id: Optional[int] = None,
    ):
        """Log a SQL query execution event.

        Args:
            query_id: Query identifier
            purpose: Purpose of the query
            sql_original: Original SQL before transformations
            sql_executed: SQL after transformations (now() replacement, SETTINGS)
            success: Whether the query succeeded
            duration: Time taken for execution
            row_count: Number of rows returned (if successful)
            columns: Column names (if successful)
            rows: Result rows (if successful)
            error_code: Error code (if failed)
            error_message: Error message (if failed)
            is_repair_attempt: Whether this is a repair attempt
            repair_attempt_number: Which repair attempt (1, 2, ...)
            parent_query_id: Original query ID for repair attempts
        """
        self._total_sql_queries += 1

        if not success and error_message:
            self._sql_errors.append(
                {
                    "query_id": query_id,
                    "round_number": self._round_number,
                    "purpose": purpose,
                    "sql": sql_executed,
                    "error_message": error_message,
                    "error_code": error_code,
                    "is_repair_attempt": is_repair_attempt,
                    "repair_attempt_number": repair_attempt_number,
                }
            )

        event = {
            "event_type": EventType.SQL_QUERY.value,
            "timestamp": self._current_timestamp(),
            "round_number": self._round_number,
            "duration": duration,
            "query_id": query_id,
            "purpose": purpose,
            "sql_original": sql_original,
            "sql_executed": sql_executed,
            "success": success,
            "row_count": row_count,
            "columns": columns,
            "rows": rows,
            "error_code": error_code,
            "error_message": error_message,
            "is_repair_attempt": is_repair_attempt,
            "repair_attempt_number": repair_attempt_number,
            "parent_query_id": parent_query_id,
        }
        self._write_event(event)

    def log_round_start(
        self,
        planned_queries: list,
        strategy: str,
    ):
        """Log the start of an investigation round.

        Args:
            planned_queries: List of planned queries for this round
            strategy: Investigation strategy
        """
        event = {
            "event_type": EventType.ROUND_START.value,
            "timestamp": self._current_timestamp(),
            "round_number": self._round_number,
            "planned_query_count": len(planned_queries),
            "planned_queries": [
                {"purpose": q.purpose, "sql": q.sql} for q in planned_queries
            ],
            "strategy": strategy,
        }
        self._write_event(event)

    def log_round_end(
        self,
        queries_executed: int,
        decision: str,
        duration: float,
    ):
        """Log the end of an investigation round.

        Args:
            queries_executed: Number of queries executed this round
            decision: Decision made (COMPLETE, CONTINUE, etc.)
            duration: Duration of the round
        """
        event = {
            "event_type": EventType.ROUND_END.value,
            "timestamp": self._current_timestamp(),
            "round_number": self._round_number,
            "duration": duration,
            "queries_executed": queries_executed,
            "decision": decision,
        }
        self._write_event(event)

    def log_error(
        self,
        exception: Exception,
        context: Optional[str] = None,
    ):
        """Log an error event.

        Args:
            exception: The exception that occurred
            context: Additional context about where the error occurred
        """
        event = {
            "event_type": EventType.ERROR.value,
            "timestamp": self._current_timestamp(),
            "round_number": self._round_number,
            "error_type": type(exception).__name__,
            "error_message": str(exception),
            "context": context,
        }
        self._write_event(event)

    def get_session_id(self) -> str:
        """Get the session ID.

        Returns:
            Session identifier string
        """
        return self._session_id

    def get_total_duration(self) -> float:
        """Get the total session duration in seconds.

        Returns:
            Duration in seconds, or 0.0 if session hasn't started
        """
        if self._session_start_time is None:
            return 0.0
        return perf_counter() - self._session_start_time

    def get_total_rounds(self) -> int:
        """Get the total number of investigation rounds.

        Returns:
            Number of rounds (1-indexed)
        """
        return self._round_number + 1

    def get_total_prompt_tokens(self) -> int:
        """Get the total number of prompt tokens used.

        Returns:
            Total prompt tokens
        """
        return self._total_prompt_tokens

    def get_total_completion_tokens(self) -> int:
        """Get the total number of completion tokens used.

        Returns:
            Total completion tokens
        """
        return self._total_completion_tokens

    def get_log_file_path(self) -> Optional[str]:
        """Get the log file path.

        Returns:
            Absolute path to log file, or None if logging is disabled or file is not open
        """
        if self._file is not None and hasattr(self._file, "name"):
            return str(Path(self._file.name).absolute())
        return None


class NullSessionLogger(SessionLogger):
    """A no-op session logger for when logging is disabled."""

    def __init__(self):
        """Initialize without any file operations."""
        self._enabled = False
        self._closed = False
        self._round_number = 0
        self._llm_call_seq = 0
        self._session_id = ""
        self._session_start_time = None
        self._total_prompt_tokens = 0
        self._total_completion_tokens = 0

    def _write_event(self, event: dict):
        """No-op write."""
        pass

    def log_session_start(self, user_question: str, config: dict):
        """No-op."""
        pass

    def close(self, outcome: str, final_answer: Optional[str] = None):
        """No-op."""
        pass

    def log_discovery(self, hosts: list, rule_tags: list, duration: float):
        """No-op."""
        pass

    def log_llm_call(
        self,
        call_type: str,
        prompt_full: str,
        raw_response: str,
        parsed_response: Any,
        response_json: dict,
        duration: float,
        parent_id: Optional[str] = None,
    ) -> str:
        """No-op, returns empty call_id."""
        return ""

    def log_sql_query(
        self,
        query_id: int,
        purpose: str,
        sql_original: str,
        sql_executed: str,
        success: bool,
        duration: float,
        **kwargs,
    ):
        """No-op."""
        pass

    def log_round_start(self, planned_queries: list, strategy: str):
        """No-op."""
        pass

    def log_round_end(self, queries_executed: int, decision: str, duration: float):
        """No-op."""
        pass

    def log_error(self, exception: Exception, context: Optional[str] = None):
        """No-op."""
        pass

    def get_session_id(self) -> str:
        """Get the session ID."""
        return self._session_id

    def get_total_duration(self) -> float:
        """Get the total session duration."""
        return 0.0

    def get_total_rounds(self) -> int:
        """Get the total number of investigation rounds."""
        return self._round_number + 1

    def get_total_prompt_tokens(self) -> int:
        """Get the total number of prompt tokens used."""
        return self._total_prompt_tokens

    def get_total_completion_tokens(self) -> int:
        """Get the total number of completion tokens used."""
        return self._total_completion_tokens

    def get_log_file_path(self) -> Optional[str]:
        """Get the log file path."""
        return None


def create_session_logger(config: dict, session_id: str) -> SessionLogger:
    """Factory function to create a session logger.

    Args:
        config: Configuration dictionary
        session_id: Unique session identifier

    Returns:
        SessionLogger if logging is enabled, NullSessionLogger otherwise
    """
    logging_config = config.get("logging", {})
    if logging_config.get("enabled", True):
        return SessionLogger(config, session_id)
    return NullSessionLogger()
