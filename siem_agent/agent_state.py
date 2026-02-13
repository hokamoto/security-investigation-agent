"""Agent state container for the BAML-based SIEM Agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List

from siem_agent.clickhouse import ClickHouseClient

if TYPE_CHECKING:
    from siem_agent.session_logger import SessionLogger


@dataclass
class ExecutedQuery:
    """Container for a successfully executed query.

    This tracks only queries that have been executed successfully.
    Failed queries are not stored here.

    Attributes:
        query_id: Global query ID (unique across all rounds)
        sql: The original SQL query without any transformations (no now() replacement, no SETTINGS clause)
        purpose: The reason/purpose for executing this query
        result: The full query result dictionary from execute_query()
                Contains 'columns', 'rows', 'row_count', 'sql', 'success'
        interpretation: Interpretation of the query result (populated after synthesis)
                       Should include <fact> tags for numerical values and IP addresses only
        gaps_identified: Missing information revealed by this query (null if none)
                        Populated after synthesis
    """

    query_id: int
    sql: str
    purpose: str
    result: Dict[str, Any]
    interpretation: str = ""  # Populated after synthesis
    gaps_identified: str | None = None  # Populated after synthesis


@dataclass
class AgentState:
    """Container for agent state that is passed between functions.

    This reduces the number of parameters passed to functions by grouping
    related state into a single object.

    Attributes:
        ch_client: ClickHouse client instance for database operations
        config: Configuration dictionary loaded from config.yaml
        available_hosts: List of discovered host names from database
        available_rule_tags: List of discovered rule tags from database
        session_timestamp: Session timestamp in ISO format (e.g., '2026-01-29T12:00:00Z')
        user_question: The user's security investigation question
        current_replanning_round: Current replanning round number (0-indexed)
        debug: Enable debug output (default: False)
        investigation_strategy: Investigation strategy from initial planning step
        executed_queries: List of successfully executed queries with their results
        synthesis_summary: Cumulative synthesis summary from the previous round (empty for round 0)
        investigation_log: List of round data dicts for the investigation log UI
    """

    ch_client: ClickHouseClient
    config: dict
    available_hosts: List[str]
    available_rule_tags: List[str]
    session_timestamp: str
    user_question: str = ""
    current_replanning_round: int = 0
    debug: bool = False
    investigation_strategy: str = ""
    executed_queries: List[ExecutedQuery] = field(default_factory=list)
    next_query_id: int = 1  # Global query ID counter (continues across rounds)
    synthesis_summary: str = ""  # Cumulative synthesis summary from previous round
    supporting_data: str = ""  # Key data points supporting the final answer
    data_gaps: str = ""  # Facts that couldn't be established due to insufficient data
    investigation_log: List[Dict[str, Any]] = field(default_factory=list)
    original_language: str = "English"  # Detected language of the user's original question
    session_logger: SessionLogger = field(default=None)  # Session logger for structured logging

    @property
    def database_name(self) -> str:
        """Get database name from ClickHouse client."""
        return self.ch_client.database_name

    @property
    def siem_log_table_name(self) -> str:
        """Get SIEM log table name from ClickHouse client."""
        return self.ch_client.siem_log_table_name

    @property
    def cdn_log_table_name(self) -> str:
        """Get CDN log table name from ClickHouse client."""
        return self.ch_client.cdn_log_table_name

    @property
    def max_replanning_rounds(self) -> int:
        """Get max replanning rounds from config."""
        return self.config.get("agent", {}).get("max_replanning_rounds", 3)

    @property
    def max_sql_repair_retries(self) -> int:
        """Get max SQL repair retries from config."""
        return self.config.get("agent", {}).get("max_sql_repair_retries", 2)
