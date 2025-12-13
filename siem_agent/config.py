"""
Configuration loading and state definition for SIEM Agent
"""

import yaml
from pathlib import Path
from typing import TypedDict, List, Dict, Any, Literal, Optional
from pydantic import BaseModel, Field, model_validator

# Load configuration from YAML
CONFIG_FILE = Path(__file__).parent.parent / "config.yaml"
with open(CONFIG_FILE, 'r') as f:
    CONFIG = yaml.safe_load(f)

# Load prompts from YAML
PROMPTS_FILE = Path(__file__).parent.parent / "prompts.yaml"
with open(PROMPTS_FILE, 'r') as f:
    PROMPTS = yaml.safe_load(f)

# Pydantic Models for Structured LLM Outputs

class PlannedQuery(BaseModel):
    """Single query inside the LLM-generated investigation plan."""
    query_id: int
    purpose: str
    sql: str
    table: Literal["waf", "cdn", "both"]
    expected_result_type: str


class InvestigationPlan(BaseModel):
    """Structured plan produced by LLM before execution starts."""
    rationale: str
    queries: List[PlannedQuery]
    is_answerable: bool
    unanswerable_reason: str = ""
    estimated_complexity: Literal["simple", "moderate", "complex"]

    @model_validator(mode="after")
    def validate_queries(self) -> "InvestigationPlan":
        """Ensure answerable plans include between 1 and 10 queries."""
        if self.is_answerable and not self.queries:
            raise ValueError("Answerable plans must include at least one query")
        if len(self.queries) > 10:
            raise ValueError("InvestigationPlan supports a maximum of 10 queries")
        return self


class SynthesisResponse(BaseModel):
    """LLM synthesis output that answers the question."""
    answer: str
    confidence: Literal["high", "medium", "low"]
    data_gaps: List[str] = Field(default_factory=list)


class ReplanDecision(BaseModel):
    """Decision whether additional investigation is needed after synthesis."""
    needs_replanning: bool
    rationale: str
    suggested_next_steps: List[str] = Field(default_factory=list)
    estimated_additional_queries: int = Field(ge=0, le=10, default=0)


class SummaryQuery(BaseModel):
    """A statistical summary query for handling large result sets."""
    purpose: str = Field(description="What insight this summary provides")
    sql: str = Field(description="SQL query for statistical summary")
    query_type: Literal["overview", "aggregation", "samples"] = Field(
        description="Type of summary: overview (statistical), aggregation (patterns), or samples (examples)"
    )


class StatisticalSummaryQueries(BaseModel):
    """Collection of queries that summarize large result sets."""
    rationale: str = Field(description="Why these summaries provide equivalent insight to the original query")
    queries: List[SummaryQuery] = Field(
        description="1-3 summary queries that replace the original oversized query",
        min_length=1,
        max_length=3
    )


# Agent State (Simplified)
class SQLRepairResponse(BaseModel):
    """Response model for SQL repair (validation or execution errors)"""
    sql: str


class AgentState(TypedDict):
    # User input
    user_question: str
    # Database connection
    database_name: str
    siem_log_table_name: str
    cdn_log_table_name: str
    available_hosts: List[str]
    available_rule_tags: List[str]
    # Planning and execution tracking
    investigation_plan: Optional[Dict[str, Any]]
    plan_rationale: str
    is_answerable: bool
    unanswerable_reason: str
    query_execution_history: List[Dict[str, Any]]
    current_query_index: int
    execution_errors: List[str]
    next_node: str
    answer: str  # Final answer when investigation is complete
    # Re-planning tracking
    current_replanning_round: int  # Current re-planning iteration (0 = initial plan)
    max_replanning_rounds: int  # Maximum allowed re-planning rounds
    needs_replanning: bool  # Whether additional investigation is needed
    replan_rationale: str  # Reason for re-planning
    replanning_history: List[Dict[str, Any]]  # History of all planning rounds
    synthesis_confidence: str  # Confidence level from last synthesis
    synthesis_data_gaps: List[str]  # Data gaps from last synthesis
    replan_suggested_steps: List[str]  # Suggested next steps from replan decision
    replan_estimated_queries: int  # Estimated number of additional queries needed
    # Metadata
    total_input_tokens: int  # Total LLM input tokens consumed
    total_output_tokens: int  # Total LLM output tokens consumed
    llm_call_count: int  # Total number of LLM invocations


# Global connections (initialized in main)
client = None  # type: ignore
llm = None     # type: ignore
session_logger = None  # type: ignore
