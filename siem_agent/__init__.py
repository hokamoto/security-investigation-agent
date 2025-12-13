"""
SIEM Agent - LangGraph-based Akamai WAF Log Analyzer

A minimal proof-of-concept agent that autonomously explores and analyzes
Akamai WAF SIEM data stored in ClickHouse using LLM-driven SQL generation.
"""

from .main import main

__version__ = "0.1.0"
__all__ = ["main"]
