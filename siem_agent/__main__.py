"""
Entry point for running siem_agent as a module

Usage:
    python -m siem_agent
    uv run -m siem_agent
"""

from .main import main

if __name__ == "__main__":
    main()
