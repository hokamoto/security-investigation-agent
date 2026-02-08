"""Logging and prompt-sanitization helpers."""

from __future__ import annotations

import json
import os
from typing import Any

ANSI_COLORS = {
    "reset": "\x1b[0m",
    "blue": "\x1b[34m",
    "green": "\x1b[32m",
    "cyan": "\x1b[36m",
    "red": "\x1b[31m",
}

SYSTEM_PROMPT_START = "You work as an AI assistant that helps with security investigation of Web Application Firewall (WAF) and corresponding CDN logs."
SQL_REQUIREMENTS_START = "SQL Query Requirements:"


def colorize(text: str, color: str) -> str:
    if os.getenv("NO_COLOR"):
        return text
    return f"{ANSI_COLORS[color]}{text}{ANSI_COLORS['reset']}"


def _replace_block(text: str, start: str, end_markers: list[str], replacement: str, include_end: bool) -> str:
    while True:
        start_idx = text.find(start)
        if start_idx == -1:
            return text
        end_idx = -1
        end_marker = None
        for marker in end_markers:
            idx = text.find(marker, start_idx + len(start))
            if idx != -1 and (end_idx == -1 or idx < end_idx):
                end_idx = idx
                end_marker = marker
        if end_idx == -1:
            return text
        if include_end:
            end_idx += len(end_marker)
        text = text[:start_idx] + replacement + text[end_idx:]


def sanitize_prompt_text(text: str) -> str:
    text = _replace_block(
        text,
        SYSTEM_PROMPT_START,
        [SQL_REQUIREMENTS_START],
        "<SystemPrompt()>\n\n",
        include_end=False,
    )
    text = _replace_block(
        text,
        SQL_REQUIREMENTS_START,
        [
            "## Available Hosts",
            "## Task",
            "## Step 1",
            "User Question:",
        ],
        "<SqlRequirements()>\n\n",
        include_end=False,
    )
    text = _replace_block(
        text,
        "## Databases",
        ["## Key Concepts of Akamai WAF and CDN"],
        "<DatabaseSchema()>\n\n",
        include_end=False,
    )
    return text


def json_dumps_readable(obj: Any) -> str:
    """Convert object to JSON string with actual newlines for readability."""
    return json.dumps(obj, ensure_ascii=False, indent=2).replace("\\n", "\n")
