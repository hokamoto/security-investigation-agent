"""
Structured logging utilities for SIEM Agent
"""

import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

# Structured logging setup
LOG_DIR = Path(__file__).parent.parent / "logs"


class StructuredLogger:
    """Markdown-based structured logger for session tracking"""

    def __init__(self, session_dir: Path):
        self.session_dir = session_dir
        self.step_counter = 0

        # Create session directory
        self.session_dir.mkdir(parents=True, exist_ok=True)

    def log(self, level: str, component: str, event: str, data: Optional[Dict[str, Any]] = None, elapsed_time: Optional[float] = None):
        """Write structured log entry as a Markdown file"""
        self.step_counter += 1

        # Create filename with sequential numbering
        filename = f"{self.step_counter:02d}_{event}.md"
        filepath = self.session_dir / filename

        # Build Markdown content
        timestamp = datetime.now().isoformat()
        md_content = f"# {event}\n\n"
        md_content += f"**Timestamp:** {timestamp}  \n"
        md_content += f"**Level:** {level}  \n"
        md_content += f"**Component:** {component}  \n"

        if elapsed_time is not None:
            md_content += f"**Elapsed Time:** {elapsed_time:.3f}s  \n"

        md_content += "\n"

        # Add data section if present
        if data:
            # Special handling for reasoning and final_output from llm_invoke
            if 'reasoning' in data or 'final_output' in data:
                if 'reasoning' in data and data['reasoning']:
                    md_content += "## Reasoning\n\n"
                    md_content += f"{data['reasoning']}\n\n"

                if 'final_output' in data:
                    md_content += "## Final Output\n\n"
                    md_content += f"{data['final_output']}\n\n"

                # Process any remaining keys (excluding reasoning and final_output)
                remaining_data = {k: v for k, v in data.items() if k not in ['reasoning', 'final_output']}
                if remaining_data:
                    md_content += "## Additional Data\n\n"
                    for key, value in remaining_data.items():
                        if isinstance(value, dict):
                            md_content += f"### {key}\n\n"
                            for k, v in value.items():
                                # Handle long strings in dict values with code blocks
                                if isinstance(v, str) and len(v) > 100:
                                    md_content += f"#### {k}\n\n```\n{v}\n```\n\n"
                                else:
                                    md_content += f"- **{k}:** `{v}`\n"
                            md_content += "\n"
                        elif isinstance(value, list):
                            md_content += f"### {key}\n\n"
                            for item in value:
                                md_content += f"- {item}\n"
                            md_content += "\n"
                        elif isinstance(value, str) and len(value) > 100:
                            md_content += f"### {key}\n\n```\n{value}\n```\n\n"
                        else:
                            md_content += f"**{key}:** `{value}`  \n"
            else:
                # Standard data formatting for other log types
                md_content += "## Data\n\n"
                for key, value in data.items():
                    # Format the value nicely
                    if isinstance(value, dict):
                        md_content += f"### {key}\n\n"
                        for k, v in value.items():
                            # Handle long strings in dict values with code blocks
                            if isinstance(v, str) and len(v) > 100:
                                md_content += f"#### {k}\n\n```\n{v}\n```\n\n"
                            else:
                                md_content += f"- **{k}:** `{v}`\n"
                        md_content += "\n"
                    elif isinstance(value, list):
                        md_content += f"### {key}\n\n"
                        for item in value:
                            md_content += f"- {item}\n"
                        md_content += "\n"
                    elif isinstance(value, str) and len(value) > 100:
                        # Long strings get code blocks
                        md_content += f"### {key}\n\n```\n{value}\n```\n\n"
                    else:
                        md_content += f"**{key}:** `{value}`  \n"

        # Write to file
        with open(filepath, 'w') as f:
            f.write(md_content)
