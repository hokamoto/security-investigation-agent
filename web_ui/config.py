"""
Configuration loading for SIEM Web Frontend.

All configuration is loaded from environment variables with sensible defaults.
"""

import os
from pathlib import Path
from typing import TypedDict


class Config(TypedDict):
    """Configuration dictionary type."""

    db_path: Path
    results_dir: Path
    host: str
    port: int
    max_pending_jobs: int
    job_retention_hours: int
    worker_poll_seconds: int
    job_timeout_seconds: int
    available_hosts_refresh_seconds: int
    available_hosts_cli_timeout_seconds: int
    project_root: Path


def get_config() -> Config:
    """
    Load configuration from environment variables.

    Returns:
        Config dictionary with all settings.
    """
    # Get project root (parent of web_ui module)
    project_root = Path(__file__).parent.parent

    return Config(
        db_path=Path(os.getenv("SIEM_WEB_DB_PATH", "./data/jobs.db")),
        results_dir=Path(os.getenv("SIEM_WEB_RESULTS_DIR", "./data/results")),
        host=os.getenv("SIEM_WEB_HOST", "0.0.0.0"),
        port=int(os.getenv("SIEM_WEB_PORT", "8080")),
        max_pending_jobs=int(os.getenv("SIEM_WEB_MAX_PENDING_JOBS", "10")),
        job_retention_hours=int(os.getenv("SIEM_WEB_JOB_RETENTION_HOURS", "72")),
        worker_poll_seconds=int(os.getenv("SIEM_WEB_WORKER_POLL_SECONDS", "5")),
        job_timeout_seconds=int(os.getenv("SIEM_WEB_JOB_TIMEOUT_SECONDS", "900")),
        available_hosts_refresh_seconds=int(os.getenv("SIEM_WEB_AVAILABLE_HOSTS_REFRESH_SECONDS", "300")),
        available_hosts_cli_timeout_seconds=int(os.getenv("SIEM_WEB_AVAILABLE_HOSTS_CLI_TIMEOUT_SECONDS", "60")),
        project_root=project_root,
    )


# Global config instance
CONFIG = get_config()
