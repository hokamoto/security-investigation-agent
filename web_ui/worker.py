"""
Worker process for executing SIEM Agent jobs.

This process:
1. Polls the database for pending jobs
2. Claims jobs atomically
3. Executes the CLI via subprocess
4. Saves results and updates job status
5. Handles graceful shutdown
"""

import json
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, UTC
from pathlib import Path

import yaml

from .config import CONFIG
from .db import (
    init_db,
    claim_next_pending_job,
    mark_completed,
    mark_failed,
    recover_stale_jobs,
    cleanup_old_jobs,
    replace_available_hosts,
    set_available_hosts_error,
)
from siem_agent.clickhouse import ClickHouseClient


# Global shutdown flag
shutdown_requested = False


def load_agent_config() -> dict:
    """Load SIEM agent config from project config.yaml."""
    config_path = Path(CONFIG['project_root']) / "config.yaml"
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def signal_handler(signum: int, frame) -> None:
    """
    Handle SIGTERM/SIGINT for graceful shutdown.

    Sets global flag to stop processing new jobs.
    """
    global shutdown_requested
    print(f"\nReceived signal {signum}. Finishing current job then exiting...")
    shutdown_requested = True


def execute_job(job_id: str, question: str) -> None:
    """
    Execute a single job via subprocess.

    Args:
        job_id: Job UUID.
        question: User's security question.
    """
    print(f"[{job_id[:8]}] Starting job: {question[:60]}...")

    # Prepare result directory
    result_dir = CONFIG['results_dir'] / job_id
    result_dir.mkdir(parents=True, exist_ok=True)
    result_path = result_dir / "output.json"
    stdout_path = result_dir / "stdout.txt"
    stderr_path = result_dir / "stderr.txt"

    # Build command. Current SIEM agent writes JSON to stdout when --json is provided.
    cmd = [
        "uv", "run", "-m", "siem_agent",
        "--json",
        question
    ]

    try:
        # Execute with timeout
        process = subprocess.run(
            cmd,
            cwd=str(CONFIG['project_root']),
            capture_output=True,
            encoding='utf-8',
            timeout=CONFIG['job_timeout_seconds'],
        )

        # Save stdout/stderr regardless of exit code
        stdout_path.write_text(process.stdout, encoding='utf-8')
        stderr_path.write_text(process.stderr, encoding='utf-8')

        if process.returncode != 0:
            error_msg = process.stderr or f"Process exited with code {process.returncode}"
            mark_failed(job_id, error_msg[:500])  # Truncate long errors
            print(f"[{job_id[:8]}] Failed: {error_msg[:100]}")
            return

        # Parse JSON output from stdout and persist for UI rendering.
        try:
            result_payload = json.loads(process.stdout)
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse JSON output: {e}"
            mark_failed(job_id, error_msg[:500])
            print(f"[{job_id[:8]}] {error_msg}")
            return

        result_path.write_text(
            json.dumps(result_payload, ensure_ascii=False, indent=2),
            encoding='utf-8',
        )
        mark_completed(job_id, str(result_path))
        print(f"[{job_id[:8]}] Completed successfully")

    except subprocess.TimeoutExpired:
        timeout = CONFIG['job_timeout_seconds']
        error_msg = f"Job timed out after {timeout} seconds"
        mark_failed(job_id, error_msg)
        print(f"[{job_id[:8]}] {error_msg}")

        # Save partial output if exists
        if result_path.exists():
            try:
                stderr_path.write_text(f"TIMEOUT: {error_msg}\n", encoding='utf-8')
            except Exception:
                pass

    except Exception as e:
        error_msg = f"Worker error: {str(e)}"
        mark_failed(job_id, error_msg[:500])
        print(f"[{job_id[:8]}] {error_msg}")


def refresh_available_hosts() -> None:
    """
    Refresh available hosts by querying ClickHouse directly and store in SQLite.
    """
    try:
        agent_config = load_agent_config()
        with ClickHouseClient(config=agent_config) as ch_client:
            hosts, _ = ch_client.discover_hosts_and_tags()

        updated_at = datetime.now(UTC).isoformat().replace('+00:00', 'Z')
        replace_available_hosts(hosts, updated_at)
        print(f"[hosts] Refreshed {len(hosts)} hosts")
    except Exception as e:
        error_msg = f"Available hosts refresh failed: {e}"
        error_at = datetime.now(UTC).isoformat().replace('+00:00', 'Z')
        set_available_hosts_error(error_msg[:300], error_at)
        print(f"[hosts] {error_msg}")


def main_loop() -> None:
    """
    Main worker loop.

    Polls for jobs, executes them, and performs cleanup.
    """
    global shutdown_requested

    print("SIEM Web Worker starting...")
    print(f"Database: {CONFIG['db_path']}")
    print(f"Results: {CONFIG['results_dir']}")
    print(f"Poll interval: {CONFIG['worker_poll_seconds']}s")
    print(f"Job timeout: {CONFIG['job_timeout_seconds']}s")
    print()

    # Initialize database
    init_db()

    # Recover stale jobs from previous crashes
    recovered = recover_stale_jobs()
    if recovered > 0:
        print(f"Recovered {recovered} stale job(s) from previous run\n")

    # Cleanup counter (cleanup every 10 idle cycles)
    cleanup_counter = 0

    def available_hosts_loop() -> None:
        while not shutdown_requested:
            refresh_available_hosts()
            time.sleep(CONFIG['available_hosts_refresh_seconds'])

    hosts_thread = threading.Thread(target=available_hosts_loop, daemon=True)
    hosts_thread.start()

    while not shutdown_requested:
        # Try to claim a job
        job = claim_next_pending_job()

        if job:
            job_id, question = job
            execute_job(job_id, question)
            cleanup_counter = 0  # Reset cleanup counter
        else:
            # No jobs available - cleanup and sleep
            cleanup_counter += 1

            if cleanup_counter >= 10:
                deleted = cleanup_old_jobs()
                if deleted > 0:
                    print(f"Cleaned up {deleted} old job(s)")
                cleanup_counter = 0

            time.sleep(CONFIG['worker_poll_seconds'])

    print("Worker shutdown complete")


def main() -> None:
    """
    Entry point for worker process.
    """
    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        main_loop()
    except Exception as e:
        print(f"FATAL: Worker crashed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
