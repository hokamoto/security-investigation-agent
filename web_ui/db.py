"""
Database operations for job queue management.

All operations use proper SQLite transactions for atomicity.
"""

import logging
import sqlite3
import uuid
from datetime import datetime, UTC
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Any

from .config import CONFIG

logger = logging.getLogger(__name__)


def init_db() -> None:
    """
    Initialize the database schema.

    Creates tables and indexes if they don't exist.
    Safe to call multiple times (idempotent).
    """
    db_path = CONFIG['db_path']
    logger.info(f"Initializing database at {db_path}")

    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                question TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                result_path TEXT,
                error_message TEXT,
                CHECK (status IN ('pending', 'running', 'completed', 'failed'))
            );

            CREATE INDEX IF NOT EXISTS idx_jobs_status_created
                ON jobs(status, created_at);

            CREATE INDEX IF NOT EXISTS idx_jobs_completed_at
                ON jobs(completed_at) WHERE completed_at IS NOT NULL;

            CREATE TABLE IF NOT EXISTS available_hosts (
                host TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS available_hosts_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)
        conn.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise
    finally:
        conn.close()


def _get_available_hosts_meta(conn: sqlite3.Connection, key: str) -> Optional[str]:
    cursor = conn.execute("SELECT value FROM available_hosts_meta WHERE key = ?", (key,))
    row = cursor.fetchone()
    return row[0] if row else None


def _set_available_hosts_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("""
        INSERT INTO available_hosts_meta (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    """, (key, value))


def replace_available_hosts(hosts: List[str], updated_at: str) -> None:
    """
    Replace available hosts list and update metadata.

    Args:
        hosts: List of available host strings.
        updated_at: ISO timestamp for when the data was fetched.
    """
    conn = get_db()
    try:
        with conn:
            conn.execute("DELETE FROM available_hosts")
            conn.executemany(
                "INSERT INTO available_hosts (host, updated_at) VALUES (?, ?)",
                [(host, updated_at) for host in hosts],
            )
            _set_available_hosts_meta(conn, "last_updated", updated_at)
            _set_available_hosts_meta(conn, "last_error", "")
            _set_available_hosts_meta(conn, "last_error_at", "")
    finally:
        conn.close()


def set_available_hosts_error(error_message: str, error_at: str) -> None:
    """
    Record an available hosts refresh error without replacing data.

    Args:
        error_message: Error string.
        error_at: ISO timestamp for when the error occurred.
    """
    conn = get_db()
    try:
        with conn:
            _set_available_hosts_meta(conn, "last_error", error_message)
            _set_available_hosts_meta(conn, "last_error_at", error_at)
    finally:
        conn.close()


def get_available_hosts() -> Dict[str, Any]:
    """
    Fetch available hosts list and metadata.

    Returns:
        Dict with hosts, last_updated, last_error, last_error_at.
    """
    conn = get_db()
    try:
        cursor = conn.execute("SELECT host FROM available_hosts ORDER BY host ASC")
        hosts = [row[0] for row in cursor.fetchall()]
        last_updated = _get_available_hosts_meta(conn, "last_updated")
        last_error = _get_available_hosts_meta(conn, "last_error")
        last_error_at = _get_available_hosts_meta(conn, "last_error_at")
        return {
            "hosts": hosts,
            "last_updated": last_updated,
            "last_error": last_error,
            "last_error_at": last_error_at,
        }
    finally:
        conn.close()


def get_db() -> sqlite3.Connection:
    """
    Get a database connection.

    Returns:
        SQLite connection with Row factory for dict-like access.
    """
    conn = sqlite3.connect(CONFIG['db_path'])
    conn.row_factory = sqlite3.Row
    return conn


def create_job(question: str) -> str:
    """
    Create a new job in pending state.

    Args:
        question: User's security question.

    Returns:
        Job ID (UUID).
    """
    job_id = str(uuid.uuid4())
    created_at = datetime.now(UTC).isoformat().replace('+00:00', 'Z')

    logger.info(f"Creating job {job_id}")

    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO jobs (id, question, status, created_at)
            VALUES (?, ?, 'pending', ?)
        """, (job_id, question, created_at))
        conn.commit()
        logger.info(f"Job {job_id} created in database")
    except Exception as e:
        logger.error(f"Failed to create job {job_id}: {e}")
        raise
    finally:
        conn.close()

    return job_id


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    """
    Get job by ID.

    Args:
        job_id: Job UUID.

    Returns:
        Job dict or None if not found.
    """
    conn = get_db()
    try:
        cursor = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_jobs(limit: int = 50) -> List[Dict[str, Any]]:
    """
    List recent jobs (newest first).

    Args:
        limit: Maximum number of jobs to return.

    Returns:
        List of job dicts.
    """
    conn = get_db()
    try:
        cursor = conn.execute("""
            SELECT * FROM jobs
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def count_pending_jobs() -> int:
    """
    Count jobs in pending state.

    Returns:
        Number of pending jobs.
    """
    conn = get_db()
    try:
        cursor = conn.execute("SELECT COUNT(*) FROM jobs WHERE status = 'pending'")
        return cursor.fetchone()[0]
    finally:
        conn.close()


def claim_next_pending_job() -> Optional[Tuple[str, str]]:
    """
    Atomically claim the next pending job.

    This is the critical operation for worker concurrency.
    Uses a transaction to ensure only one worker claims each job.

    Returns:
        (job_id, question) tuple or None if no pending jobs.
    """
    conn = get_db()
    try:
        with conn:  # Transaction context
            cursor = conn.execute("""
                SELECT id, question FROM jobs
                WHERE status = 'pending'
                ORDER BY created_at ASC
                LIMIT 1
            """)
            row = cursor.fetchone()

            if row:
                job_id = row['id']
                started_at = datetime.now(UTC).isoformat().replace('+00:00', 'Z')

                # Atomic update with status check (prevent race conditions)
                conn.execute("""
                    UPDATE jobs
                    SET status = 'running',
                        started_at = ?
                    WHERE id = ? AND status = 'pending'
                """, (started_at, job_id))

                return (job_id, row['question'])

        return None
    finally:
        conn.close()


def mark_completed(job_id: str, result_path: str) -> None:
    """
    Mark job as completed.

    Args:
        job_id: Job UUID.
        result_path: Path to output.json file.
    """
    completed_at = datetime.now(UTC).isoformat().replace('+00:00', 'Z')

    conn = get_db()
    try:
        conn.execute("""
            UPDATE jobs
            SET status = 'completed',
                completed_at = ?,
                result_path = ?
            WHERE id = ?
        """, (completed_at, result_path, job_id))
        conn.commit()
    finally:
        conn.close()


def mark_failed(job_id: str, error_message: str) -> None:
    """
    Mark job as failed.

    Args:
        job_id: Job UUID.
        error_message: Error description.
    """
    completed_at = datetime.now(UTC).isoformat().replace('+00:00', 'Z')

    conn = get_db()
    try:
        conn.execute("""
            UPDATE jobs
            SET status = 'failed',
                completed_at = ?,
                error_message = ?
            WHERE id = ?
        """, (completed_at, error_message, job_id))
        conn.commit()
    finally:
        conn.close()


def delete_job(job_id: str) -> bool:
    """
    Delete job from database.

    Args:
        job_id: Job UUID.

    Returns:
        True if job was deleted, False if not found.
    """
    conn = get_db()
    try:
        cursor = conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def recover_stale_jobs() -> int:
    """
    Reset running jobs older than timeout.

    This is called on worker startup to recover from crashes.

    Returns:
        Number of jobs recovered.
    """
    timeout_seconds = CONFIG['job_timeout_seconds']

    conn = get_db()
    try:
        cursor = conn.execute("""
            UPDATE jobs
            SET status = 'pending',
                started_at = NULL
            WHERE status = 'running'
              AND datetime(started_at) < datetime('now', '-' || ? || ' seconds')
        """, (timeout_seconds,))
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def get_pending_position(job_id: str) -> Optional[int]:
    """
    Get queue position for a pending job.

    Args:
        job_id: Job UUID.

    Returns:
        Queue position (1-indexed) or None if not pending.
    """
    conn = get_db()
    try:
        cursor = conn.execute("""
            WITH ranked AS (
                SELECT id, ROW_NUMBER() OVER (ORDER BY created_at ASC) as position
                FROM jobs
                WHERE status = 'pending'
            )
            SELECT position FROM ranked WHERE id = ?
        """, (job_id,))
        row = cursor.fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def cleanup_old_jobs() -> int:
    """
    Delete completed/failed jobs older than retention period.

    Also deletes associated result files.

    Returns:
        Number of jobs deleted.
    """
    import shutil

    retention_hours = CONFIG['job_retention_hours']

    conn = get_db()
    try:
        # Find old jobs with result paths
        cursor = conn.execute("""
            SELECT id, result_path FROM jobs
            WHERE status IN ('completed', 'failed')
              AND datetime(completed_at) < datetime('now', '-' || ? || ' hours')
        """, (retention_hours,))

        jobs_to_delete = cursor.fetchall()

        # Delete result files
        for row in jobs_to_delete:
            result_path = row['result_path']
            if result_path:
                result_dir = Path(result_path).parent
                if result_dir.exists():
                    try:
                        shutil.rmtree(result_dir)
                    except Exception:
                        pass  # Best-effort cleanup

        # Delete job records
        if jobs_to_delete:
            job_ids = [row['id'] for row in jobs_to_delete]
            placeholders = ','.join('?' * len(job_ids))
            conn.execute(f"DELETE FROM jobs WHERE id IN ({placeholders})", job_ids)
            conn.commit()

        return len(jobs_to_delete)
    finally:
        conn.close()
