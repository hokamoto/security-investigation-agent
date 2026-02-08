"""
Bottle web application for SIEM Agent frontend.

Routes:
- GET /              - Home page with job list and submit form
- POST /jobs         - Submit new job
- GET /jobs/<id>     - Job detail page
- POST /jobs/<id>/delete - Delete job
"""

import json
import logging
import shutil
import traceback
from pathlib import Path
from typing import Dict, Any, Optional

from bottle import Bottle, request, response, redirect, abort, template, TEMPLATE_PATH, TEMPLATES, HTTPResponse

from .config import CONFIG
from .db import (
    create_job,
    get_job,
    list_jobs,
    count_pending_jobs,
    delete_job,
    get_pending_position,
    get_available_hosts,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configure template path
TEMPLATE_PATH.insert(0, str(Path(__file__).parent / 'templates'))

# Clear template cache to ensure changes are loaded
TEMPLATES.clear()

# Create Bottle app
app = Bottle()

# Force UTF-8 decoding for incoming form data.
@app.hook('before_request')
def force_request_utf8():
    request.charset = 'utf-8'

# Set default encoding for responses
@app.hook('after_request')
def enable_utf8():
    """Set UTF-8 encoding for all responses."""
    if response.content_type.startswith('text/'):
        if 'charset' not in response.content_type:
            response.content_type += '; charset=utf-8'


def load_job_result(result_path: str) -> Optional[Dict[str, Any]]:
    """
    Load JSON result from file.

    Args:
        result_path: Path to output.json.

    Returns:
        Parsed JSON dict or None if file doesn't exist.
    """
    try:
        with open(result_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def has_pending_or_running_jobs(jobs: list) -> bool:
    """
    Check if any jobs are pending or running.

    Args:
        jobs: List of job dicts.

    Returns:
        True if auto-refresh should be enabled.
    """
    return any(job['status'] in ('pending', 'running') for job in jobs)


@app.route('/')
def index():
    """
    Home page with job submission form and recent jobs list.
    """
    jobs = list_jobs(limit=50)
    needs_refresh = has_pending_or_running_jobs(jobs)
    available_hosts_data = get_available_hosts()

    # Add refresh meta tag if needed
    head_extra = ''
    if needs_refresh:
        head_extra = '<meta http-equiv="refresh" content="10">'

    return template(
        'index',
        jobs=jobs,
        head_extra=head_extra,
        available_hosts=available_hosts_data.get("hosts", []),
        available_hosts_last_updated=available_hosts_data.get("last_updated"),
        available_hosts_last_error=available_hosts_data.get("last_error"),
        available_hosts_last_error_at=available_hosts_data.get("last_error_at"),
    )


@app.route('/jobs', method='POST')
def submit_job():
    """
    Submit a new job.

    Form data:
        question: User's security question

    Returns:
        303 redirect to job detail page on success.
        400 if question is empty.
        429 if queue is full.
    """
    try:
        question = request.forms.getunicode('question', '').strip()
        logger.info(f"Received job submission: {question[:100]}")

        # Validate question
        if not question:
            logger.warning("Job submission rejected: empty question")
            abort(400, "Question is required")

        # Check queue limit
        pending_count = count_pending_jobs()
        logger.info(f"Current pending jobs: {pending_count}/{CONFIG['max_pending_jobs']}")

        if pending_count >= CONFIG['max_pending_jobs']:
            logger.warning("Job submission rejected: queue full")
            abort(429, "Too many pending jobs. Please try again later.")

        # Create job
        job_id = create_job(question)
        logger.info(f"Job created successfully: {job_id}")

        return redirect(f'/jobs/{job_id}', code=303)

    except HTTPResponse:
        raise  # Re-raise redirect/abort responses
    except Exception as e:
        logger.error(f"Error creating job: {str(e)}")
        logger.error(traceback.format_exc())
        abort(500, f"Internal server error: {str(e)}")


@app.route('/jobs/<job_id>')
def job_detail(job_id):
    """
    Job detail page.

    Shows status, results, and appropriate content based on job state.
    """
    job = get_job(job_id)
    if not job:
        abort(404, "Job not found")

    status = job['status']
    head_extra = ''
    result_data = None
    queue_position = None

    # Auto-refresh for pending/running jobs
    if status in ('pending', 'running'):
        head_extra = '<meta http-equiv="refresh" content="5">'

        if status == 'pending':
            queue_position = get_pending_position(job_id)

    # Load result for completed jobs
    if status == 'completed' and job['result_path']:
        result_data = load_job_result(job['result_path'])

    return template(
        'job_detail',
        job=job,
        result_data=result_data,
        queue_position=queue_position,
        head_extra=head_extra,
    )


@app.route('/jobs/<job_id>/delete', method='POST')
def delete_job_route(job_id):
    """
    Delete a job and its result files.

    Returns:
        303 redirect to home page on success.
        404 if job not found.
        409 if job is running.
    """
    try:
        job = get_job(job_id)
        if not job:
            abort(404, "Job not found")

        if job['status'] == 'running':
            abort(409, "Cannot delete running job")

        # Delete result files
        if job['result_path']:
            result_dir = Path(job['result_path']).parent
            if result_dir.exists():
                try:
                    shutil.rmtree(result_dir)
                except Exception as e:
                    logger.warning(f"Failed to delete result files for job {job_id}: {e}")

        # Delete job record
        delete_job(job_id)
        logger.info(f"Job deleted: {job_id}")

        return redirect('/', code=303)

    except HTTPResponse:
        raise  # Re-raise redirect/abort responses
    except Exception as e:
        logger.error(f"Error deleting job {job_id}: {str(e)}")
        logger.error(traceback.format_exc())
        abort(500, f"Internal server error: {str(e)}")


# Error handlers
@app.error(400)
def error400(err):
    message = str(err.body) if err.body else "Bad request"
    return template('error', code=400, message=message, title="Bad Request")


@app.error(404)
def error404(err):
    message = str(err.body) if err.body else "The requested page was not found"
    return template('error', code=404, message=message, title="Not Found")


@app.error(409)
def error409(err):
    message = str(err.body) if err.body else "Conflict"
    return template('error', code=409, message=message, title="Conflict")


@app.error(429)
def error429(err):
    message = str(err.body) if err.body else "Too many requests"
    return template('error', code=429, message=message, title="Too Many Requests")


@app.error(500)
def error500(err):
    logger.error(f"500 error: {err}")
    if hasattr(err, 'traceback'):
        logger.error(err.traceback)
    message = str(err.body) if err.body else "Internal server error"
    return template('error', code=500, message=message, title="Error")
