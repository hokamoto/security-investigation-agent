#!/usr/bin/env python3
"""
Session Log Viewer Web Application.

A Bottle-based web application for viewing SIEM Agent session logs.

Usage:
    python app.py [--port 8080] [--logs-dir ../logs]
"""

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from bottle import Bottle, request, response, abort

app = Bottle()

# Global configuration
LOGS_DIR = Path("../logs")


def load_events(log_file: Path) -> list[dict[str, Any]]:
    """Load and parse JSONL log file."""
    events = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def extract_metadata(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract session metadata from session_start event."""
    for event in events:
        if event.get("event_type") == "session_start":
            data = event.get("data", {})
            return {
                "session_id": data.get("session_id", "Unknown"),
                "user_question": data.get("user_question", "N/A"),
                "timestamp": event.get("timestamp", "N/A"),
            }
    return {"session_id": "Unknown", "user_question": "N/A", "timestamp": "N/A"}


def extract_summary(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Extract summary statistics from session_end event."""
    for event in events:
        if event.get("event_type") == "session_end":
            data = event.get("data", {})
            return {
                "outcome": data.get("outcome", "N/A"),
                "total_rounds": data.get("total_rounds", 0),
                "total_llm_calls": data.get("total_llm_calls", 0),
                "total_sql_queries": data.get("total_sql_queries", 0),
                "total_prompt_tokens": data.get("total_prompt_tokens", 0),
                "total_completion_tokens": data.get("total_completion_tokens", 0),
                "total_duration": data.get("total_duration", 0),
                "final_answer": data.get("final_answer"),
            }
    return None


def truncate_large_field(value: Any, max_chars: int = 100000) -> tuple[Any, bool]:
    """Truncate large string fields. Returns (value, was_truncated)."""
    if isinstance(value, str) and len(value) > max_chars:
        return value[:max_chars] + f"...\n\n[TRUNCATED - original length: {len(value)} chars]", True
    elif isinstance(value, list) and len(value) > 50:
        return value[:50] + [f"...\n[TRUNCATED - {len(value) - 50} more items]"], True
    return value, False


def prepare_event_data(event: dict[str, Any]) -> dict[str, Any]:
    """Prepare event data for JSON embedding, truncating large fields."""
    data_copy = event.get("data", {}).copy() if event.get("data") else {}

    # Truncate specific large fields
    large_fields = ["prompt", "raw_response", "rows"]
    for field in large_fields:
        if field in data_copy:
            data_copy[field], _ = truncate_large_field(data_copy[field])

    return data_copy


def get_css_styles() -> str:
    """Return embedded CSS styles."""
    return """
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        line-height: 1.6;
        color: #333;
        background-color: #f5f5f5;
        padding: 20px;
    }

    .header {
        background: white;
        padding: 20px;
        border-radius: 8px;
        margin-bottom: 20px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .header h1 {
        color: #1a202c;
        margin-bottom: 15px;
        font-size: 24px;
    }

    .header h1 a {
        color: inherit;
        text-decoration: none;
    }

    .header h1 a:hover {
        color: #3b82f6;
    }

    .back-link {
        display: inline-block;
        margin-bottom: 15px;
        color: #3b82f6;
        text-decoration: none;
        font-size: 14px;
    }

    .back-link:hover {
        text-decoration: underline;
    }

    .metadata {
        display: grid;
        gap: 10px;
        font-size: 14px;
    }

    .metadata div {
        padding: 8px;
        background: #f7fafc;
        border-radius: 4px;
    }

    .filters {
        background: white;
        padding: 20px;
        border-radius: 8px;
        margin-bottom: 20px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .filters h2 {
        font-size: 18px;
        margin-bottom: 15px;
        color: #1a202c;
    }

    .filter-section {
        margin-bottom: 15px;
    }

    .filter-section h3 {
        font-size: 14px;
        margin-bottom: 10px;
        color: #4a5568;
    }

    .filter-checkboxes {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
        gap: 8px;
    }

    .filter-checkboxes label {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 13px;
        cursor: pointer;
        padding: 4px 8px;
        border-radius: 4px;
        transition: background 0.2s;
    }

    .filter-checkboxes label:hover {
        background: #f7fafc;
    }

    .filter-checkboxes input[type="checkbox"],
    .filter-radios input[type="radio"] {
        cursor: pointer;
    }

    .filter-radios {
        display: flex;
        gap: 15px;
    }

    .filter-radios label {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 13px;
        cursor: pointer;
    }

    .clear-filters-btn {
        background: #e53e3e;
        color: white;
        border: none;
        padding: 8px 16px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 14px;
        margin-top: 10px;
        transition: background 0.2s;
    }

    .clear-filters-btn:hover {
        background: #c53030;
    }

    .summary {
        background: white;
        padding: 20px;
        border-radius: 8px;
        margin-bottom: 20px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .summary h2 {
        font-size: 18px;
        margin-bottom: 15px;
        color: #1a202c;
    }

    .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 15px;
        margin-bottom: 15px;
    }

    .summary-item {
        padding: 12px;
        background: #f7fafc;
        border-radius: 4px;
    }

    .summary-label {
        font-size: 12px;
        color: #718096;
        margin-bottom: 4px;
    }

    .summary-value {
        font-size: 16px;
        font-weight: 600;
        color: #1a202c;
    }

    .final-answer {
        padding: 12px;
        background: #edf2f7;
        border-left: 4px solid #4299e1;
        border-radius: 4px;
        font-size: 14px;
    }

    .events-container {
        background: white;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        overflow: hidden;
    }

    table {
        width: 100%;
        border-collapse: collapse;
    }

    thead {
        background: #2d3748;
        color: white;
    }

    thead th {
        padding: 12px;
        text-align: left;
        font-size: 13px;
        font-weight: 600;
    }

    tbody tr.event-row {
        border-bottom: 1px solid #e2e8f0;
        cursor: pointer;
        transition: background 0.2s;
    }

    tbody tr.event-row:hover {
        background: #f7fafc;
    }

    tbody td {
        padding: 12px;
        font-size: 13px;
    }

    .event-num {
        color: #718096;
        font-weight: 600;
        width: 60px;
    }

    .event-type-badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 600;
        color: white;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .timestamp {
        color: #4a5568;
        font-size: 14px;
        white-space: nowrap;
    }

    .round-num {
        color: #718096;
        font-weight: 600;
        text-align: center;
    }

    .duration {
        color: #718096;
        font-weight: 600;
        text-align: right;
        white-space: nowrap;
    }

    .message {
        max-width: 500px;
    }

    .expand-icon {
        text-align: center;
        font-size: 14px;
        color: #4a5568;
        width: 40px;
    }

    .details-row {
        display: none;
        background: #f7fafc;
    }

    .details-row.expanded {
        display: table-row;
    }

    .details-cell {
        padding: 20px;
        border-bottom: 1px solid #e2e8f0;
    }

    .details-content {
        background: #1a202c;
        color: #e2e8f0;
        padding: 15px;
        border-radius: 4px;
        overflow-x: auto;
        max-height: 600px;
        overflow-y: auto;
    }

    .details-content pre {
        margin: 0;
        font-size: 12px;
        line-height: 1.5;
        white-space: pre-wrap;
        word-wrap: break-word;
    }

    .hidden {
        display: none !important;
    }

    /* Log list specific styles */
    .log-list {
        background: white;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        overflow: hidden;
    }

    .log-item {
        display: block;
        padding: 16px 20px;
        border-bottom: 1px solid #e2e8f0;
        text-decoration: none;
        color: inherit;
        transition: background 0.2s;
    }

    .log-item:hover {
        background: #f7fafc;
    }

    .log-item:last-child {
        border-bottom: none;
    }

    .log-item-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 8px;
    }

    .log-item-filename {
        font-weight: 600;
        color: #1a202c;
        font-size: 14px;
    }

    .log-item-meta {
        display: flex;
        gap: 15px;
        font-size: 12px;
        color: #718096;
    }

    .log-item-question {
        font-size: 13px;
        color: #4a5568;
        margin-top: 8px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .outcome-badge {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 10px;
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
    }

    .outcome-success {
        background: #c6f6d5;
        color: #22543d;
    }

    .outcome-error {
        background: #fed7d7;
        color: #742a2a;
    }

    .outcome-unknown {
        background: #e2e8f0;
        color: #4a5568;
    }

    .no-logs {
        padding: 40px;
        text-align: center;
        color: #718096;
    }
    """


def get_javascript_code() -> str:
    """Return embedded JavaScript code for viewer page."""
    return r"""
    function renderTable() {
        const tbody = document.getElementById('events-tbody');
        tbody.innerHTML = '';

        allEvents.forEach((event, index) => {
            const eventNum = index + 1;
            const eventType = event.event_type;
            const timestamp = event.timestamp.replace(/\+\d{2}:\d{2}$/, ''); // Remove timezone
            const message = event.message || '';
            const data = event.data || {};
            const roundNum = data.round_number !== undefined ? data.round_number : '';
            const duration = data.duration !== undefined ? data.duration.toFixed(2) + 's' : '';

            // Determine SQL success status
            let sqlSuccess = 'n/a';
            let badgeColor = '';
            if (eventType === 'sql_query') {
                sqlSuccess = data.success ? 'true' : 'false';
                badgeColor = data.success ? '#22c55e' : '#ef4444';
            } else {
                const colorMap = {
                    'session_start': '#3b82f6',
                    'session_end': '#3b82f6',
                    'discovery': '#06b6d4',
                    'llm_call': '#a855f7',
                    'round_start': '#6366f1',
                    'round_end': '#6366f1',
                    'error': '#dc2626'
                };
                badgeColor = colorMap[eventType] || '#718096';
            }

            // Display full message without truncation
            const displayMessage = message;

            // Create main row
            const mainRow = document.createElement('tr');
            mainRow.className = 'event-row';
            mainRow.dataset.eventType = eventType;
            mainRow.dataset.sqlSuccess = sqlSuccess;
            mainRow.dataset.eventIndex = index;
            mainRow.onclick = () => toggleDetails(index);

            mainRow.innerHTML = `
                <td class="event-num">${eventNum}</td>
                <td><span class="event-type-badge" style="background-color: ${badgeColor}">${eventType}</span></td>
                <td class="timestamp">${timestamp}</td>
                <td class="round-num">${roundNum}</td>
                <td class="duration">${duration}</td>
                <td class="message">${escapeHtml(displayMessage)}</td>
                <td class="expand-icon"><span id="icon-${index}">▶</span></td>
            `;

            // Create details row
            const detailsRow = document.createElement('tr');
            detailsRow.className = 'details-row';
            detailsRow.id = `details-${index}`;
            detailsRow.dataset.eventType = eventType;
            detailsRow.dataset.sqlSuccess = sqlSuccess;

            const fullData = {
                event_type: eventType,
                timestamp: timestamp,
                message: message,
                data: data
            };

            detailsRow.innerHTML = `
                <td colspan="7" class="details-cell">
                    <div class="details-content">
                        <pre>${escapeHtml(JSON.stringify(fullData, null, 2))}</pre>
                    </div>
                </td>
            `;

            tbody.appendChild(mainRow);
            tbody.appendChild(detailsRow);
        });

        applyFilters();
    }

    function toggleDetails(index) {
        const detailsRow = document.getElementById(`details-${index}`);
        const icon = document.getElementById(`icon-${index}`);

        if (detailsRow.classList.contains('expanded')) {
            detailsRow.classList.remove('expanded');
            icon.textContent = '▶';
        } else {
            detailsRow.classList.add('expanded');
            icon.textContent = '▼';
        }
    }

    function getSelectedEventTypes() {
        const checkboxes = document.querySelectorAll('.event-type-filter:checked');
        return Array.from(checkboxes).map(cb => cb.value);
    }

    function getSqlFilterState() {
        const selected = document.querySelector('input[name="sql-filter"]:checked');
        return selected ? selected.value : 'all';
    }

    function applyFilters() {
        const selectedEventTypes = getSelectedEventTypes();
        const sqlFilter = getSqlFilterState();

        // Get all rows (both event rows and details rows)
        const allRows = document.querySelectorAll('#events-tbody tr');

        allRows.forEach(row => {
            const eventType = row.dataset.eventType;
            const sqlSuccess = row.dataset.sqlSuccess;

            // Check event type filter
            const eventTypeMatch = selectedEventTypes.length === 0 || selectedEventTypes.includes(eventType);

            // Check SQL filter (only for sql_query events)
            let sqlMatch = true;
            if (eventType === 'sql_query' && sqlFilter !== 'all') {
                sqlMatch = (sqlFilter === 'success' && sqlSuccess === 'true') ||
                          (sqlFilter === 'failed' && sqlSuccess === 'false');
            }

            // Show or hide row
            if (eventTypeMatch && sqlMatch) {
                row.classList.remove('hidden');
            } else {
                row.classList.add('hidden');
                // If this is a details row, also collapse it
                if (row.classList.contains('details-row')) {
                    row.classList.remove('expanded');
                    const index = row.id.replace('details-', '');
                    const icon = document.getElementById(`icon-${index}`);
                    if (icon) icon.textContent = '▶';
                }
            }
        });
    }

    function clearFilters() {
        // Uncheck all event type checkboxes
        document.querySelectorAll('.event-type-filter').forEach(cb => cb.checked = false);
        // Reset SQL filter to 'all'
        document.getElementById('sql-all').checked = true;
        applyFilters();
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Initialize
    document.addEventListener('DOMContentLoaded', () => {
        renderTable();

        // Add event listeners for filters
        document.querySelectorAll('.event-type-filter').forEach(cb => {
            cb.addEventListener('change', applyFilters);
        });

        document.querySelectorAll('input[name="sql-filter"]').forEach(radio => {
            radio.addEventListener('change', applyFilters);
        });

        document.getElementById('clear-filters-btn').addEventListener('click', clearFilters);
    });
    """


def get_filters_html() -> str:
    """Return filters section HTML."""
    event_types = [
        "session_start",
        "session_end",
        "discovery",
        "llm_call",
        "sql_query",
        "round_start",
        "round_end",
        "error"
    ]

    checkboxes_html = '\n'.join([
        f'<label><input type="checkbox" class="event-type-filter" value="{et}"> {et}</label>'
        for et in event_types
    ])

    return f"""
    <div class="filters">
        <h2>Filters</h2>
        <div class="filter-section">
            <h3>Event Types</h3>
            <div class="filter-checkboxes">
                {checkboxes_html}
            </div>
        </div>
        <div class="filter-section">
            <h3>SQL Query Status</h3>
            <div class="filter-radios">
                <label><input type="radio" name="sql-filter" value="all" id="sql-all" checked> All</label>
                <label><input type="radio" name="sql-filter" value="success"> Success Only</label>
                <label><input type="radio" name="sql-filter" value="failed"> Failed Only</label>
            </div>
        </div>
        <button id="clear-filters-btn" class="clear-filters-btn">Clear All Filters</button>
    </div>
    """


def generate_header_html(metadata: dict[str, Any], show_back_link: bool = False) -> str:
    """Generate header section HTML."""
    back_link = '<a href="/" class="back-link">&larr; Back to Log List</a>' if show_back_link else ''
    return f"""
    <div class="header">
        {back_link}
        <h1><a href="/">Session Log Viewer</a></h1>
        <div class="metadata">
            <div><strong>Session ID:</strong> {metadata['session_id']}</div>
            <div><strong>Timestamp:</strong> {metadata['timestamp']}</div>
            <div><strong>User Question:</strong> {metadata['user_question']}</div>
        </div>
    </div>
    """


def generate_summary_html(summary: dict[str, Any] | None) -> str:
    """Generate summary section HTML."""
    if not summary:
        return '<div class="summary"><p>Session in progress or summary not available</p></div>'

    final_answer = summary.get("final_answer", "")

    return f"""
    <div class="summary">
        <h2>Session Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="summary-label">Outcome</div>
                <div class="summary-value">{summary['outcome']}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Total Rounds</div>
                <div class="summary-value">{summary['total_rounds']}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">LLM Calls</div>
                <div class="summary-value">{summary['total_llm_calls']}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">SQL Queries</div>
                <div class="summary-value">{summary['total_sql_queries']}</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Tokens</div>
                <div class="summary-value">{summary['total_prompt_tokens']} prompt + {summary['total_completion_tokens']} completion</div>
            </div>
            <div class="summary-item">
                <div class="summary-label">Duration</div>
                <div class="summary-value">{summary['total_duration']:.2f}s</div>
            </div>
        </div>
        {f'<div class="final-answer"><strong>Final Answer:</strong> {final_answer}</div>' if final_answer else ''}
    </div>
    """


def get_log_files() -> list[dict[str, Any]]:
    """Get list of log files with metadata."""
    log_files = []

    if not LOGS_DIR.exists():
        return log_files

    for log_path in LOGS_DIR.glob("session_*.jsonl"):
        try:
            stat = log_path.stat()
            file_info = {
                "filename": log_path.name,
                "path": log_path,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "created": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }

            # Extract metadata from log file
            events = load_events(log_path)
            if events:
                metadata = extract_metadata(events)
                summary = extract_summary(events)
                file_info["user_question"] = metadata.get("user_question", "N/A")
                file_info["outcome"] = summary.get("outcome", "In Progress") if summary else "In Progress"
            else:
                file_info["user_question"] = "N/A"
                file_info["outcome"] = "Empty"

            log_files.append(file_info)
        except Exception:
            continue

    # Sort by modification time (newest first)
    log_files.sort(key=lambda x: x["mtime"], reverse=True)

    return log_files


def format_file_size(size: int) -> str:
    """Format file size in human-readable format."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"


def get_outcome_class(outcome: str) -> str:
    """Get CSS class for outcome badge."""
    outcome_lower = outcome.lower()
    if outcome_lower in ("success", "completed"):
        return "outcome-success"
    elif outcome_lower in ("error", "failed"):
        return "outcome-error"
    else:
        return "outcome-unknown"


@app.route("/")
def index():
    """Log file list page."""
    log_files = get_log_files()
    css_styles = get_css_styles()

    if not log_files:
        log_list_html = '<div class="no-logs">No log files found in logs directory.</div>'
    else:
        items_html = []
        for log in log_files:
            outcome_class = get_outcome_class(log["outcome"])
            question_preview = log["user_question"][:100] + "..." if len(log["user_question"]) > 100 else log["user_question"]

            item_html = f"""
            <a href="/view/{log['filename']}" class="log-item">
                <div class="log-item-header">
                    <span class="log-item-filename">{log['filename']}</span>
                    <span class="outcome-badge {outcome_class}">{log['outcome']}</span>
                </div>
                <div class="log-item-meta">
                    <span>{log['created']}</span>
                    <span>{format_file_size(log['size'])}</span>
                </div>
                <div class="log-item-question">{question_preview}</div>
            </a>
            """
            items_html.append(item_html)

        log_list_html = f'<div class="log-list">{"".join(items_html)}</div>'

    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Session Log Viewer</title>
    <style>{css_styles}</style>
</head>
<body>
    <div class="header">
        <h1>Session Log Viewer</h1>
        <div class="metadata">
            <div><strong>Logs Directory:</strong> {LOGS_DIR.resolve()}</div>
            <div><strong>Total Files:</strong> {len(log_files)}</div>
        </div>
    </div>
    {log_list_html}
</body>
</html>
"""
    response.content_type = "text/html; charset=utf-8"
    return html


@app.route("/view/<filename>")
def view_log(filename: str):
    """Log viewer page."""
    # Validate filename to prevent path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        abort(400, "Invalid filename")

    log_path = LOGS_DIR / filename

    if not log_path.exists():
        abort(404, f"Log file not found: {filename}")

    if not log_path.is_file():
        abort(400, "Not a file")

    # Load and process events
    events = load_events(log_path)

    if not events:
        abort(400, "No events found in log file")

    metadata = extract_metadata(events)
    summary = extract_summary(events)

    # Prepare events for JSON embedding
    prepared_events = []
    for event in events:
        prepared_event = {
            "event_type": event.get("event_type"),
            "timestamp": event.get("timestamp"),
            "message": event.get("message", ""),
            "data": prepare_event_data(event)
        }
        prepared_events.append(prepared_event)

    # Generate HTML
    header_html = generate_header_html(metadata, show_back_link=True)
    filters_html = get_filters_html()
    summary_html = generate_summary_html(summary)
    css_styles = get_css_styles()
    javascript_code = get_javascript_code()
    events_json = json.dumps(prepared_events, ensure_ascii=False, indent=2)

    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Session Log Viewer - {metadata['session_id']}</title>
    <style>{css_styles}</style>
</head>
<body>
    {header_html}
    {filters_html}
    {summary_html}

    <div class="events-container">
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Event Type</th>
                    <th>Timestamp</th>
                    <th>Round</th>
                    <th>Duration</th>
                    <th>Message</th>
                    <th></th>
                </tr>
            </thead>
            <tbody id="events-tbody">
            </tbody>
        </table>
    </div>

    <script>
        allEvents = {events_json};
        {javascript_code}
    </script>
</body>
</html>
"""
    response.content_type = "text/html; charset=utf-8"
    return html


def main():
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Session Log Viewer Web Application"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8081,
        help="Port to run the server on (default: 8080)"
    )
    parser.add_argument(
        "--logs-dir",
        type=str,
        default="../logs",
        help="Directory containing log files (default: ../logs)"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)"
    )
    args = parser.parse_args()

    global LOGS_DIR
    LOGS_DIR = Path(args.logs_dir)

    if not LOGS_DIR.exists():
        print(f"Warning: Logs directory does not exist: {LOGS_DIR.resolve()}")

    print(f"Starting Session Log Viewer on http://{args.host}:{args.port}")
    print(f"Logs directory: {LOGS_DIR.resolve()}")

    app.run(host=args.host, port=args.port, debug=False, reloader=False)


if __name__ == "__main__":
    main()
