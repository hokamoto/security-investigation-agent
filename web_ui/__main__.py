"""
Entry point for SIEM Web Frontend.

Usage:
    uv run -m web_ui
"""

from .app import app
from .config import CONFIG
from .db import init_db


def main():
    """
    Start the web server.
    """
    # Initialize database
    init_db()

    # Ensure results directory exists
    CONFIG['results_dir'].mkdir(parents=True, exist_ok=True)

    print("SIEM Web Frontend starting...")
    print(f"Database: {CONFIG['db_path']}")
    print(f"Results: {CONFIG['results_dir']}")
    print(f"URL: http://{CONFIG['host']}:{CONFIG['port']}/")
    print()

    # Start server
    app.run(
        host=CONFIG['host'],
        port=CONFIG['port'],
        debug=False,  # Enable debug mode (disables template cache, shows detailed errors)
        reloader=False,  # Disable auto-reload (causes double process)
    )


if __name__ == "__main__":
    main()
