"""Single application launcher for Bug Bounty AI - Local Research Workspace.

Starts the FastAPI server, serves the compiled React single-origin UI,
and opens http://127.0.0.1:8000 automatically in the browser.
"""

import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import webbrowser

HOST = "127.0.0.1"
PORT = 8000
URL = f"http://{HOST}:{PORT}"


def verify_frontend_build() -> None:
    """Ensure compiled React bundle exists; run build if missing."""
    repo_root = Path(__file__).resolve().parent
    dist_index = repo_root / "frontend" / "dist" / "index.html"

    if not dist_index.exists():
        print("[Launcher] Compiled frontend bundle not found. Building with npm...")
        frontend_dir = repo_root / "frontend"
        try:
            npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
            subprocess.run([npm_cmd, "run", "build"], cwd=str(frontend_dir), check=True)
            print("[Launcher] Frontend build complete.")
        except Exception as exc:
            print(f"[Launcher] Warning: Automated frontend build failed ({exc}). Using secure fallback template.")


def open_browser_delayed(url: str, delay: float = 1.0) -> None:
    """Open the browser once the server has booted."""
    time.sleep(delay)
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main() -> None:
    verify_frontend_build()

    from src.database.manager import DatabaseManager
    from src.dashboard.app import create_dashboard_app
    import uvicorn

    db = DatabaseManager()
    user_count = db.user_count()

    admin_user = os.environ.get("ULTRON_ADMIN_USERNAME")
    admin_pass = os.environ.get("ULTRON_ADMIN_PASSWORD")

    # Safe initial bootstrap if environment variables are provided and no accounts exist
    if user_count == 0 and admin_user and admin_pass:
        from src.dashboard.auth import hash_password
        db.create_user(
            username=admin_user.strip(),
            password_hash=hash_password(admin_pass),
            role="admin",
            is_active=True,
        )
        print(f"[Launcher] Initial administrator account '{admin_user.strip()}' provisioned from environment.")
        user_count = db.user_count()

    print("=" * 60)
    if user_count == 0:
        print("LOCAL ULTRON - RESEARCH WORKSPACE [BOOTSTRAP REQUIRED]")
        print("=" * 60)
        print("Status: Authentication is ENABLED, but no user accounts exist.")
        print("Setup needed: Provision an administrator account before logging in:")
        print("  python -m src.dashboard.bootstrap --username <admin>")
        print("  or export ULTRON_ADMIN_USERNAME and ULTRON_ADMIN_PASSWORD")
    else:
        print("LOCAL ULTRON - RESEARCH WORKSPACE")
        print("=" * 60)
        print(f"Status: Authentication ENABLED ({user_count} account(s) registered).")
        print("Application ready:")

    print()
    print(URL)
    print()
    print("Press Ctrl+C to stop.")
    print("=" * 60)

    # Spawn background thread to open browser
    opener = threading.Thread(target=open_browser_delayed, args=(URL, 1.2), daemon=True)
    opener.start()

    app = create_dashboard_app(db_manager=db, require_auth=True)
    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":
    main()
