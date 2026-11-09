"""Operator CLI Bootstrap Tool for Ultron Dashboard Accounts.

Usage:
  python -m src.dashboard.bootstrap --username <username> [--role admin|reviewer|observer] [--reset] [--no-confirm]

Ensures:
- Safe password entry via getpass without echoing or command-line exposure
- Safe confirmation prompt to prevent typing mistakes
- Initial administrator provisioning without shipping default passwords
- Safe password reset for account recovery
- Passwords are encrypted with scrypt and never displayed or stored in plaintext
- Overwrites prevented unless --reset is explicitly passed
"""

import argparse
import getpass
from pathlib import Path
import sys
from typing import Optional

from src.database.manager import DatabaseManager
from src.dashboard.auth import hash_password, verify_password


def prompt_password(prompt: str = "Enter password: ") -> str:
    """Securely prompt for password without echoing."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    try:
        # Check if getpass has been mocked or replaced in testing
        if getpass.getpass.__module__ != "getpass" or getpass.getpass.__name__ != "win_getpass":
            return getpass.getpass(prompt)
    except Exception:
        pass
    # Piped or redirected input (CI, test automation, scripts)
    line = sys.stdin.readline()
    if not line:
        return ""
    return line.rstrip("\r\n")


def bootstrap_user(
    username: str,
    password: str,
    role: str = "admin",
    reset_if_exists: bool = False,
    db_path: str = "data/evidence.db",
) -> int:
    """Core programmatic provisioning logic.
    
    Accepts password directly for internal callers, test suites, or CLI handler.
    Hashes via scrypt and stores in database.
    """
    clean_user = username.strip().lower()
    clean_role = role.strip().lower()
    if clean_role not in ("admin", "reviewer", "observer"):
        print(f"[Error] Invalid role '{role}'. Allowed: admin, reviewer, observer", file=sys.stderr)
        return 1

    if not password or len(password) < 8:
        print("[Error] Password must be at least 8 characters long.", file=sys.stderr)
        return 1

    try:
        db = DatabaseManager(db_path=Path(db_path))
        db.initialize_schema()
    except Exception as e:
        print(f"[Error] Database initialization failed: {e}", file=sys.stderr)
        return 1

    try:
        existing = db.get_user(clean_user)
        hashed = hash_password(password)

        if existing:
            if not reset_if_exists:
                print(f"[Error] User '{clean_user}' already exists with role '{existing['role']}'. Use --reset to update password.", file=sys.stderr)
                return 1
            db.update_user_password(clean_user, hashed)
            db.update_user_role(clean_user, clean_role)
            db.set_user_active(clean_user, True)
            print(f"[Success] Password and role updated for user '{clean_user}' (role: {clean_role}).")
            return 0

        db.create_user(clean_user, hashed, role=clean_role, is_active=True)
        print(f"[Success] User '{clean_user}' created successfully with role '{clean_role}'.")
        return 0
    except Exception as e:
        print(f"[Error] Failed to store user account: {e}", file=sys.stderr)
        return 1


def main(argv: Optional[list] = None) -> None:
    parser = argparse.ArgumentParser(description="Bootstrap or reset Ultron dashboard accounts.")
    parser.add_argument("--username", "-u", required=True, help="Username to create or reset")
    parser.add_argument("--role", "-r", default="admin", choices=["admin", "reviewer", "observer"], help="Role to assign (default: admin)")
    parser.add_argument("--reset", action="store_true", help="Reset password and role if user already exists")
    parser.add_argument("--no-confirm", action="store_true", help="Skip confirmation prompt for password")
    parser.add_argument("--db-path", default="data/evidence.db", help="Path to evidence.db SQLite database")

    args = parser.parse_args(argv)

    # Securely prompt for password
    password = prompt_password("Enter password: ")
    if not password:
        print("[Error] Password cannot be empty.", file=sys.stderr)
        sys.exit(1)

    if not args.no_confirm:
        confirm = prompt_password("Confirm password: ")
        if password != confirm:
            print("[Error] Password confirmation mismatch. Passwords do not match.", file=sys.stderr)
            sys.exit(1)

    code = bootstrap_user(
        username=args.username,
        password=password,
        role=args.role,
        reset_if_exists=args.reset,
        db_path=args.db_path,
    )
    sys.exit(code)


if __name__ == "__main__":
    main()
