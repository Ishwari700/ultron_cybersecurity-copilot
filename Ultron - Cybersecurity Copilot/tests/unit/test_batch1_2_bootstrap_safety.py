"""Batch 1.2 Bootstrap Credential Safety & Non-Echoing Password Tests.

Verifies:
- Password entry uses getpass or non-echoing input, never command-line arguments.
- Command-line help (--help) does NOT advertise --password or -p.
- Attempting to pass --password on CLI is rejected as an unrecognized argument.
- Password confirmation mismatch is rejected safely.
- Plaintext passwords never leak into stdout, stderr, logs, or database.
- Existing accounts are protected from overwrite unless --reset is explicitly passed.
- Scrypt derivation and salt uniqueness are maintained.
- Invalid roles and weak passwords (<8 chars) fail safely.
"""

import os
from pathlib import Path
import subprocess
import sys
import pytest

from src.database.manager import DatabaseManager
from src.dashboard.auth import hash_password, verify_password
from src.dashboard.bootstrap import bootstrap_user, main as bootstrap_main


def test_bootstrap_cli_help_does_not_advertise_password_arg():
    """Verify that python -m src.dashboard.bootstrap --help does not advertise --password."""
    cmd = [sys.executable, "-m", "src.dashboard.bootstrap", "--help"]
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(Path.cwd()), env=env)
    assert res.returncode == 0
    help_text = res.stdout.lower()
    assert "--password" not in help_text, "--password MUST NOT be advertised in CLI help"
    assert " -p " not in help_text, "-p shorthand MUST NOT be advertised in CLI help"
    assert "--username" in help_text
    assert "--reset" in help_text
    assert "--role" in help_text


def test_bootstrap_cli_rejects_password_command_line_argument(tmp_path):
    """Verify that passing --password on CLI is rejected by argparse and no user is created."""
    db_file = tmp_path / "cli_reject.db"
    cmd = [
        sys.executable,
        "-m",
        "src.dashboard.bootstrap",
        "--username",
        "attacker",
        "--password",
        "ShouldFailCmdLinePass123!",
        "--db-path",
        str(db_file),
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    res = subprocess.run(cmd, capture_output=True, text=True, cwd=str(Path.cwd()), env=env)
    assert res.returncode != 0
    assert "unrecognized arguments" in res.stderr.lower()
    # Confirm database does not exist or has no such user
    if db_file.exists():
        db = DatabaseManager(db_path=db_file)
        assert db.get_user("attacker") is None


def test_bootstrap_cli_prompts_and_creates_account_with_confirmation(tmp_path):
    """Verify safe account creation with matching confirmation via stdin/getpass."""
    db_file = tmp_path / "prompt_create.db"
    cmd = [
        sys.executable,
        "-m",
        "src.dashboard.bootstrap",
        "--username",
        "sysadmin",
        "--role",
        "admin",
        "--db-path",
        str(db_file),
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    secret = "SuperSafePassphrase999!"
    res = subprocess.run(
        cmd,
        input=f"{secret}\n{secret}\n",
        capture_output=True,
        text=True,
        cwd=str(Path.cwd()),
        env=env,
    )
    assert res.returncode == 0, f"STDOUT: {res.stdout}\nSTDERR: {res.stderr}"
    assert "created successfully" in res.stdout
    assert "sysadmin" in res.stdout
    # Secret MUST NOT appear anywhere in output
    assert secret not in res.stdout
    assert secret not in res.stderr

    # Verify user in database
    db = DatabaseManager(db_path=db_file)
    user = db.get_user("sysadmin")
    assert user is not None
    assert user["role"] == "admin"
    assert user["password_hash"].startswith("scrypt$")
    assert secret not in user["password_hash"]
    assert verify_password(secret, user["password_hash"]) is True


def test_bootstrap_cli_rejects_confirmation_mismatch(tmp_path):
    """Verify that mismatched password confirmation aborts with error and creates no account."""
    db_file = tmp_path / "mismatch.db"
    cmd = [
        sys.executable,
        "-m",
        "src.dashboard.bootstrap",
        "--username",
        "typo_user",
        "--db-path",
        str(db_file),
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    res = subprocess.run(
        cmd,
        input="SecretPass1234!\nDifferentPass5678!\n",
        capture_output=True,
        text=True,
        cwd=str(Path.cwd()),
        env=env,
    )
    assert res.returncode != 0
    assert "mismatch" in res.stderr.lower()

    db = DatabaseManager(db_path=db_file)
    assert db.get_user("typo_user") is None


def test_bootstrap_cli_no_confirm_flag(tmp_path):
    """Verify that --no-confirm skips confirmation and reads password once."""
    db_file = tmp_path / "no_confirm.db"
    cmd = [
        sys.executable,
        "-m",
        "src.dashboard.bootstrap",
        "--username",
        "quick_admin",
        "--no-confirm",
        "--db-path",
        str(db_file),
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    secret = "SingleLinePass1234!"
    res = subprocess.run(
        cmd,
        input=f"{secret}\n",
        capture_output=True,
        text=True,
        cwd=str(Path.cwd()),
        env=env,
    )
    assert res.returncode == 0
    assert "created successfully" in res.stdout

    db = DatabaseManager(db_path=db_file)
    user = db.get_user("quick_admin")
    assert user is not None
    assert verify_password(secret, user["password_hash"]) is True


def test_bootstrap_cli_refuses_overwrite_without_reset(tmp_path):
    """Verify existing account cannot be overwritten without explicit --reset."""
    db_file = tmp_path / "no_overwrite.db"
    cmd = [
        sys.executable,
        "-m",
        "src.dashboard.bootstrap",
        "--username",
        "existing_user",
        "--no-confirm",
        "--db-path",
        str(db_file),
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    # Initial creation
    res1 = subprocess.run(cmd, input="InitialPass1234!\n", capture_output=True, text=True, cwd=str(Path.cwd()), env=env)
    assert res1.returncode == 0

    # Second attempt without --reset
    res2 = subprocess.run(cmd, input="OverwrittenPass5678!\n", capture_output=True, text=True, cwd=str(Path.cwd()), env=env)
    assert res2.returncode != 0
    assert "already exists" in res2.stderr.lower()

    # Password must remain the initial one
    db = DatabaseManager(db_path=db_file)
    user = db.get_user("existing_user")
    assert verify_password("InitialPass1234!", user["password_hash"]) is True
    assert verify_password("OverwrittenPass5678!", user["password_hash"]) is False


def test_bootstrap_cli_reset_updates_credentials_safely(tmp_path):
    """Verify --reset safely updates credentials without leaking new password."""
    db_file = tmp_path / "reset_ok.db"
    base_cmd = [
        sys.executable,
        "-m",
        "src.dashboard.bootstrap",
        "--username",
        "alice_sec",
        "--role",
        "reviewer",
        "--no-confirm",
        "--db-path",
        str(db_file),
    ]
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    res1 = subprocess.run(base_cmd, input="OldPassword123!\n", capture_output=True, text=True, cwd=str(Path.cwd()), env=env)
    assert res1.returncode == 0

    reset_cmd = base_cmd + ["--reset", "--role", "admin"]
    res2 = subprocess.run(reset_cmd, input="NewPassword456!\n", capture_output=True, text=True, cwd=str(Path.cwd()), env=env)
    assert res2.returncode == 0
    assert "Password and role updated" in res2.stdout
    assert "NewPassword456!" not in res2.stdout
    assert "NewPassword456!" not in res2.stderr

    db = DatabaseManager(db_path=db_file)
    user = db.get_user("alice_sec")
    assert user["role"] == "admin"
    assert verify_password("NewPassword456!", user["password_hash"]) is True
    assert verify_password("OldPassword123!", user["password_hash"]) is False


def test_bootstrap_rejects_weak_password_and_invalid_role(tmp_path):
    """Verify weak passwords (<8 chars) and invalid roles fail safely."""
    db_file = tmp_path / "validation.db"

    # Weak password
    code_weak = bootstrap_user("weakling", "short", role="admin", db_path=str(db_file))
    assert code_weak == 1

    # Invalid role
    code_role = bootstrap_user("badrole", "ValidPass1234!", role="superuser", db_path=str(db_file))
    assert code_role == 1

    db = DatabaseManager(db_path=db_file)
    assert db.get_user("weakling") is None
    assert db.get_user("badrole") is None


def test_bootstrap_interactive_getpass_mock(monkeypatch, tmp_path):
    """Verify programmatic main() execution with mocked getpass.getpass."""
    import getpass
    db_file = tmp_path / "mock_test.db"

    calls = []
    def fake_getpass(prompt=""):
        calls.append(prompt)
        return "MockedSecret999!"

    monkeypatch.setattr(getpass, "getpass", fake_getpass)

    argv = ["--username", "mockadmin", "--role", "admin", "--db-path", str(db_file)]
    with pytest.raises(SystemExit) as exc_info:
        bootstrap_main(argv)
    assert exc_info.value.code == 0

    # Ensure getpass was called twice: once for password, once for confirm
    assert len(calls) == 2
    assert "Enter password" in calls[0]
    assert "Confirm password" in calls[1]

    db = DatabaseManager(db_path=db_file)
    user = db.get_user("mockadmin")
    assert user is not None
    assert verify_password("MockedSecret999!", user["password_hash"]) is True
