import os
from pathlib import Path
import sys

# Ensure repository root is on sys.path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.core.test_integrity import (
    TestPathIntegrityError,
    verify_application_imports,
    verify_test_item_paths,
)


def pytest_collection_modifyitems(session, config, items):
    """Enforces that all collected tests and loaded application modules are from the authorized repo root."""
    try:
        verify_application_imports()
        test_paths = [getattr(item, "fspath", None) or getattr(item, "path", None) for item in items]
        verify_test_item_paths([p for p in test_paths if p is not None])
    except TestPathIntegrityError as exc:
        import pytest
        pytest.exit(f"FATAL TEST PATH INTEGRITY VIOLATION: {exc}", returncode=1)
