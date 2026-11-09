"""Unit Tests for Workstream A — Test Path & Import Integrity Guard.

Tests:
1. Authoritative repository root resolution.
2. Verified location of core application imports (src.*).
3. Synthetic detection and rejection of foreign test paths.
4. Synthetic detection and rejection of foreign module imports.
5. Explicit allowlist handling (strict, no broad wildcards).
6. Clear diagnostic messages containing offending path and expected root.
"""

from pathlib import Path
import sys
import pytest

from src.core.test_integrity import (
    TestPathIntegrityError,
    get_authorized_repo_root,
    verify_application_imports,
    verify_test_item_paths,
    run_test_path_integrity_check,
)


def test_authoritative_repo_root_resolution():
    """Verify that get_authorized_repo_root resolves to the active checkout directory."""
    root = get_authorized_repo_root()
    assert root.exists(), f"Repo root does not exist: {root}"
    assert (root / "src").exists(), f"src/ not found under repo root: {root}"
    assert (root / "tests").exists(), f"tests/ not found under repo root: {root}"
    assert (root / "pyproject.toml").exists(), f"pyproject.toml not found under: {root}"


def test_core_application_imports_contained_in_authorized_root():
    """Verify that all currently loaded src.* modules resolve within the active checkout."""
    # Ensure critical packages are imported
    import src
    import src.core
    import src.assessment
    import src.dashboard
    import src.scope
    import src.eval

    import_map = verify_application_imports()
    assert len(import_map) > 0, "No application modules were inspected"

    root = get_authorized_repo_root().resolve()
    for mod_name, mod_path in import_map.items():
        assert str(Path(mod_path).resolve()).lower().startswith(str(root).lower()), (
            f"Module '{mod_name}' resolved outside repo root: '{mod_path}'"
        )
        assert "bug bounty ai" not in mod_path.lower(), (
            f"Module '{mod_name}' still references legacy path: '{mod_path}'"
        )


def test_synthetic_foreign_test_path_rejected():
    """Verify that a test originating from an external checkout is detected and rejected."""
    root = get_authorized_repo_root()
    synthetic_foreign_paths = [
        Path("C:/Projects/Bug Bounty AI/tests/unit/test_legacy.py"),
        Path("D:/OtherProject/tests/test_external.py"),
        Path("C:/Users/someone/Desktop/test_rogue.py"),
    ]

    for foreign_p in synthetic_foreign_paths:
        with pytest.raises(TestPathIntegrityError) as exc_info:
            verify_test_item_paths([foreign_p], authorized_root=root)
        err_msg = str(exc_info.value)
        assert "Foreign test collection detected" in err_msg
        assert str(foreign_p.resolve()) in err_msg or str(foreign_p) in err_msg
        assert str(root.resolve()) in err_msg


def test_synthetic_foreign_module_import_rejected(monkeypatch):
    """Verify that an application module pointing to an external path is detected and rejected."""
    root = get_authorized_repo_root()

    class FakeForeignModule:
        __file__ = "C:/Projects/Bug Bounty AI/src/dashboard/app.py"

    monkeypatch.setitem(sys.modules, "src.dashboard.fake_rogue_module", FakeForeignModule())

    with pytest.raises(TestPathIntegrityError) as exc_info:
        verify_application_imports(authorized_root=root)

    err_msg = str(exc_info.value)
    assert "Contaminated module import" in err_msg
    assert "src.dashboard.fake_rogue_module" in err_msg
    assert "Bug Bounty AI" in err_msg or "fake_rogue_module" in err_msg


def test_allowlist_permits_explicit_paths_only():
    """Verify that only explicitly allowlisted paths are tolerated beyond the repo root."""
    root = get_authorized_repo_root()
    foreign_path = Path("C:/ExternalSandbox/test_isolated.py")

    # Without allowlist: must fail
    with pytest.raises(TestPathIntegrityError):
        verify_test_item_paths([foreign_path], authorized_root=root)

    # With explicit allowlist: must pass
    verified = verify_test_item_paths(
        [foreign_path],
        authorized_root=root,
        allowlist=[Path("C:/ExternalSandbox")],
    )
    assert len(verified) == 1
    assert str(foreign_path.resolve()) in verified


def test_run_test_path_integrity_check_end_to_end():
    """Verify that end-to-end check passes cleanly on the active repo and collected items."""
    root = get_authorized_repo_root()
    test_files = list((root / "tests" / "unit").glob("test_*.py"))
    assert len(test_files) > 10

    class MockItem:
        def __init__(self, p):
            self.fspath = p

    mock_items = [MockItem(p) for p in test_files]
    result = run_test_path_integrity_check(items=mock_items)

    assert result["status"] == "PASS"
    assert result["verified_test_items_count"] == len(test_files)
    assert result["verified_modules_count"] > 0


def test_adversarial_sibling_directory_sharing_prefix_rejected():
    """Adversarial Test 2: Sibling directory sharing identical string prefix

    (e.g., '.../Ultron - Cybersecurity Copilot-evil') MUST be rejected.
    """
    root = get_authorized_repo_root()
    sibling_evil_path = Path(str(root) + "-evil") / "tests" / "unit" / "test_evil.py"

    with pytest.raises(TestPathIntegrityError) as exc_info:
        verify_test_item_paths([sibling_evil_path], authorized_root=root)

    err = str(exc_info.value)
    assert "Foreign test collection detected" in err
    assert "-evil" in err


def test_adversarial_parent_directory_traversal_rejected():
    """Adversarial Test 4: Path escaping through '..' MUST be rejected."""
    root = get_authorized_repo_root()
    traversal_path = root / "tests" / ".." / ".." / "external_attack" / "test_pwn.py"

    with pytest.raises(TestPathIntegrityError) as exc_info:
        verify_test_item_paths([traversal_path], authorized_root=root)

    err = str(exc_info.value)
    assert "Foreign test collection detected" in err


def test_windows_casing_and_normalization_containment():
    """Adversarial Test 7: Windows case-insensitive path normalization works correctly,

    while rejecting non-contained paths regardless of casing.
    """
    root = get_authorized_repo_root()
    # Correct path with lowercase drive & path
    mixed_case_valid = Path(str(root).lower()) / "tests" / "unit" / "test_sample.py"
    verified = verify_test_item_paths([mixed_case_valid], authorized_root=root)
    assert len(verified) == 1

    # Evil sibling with lowercase
    mixed_case_evil = Path(str(root).lower() + "-rogue") / "tests" / "unit" / "test_sample.py"
    with pytest.raises(TestPathIntegrityError):
        verify_test_item_paths([mixed_case_evil], authorized_root=root)

