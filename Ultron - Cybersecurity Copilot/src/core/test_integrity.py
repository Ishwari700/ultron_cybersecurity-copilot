"""Test Path and Import Integrity Guard for Ultron.

Ensures that:
1. The repository root resolves authoritatively to the active checkout.
2. Application modules (src.*) import exclusively from the authorized project root.
3. Pytest discovery collects test modules exclusively from authorized repository paths.
4. Foreign repositories (e.g. legacy checkouts, sibling projects) cannot contaminate imports or collection.
"""

from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Union


class TestPathIntegrityError(Exception):
    """Raised when an import or test item resolves to an unauthorized path."""
    __test__ = False



def get_authorized_repo_root() -> Path:
    """Returns the authoritative resolved repository root for Ultron."""
    return Path(__file__).resolve().parent.parent.parent


REPO_ROOT = get_authorized_repo_root()


def is_component_contained(candidate: Union[str, Path], parent: Union[str, Path]) -> bool:
    """Verifies that candidate path is strictly contained within parent directory

    using component-aware path resolution, rejecting sibling directories sharing textual prefixes.
    """
    try:
        cand_p = Path(candidate).resolve()
        parent_p = Path(parent).resolve()

        # Component parts check (case-normalized for Windows compatibility)
        cand_parts = [p.lower() for p in cand_p.parts]
        parent_parts = [p.lower() for p in parent_p.parts]

        if len(cand_parts) < len(parent_parts):
            return False

        if cand_parts[:len(parent_parts)] != parent_parts:
            return False

        # Additional standard pathlib containment check
        try:
            return cand_p.is_relative_to(parent_p)
        except (ValueError, AttributeError):
            return cand_parts[:len(parent_parts)] == parent_parts
    except Exception:
        return False


def verify_application_imports(
    authorized_root: Optional[Path] = None,
    allowlist: Optional[List[Union[str, Path]]] = None,
) -> Dict[str, str]:
    """Verifies that all loaded application modules (src.*) resolve within the authorized root.
    
    Returns a dict mapping module name to resolved file path.
    Raises TestPathIntegrityError if any application module resolves outside the authorized root.
    """
    root = (authorized_root or get_authorized_repo_root()).resolve()
    allowed_dirs = [root / "src"]
    if allowlist:
        for p in allowlist:
            allowed_dirs.append(Path(p).resolve())

    verified: Dict[str, str] = {}
    for mod_name, mod in list(sys.modules.items()):
        if not mod_name.startswith("src") or mod is None:
            continue
        mod_file = getattr(mod, "__file__", None)
        if not mod_file:
            continue

        resolved_file = Path(mod_file).resolve()
        is_allowed = any(
            is_component_contained(resolved_file, d)
            for d in allowed_dirs
        )
        if not is_allowed:
            raise TestPathIntegrityError(
                f"Contaminated module import: '{mod_name}' resolved to '{resolved_file}', "
                f"which is outside authorized root '{root}'"
            )
        verified[mod_name] = str(resolved_file)

    return verified


def verify_test_item_paths(
    test_paths: List[Union[str, Path]],
    authorized_root: Optional[Path] = None,
    allowlist: Optional[List[Union[str, Path]]] = None,
) -> List[str]:
    """Verifies that all collected test paths resolve within the authorized repository root.
    
    Returns list of verified absolute paths.
    Raises TestPathIntegrityError if any collected test item originates outside the authorized root.
    """
    root = (authorized_root or get_authorized_repo_root()).resolve()
    allowed_dirs = [root]
    if allowlist:
        for p in allowlist:
            allowed_dirs.append(Path(p).resolve())

    verified: List[str] = []
    for tp in test_paths:
        resolved_tp = Path(tp).resolve()
        is_allowed = any(
            is_component_contained(resolved_tp, d)
            for d in allowed_dirs
        )
        if not is_allowed:
            raise TestPathIntegrityError(
                f"Foreign test collection detected: '{resolved_tp}' originates outside "
                f"authorized repository root '{root}'"
            )
        verified.append(str(resolved_tp))

    return verified


def run_test_path_integrity_check(
    items: Optional[List[Any]] = None,
    allowlist: Optional[List[Union[str, Path]]] = None,
) -> Dict[str, Any]:
    """Runs end-to-end integrity checks on active application modules and collected pytest items."""
    root = get_authorized_repo_root()
    import_map = verify_application_imports(authorized_root=root, allowlist=allowlist)

    collected_paths: List[Path] = []
    if items:
        for item in items:
            fspath = getattr(item, "fspath", None) or getattr(item, "path", None)
            if fspath:
                collected_paths.append(Path(str(fspath)))
        verify_test_item_paths(collected_paths, authorized_root=root, allowlist=allowlist)

    return {
        "status": "PASS",
        "repo_root": str(root),
        "verified_modules_count": len(import_map),
        "verified_test_items_count": len(collected_paths),
    }
