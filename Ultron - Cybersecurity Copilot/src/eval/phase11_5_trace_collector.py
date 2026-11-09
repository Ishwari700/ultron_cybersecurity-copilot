"""Milestone M2 Phase 11.5: Label-Free Raw Interaction Trace Collector.

Captures exactly one frozen, label-free raw interaction trace per scenario
across all 84 scenarios in data/benchmarks/m1_5_frozen_manifest.json.

Strict Guarantees:
- Zero ground-truth leakage (no designation, ground_truth_vulnerable, gold category, gold parameter, scorer label)
- Zero secret leakage (credentials typed-quarantined/redacted: SECRET_LEAK_COUNT = 0)
- Canonical JSON formatting and deterministic trace hashing
"""

import copy
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Set, Tuple

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.eval.scenarios import get_gold_set_scenarios, EvaluationScenario
from src.eval.synthetic_app import SyntheticApp


# Forbidden Ground-Truth & Evaluator Verdict Keys
FORBIDDEN_GT_KEYS: Set[str] = {
    "ground_truth_vulnerable",
    "vulnerable_variant",
    "designation",
    "category",
    "category_id",
    "gold_category",
    "gold_parameter",
    "scorer_label",
    "expected_decision",
    "hidden_label",
    "is_vulnerable",
    "vulnerability_category",
    "ground_truth",
}

# Suspicious Secret Patterns
SECRET_VALUE_PATTERNS = [
    re.compile(r"token_[a-z0-9_]+", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    re.compile(r"Bearer\s+(?!\[REDACTED\])[A-Za-z0-9_\-\.]+", re.IGNORECASE),
]


def audit_for_forbidden_keys(obj: Any, path: str = "") -> List[str]:
    """Recursively checks if any forbidden ground-truth key exists in obj."""
    violations = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            current_path = f"{path}.{k}" if path else str(k)
            if k in FORBIDDEN_GT_KEYS:
                violations.append(f"Forbidden key '{k}' found at {current_path}")
            violations.extend(audit_for_forbidden_keys(v, current_path))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            violations.extend(audit_for_forbidden_keys(item, f"{path}[{idx}]"))
    return violations


def audit_for_secrets(obj: Any, path: str = "") -> List[str]:
    """Recursively scans all string values for unredacted secrets."""
    leaks = []
    if isinstance(obj, str):
        for pat in SECRET_VALUE_PATTERNS:
            match = pat.search(obj)
            if match:
                leaks.append(f"Secret matched pattern '{pat.pattern}' in string at {path}: '{match.group(0)}'")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            current_path = f"{path}.{k}" if path else str(k)
            leaks.extend(audit_for_secrets(v, current_path))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            leaks.extend(audit_for_secrets(item, f"{path}[{idx}]"))
    return leaks


def canonical_json_bytes(data: Any) -> bytes:
    """Canonical JSON serialization per Section 16."""
    return json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def generate_trace_for_scenario(scenario: EvaluationScenario) -> Dict[str, Any]:
    """
    Simulates interaction on SyntheticApp and returns a strictly label-free trace.
    """
    app = SyntheticApp(scenario.app_family, vulnerable_variant=scenario.vulnerable_variant)
    asset = scenario.target_asset
    raw_path = asset.get("raw_path") or asset.get("normalized_path")
    http_method = asset.get("method", "GET")

    # 1. Determine resource, owner, tenant, and state before
    if "/invoices/" in raw_path:
        resource_id = raw_path.split("/")[-1]
        inv = app.invoices.get(resource_id, {})
        resource_owner = inv.get("owner", "user_a" if "100" in resource_id else "user_b")
        resource_tenant = inv.get("tenant", "org_a" if "100" in resource_id else "org_b")
        state_before = inv.get("status", "ISSUED")
    elif "/subscriptions/" in raw_path:
        resource_id = raw_path.split("/")[-1]
        sub = app.subscriptions.get(resource_id, {})
        resource_owner = sub.get("owner", "user_a" if "100" in resource_id else "user_b")
        resource_tenant = sub.get("tenant", "org_a" if "100" in resource_id else "org_b")
        state_before = sub.get("status", "ACTIVE")
    elif "/orders/" in raw_path:
        parts = raw_path.split("/")
        resource_id = parts[4] if len(parts) > 4 else "ORD-001"
        ord_obj = app.orders.get(resource_id, {})
        resource_owner = ord_obj.get("owner", "user_a")
        resource_tenant = "org_a"
        state_before = ord_obj.get("state", "CREATED")
    elif "/users/" in raw_path:
        parts = raw_path.split("/")
        resource_id = parts[4] if len(parts) > 4 else "user_a"
        resource_owner = resource_id
        resource_tenant = "org_a" if resource_id == "user_a" else "org_b"
        state_before = "ACTIVE"
    elif "/docs/" in raw_path:
        parts = raw_path.split("/")
        resource_id = parts[4] if len(parts) > 4 else "DOC-100"
        doc = app.documents.get(resource_id, {})
        resource_owner = doc.get("owner", "user_a" if "100" in resource_id else "user_b")
        resource_tenant = doc.get("tenant", "org_a" if "100" in resource_id else "org_b")
        state_before = "ACTIVE"
    elif "/approvals/" in raw_path:
        parts = raw_path.split("/")
        resource_id = parts[4] if len(parts) > 4 else "APP-100"
        appr = app.approvals.get(resource_id, {})
        resource_owner = appr.get("owner", "user_a")
        resource_tenant = "org_a"
        state_before = appr.get("state", "DRAFT")
    elif "/records/" in raw_path or "/prescriptions/" in raw_path:
        resource_id = raw_path.split("/")[-1]
        resource_owner = "user_a"
        resource_tenant = "org_a"
        state_before = "ACTIVE"
    elif "/devices/" in raw_path:
        parts = raw_path.split("/")
        resource_id = parts[4] if len(parts) > 4 else "DEV-100"
        dev = app.devices.get(resource_id, {})
        resource_owner = dev.get("owner", "user_a" if "100" in resource_id else "user_b")
        resource_tenant = "org_a" if resource_owner == "user_a" else "org_b"
        state_before = dev.get("status", "ONLINE")
    else:
        resource_id = "PUBLIC_CATALOG"
        resource_owner = "SYSTEM"
        resource_tenant = "PUBLIC"
        state_before = "ACTIVE"

    # 2. Caller determination
    is_public = any(
        p in raw_path
        for p in [
            "openid-configuration",
            "/jwks",
            "/pricing",
            "/catalog",
            "/products",
            "/templates",
            "/clinic-hours",
            "/status",
        ]
    )
    if is_public:
        requester_id = "anonymous"
        requester_role = "unauthenticated"
        requester_tenant = "public"
        req_headers = {}
        status_code, body = app.handle_request(http_method, raw_path)
    else:
        requester_id = "user_b" if resource_owner == "user_a" else "user_a"
        requester_role = "customer"
        requester_tenant = "org_b" if requester_id == "user_b" else "org_a"
        token = app.users[requester_id]["token"]
        # Actual live request executed with internal mock token
        status_code, body = app.handle_request(
            http_method,
            raw_path,
            headers={"Authorization": f"Bearer {token}"},
        )
        # Stored headers are strictly REDACTED
        req_headers = {"Authorization": "Bearer [REDACTED]"}

    # 3. State after transition
    if "/orders/" in raw_path:
        state_after = app.orders.get(resource_id, {}).get("state", state_before)
    elif "/approvals/" in raw_path:
        state_after = app.approvals.get(resource_id, {}).get("state", state_before)
    else:
        state_after = state_before

    # 4. Parameters sanitation (observable fields only)
    sanitized_parameters = []
    for p in scenario.parameters:
        clean_p = {
            "param_id": p.get("param_id", "PARAM-01"),
            "name": p.get("name", ""),
            "location": p.get("location", "path"),
            "value": p.get("value", ""),
        }
        sanitized_parameters.append(clean_p)

    trace_dict = {
        "scenario_id": scenario.scenario_id,
        "interaction_id": "INT-01",
        "requester_identity": requester_id,
        "requester_role": requester_role,
        "requester_tenant": requester_tenant,
        "route": raw_path,
        "method": http_method,
        "parameters": sanitized_parameters,
        "request_headers": req_headers,
        "response_status": status_code,
        "response_headers": {"Content-Type": "application/json"},
        "response_body": body,
        "observed_resource": resource_id,
        "observed_owner": resource_owner,
        "observed_tenant": resource_tenant,
        "observed_state_transition": {
            "state_before": state_before,
            "state_after": state_after,
        },
        "source_fact_ids": ["FACT-OBSERVED-INTERACTION-01"],
        "trace_timestamp": "2026-09-18T17:45:00.000Z",
        "sequence_metadata": {"probe_index": 1},
    }

    # Strict assertion against forbidden keys
    violations = audit_for_forbidden_keys(trace_dict)
    if violations:
        raise AssertionError(f"Ground-truth leakage in trace for {scenario.scenario_id}: {violations}")

    # Strict assertion against secrets
    leaks = audit_for_secrets(trace_dict)
    if leaks:
        raise AssertionError(f"Secret leakage in trace for {scenario.scenario_id}: {leaks}")

    return trace_dict


def collect_and_freeze_all_traces(
    output_dir: Path = Path("data/experiments/phase11_5_raw_traces"),
) -> Tuple[Dict[str, str], str]:
    """
    Collects raw traces for all 84 official benchmark scenarios,
    writes them to output_dir, and computes the deterministic trace-set hash.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    scenarios = get_gold_set_scenarios()
    assert len(scenarios) == 84, f"Expected 84 scenarios, got {len(scenarios)}"

    individual_hashes: Dict[str, str] = {}
    total_forbidden_violations = 0
    total_secret_leaks = 0

    print(f"Collecting raw traces for {len(scenarios)} scenarios...")
    for idx, sc in enumerate(scenarios):
        trace = generate_trace_for_scenario(sc)
        sid = sc.scenario_id

        # Verify audits
        violations = audit_for_forbidden_keys(trace)
        if violations:
            total_forbidden_violations += len(violations)
            print(f"ERROR: Forbidden keys in {sid}: {violations}")

        leaks = audit_for_secrets(trace)
        if leaks:
            total_secret_leaks += len(leaks)
            print(f"ERROR: Secret leaks in {sid}: {leaks}")

        # Canonical bytes and individual SHA-256
        c_bytes = canonical_json_bytes(trace)
        trace_hash = hashlib.sha256(c_bytes).hexdigest()
        individual_hashes[sid] = trace_hash

        # Write formatted JSON file
        out_file = output_dir / f"{sid}.json"
        out_file.write_text(json.dumps(trace, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")

    if total_forbidden_violations > 0:
        raise AssertionError(f"HARD STOP: {total_forbidden_violations} ground-truth violations found in traces!")
    if total_secret_leaks > 0:
        raise AssertionError(f"HARD STOP: {total_secret_leaks} secret leaks found in traces!")

    # Cumulative deterministic trace set SHA-256 over ordered scenario IDs
    ordered_items = [{"scenario_id": sid, "trace_hash": individual_hashes[sid]} for sid in [s.scenario_id for s in scenarios]]
    trace_set_sha = hashlib.sha256(canonical_json_bytes(ordered_items)).hexdigest()

    print(f"All 84 traces collected successfully.")
    print(f"TRACE_SET_SHA256: {trace_set_sha}")
    print(f"SECRET_LEAK_COUNT: 0")
    print(f"NO_GROUND_TRUTH_LEAKAGE: TRUE")

    return individual_hashes, trace_set_sha


if __name__ == "__main__":
    collect_and_freeze_all_traces()
