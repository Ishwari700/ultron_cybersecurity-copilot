"""
Milestone M5 Phase 11.3: Allowed Sets Extraction Engine.

Deterministically extracts bounded allowed fact IDs and allowed target IDs
from scenario structural evidence (Channel A LosslessStructuralPack)
under strict ground-truth firewall constraints.
"""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.eval.scenarios import EvaluationScenario
from src.evidence.cascade_models import LosslessStructuralPack

FACT_ID_REGEX = re.compile(r"^FACT-[A-Za-z0-9_\-]+$")
TARGET_ID_REGEX = re.compile(r"^EP-[A-Za-z0-9_\-]+$")

FORBIDDEN_FIREWALL_PATTERNS = [
    re.compile(r"[\b_\-]vuln[\b_\-]", re.IGNORECASE),
    re.compile(r"[\b_\-]patch[\b_\-]", re.IGNORECASE),
    re.compile(r"\bvulnerable\b", re.IGNORECASE),
    re.compile(r"\bpatched\b", re.IGNORECASE),
    re.compile(r"\bground_truth\b", re.IGNORECASE),
    re.compile(r"\bexpected_decision\b", re.IGNORECASE),
]


class ScenarioAllowedSets(BaseModel):
    """Container for scenario-local deterministic allowed sets."""
    scenario_id: str
    allowed_fact_ids: List[str]
    allowed_target_ids: List[str]
    allowed_fact_ids_hash: str
    allowed_target_ids_hash: str
    count_allowed_facts: int
    count_allowed_targets: int


def assert_firewall_compliance(value: str, context: str) -> None:
    """Verifies that no ground truth or evaluation labels leak into identifiers."""
    for pattern in FORBIDDEN_FIREWALL_PATTERNS:
        if pattern.search(value):
            raise ValueError(
                f"FIREWALL BREACH: Forbidden pattern '{pattern.pattern}' detected in {context}: '{value}'"
            )


def extract_allowed_fact_ids(
    scenario: EvaluationScenario,
    pack: Optional[LosslessStructuralPack] = None,
) -> List[str]:
    r"""
    Deterministically extracts canonical allowed fact IDs from scenario evidence.
    Guarantees:
    - Neutral identifiers only
    - Regex compliance (^FACT-[A-Za-z0-9_\-]+$)
    - Sorted and deduplicated
    - Zero ground-truth leakage
    """
    facts_source = []
    if pack is not None and pack.observed_facts:
        facts_source = pack.observed_facts
    elif scenario.initial_evidence:
        facts_source = scenario.initial_evidence

    fact_ids = set()
    for item in facts_source:
        fid = item.get("fact_id") if isinstance(item, dict) else getattr(item, "fact_id", None)
        if fid:
            assert FACT_ID_REGEX.match(fid), f"Malformed FACT ID: '{fid}'"
            assert_firewall_compliance(fid, "fact_id")
            fact_ids.add(fid)

    if not fact_ids:
        # Default neutral fallback if empty
        fact_ids.add("FACT-00000001")

    return sorted(list(fact_ids))


def extract_allowed_target_ids(
    scenario: EvaluationScenario,
    pack: Optional[LosslessStructuralPack] = None,
) -> List[str]:
    r"""
    Deterministically extracts canonical allowed target identifiers from Channel A structural envelope.
    Guarantees:
    - Endpoint identifier schema (^EP-[A-Za-z0-9_\-]+$)
    - Sorted and deduplicated
    - Zero ground-truth leakage
    """
    target_ids = set()
    if pack is not None and pack.endpoint_id:
        ep_id = pack.endpoint_id
        assert TARGET_ID_REGEX.match(ep_id), f"Malformed Endpoint ID: '{ep_id}'"
        assert_firewall_compliance(ep_id, "endpoint_id")
        target_ids.add(ep_id)
    else:
        asset_id = scenario.target_asset.get("asset_id", f"ASSET-{scenario.scenario_id}")
        # Strip potential scenario specific suffix to ensure firewall isolation
        clean_asset = asset_id.replace("-VULN-", "-").replace("-PATCH-", "-")
        ep_id = f"EP-{clean_asset}"
        assert TARGET_ID_REGEX.match(ep_id), f"Malformed generated Endpoint ID: '{ep_id}'"
        assert_firewall_compliance(ep_id, "endpoint_id")
        target_ids.add(ep_id)

    return sorted(list(target_ids))


def build_scenario_allowed_sets(
    scenario: EvaluationScenario,
    pack: Optional[LosslessStructuralPack] = None,
) -> ScenarioAllowedSets:
    """Builds complete audited allowed sets container for a scenario."""
    facts = extract_allowed_fact_ids(scenario, pack=pack)
    targets = extract_allowed_target_ids(scenario, pack=pack)

    facts_bytes = json.dumps(facts, sort_keys=True).encode("utf-8")
    targets_bytes = json.dumps(targets, sort_keys=True).encode("utf-8")

    facts_hash = hashlib.sha256(facts_bytes).hexdigest()
    targets_hash = hashlib.sha256(targets_bytes).hexdigest()

    return ScenarioAllowedSets(
        scenario_id=scenario.scenario_id,
        allowed_fact_ids=facts,
        allowed_target_ids=targets,
        allowed_fact_ids_hash=facts_hash,
        allowed_target_ids_hash=targets_hash,
        count_allowed_facts=len(facts),
        count_allowed_targets=len(targets),
    )
