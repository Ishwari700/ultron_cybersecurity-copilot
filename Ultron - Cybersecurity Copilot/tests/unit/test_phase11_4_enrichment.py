"""Unit tests for Phase 11.4 Typed Observable Interaction Evidence Generator."""

import json
import pytest
from src.eval.scenarios import get_gold_set_scenarios
from src.eval.synthetic_app import SyntheticApp
from src.eval.phase11_4_enrichment import (
    InteractionEvidenceGenerator,
    FORBIDDEN_GT_KEYS,
)

def test_ground_truth_leakage_assertion():
    """Verify that any forbidden GT key raises an AssertionError immediately."""
    for key in FORBIDDEN_GT_KEYS:
        with pytest.raises(AssertionError, match="GROUND-TRUTH LEAKAGE DETECTED"):
            InteractionEvidenceGenerator.assert_no_ground_truth_leakage({key: "leaked_val"})

def test_fact_preservation_and_lineage():
    """Verify BASE_FACTS ⊆ ENRICHED_FACTS and lineage integrity across 48 scenarios."""
    manifest = json.load(open("data/experiments/phase11_4_scenario_manifest.json"))
    gold = {s.scenario_id: s for s in get_gold_set_scenarios()}

    assert len(manifest["ordered_scenarios"]) == 48

    for item in manifest["ordered_scenarios"]:
        sid = item["scenario_id"]
        s = gold[sid]
        fam = item["app_family"]
        is_vuln = (item["designation"] == "vulnerable")
        app = SyntheticApp(fam, vulnerable_variant=is_vuln)

        base_facts = [dict(f) for f in s.initial_evidence]

        enriched_facts, enriched_identities, lineage = InteractionEvidenceGenerator.generate(
            scenario_id=sid,
            app_family=fam,
            target_asset=s.target_asset,
            parameters=s.parameters,
            base_facts=base_facts,
            identities=s.identities,
            target_app=app,
        )

        # 1. Fact preservation
        assert len(enriched_facts) == len(base_facts) + 2
        for idx, bf in enumerate(base_facts):
            assert enriched_facts[idx] == bf, f"Base fact modified in {sid}!"

        # 2. Lineage contains all 21 allowed fields
        assert len(lineage.fields) == 21
        for f_name in InteractionEvidenceGenerator.ALLOWED_FIELD_NAMES:
            assert f_name in lineage.fields
            field_entry = lineage.fields[f_name]
            assert field_entry["name"] == f_name
            assert field_entry["epistemic_status"] in ("OBSERVED_FACT", "DERIVED_FACT", "UNKNOWN")
            assert field_entry["source_fact_id"] in ("FACT-OBSERVED-INTERACTION-01", "FACT-DERIVED-RELATION-01")

        # 3. Derived fact safety: no security verdict in statement or fields
        for f in enriched_facts:
            stmt = f.get("statement", "").lower()
            assert "is_vulnerable" not in stmt
            assert "ground_truth" not in stmt
            assert "scorer_label" not in stmt
            assert "gold_" not in stmt
