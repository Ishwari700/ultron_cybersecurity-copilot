"""Phase 11.4: Secondary Field Ablation Study (Section 21).

Performs a small exploratory secondary attribution experiment on a fixed subset of 6 scenarios
(1 from each application family) to determine the marginal attribution of each evidence class:
A. Identity (requester identity removed)
B. Ownership (resource owner identity removed)
C. Role (requester/resource role removed)
D. Tenant (requester/resource tenant removed)
E. Authorization Requirement (required role/policy removed)
F. Observed Response (HTTP status/response body removed)
"""

import copy
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.evidence.structural_diff import StructuralDiffEngine
from src.evidence.cascade_models import CascadeHandoffPacket
from src.evidence.gate import EvidencePreservationGate
from src.engine.router import DeterministicRouter
from src.evidence.provenance import compute_provenance_hash
from src.engine.context_builder import ReasoningContextBuilder, TRACK_A_7B_BASELINE
from src.engine.reasoning_runner import CascadeGroundingValidator
from src.eval.extractor import extract_decision
from src.eval.scenarios import get_gold_set_scenarios
from src.eval.synthetic_app import SyntheticApp
from src.eval.phase11_4_enrichment import InteractionEvidenceGenerator
from src.eval.run_phase11_4_replication import (
    PINNED_7B_MODEL,
    query_ollama_model,
)

SUBSET_SCENARIOS = [
    "SCEN-SAAS_BILLING-INV-DETAILS-VULN-01",
    "SCEN-ECOMMERCE_ORDERS-ORD-REFUND-VULN-01",
    "SCEN-IDENTITY_PROVIDER-USER-ROLES-VULN-01",
    "SCEN-DOCUMENT_COLLABORATION-DOC-EXPORT-VULN-01",
    "SCEN-HEALTHCARE_PORTAL-PATIENT-REC-VULN-01",
    "SCEN-IOT_FLEET_MGMT-DEVICE-CMD-VULN-01",
]

ABLATION_CLASSES = [
    ("FULL_ENRICHED", "Full Condition B with all 21 typed fields"),
    ("ABLATE_A_IDENTITY", "Requester identity removed/masked as UNKNOWN"),
    ("ABLATE_B_OWNERSHIP", "Resource owner identity removed/masked as UNKNOWN"),
    ("ABLATE_C_ROLE", "Requester/resource roles removed/masked as UNKNOWN"),
    ("ABLATE_D_TENANT", "Tenant boundaries removed/masked as UNKNOWN"),
    ("ABLATE_E_AUTH_REQ", "Documented authorization requirements removed"),
    ("ABLATE_F_RESPONSE", "Observed HTTP response status/body removed"),
]

def run_ablation_scenario(
    s,
    ablation_name: str,
) -> Dict[str, Any]:
    sid = s.scenario_id
    fam = s.app_family
    asset = s.target_asset
    app = SyntheticApp(fam, vulnerable_variant=True)

    endpoint_id = asset.get("endpoint_id") or ("EP-" + asset.get("asset_id", sid))
    asset_id = asset.get("asset_id", sid)
    route_template = asset.get("normalized_path") or asset.get("raw_path")
    http_method = asset.get("method", "GET")
    mutability = asset.get("application_mutability", "READ_ONLY")

    base_facts = []
    for ev in s.initial_evidence:
        f = dict(ev)
        f["endpoint_id"] = endpoint_id
        f["asset_id"] = asset_id
        f["route_template"] = route_template
        f["http_method"] = http_method
        f["application_mutability"] = mutability
        f["parameters"] = s.parameters
        if ablation_name == "ABLATE_E_AUTH_REQ":
            f["statement"] = f"{http_method} {asset.get('raw_path', '')} endpoint."
        base_facts.append(f)

    enriched_facts, enriched_identities, lineage = InteractionEvidenceGenerator.generate(
        scenario_id=sid,
        app_family=fam,
        target_asset=asset,
        parameters=s.parameters,
        base_facts=base_facts,
        identities=s.identities,
        target_app=app,
    )

    # Apply ablation modifications to enriched_facts & identities
    ablated_facts = copy.deepcopy(enriched_facts)
    ablated_identities = copy.deepcopy(enriched_identities)

    for f in ablated_facts:
        stmt = f.get("statement", "")
        if ablation_name == "ABLATE_A_IDENTITY":
            f["caller_identity_id"] = "UNKNOWN"
            stmt = stmt.replace("requester_identity_id='user_b'", "requester_identity_id='UNKNOWN'")
            stmt = stmt.replace("requester_identity_id='user_a'", "requester_identity_id='UNKNOWN'")
            stmt = stmt.replace("requester_identity_id != resource_owner_identity_id", "requester_identity_id unknown")
            stmt = stmt.replace("cross_identity_access=true", "cross_identity_access=UNKNOWN")
        elif ablation_name == "ABLATE_B_OWNERSHIP":
            f["resource_owner_id"] = "UNKNOWN"
            stmt = stmt.replace("owner='user_a'", "owner='UNKNOWN'").replace("owner='user_b'", "owner='UNKNOWN'")
            stmt = stmt.replace("requester_identity_id != resource_owner_identity_id", "resource_owner unknown")
            stmt = stmt.replace("cross_identity_access=true", "cross_identity_access=UNKNOWN")
            ablated_identities = [{"identity_id": "user_a", "role": "customer", "tenant": "org_a", "owned_resources": []}, {"identity_id": "user_b", "role": "customer", "tenant": "org_b", "owned_resources": []}]
        elif ablation_name == "ABLATE_C_ROLE":
            f["caller_role"] = "UNKNOWN"
            stmt = stmt.replace("role='customer'", "role='UNKNOWN'")
            stmt = stmt.replace("role='admin'", "role='UNKNOWN'")
        elif ablation_name == "ABLATE_D_TENANT":
            stmt = stmt.replace("tenant='org_a'", "tenant='UNKNOWN'").replace("tenant='org_b'", "tenant='UNKNOWN'")
            stmt = stmt.replace("cross_tenant_access=true", "cross_tenant_access=UNKNOWN")
        elif ablation_name == "ABLATE_F_RESPONSE":
            f["response_status"] = None
            f["response_body"] = None
            stmt = stmt.replace("Status code: 200.", "Status code: UNKNOWN.").replace("Access result: 'GRANTED'.", "Access result: 'UNKNOWN'.")
            stmt = stmt.replace("was returned to requester", "status unobserved")
        f["statement"] = stmt

    pack = StructuralDiffEngine.compute(ablated_facts, ablated_identities)
    gate_res = EvidencePreservationGate.validate(channel_a=pack, raw_triage=None)
    dec = DeterministicRouter.evaluate_escalation(pack, gate_res)
    p_hash = compute_provenance_hash(pack, gate_res, dec)

    handoff = CascadeHandoffPacket(
        schema_version="2.0.0",
        channel_a_structural=pack,
        routing_decision=dec,
        provenance_hash=p_hash,
        validated_triage=None,
    )

    ctx = ReasoningContextBuilder.build_context(
        handoff_packet=handoff,
        model_identifier=PINNED_7B_MODEL,
        cascade_mode=TRACK_A_7B_BASELINE,
    )

    raw_text, raw_present, parsed_json, infer_lat, err_str = query_ollama_model(ctx.prompt)
    ext_res = extract_decision(parsed_json)

    grounding_valid = True
    if ext_res.decision == "HYPOTHESIS" and ext_res.normalized_hypothesis:
        gv = CascadeGroundingValidator.validate_grounding(pack, ext_res.normalized_hypothesis)
        grounding_valid = gv.valid

    useful = bool(ext_res.decision == "HYPOTHESIS" and grounding_valid and s.ground_truth_vulnerable)

    return {
        "scenario_id": sid,
        "app_family": fam,
        "ablation_class": ablation_name,
        "extracted_decision": ext_res.decision,
        "useful": useful,
        "grounding_valid": grounding_valid,
        "inference_latency_s": infer_lat,
    }


def run_full_ablation_study() -> Dict[str, Any]:
    gold = {s.scenario_id: s for s in get_gold_set_scenarios()}
    results = {}

    print("======================================================================")
    print(" PHASE 11.4: SECONDARY FIELD ABLATION STUDY (Section 21)")
    print("======================================================================")
    print(f"Fixed Subset: {len(SUBSET_SCENARIOS)} scenarios across 6 application families")
    print(f"Ablation Classes: {len(ABLATION_CLASSES)} configurations per scenario\n")

    summary_by_ablation = {ac[0]: {"useful_count": 0, "total": len(SUBSET_SCENARIOS)} for ac in ABLATION_CLASSES}

    for sid in SUBSET_SCENARIOS:
        s = gold[sid]
        print(f"Testing {sid} ({s.app_family})...")
        scen_res = {}
        for ac_code, ac_desc in ABLATION_CLASSES:
            t0 = time.perf_counter()
            r = run_ablation_scenario(s, ac_code)
            t1 = time.perf_counter()
            scen_res[ac_code] = r
            if r["useful"]:
                summary_by_ablation[ac_code]["useful_count"] += 1
            print(f"  [{ac_code}]: {r['extracted_decision']} (useful={r['useful']}, {t1-t0:.1f}s)")
        results[sid] = scen_res

    ablation_summary = {}
    for ac_code, ac_desc in ABLATION_CLASSES:
        u_cnt = summary_by_ablation[ac_code]["useful_count"]
        tot = summary_by_ablation[ac_code]["total"]
        ablation_summary[ac_code] = {
            "description": ac_desc,
            "useful_count": u_cnt,
            "total": tot,
            "yield": round(u_cnt / tot, 4),
        }

    output_data = {
        "metadata": {
            "study_name": "Phase 11.4 Secondary Field Ablation Study",
            "scenarios_tested": len(SUBSET_SCENARIOS),
            "ablation_conditions": len(ABLATION_CLASSES),
        },
        "summary": ablation_summary,
        "detailed_results": results,
    }

    out_path = Path("reports/m2_phase11_4_ablation_study.json")
    out_path.write_text(json.dumps(output_data, indent=2), encoding="utf-8")
    print(f"\nWrote ablation study results to {out_path}")
    return output_data

if __name__ == "__main__":
    run_full_ablation_study()
