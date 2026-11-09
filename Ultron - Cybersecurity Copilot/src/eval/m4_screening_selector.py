"""Deterministic M4.8 Screening Scoring, Hard-Gate Evaluation, and Final Configuration Selector.

Implements M4 Plan Section 11 & Section 13:
- Computes Scenario-Level Useful Hypothesis Rate (exact denominator N=20)
- Computes Secondary Safety Metrics: TPR (N=10), TNR (N=10), FP, FN
- Evaluates Discrete Small-N Hard Gates (exact integers):
    * Gate 1: Safety Floor (TNR >= 90.0%, FP <= 1 on N=20)
    * Gate 2: Compute Envelope (num_predict=300, 1 call, latency <= 25,000ms)
    * Gate 3: Syntax Validity (Truncation count == 0 on N=20)
    * Gate 4: Namespace Validity (Violation count == 0 on N=20, Validator bypass == 0)
- Ranks surviving interventions deterministically:
    1. Higher Delta UsefulHypothesisRate
    2. Lower mean latency (ms)
    3. Lower prompt token count
    4. Smaller code-diff footprint
    5. Deterministic ID (I1 < I2 < I3 < I4 < I5 < I6)
- Executes greedy combination according to Section 10.2 Compatibility Matrix
- Freezes data/eval/m4_frozen_config_manifest.json with SHA-256
- Outputs comprehensive screening summary data/eval/m4_screening_summary_20260921.json with SHA-256
"""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from src.engine.models import PrimaryFailureCategory
from src.eval.m4_screening_harness import (
    ScenarioScreeningRecord,
    ScreeningTrackId,
    TrackActivationMatrix,
)

# Pre-declared compatibility matrix from Section 10.2
# COM = Compatible, ADT = Compatible with Adapter, INC = Incompatible
COMPATIBILITY_MATRIX = {
    "I1": {"I1": "SELF", "I2": "COM", "I3": "COM", "I4": "ADT", "I5": "COM", "I6": "COM"},
    "I2": {"I1": "COM", "I2": "SELF", "I3": "COM", "I4": "COM", "I5": "COM", "I6": "COM"},
    "I3": {"I1": "COM", "I2": "COM", "I3": "SELF", "I4": "COM", "I5": "COM", "I6": "COM"},
    "I4": {"I1": "ADT", "I2": "COM", "I3": "COM", "I4": "SELF", "I5": "COM", "I6": "COM"},
    "I5": {"I1": "COM", "I2": "COM", "I3": "COM", "I4": "COM", "I5": "SELF", "I6": "COM"},
    "I6": {"I1": "COM", "I2": "COM", "I3": "COM", "I4": "COM", "I5": "COM", "I6": "SELF"},
}

CODE_DIFF_LINES = {
    "I1": 150,
    "I2": 210,
    "I3": 320,
    "I4": 450,
    "I5": 280,
    "I6": 390,
}


class TrackMetricReport(BaseModel):
    track_id: str
    activation_matrix: Dict[str, int]
    total_scenarios: int = 20
    vulnerable_total: int = 10
    control_total: int = 10

    useful_hypothesis_count: int
    useful_hypothesis_rate: float
    delta_useful_rate_vs_baseline: float

    tp: int
    tn: int
    fp: int
    fn: int
    tpr: float
    tnr: float

    abstention_count: int
    abstention_rate: float

    primary_ac1_breakdown: Dict[str, int]
    ac1_syntactic_failure_count: int
    ac1_syntactic_failure_rate: float

    grounding_valid_count: int
    grounding_validity_rate: float

    raw_namespace_breach_count: Optional[int] = None
    validator_bypass_count: Optional[int] = None

    mean_latency_ms: float
    mean_prompt_tokens: float

    gate_1_safety_pass: bool
    gate_2_envelope_pass: bool
    gate_3_syntax_pass: bool
    gate_4_namespace_pass: bool
    all_hard_gates_pass: bool
    gate_failure_reasons: List[str] = Field(default_factory=list)


def compute_track_metrics(
    records: List[ScenarioScreeningRecord],
    baseline_useful_rate: float = 0.0,
) -> TrackMetricReport:
    """Computes exact screening metrics and integer gate results for a track."""
    total = len(records)
    if total != 20:
        raise ValueError(f"Expected exactly 20 records, got {total}")

    track_id = records[0].track_id
    activation = records[0].activation_matrix

    useful_count = 0
    tp = 0
    tn = 0
    fp = 0
    fn = 0
    abstain_count = 0
    grounding_valid_count = 0
    raw_ns_breaches = 0
    val_bypasses = 0
    has_ns_metric = False

    ac1_counts: Dict[str, int] = {
        PrimaryFailureCategory.VALID.value: 0,
        PrimaryFailureCategory.RUNTIME_TRANSPORT_FAILURE.value: 0,
        PrimaryFailureCategory.MAX_TOKEN_TRUNCATION.value: 0,
        PrimaryFailureCategory.PARSER_FAILURE.value: 0,
        PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE.value: 0,
        PrimaryFailureCategory.SEMANTIC_GROUNDING_FAILURE.value: 0,
    }

    latencies = []
    prompt_tokens = []

    for r in records:
        latencies.append(r.latency_ms)
        prompt_tokens.append(max(1, len(r.prompt) // 4))

        # AC1 category
        cat_val = r.primary_failure_category
        ac1_counts[cat_val] = ac1_counts.get(cat_val, 0) + 1

        is_hypo = (r.decision == "HYPOTHESIS")
        is_vuln = r.vulnerable_variant
        is_valid_grounded = (r.is_valid is True and r.grounding_status == "VALID")

        if r.grounding_status == "VALID":
            grounding_valid_count += 1

        if r.raw_namespace_breach is not None:
            has_ns_metric = True
            if r.raw_namespace_breach is True:
                raw_ns_breaches += 1
            if r.validator_bypass is True:
                val_bypasses += 1

        if is_hypo:
            if is_vuln:
                tp += 1
                if is_valid_grounded:
                    useful_count += 1
            else:
                fp += 1
        else:
            abstain_count += 1
            if not is_vuln:
                tn += 1
            else:
                fn += 1

    useful_rate = useful_count / 20.0
    delta_vs_baseline = useful_rate - baseline_useful_rate

    tpr = tp / 10.0
    tnr = tn / 10.0
    abstain_rate = abstain_count / 20.0
    grounding_rate = grounding_valid_count / 20.0

    syntactic_failures = (
        ac1_counts[PrimaryFailureCategory.MAX_TOKEN_TRUNCATION.value]
        + ac1_counts[PrimaryFailureCategory.PARSER_FAILURE.value]
        + ac1_counts[PrimaryFailureCategory.SCHEMA_VALIDITY_FAILURE.value]
    )
    syntactic_rate = syntactic_failures / 20.0

    mean_lat = sum(latencies) / 20.0
    mean_prompt_tok = sum(prompt_tokens) / 20.0

    # Gate Evaluation (Integer First)
    failure_reasons = []

    # Gate 1: TNR >= 90.0% (FP <= 1 on N=20)
    gate_1 = (tn >= 9 and fp <= 1)
    if not gate_1:
        failure_reasons.append(f"Gate 1 Failed: TNR={tnr:.2%} (TN={tn}/10, FP={fp}/10; requires TN>=9, FP<=1)")

    # Gate 2: Compute Envelope (num_predict=300, 1 call, latency <= 25,000ms)
    gate_2 = (mean_lat <= 25000.0)
    if not gate_2:
        failure_reasons.append(f"Gate 2 Failed: Mean latency {mean_lat:.1f}ms exceeds 25,000ms ceiling")

    # Gate 3: Syntax Validity (Truncation < 1.0% -> truncation_count == 0 on N=20)
    trunc_count = ac1_counts[PrimaryFailureCategory.MAX_TOKEN_TRUNCATION.value]
    gate_3 = (trunc_count == 0)
    if not gate_3:
        failure_reasons.append(f"Gate 3 Failed: Max-token truncation count = {trunc_count} (must be 0 on N=20)")

    # Gate 4: Namespace Validity (Violation < 2.0% -> violation_count == 0 on N=20, bypass == 0)
    if has_ns_metric:
        gate_4 = (raw_ns_breaches == 0 and val_bypasses == 0)
        if not gate_4:
            failure_reasons.append(f"Gate 4 Failed: Raw namespace breaches = {raw_ns_breaches}, validator bypasses = {val_bypasses}")
    else:
        # Structurally N/A for tracks without namespace emission
        gate_4 = True

    all_gates = (gate_1 and gate_2 and gate_3 and gate_4)

    return TrackMetricReport(
        track_id=track_id,
        activation_matrix=activation,
        total_scenarios=20,
        vulnerable_total=10,
        control_total=10,
        useful_hypothesis_count=useful_count,
        useful_hypothesis_rate=useful_rate,
        delta_useful_rate_vs_baseline=round(delta_vs_baseline, 4),
        tp=tp,
        tn=tn,
        fp=fp,
        fn=fn,
        tpr=tpr,
        tnr=tnr,
        abstention_count=abstain_count,
        abstention_rate=abstain_rate,
        primary_ac1_breakdown=ac1_counts,
        ac1_syntactic_failure_count=syntactic_failures,
        ac1_syntactic_failure_rate=syntactic_rate,
        grounding_valid_count=grounding_valid_count,
        grounding_validity_rate=grounding_rate,
        raw_namespace_breach_count=raw_ns_breaches if has_ns_metric else None,
        validator_bypass_count=val_bypasses if has_ns_metric else None,
        mean_latency_ms=round(mean_lat, 2),
        mean_prompt_tokens=round(mean_prompt_tok, 1),
        gate_1_safety_pass=gate_1,
        gate_2_envelope_pass=gate_2,
        gate_3_syntax_pass=gate_3,
        gate_4_namespace_pass=gate_4,
        all_hard_gates_pass=all_gates,
        gate_failure_reasons=failure_reasons,
    )


def verify_evidence_parity_across_tracks(
    all_track_records: Dict[str, List[ScenarioScreeningRecord]],
) -> Dict[str, str]:
    """
    Verifies that for every scenario, the canonical_input_hash is 100% identical across all tracks.
    Returns mapping scenario_id -> canonical_input_hash.
    Raises RuntimeError on parity violation.
    """
    first_track_name = list(all_track_records.keys())[0]
    reference_records = {r.scenario_id: r.canonical_input_hash for r in all_track_records[first_track_name]}

    for t_name, records in all_track_records.items():
        if len(records) != len(reference_records):
            raise RuntimeError(f"Track {t_name} has {len(records)} records, expected {len(reference_records)}")
        for r in records:
            if r.scenario_id not in reference_records:
                raise RuntimeError(f"Track {t_name} scenario {r.scenario_id} not in reference set")
            expected_hash = reference_records[r.scenario_id]
            if r.canonical_input_hash != expected_hash:
                raise RuntimeError(
                    f"EVIDENCE PARITY VIOLATION in Track {t_name} scenario {r.scenario_id}! "
                    f"Expected hash {expected_hash}, got {r.canonical_input_hash}"
                )

    return reference_records


def run_greedy_configuration_selection(
    reports: Dict[str, TrackMetricReport],
) -> Tuple[TrackActivationMatrix, List[str], List[Dict[str, Any]]]:
    """
    Executes deterministic greedy combination algorithm per Section 11.2:
    1. Filter candidates passing all hard gates and with delta_useful >= 0.0000.
    2. Sort surviving candidates by:
       - Higher delta_useful DESC
       - Lower mean_latency_ms ASC
       - Lower prompt_tokens ASC
       - Smaller code_diff_lines ASC
       - Deterministic ID ASC
    3. Iteratively add compatible interventions.
    """
    # Track ID to intervention ID mapping
    track_to_intervention = {
        "E1": "I1",
        "E2": "I2",
        "E3": "I3",
        "E4": "I4",
        "E5": "I5",
        "E6": "I6",
    }

    surviving_candidates: List[Tuple[str, str, TrackMetricReport]] = []
    rejection_log: List[Dict[str, Any]] = []

    for t_name in ("E1", "E2", "E3", "E4", "E5", "E6"):
        if t_name not in reports:
            continue
        rep = reports[t_name]
        i_id = track_to_intervention[t_name]

        if not rep.all_hard_gates_pass:
            rejection_log.append({
                "intervention_id": i_id,
                "track_id": t_name,
                "status": "REJECTED_HARD_GATE",
                "reasons": rep.gate_failure_reasons,
            })
            continue

        if rep.delta_useful_rate_vs_baseline < 0.0000:
            rejection_log.append({
                "intervention_id": i_id,
                "track_id": t_name,
                "status": "REJECTED_NEGATIVE_DELTA",
                "delta": rep.delta_useful_rate_vs_baseline,
            })
            continue

        surviving_candidates.append((i_id, t_name, rep))

    # Sort surviving candidates
    def ranking_key(item: Tuple[str, str, TrackMetricReport]):
        i_id, t_name, rep = item
        return (
            -rep.delta_useful_rate_vs_baseline,  # Higher delta first
            rep.mean_latency_ms,                # Lower latency first
            rep.mean_prompt_tokens,             # Lower tokens first
            CODE_DIFF_LINES.get(i_id, 999),     # Smaller code diff first
            i_id,                               # Alphabetical tie-break
        )

    surviving_candidates.sort(key=ranking_key)

    selected_interventions: List[str] = []
    selection_steps: List[Dict[str, Any]] = []

    for i_id, t_name, rep in surviving_candidates:
        # Check compatibility with all currently selected
        compatible = True
        for sel in selected_interventions:
            rel = COMPATIBILITY_MATRIX[i_id][sel]
            if rel not in ("COM", "ADT"):
                compatible = False
                break

        if compatible:
            selected_interventions.append(i_id)
            selection_steps.append({
                "step": len(selected_interventions),
                "action": "ADDED",
                "intervention_id": i_id,
                "track_id": t_name,
                "delta_useful": rep.delta_useful_rate_vs_baseline,
                "latency_ms": rep.mean_latency_ms,
            })
        else:
            selection_steps.append({
                "step": len(selected_interventions) + 1,
                "action": "SKIPPED_INCOMPATIBLE",
                "intervention_id": i_id,
                "track_id": t_name,
            })

    # Build activation matrix for COMBINED
    combined_activation = TrackActivationMatrix(
        i1=1 if "I1" in selected_interventions else 0,
        i2=1 if "I2" in selected_interventions else 0,
        i3=1 if "I3" in selected_interventions else 0,
        i4=1 if "I4" in selected_interventions else 0,
        i5=1 if "I5" in selected_interventions else 0,
        i6=1 if "I6" in selected_interventions else 0,
    )

    return combined_activation, selected_interventions, selection_steps + rejection_log


def freeze_final_configuration_manifest(
    selected_interventions: List[str],
    combined_activation: TrackActivationMatrix,
    reports: Dict[str, TrackMetricReport],
    selection_history: List[Dict[str, Any]],
    output_path: Path = Path("data/eval/m4_frozen_config_manifest.json"),
) -> Tuple[Dict[str, Any], str]:
    """
    Serializes data/eval/m4_frozen_config_manifest.json and generates companion .sha256.
    HARD LOCK: Zero modifications permitted after freeze.
    """
    payload = {
        "manifest_schema_version": "1.0.0",
        "run_status": "OFFICIAL_M4_8_SCREENING",
        "configuration_id": f"M4-COMBINED-{'-'.join(selected_interventions) if selected_interventions else 'BASELINE'}",
        "frozen_timestamp": datetime.now(timezone.utc).isoformat(),
        "selection_rule": "Deterministic Section 11.2 Greedy Selection Protocol",
        "selected_interventions": selected_interventions,
        "activation_matrix": combined_activation.as_dict(),
        "screening_reports": {k: v.model_dump() for k, v in reports.items()},
        "selection_history": selection_history,
        "runtime_envelope": {
            "model": "qwen2.5-coder:7b",
            "model_digest_prefix": "dae161e2",
            "runtime": "Ollama v0.34.1",
            "num_ctx": 2048,
            "num_predict": 300,
            "temperature": 0.0,
            "seed": 42,
        },
        "governance_notice": (
            "HARD LOCK: This configuration is frozen strictly based on exploratory development "
            "screening results. Zero parameter tuning or code modification is permitted after this freeze. "
            "Confirmatory evaluation is conducted downstream in Phase M4.9 on the untouched 84-scenario benchmark."
        ),
    }

    canonical_bytes = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    sha256_hash = hashlib.sha256(canonical_bytes).hexdigest()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical_bytes)

    (output_path.parent / f"{output_path.name}.sha256").write_text(sha256_hash + "\n", encoding="utf-8")

    return payload, sha256_hash
