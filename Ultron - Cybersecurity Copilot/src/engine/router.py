"""DeterministicRouter: Pure Deterministic Two-Class Escalation Routing Engine.

Sole owner and producer of DeterministicRoutingDecision (Schema 3).
Consumes LosslessStructuralPack (Schema 1) and GateValidationResult (Schema 5).
Holds zero side effects; does not mutate GateValidationResult; contains no taxonomy lookup.
"""

from datetime import datetime, timezone
from typing import List, Tuple

from src.evidence.cascade_models import (
    DeterministicRoutingDecision,
    GateValidationResult,
    LosslessStructuralPack,
)


class DeterministicRouter:
    """Evaluates canonical structural evidence and GateValidationResult to determine 7B escalation."""

    @staticmethod
    def evaluate_escalation(
        diff: LosslessStructuralPack,
        gate_result: GateValidationResult,
    ) -> DeterministicRoutingDecision:
        """
        Pure deterministic computation of final DeterministicRoutingDecision.
        Sole component permitted to produce DeterministicRoutingDecision.
        """
        # 1. Class-1 High-Risk Structural Predicates (Channel A Only)
        class1_high_risk: List[str] = []
        if diff.has_privilege_level_delta:
            class1_high_risk.append("PRIVILEGE_LEVEL_DELTA_DETECTED")
        if diff.status_code_changed_under_different_role:
            class1_high_risk.append("ROLE_BASED_STATUS_CODE_DELTA")
        if diff.has_unauthenticated_success:
            class1_high_risk.append("UNAUTHENTICATED_ACCESS_SUCCESS")
        if diff.has_cross_role_response_shape_delta:
            class1_high_risk.append("CROSS_ROLE_RESPONSE_SHAPE_DELTA")

        # 2. Class-1 Cross-Identity Object Access Predicate (Channel A Only)
        class1_cross_identity: List[str] = []
        if diff.has_cross_identity_object_access_success:
            class1_cross_identity.append("CROSS_IDENTITY_OBJECT_ACCESS_SUCCESS")

        # 3. Class-1 Structural Complexity Triggers (Channel A Only)
        class1_complexity: List[str] = []
        if diff.has_unseen_endpoint_parameter or diff.has_numeric_path_identifier:
            class1_complexity.append("UNSEEN_OR_VOLATILE_PARAMETER")
        if diff.has_observed_contradictions:
            class1_complexity.append("CONTRADICTORY_EVIDENCE_EXISTS")
        if diff.application_mutability in ("STATE_CHANGING", "DESTRUCTIVE"):
            class1_complexity.append("STATE_CHANGING_ASSET_REQUIRES_DEEP_AUDIT")
        if diff.has_evidence_parse_asymmetry:
            class1_complexity.append("EVIDENCE_PARSE_ASYMMETRY")

        # REQUIRED SEMANTIC MODEL: Enforced by Construction
        # Class 1 predicates are unified into an immutable collection
        class1_signals: Tuple[str, ...] = tuple(class1_high_risk + class1_cross_identity + class1_complexity)

        # Mandatory Routing Rule:
        # if class1_signals: MUST ESCALATE UNCONDITIONALLY
        if class1_signals:
            escalate = True
        else:
            escalate = False

        # 4. Class 2: 3B-Dependent Fail-Safe & Advisory Analysis Triggers (Channel B Evaluation)
        # Class-2 processing consumes GateValidationResult (Schema 5) produced exclusively by EvidencePreservationGate.
        # Router NEVER consumes RawTriageOutput directly and never evaluates advisory malformedness or missingness flags directly.
        class_2_triggers: List[str] = []

        # Consume Gate-normalized triggers (e.g. TRIAGE_OUTPUT_MALFORMED_OR_MISSING, TRIAGE_CATEGORY_INVALID, TRIAGE_HALLUCINATION)
        for trigger in gate_result.gate_triggers:
            if trigger not in class_2_triggers:
                class_2_triggers.append(trigger)

        # Ordinary Class-2 analytical trigger: ambiguity on sensitive category evaluated on validated_triage
        vt = gate_result.validated_triage
        if vt is not None:
            if vt.decision == "INSUFFICIENT_EVIDENCE" and vt.is_sensitive_category:
                if "TRIAGE_AMBIGUITY_ON_SENSITIVE_CATEGORY" not in class_2_triggers:
                    class_2_triggers.append("TRIAGE_AMBIGUITY_ON_SENSITIVE_CATEGORY")

        if class_2_triggers:
            escalate = True

        # Semantic Derivations:
        # has_high_risk_signal and high_risk_signals derive ONLY from class1_high_risk + class1_cross_identity
        has_high_risk = len(class1_high_risk) > 0 or len(class1_cross_identity) > 0
        all_reasons = list(class1_signals) + class_2_triggers

        # Fail-Safe Derivation: Strictly derived from gate_result.fail_safe_required.
        # Ordinary Class-2 analysis triggers (e.g. TRIAGE_AMBIGUITY_ON_SENSITIVE_CATEGORY)
        # do NOT set fail_safe_triggered = True unless gate_result.fail_safe_required is True.
        fail_safe_triggered = gate_result.fail_safe_required

        return DeterministicRoutingDecision(
            schema_version="2.0.0",
            escalate=escalate,
            has_high_risk_signal=has_high_risk,
            high_risk_signals=list(class1_high_risk + class1_cross_identity),
            deep_analysis_triggers=list(class1_complexity) + class_2_triggers,
            reasons=all_reasons,
            fail_safe_triggered=fail_safe_triggered,
            evaluated_timestamp=datetime.now(timezone.utc).isoformat(),
        )
