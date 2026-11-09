"""Milestone M2 Phase 11: Corrected Deterministic Decision Extractor & Failure Taxonomy.

Implements the forensic decision extraction contract:
1. Normalizes hypothesis objects safely unwrapping:
   - Direct hypothesis dictionaries
   - Nested "ReasoningHypothesis" dictionaries
   - Nested "finding" dictionaries
2. Supports observed fields:
   - VulnerabilityExists / vulnerability_exists (boolean or parseable boolean string/int)
   - decision / Decision (HYPOTHESIS, SUSPECTED_VULNERABILITY, BENIGN_NO_ISSUE, NO_RELEVANT_FUNCTIONALITY, INSUFFICIENT_EVIDENCE, UNCERTAIN)
   - VulnerabilityType / vulnerability_type / Type / type (preserved as extracted evidence)
3. Detects and records conflicts:
   - Conflicting VulnerabilityExists=True and benign decision -> UNCERTAIN / INSUFFICIENT_EVIDENCE
   - Conflicting VulnerabilityExists=False and positive decision -> UNCERTAIN / INSUFFICIENT_EVIDENCE
   - Conflicting VulnerabilityExists=False and non-empty VulnerabilityType -> UNCERTAIN / INSUFFICIENT_EVIDENCE
4. Strictly deterministic:
   - Never accesses ground truth
   - Never uses free-text heuristics for vulnerability classification
   - Never silently converts malformed, empty, or None outputs into benign NO_RELEVANT_FUNCTIONALITY
   - Does NOT blindly convert non-empty VulnerabilityType alone into VULNERABLE without explicit signal
5. Full 9-class earliest primary failure taxonomy (Section 7).
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


class FailureLayer:
    """Explicit 9-class earliest primary failure taxonomy."""
    MODEL_OUTPUT_FAILURE = "MODEL_OUTPUT_FAILURE"
    JSON_PARSE_FAILURE = "JSON_PARSE_FAILURE"
    HYPOTHESIS_NORMALIZATION_FAILURE = "HYPOTHESIS_NORMALIZATION_FAILURE"
    DECISION_EXTRACTION_FAILURE = "DECISION_EXTRACTION_FAILURE"
    GROUNDING_FAILURE = "GROUNDING_FAILURE"
    ROUTING_FALSE_NEGATIVE = "ROUTING_FALSE_NEGATIVE"
    REASONING_INCORRECT_LOGIC = "REASONING_INCORRECT_LOGIC"
    SCORER_CONTRACT_FAILURE = "SCORER_CONTRACT_FAILURE"
    OTHER_IMPLEMENTATION_FAILURE = "OTHER_IMPLEMENTATION_FAILURE"


@dataclass(frozen=True)
class ExtractionResult:
    """Immutable structured extraction result capturing decision, evidence, and failure reasons."""
    decision: str  # "HYPOTHESIS" | "NO_RELEVANT_FUNCTIONALITY" | "INSUFFICIENT_EVIDENCE"
    vulnerability_type: Optional[str] = None
    vulnerability_exists: Optional[bool] = None
    raw_decision_field: Optional[str] = None
    normalized_hypothesis: Optional[Dict[str, Any]] = None
    failure_reason: Optional[str] = None
    is_valid: bool = True


def normalize_hypothesis(hyp: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Safely unwraps nested wrapper objects (ReasoningHypothesis, finding).
    Returns (normalized_dict, error_reason).
    """
    if hyp is None:
        return None, "NULL_PAYLOAD: Hypothesis payload is None"

    if not isinstance(hyp, dict):
        return None, f"MALFORMED_STRUCTURE: Expected dictionary payload, got {type(hyp).__name__}"

    if len(hyp) == 0:
        return None, "EMPTY_PAYLOAD: Hypothesis dictionary is empty"

    # Pattern 1: Nested ReasoningHypothesis
    if "ReasoningHypothesis" in hyp:
        inner = hyp["ReasoningHypothesis"]
        if not isinstance(inner, dict):
            return None, f"MALFORMED_STRUCTURE: Nested ReasoningHypothesis is {type(inner).__name__}, expected dict"
        if len(inner) == 0:
            return None, "EMPTY_PAYLOAD: Nested ReasoningHypothesis dictionary is empty"
        # Inner may optionally nest a finding
        if "finding" in inner and isinstance(inner["finding"], dict):
            inner = inner["finding"]
            if len(inner) == 0:
                return None, "EMPTY_PAYLOAD: Nested finding dictionary is empty"
        return inner, None

    # Pattern 2: Nested finding
    if "finding" in hyp:
        inner = hyp["finding"]
        if not isinstance(inner, dict):
            return None, f"MALFORMED_STRUCTURE: Nested finding is {type(inner).__name__}, expected dict"
        if len(inner) == 0:
            return None, "EMPTY_PAYLOAD: Nested finding dictionary is empty"
        return inner, None

    # Pattern 3: Direct dictionary
    return hyp, None


def _parse_bool_value(val: Any) -> Tuple[Optional[bool], bool]:
    """Parses a value into a boolean. Returns (bool_val, is_valid_bool)."""
    if isinstance(val, bool):
        return val, True
    if isinstance(val, (int, float)) and val in (0, 1):
        return bool(val), True
    if isinstance(val, str):
        s = val.strip().lower()
        if s in ("true", "1", "yes"):
            return True, True
        if s in ("false", "0", "no"):
            return False, True
    return None, False


def extract_decision(hyp: Any) -> ExtractionResult:
    """
    Deterministically extracts decision and structured metadata from model hypothesis.
    Enforces frozen contract invariants without heuristic classification.
    """
    normalized, norm_err = normalize_hypothesis(hyp)
    if norm_err is not None:
        return ExtractionResult(
            decision="INSUFFICIENT_EVIDENCE",
            vulnerability_type=None,
            vulnerability_exists=None,
            raw_decision_field=None,
            normalized_hypothesis=None,
            failure_reason=norm_err,
            is_valid=False,
        )

    # Search for VulnerabilityExists field (case/alias insensitive)
    vuln_exists_raw = None
    vuln_exists_key = None
    for k, v in normalized.items():
        k_clean = k.replace("_", "").lower()
        if k_clean == "vulnerabilityexists":
            vuln_exists_raw = v
            vuln_exists_key = k
            break

    vuln_exists_val: Optional[bool] = None
    if vuln_exists_raw is not None:
        b_val, is_valid_b = _parse_bool_value(vuln_exists_raw)
        if not is_valid_b:
            return ExtractionResult(
                decision="INSUFFICIENT_EVIDENCE",
                vulnerability_type=None,
                vulnerability_exists=None,
                raw_decision_field=None,
                normalized_hypothesis=normalized,
                failure_reason=f"INVALID_FIELD_TYPE: {vuln_exists_key} value '{vuln_exists_raw}' is not a valid boolean",
                is_valid=False,
            )
        vuln_exists_val = b_val

    # Search for decision field
    raw_decision: Optional[str] = None
    for k, v in normalized.items():
        if k.lower() == "decision":
            if isinstance(v, str):
                raw_decision = v.strip().upper()
            elif v is not None:
                raw_decision = str(v).strip().upper()
            break

    # Search for VulnerabilityType / Type field
    vuln_type: Optional[str] = None
    for k, v in normalized.items():
        k_clean = k.replace("_", "").lower()
        if k_clean in ("vulnerabilitytype", "type"):
            if isinstance(v, str) and v.strip():
                vuln_type = v.strip()
                break

    # -------------------------------------------------------------
    # Conflict Detection (Deterministic Uncertain / Fail-Safe)
    # -------------------------------------------------------------
    # Conflict 1: Explicit True with explicit benign decision
    if vuln_exists_val is True and raw_decision in ("NO_RELEVANT_FUNCTIONALITY", "BENIGN_NO_ISSUE", "BENIGN", "FALSE"):
        return ExtractionResult(
            decision="INSUFFICIENT_EVIDENCE",
            vulnerability_type=vuln_type,
            vulnerability_exists=True,
            raw_decision_field=raw_decision,
            normalized_hypothesis=normalized,
            failure_reason="CONFLICTING_FIELDS: VulnerabilityExists=True conflicts with benign decision string",
            is_valid=False,
        )

    # Conflict 2: Explicit False with explicit positive decision
    if vuln_exists_val is False and raw_decision in ("HYPOTHESIS", "SUSPECTED_VULNERABILITY", "VULNERABLE", "TRUE"):
        return ExtractionResult(
            decision="INSUFFICIENT_EVIDENCE",
            vulnerability_type=vuln_type,
            vulnerability_exists=False,
            raw_decision_field=raw_decision,
            normalized_hypothesis=normalized,
            failure_reason="CONFLICTING_FIELDS: VulnerabilityExists=False conflicts with positive decision string",
            is_valid=False,
        )

    # Conflict 3: Explicit False with non-empty vulnerability type
    if vuln_exists_val is False and vuln_type is not None:
        return ExtractionResult(
            decision="INSUFFICIENT_EVIDENCE",
            vulnerability_type=vuln_type,
            vulnerability_exists=False,
            raw_decision_field=raw_decision,
            normalized_hypothesis=normalized,
            failure_reason=f"CONFLICTING_FIELDS: VulnerabilityExists=False conflicts with non-empty VulnerabilityType '{vuln_type}'",
            is_valid=False,
        )

    # -------------------------------------------------------------
    # Decision Resolution
    # -------------------------------------------------------------
    if vuln_exists_val is True:
        return ExtractionResult(
            decision="HYPOTHESIS",
            vulnerability_type=vuln_type,
            vulnerability_exists=True,
            raw_decision_field=raw_decision,
            normalized_hypothesis=normalized,
            failure_reason=None,
            is_valid=True,
        )

    if vuln_exists_val is False:
        failure_reason = None
        if raw_decision in ("INSUFFICIENT_EVIDENCE", "UNCERTAIN", "UNKNOWN"):
            failure_reason = f"EXPLICIT_ABSTENTION: Model signaled '{raw_decision}'"
        return ExtractionResult(
            decision="NO_RELEVANT_FUNCTIONALITY",
            vulnerability_type=None,
            vulnerability_exists=False,
            raw_decision_field=raw_decision,
            normalized_hypothesis=normalized,
            failure_reason=failure_reason,
            is_valid=True,
        )

    # If VulnerabilityExists flag is absent, check explicit decision field
    if raw_decision is not None:
        if raw_decision in ("HYPOTHESIS", "SUSPECTED_VULNERABILITY", "VULNERABLE", "TRUE"):
            return ExtractionResult(
                decision="HYPOTHESIS",
                vulnerability_type=vuln_type,
                vulnerability_exists=True,
                raw_decision_field=raw_decision,
                normalized_hypothesis=normalized,
                failure_reason=None,
                is_valid=True,
            )
        if raw_decision in ("NO_RELEVANT_FUNCTIONALITY", "BENIGN_NO_ISSUE", "BENIGN", "FALSE"):
            return ExtractionResult(
                decision="NO_RELEVANT_FUNCTIONALITY",
                vulnerability_type=vuln_type,
                vulnerability_exists=False,
                raw_decision_field=raw_decision,
                normalized_hypothesis=normalized,
                failure_reason=None,
                is_valid=True,
            )
        if raw_decision in ("INSUFFICIENT_EVIDENCE", "UNCERTAIN", "UNKNOWN"):
            return ExtractionResult(
                decision="NO_RELEVANT_FUNCTIONALITY",
                vulnerability_type=vuln_type,
                vulnerability_exists=False,
                raw_decision_field=raw_decision,
                normalized_hypothesis=normalized,
                failure_reason=f"EXPLICIT_ABSTENTION: Model signaled '{raw_decision}'",
                is_valid=True,
            )
        return ExtractionResult(
            decision="INSUFFICIENT_EVIDENCE",
            vulnerability_type=vuln_type,
            vulnerability_exists=None,
            raw_decision_field=raw_decision,
            normalized_hypothesis=normalized,
            failure_reason=f"UNKNOWN_DECISION_VALUE: Unrecognized decision string '{raw_decision}'",
            is_valid=False,
        )

    # Fallback: Neither VulnerabilityExists nor decision field is present.
    # Per Rule D & Section 4 warning: We preserve VulnerabilityType as extracted evidence,
    # but do NOT automatically override the frozen scoring contract by treating it as VULNERABLE,
    # nor do we silently treat it as benign.
    if vuln_type is not None:
        return ExtractionResult(
            decision="INSUFFICIENT_EVIDENCE",
            vulnerability_type=vuln_type,
            vulnerability_exists=None,
            raw_decision_field=None,
            normalized_hypothesis=normalized,
            failure_reason=f"UNRESOLVED_DECISION: VulnerabilityType '{vuln_type}' present without explicit VulnerabilityExists or decision flag",
            is_valid=False,
        )

    return ExtractionResult(
        decision="INSUFFICIENT_EVIDENCE",
        vulnerability_type=None,
        vulnerability_exists=None,
        raw_decision_field=None,
        normalized_hypothesis=normalized,
        failure_reason="UNRESOLVED_DECISION: Neither VulnerabilityExists nor decision flag present in payload",
        is_valid=False,
    )


def extract_decision_from_hypothesis(hyp: Optional[Dict[str, Any]]) -> str:
    """Backward-compatible string extractor returning canonical decision string."""
    return extract_decision(hyp).decision


def classify_earliest_failure(
    raw_output_present: bool,
    raw_error: Optional[str],
    json_parse_status: str,
    extraction_result: Optional[ExtractionResult],
    grounding_valid: Optional[bool],
    is_breakout: bool,
    escalated: Optional[bool],
    ground_truth_vulnerable: bool,
    called_7b: bool,
    final_decision: str,
    useful: bool,
) -> Tuple[Optional[str], List[str]]:
    """
    Assigns exactly one earliest primary failure layer and any secondary causes.
    Follows chronological pipeline order:
      MODEL_OUTPUT_FAILURE
      -> JSON_PARSE_FAILURE
      -> HYPOTHESIS_NORMALIZATION_FAILURE
      -> DECISION_EXTRACTION_FAILURE
      -> ROUTING_FALSE_NEGATIVE
      -> GROUNDING_FAILURE
      -> REASONING_INCORRECT_LOGIC
      -> SCORER_CONTRACT_FAILURE
    Returns (primary_layer, secondary_causes).
    """
    secondary: List[str] = []

    # 1. Model output failure (timeout, transport error, missing response)
    if not raw_output_present:
        primary = FailureLayer.MODEL_OUTPUT_FAILURE
        if raw_error:
            secondary.append(f"Model Error: {raw_error}")
        return primary, secondary

    # 2. JSON parse failure
    if json_parse_status == "FAILURE":
        primary = FailureLayer.JSON_PARSE_FAILURE
        if raw_error:
            secondary.append(f"Parse Error: {raw_error}")
        return primary, secondary

    # 3 & 4. Extraction & Normalization
    if extraction_result is not None and not extraction_result.is_valid:
        reason = extraction_result.failure_reason or ""
        if "EXPLICIT_ABSTENTION" in reason:
            pass
        elif "MALFORMED_STRUCTURE" in reason or "EMPTY_PAYLOAD" in reason or "NULL_PAYLOAD" in reason:
            primary = FailureLayer.HYPOTHESIS_NORMALIZATION_FAILURE
            secondary.append(reason)
            return primary, secondary
        else:
            primary = FailureLayer.DECISION_EXTRACTION_FAILURE
            secondary.append(reason)
            return primary, secondary

    # 5. Routing false negative (Track C: scenario is vulnerable, but 3B triage did not escalate; 7B never received it)
    if ground_truth_vulnerable and escalated is False and not called_7b:
        primary = FailureLayer.ROUTING_FALSE_NEGATIVE
        secondary.append("3B Triage filtered out vulnerable scenario before 7B invocation")
        return primary, secondary

    # 6. Grounding failure or Prompt Injection Breakout
    if final_decision == "HYPOTHESIS":
        if grounding_valid is False or is_breakout:
            primary = FailureLayer.GROUNDING_FAILURE
            if is_breakout:
                secondary.append("Prompt injection breakout detected")
            if grounding_valid is False:
                secondary.append("Grounding validation rejected unsupported identifiers")
            return primary, secondary

    # 7. Reasoning incorrect logic
    # Case A: Vulnerable scenario, but model concluded NO_RELEVANT_FUNCTIONALITY or INSUFFICIENT_EVIDENCE
    if ground_truth_vulnerable and final_decision != "HYPOTHESIS":
        primary = FailureLayer.REASONING_INCORRECT_LOGIC
        secondary.append(f"Model concluded '{final_decision}' on ground-truth vulnerable target")
        return primary, secondary

    # Case B: Non-vulnerable scenario (patched / neg control), but model concluded HYPOTHESIS (False Positive)
    if not ground_truth_vulnerable and final_decision == "HYPOTHESIS" and grounding_valid is True:
        primary = FailureLayer.REASONING_INCORRECT_LOGIC
        secondary.append("Model emitted vulnerable HYPOTHESIS on non-vulnerable target (False Positive)")
        return primary, secondary

    # If non-vulnerable and concluded NO_RELEVANT_FUNCTIONALITY -> Correct abstention (Success!)
    # If vulnerable and concluded HYPOTHESIS and grounded -> Useful finding (Success!)
    if ground_truth_vulnerable and final_decision == "HYPOTHESIS" and useful:
        return None, []

    if not ground_truth_vulnerable and final_decision in ("NO_RELEVANT_FUNCTIONALITY", "INSUFFICIENT_EVIDENCE"):
        return None, []

    return None, []
