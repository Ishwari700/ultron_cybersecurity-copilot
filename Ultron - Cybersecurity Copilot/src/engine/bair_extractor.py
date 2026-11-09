"""Bounded Analytical Inference Representation (BAIR) Extractor & Validator.

Milestone M4 Phase M4.5 (Intervention I4):
Deterministic AST/slot extractor for BAIR XML markup mapping directly into the
canonical downstream S0 schema (HypothesisModelOutput).

Strict Separation of Concerns:
- parser: syntax/structure only (XML integrity, slot grammar)
- validator: decision-dependent structural rules + supplied empirical_evidence_present state
- mapper: deterministic field mapping only (zero semantic rewriting, zero citation substitution)
"""

import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple, Union

from src.engine.models import (
    BairJsonObject,
    HypothesisDecision,
    HypothesisModelOutput,
)

# Canonical 7-slot BAIR vocabulary (zero eighth slot permitted)
ALLOWED_BAIR_SLOTS = (
    "invariant",
    "evidence_gap",
    "affected_target",
    "decision",
    "facts",
    "methodology",
    "falsification",
)


class BairParseError(ValueError):
    """Raised when BAIR raw text contains invalid XML syntax or malformed markup structure."""
    pass


class BairSchemaError(ValueError):
    """Raised when BAIR content violates decision-dependent structural rules or slot constraints."""
    pass


def parse_bair(raw_text: str) -> Dict[str, str]:
    """
    Parse BAIR XML markup from raw model output.
    Enforces syntactic structure only:
    - Exactly one <bair>...</bair> block
    - Balanced XML tags
    - Zero unknown slots
    - Zero duplicate slots
    - Children must not contain nested elements or attributes

    Returns raw string content for each extracted slot.
    """
    if not raw_text or not isinstance(raw_text, str) or not raw_text.strip():
        raise BairParseError("Empty or non-string BAIR input")

    cleaned = raw_text.strip()
    # Strip optional markdown code fences
    if cleaned.startswith("```xml"):
        cleaned = cleaned[6:]
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    cleaned = cleaned.strip()

    # Verify exactly one <bair> opening and </bair> closing tag
    opening_count = len(re.findall(r"<bair[\s>]", cleaned, re.IGNORECASE))
    closing_count = len(re.findall(r"</bair>", cleaned, re.IGNORECASE))

    if opening_count == 0 or closing_count == 0:
        raise BairParseError("Missing <bair> or </bair> root tag")
    if opening_count > 1 or closing_count > 1:
        raise BairParseError("Ambiguous multiple <bair>...</bair> root blocks detected")

    # Locate the exact boundary of the <bair>...</bair> block
    match = re.search(r"(<bair[\s>].*?</bair>)", cleaned, re.DOTALL | re.IGNORECASE)
    if not match:
        raise BairParseError("Failed to extract bounded <bair>...</bair> block")
    bair_block = match.group(1).strip()

    # Parse XML via standard library ElementTree
    try:
        root = ET.fromstring(bair_block)
    except Exception as exc:
        raise BairParseError(f"XML parse error in BAIR block: {exc}") from exc

    if root.tag.lower() != "bair":
        raise BairParseError(f"Expected root element <bair>, got <{root.tag}>")

    if root.attrib:
        raise BairSchemaError("Root element <bair> must not contain XML attributes")

    seen_slots = set()
    raw_slots: Dict[str, str] = {}

    for child in root:
        slot_name = child.tag.strip().lower()

        # Reject unknown slot
        if slot_name not in ALLOWED_BAIR_SLOTS:
            raise BairSchemaError(f"Unknown slot in BAIR representation: <{child.tag}>")

        # Reject duplicate slot
        if slot_name in seen_slots:
            raise BairSchemaError(f"Duplicate slot in BAIR representation: <{child.tag}>")
        seen_slots.add(slot_name)

        # Reject attributes on slot tags
        if child.attrib:
            raise BairSchemaError(f"Slot <{child.tag}> must not contain XML attributes")

        # Reject nested child elements within slot tags
        if len(child) > 0:
            raise BairSchemaError(f"Slot <{child.tag}> must contain text only, not nested elements")

        text_content = (child.text or "").strip()
        raw_slots[slot_name] = text_content

    return raw_slots


def _check_falsification_completeness(falsification_text: str) -> None:
    """
    Validate that <falsification> is a bounded complete experiment specification containing:
    1. A concrete observation that would support the hypothesis.
    2. A concrete observation that would disprove/falsify the hypothesis.
    """
    if not falsification_text or not falsification_text.strip():
        raise BairSchemaError("Falsification slot must not be empty")

    lower = falsification_text.lower()
    has_supporting = any(term in lower for term in ["support", "confirm", "positive", "observed", "expected"])
    has_disproving = any(term in lower for term in ["disprov", "falsif", "reject", "refut", "negative", "403", "404", "400", "block"])

    if not has_supporting:
        raise BairSchemaError("Falsification slot missing supporting observation specification")
    if not has_disproving:
        raise BairSchemaError("Falsification slot missing disproving/falsifying observation specification")


def _is_canonical_target_empirical_fact(item: Any) -> bool:
    """
    Verify whether an item represents canonical target empirical evidence ONLY.
    Strictly rejects:
    - VAPT knowledge chunks (chunk_id, CHK-xxx)
    - Methodology references (source_name in OWASP/CWE/WSTG/ASVS)
    - Model-derived or synthetic content
    - Empty or non-dict items
    """
    if not isinstance(item, dict):
        return False
    # Must not be a knowledge chunk / methodology
    if "chunk_id" in item:
        return False
    fid = str(item.get("fact_id") or item.get("evidence_id") or "")
    if fid.startswith("CHK-") or "CHK-" in fid:
        return False
    # Must not be model-derived
    if item.get("model_derived") or item.get("is_synthetic") or item.get("source") == "model":
        return False
    # Must not be VAPT / OWASP knowledge source
    src = str(item.get("source_name") or item.get("source_type") or "").upper()
    if any(k in src for k in ("WSTG", "ASVS", "CWE", "OWASP", "VAPT", "METHODOLOGY")):
        return False
    # Must have canonical FACT ID or target observation statement
    if fid.startswith("FACT-"):
        return True
    if "fact_id" in item and item["fact_id"]:
        return True
    if "statement" in item and item["statement"]:
        return True
    return False


def determine_empirical_evidence_present(
    channel_a: Optional[Any] = None,
    retrieved_evidence: Optional[Any] = None,
    explicit_signal: Optional[bool] = None,
) -> bool:
    """
    Deterministically derive whether empirical target evidence exists from canonical
    target evidence representations available in the execution context.

    Required Invariant:
        empirical_evidence_present = deterministic presence of CANONICAL TARGET EMPIRICAL EVIDENCE ONLY.

    The flag MUST NOT become true because of:
    - VAPT Knowledge RAG chunks
    - OWASP WSTG / ASVS / CWE knowledge
    - methodology references
    - CHK namespace material
    - model-derived content
    - evidence-gap text
    - falsification text
    - general retrieved knowledge
    - inferred observations
    - any other non-target knowledge

    MUST NOT be:
    - generated by the LLM
    - parsed from <facts>
    - inferred from <decision>
    - inferred from prose
    - inferred from <evidence_gap>
    - inferred from <falsification>
    - inferred from methodology references
    """
    if explicit_signal is not None:
        return bool(explicit_signal)

    if channel_a is not None:
        facts = getattr(channel_a, "observed_facts", None)
        if facts is None and isinstance(channel_a, dict):
            facts = channel_a.get("observed_facts")
        if facts:
            if any(_is_canonical_target_empirical_fact(f) for f in facts):
                return True

    if retrieved_evidence is not None:
        if isinstance(retrieved_evidence, (list, tuple, set)):
            if any(_is_canonical_target_empirical_fact(item) for item in retrieved_evidence):
                return True
        elif isinstance(retrieved_evidence, dict):
            facts = retrieved_evidence.get("facts") or retrieved_evidence.get("observed_facts")
            if facts and isinstance(facts, (list, tuple, set)):
                if any(_is_canonical_target_empirical_fact(item) for item in facts):
                    return True

    return False


def validate_bair(
    slots: Dict[str, str],
    empirical_evidence_present: bool,
) -> Dict[str, Any]:
    """
    Apply decision-dependent structural validation rules to parsed BAIR slots.
    Preserves exact behavior matrix:
    - HYPOTHESIS: invariant, evidence_gap, affected_target, decision, facts, falsification (supporting+disproving) required.
    - INSUFFICIENT_EVIDENCE: invariant, evidence_gap, affected_target, decision, falsification required.
      facts is REQUIRED if empirical_evidence_present==True, OPTIONAL if False.
    - NO_RELEVANT_FUNCTIONALITY: invariant, affected_target, decision required. facts/evidence_gap/falsification optional.
    - CONFIRMED: Strictly rejected.
    """
    decision_raw = slots.get("decision", "").strip().upper()
    if not decision_raw:
        raise BairSchemaError("Missing mandatory <decision> slot")

    if decision_raw == "CONFIRMED":
        raise BairSchemaError("CONFIRMED decision is strictly forbidden in reasoning engine")

    valid_decisions = {d.value for d in HypothesisDecision}
    if decision_raw not in valid_decisions:
        raise BairSchemaError(f"Invalid decision value: {decision_raw!r}")

    # Parse entity IDs strictly preserving exact strings
    facts_raw = slots.get("facts", "")
    parsed_facts = [s for s in re.split(r"[,;\s]+", facts_raw.strip()) if s] if facts_raw else []

    methodology_raw = slots.get("methodology", "")
    parsed_methodology = [s for s in re.split(r"[,;\s]+", methodology_raw.strip()) if s] if methodology_raw else []

    # Disallow synthetic placeholder tokens in facts or methodology
    placeholder_tokens = {"none", "n/a", "na", "null", "[]", "{}"}
    for fid in parsed_facts:
        if fid.lower() in placeholder_tokens:
            raise BairSchemaError(f"Placeholder token {fid!r} is strictly forbidden in <facts> slot")
    for mid in parsed_methodology:
        if mid.lower() in placeholder_tokens:
            raise BairSchemaError(f"Placeholder token {mid!r} is strictly forbidden in <methodology> slot")

    invariant = slots.get("invariant", "").strip()
    evidence_gap = slots.get("evidence_gap", "").strip()
    affected_target = slots.get("affected_target", "").strip()
    falsification = slots.get("falsification", "").strip()

    # Decision-dependent validation rules
    if decision_raw == HypothesisDecision.HYPOTHESIS.value:
        if not invariant:
            raise BairSchemaError("Mandatory <invariant> slot missing or empty for HYPOTHESIS")
        if not evidence_gap:
            raise BairSchemaError("Mandatory <evidence_gap> slot missing or empty for HYPOTHESIS")
        if not affected_target:
            raise BairSchemaError("Mandatory <affected_target> slot missing or empty for HYPOTHESIS")
        if not parsed_facts:
            raise BairSchemaError("Mandatory <facts> slot missing or empty for HYPOTHESIS")
        _check_falsification_completeness(falsification)

    elif decision_raw == HypothesisDecision.INSUFFICIENT_EVIDENCE.value:
        if not invariant:
            raise BairSchemaError("Mandatory <invariant> slot missing or empty for INSUFFICIENT_EVIDENCE")
        if not evidence_gap:
            raise BairSchemaError("Mandatory <evidence_gap> slot missing or empty for INSUFFICIENT_EVIDENCE")
        if not affected_target:
            raise BairSchemaError("Mandatory <affected_target> slot missing or empty for INSUFFICIENT_EVIDENCE")
        if not falsification:
            raise BairSchemaError("Mandatory <falsification> slot missing or empty for INSUFFICIENT_EVIDENCE")

        # Empirical evidence state rule:
        # Case 1: empirical_evidence_present == True and facts absent => BairSchemaError
        # Case 2: empirical_evidence_present == True and facts present => accepted
        # Case 3: empirical_evidence_present == False and facts absent => accepted
        # Case 4: empirical_evidence_present == False and facts present => accepted (optional slot)
        if empirical_evidence_present and not parsed_facts:
            raise BairSchemaError(
                "Decision INSUFFICIENT_EVIDENCE with empirical_evidence_present=True requires non-empty <facts> slot"
            )

    elif decision_raw == HypothesisDecision.NO_RELEVANT_FUNCTIONALITY.value:
        if not invariant:
            raise BairSchemaError("Mandatory <invariant> slot missing or empty for NO_RELEVANT_FUNCTIONALITY")
        if not affected_target:
            raise BairSchemaError("Mandatory <affected_target> slot missing or empty for NO_RELEVANT_FUNCTIONALITY")

    return {
        "invariant": invariant,
        "evidence_gap": evidence_gap or None,
        "affected_target": affected_target,
        "decision": decision_raw,
        "parsed_facts": parsed_facts,
        "parsed_methodology": parsed_methodology,
        "falsification": falsification or None,
        "raw_slots": slots,
    }


def map_bair_to_s0(validated: Dict[str, Any]) -> HypothesisModelOutput:
    """
    Deterministic mapping from validated BAIR slots to canonical S0 HypothesisModelOutput.
    Zero semantic inference, zero citation substitution, zero vulnerability inference.
    """
    invariant = validated["invariant"]
    evidence_gap = validated["evidence_gap"]
    affected_target = validated["affected_target"]
    decision = HypothesisDecision(validated["decision"])
    facts = validated["parsed_facts"]
    methodology = validated["parsed_methodology"]
    falsification = validated["falsification"]

    # experiment_proposal is copied directly from falsification without semantic rewriting
    experiment_proposal = falsification or "None required"
    reasoning_summary = f"BAIR evaluation: {invariant}. Evidence gap: {evidence_gap or 'None'}."

    return HypothesisModelOutput(
        invariant=invariant,
        evidence_gap=evidence_gap,
        affected_target=affected_target,
        decision=decision,
        supporting_evidence_ids=facts,
        methodology_references=methodology,
        reasoning_summary=reasoning_summary,
        experiment_proposal=experiment_proposal,
    )


def parse_bair_json(raw_text: str) -> Dict[str, Any]:
    """
    Parse BAIR JSON representation from raw model output.
    Enforces syntactic structure only:
    - Strips markdown fences if present
    - Decodes via json.loads
    - Root must be a dictionary
    - Rejects unknown keys outside the canonical 7 slots
    """
    if not raw_text or not isinstance(raw_text, str) or not raw_text.strip():
        raise BairParseError("Empty or non-string BAIR JSON input")

    cleaned = raw_text.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:].strip()
    elif cleaned.startswith("```"):
        cleaned = cleaned[3:].strip()
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3].strip()

    try:
        data = json.loads(cleaned)
    except Exception as exc:
        raise BairParseError(f"JSON parse error in BAIR response: {exc}") from exc

    if not isinstance(data, dict):
        raise BairParseError("Decoded JSON root is not a dictionary")

    allowed_keys = {
        "invariant",
        "evidence_gap",
        "affected_target",
        "decision",
        "empirical_facts",
        "methodology_references",
        "experiment_action",
        "supporting_outcome",
        "disproving_outcome",
        "falsification_description",
        "falsification_plan",
    }
    for k in data.keys():
        if k not in allowed_keys:
            raise BairSchemaError(f"Unknown slot in BAIR JSON representation: {k}")

    return data


def validate_bair_json(
    data: Union[Dict[str, Any], BairJsonObject],
    empirical_evidence_present: bool = True,
) -> BairJsonObject:
    """
    Apply decision-dependent structural validation rules to parsed BAIR JSON object.
    Preserves exact behavior matrix:
    - HYPOTHESIS: invariant, evidence_gap, affected_target, decision, empirical_facts,
      typed experiment fields (experiment_action, supporting_outcome, disproving_outcome) required.
    - INSUFFICIENT_EVIDENCE: invariant, evidence_gap, affected_target, decision required.
      empirical_facts is REQUIRED if empirical_evidence_present==True, OPTIONAL if False.
      typed experiment fields are optional.
    - NO_RELEVANT_FUNCTIONALITY: invariant, affected_target, decision required.
    - CONFIRMED: Strictly rejected.
    """
    if isinstance(data, dict):
        try:
            bair_obj = BairJsonObject.model_validate(data)
        except Exception as exc:
            raise BairSchemaError(f"BAIR JSON schema validation error: {exc}") from exc
    elif isinstance(data, BairJsonObject):
        bair_obj = data
    else:
        raise BairSchemaError(f"Expected BairJsonObject or dict, got {type(data).__name__}")

    # Empirical evidence state rule for INSUFFICIENT_EVIDENCE:
    if bair_obj.decision == HypothesisDecision.INSUFFICIENT_EVIDENCE:
        if empirical_evidence_present and not bair_obj.empirical_facts:
            raise BairSchemaError(
                "Decision INSUFFICIENT_EVIDENCE with empirical_evidence_present=True requires non-empty empirical_facts slot"
            )

    return bair_obj


def map_bair_json_to_s0(
    bair: BairJsonObject,
    target_asset: Optional[Dict[str, Any]] = None,
    category_id: Optional[str] = None,
) -> HypothesisModelOutput:
    """
    Deterministic mapping from validated BairJsonObject to canonical S0 HypothesisModelOutput.
    Zero semantic inference, zero citation substitution, fail closed on invalid/ambiguous mapping.
    """
    if not isinstance(bair, BairJsonObject):
        raise TypeError(f"Expected BairJsonObject, got {type(bair).__name__}")

    # Build experiment_proposal from typed fields or legacy plan
    if bair.experiment_action and bair.supporting_outcome and bair.disproving_outcome:
        action_val = bair.experiment_action.value if hasattr(bair.experiment_action, "value") else str(bair.experiment_action)
        supp_val = bair.supporting_outcome.value if hasattr(bair.supporting_outcome, "value") else str(bair.supporting_outcome)
        disp_val = bair.disproving_outcome.value if hasattr(bair.disproving_outcome, "value") else str(bair.disproving_outcome)
        desc_str = f" ({bair.falsification_description})" if bair.falsification_description else ""
        experiment_proposal = f"Action: {action_val}; Breach: {supp_val}; Safe: {disp_val}{desc_str}"
    elif bair.falsification_plan:
        experiment_proposal = bair.falsification_plan
    else:
        experiment_proposal = "None required"

    reasoning_summary = f"BAIR evaluation: {bair.invariant}. Evidence gap: {bair.evidence_gap or 'None'}."

    asset_id = (target_asset or {}).get("asset_id") or bair.affected_target

    action_val = bair.experiment_action.value if hasattr(bair.experiment_action, "value") else (str(bair.experiment_action) if bair.experiment_action else None)
    supp_val = bair.supporting_outcome.value if hasattr(bair.supporting_outcome, "value") else (str(bair.supporting_outcome) if bair.supporting_outcome else None)
    disp_val = bair.disproving_outcome.value if hasattr(bair.disproving_outcome, "value") else (str(bair.disproving_outcome) if bair.disproving_outcome else None)

    return HypothesisModelOutput(
        invariant=bair.invariant,
        evidence_gap=bair.evidence_gap,
        affected_target=bair.affected_target,
        decision=bair.decision,
        supporting_evidence_ids=list(bair.empirical_facts),
        methodology_references=list(bair.methodology_references),
        cited_methodology_chunk_ids=list(bair.methodology_references),
        reasoning_summary=reasoning_summary,
        experiment_proposal=experiment_proposal,
        experiment_action=action_val,
        supporting_outcome=supp_val,
        disproving_outcome=disp_val,
        falsification_description=bair.falsification_description,
        category=category_id,
        asset_id=asset_id,
    )


class BairExtractor:
    """Deterministic AST/slot extractor and validator for BAIR representations."""

    @classmethod
    def extract_bair(
        cls,
        raw_text: str,
        empirical_evidence_present: bool,
    ) -> Tuple[Dict[str, Any], HypothesisModelOutput]:
        """
        Execute full BAIR XML extraction pipeline:
        parse_bair -> validate_bair -> map_bair_to_s0.
        Fails closed on any structural or schema failure.
        """
        raw_slots = parse_bair(raw_text)
        validated = validate_bair(raw_slots, empirical_evidence_present=empirical_evidence_present)
        canonical = map_bair_to_s0(validated)
        return validated, canonical

    @classmethod
    def extract_bair_json(
        cls,
        raw_text: str,
        empirical_evidence_present: bool = True,
        target_asset: Optional[Dict[str, Any]] = None,
        category_id: Optional[str] = None,
    ) -> Tuple[BairJsonObject, HypothesisModelOutput]:
        """
        Execute full BAIR JSON extraction pipeline:
        parse_bair_json -> validate_bair_json -> map_bair_json_to_s0.
        Fails closed on any structural or schema failure.
        """
        raw_dict = parse_bair_json(raw_text)
        validated = validate_bair_json(raw_dict, empirical_evidence_present=empirical_evidence_present)
        canonical = map_bair_json_to_s0(validated, target_asset=target_asset, category_id=category_id)
        return validated, canonical
