"""
Milestone M5 Phase 11.3: Grounding Protocol Contracts & Schemas.

Defines the prompt blocks, field instructions, and Ollama constrained decoding JSON schemas
for conditions:
- P1 (Control: Phase 11.2 Attack Predicate baseline, free facts and free target)
- P2 (Treatment 1: Fact Citation Shielding, bounded fact IDs)
- P3 (Treatment 2: Fact + Target Shielding, bounded fact IDs and bounded target IDs)
"""

import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from src.engine.models import (
    FACT_NAMESPACE_PATTERN,
    CHK_NAMESPACE_PATTERN,
    HypothesisDecision,
    VALID_ACTION_PREDICATES,
)
from src.eval.phase11_2_polarity.attack_predicate import (
    AttackPredicate,
    SecurityPropertyDomain,
)
from src.eval.phase11_2_polarity.protocol import (
    P1_PROMPT_INSTRUCTION,
    P1BairJsonObject,
    parse_p1_response,
)


def render_p2_prompt_instruction(allowed_fact_ids: List[str]) -> str:
    """Renders P2 prompt instruction with bounded available evidence IDs."""
    fact_ids_block = json.dumps(allowed_fact_ids, indent=2)
    return (
        f"OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - P2_FACT_SHIELDED):\n"
        f"AVAILABLE_EVIDENCE_IDS:\n{fact_ids_block}\n\n"
        f"Emit your evaluation strictly as a single JSON object with these fields:\n"
        f"{{\n"
        f'  "invariant": "Security invariant statement evaluated against target",\n'
        f'  "evidence_gap": "Missing observation or gap in evidence (null if none)",\n'
        f'  "affected_target": "Target endpoint, asset ID, or parameter",\n'
        f'  "decision": "HYPOTHESIS" | "INSUFFICIENT_EVIDENCE" | "NO_RELEVANT_FUNCTIONALITY",\n'
        f'  "empirical_facts": ["FACT-xxx", ...],\n'
        f'  "methodology_references": ["CHK-xxx"],\n'
        f'  "attack_predicate": {{\n'
        f'    "subject": "Role/identity initiating attack",\n'
        f'    "operation": "Must match supplied deterministic experiment_action",\n'
        f'    "target": "Target endpoint, parameter, or resource identifier under test",\n'
        f'    "security_property": "Security property asserting breach",\n'
        f'    "expected_violation": "Brief statement of unauthorized condition"\n'
        f'  }} | null,\n'
        f'  "falsification_description": "Brief explanation of verification experiment (or null if none)"\n'
        f"}}\n\n"
        f"FIELD CONSTRAINTS & NAMESPACE RULES:\n"
        f"- 'empirical_facts': cite ONLY valid identifiers from AVAILABLE_EVIDENCE_IDS above. Inventing new fact IDs is strictly forbidden. Emit [] if abstaining.\n"
        f"- 'methodology_references': cite ONLY valid CHK-* identifiers actually supplied. If none, emit [].\n"
        f"- For HYPOTHESIS: 'attack_predicate' is MANDATORY. 'attack_predicate.operation' MUST match supplied experiment_action.\n"
        f"- For INSUFFICIENT_EVIDENCE or NO_RELEVANT_FUNCTIONALITY: 'attack_predicate' must be null.\n"
        f"- Do NOT emit 'supporting_outcome' or 'disproving_outcome'. These are bound deterministically.\n"
        f"- NEVER emit CONFIRMED as the decision.\n"
        f"- Do NOT wrap output in markdown formatting or add extra keys."
    )


def render_p3_prompt_instruction(
    allowed_fact_ids: List[str],
    allowed_target_ids: List[str],
) -> str:
    """Renders P3 prompt instruction with bounded available evidence IDs and target identifiers."""
    fact_ids_block = json.dumps(allowed_fact_ids, indent=2)
    target_ids_block = json.dumps(allowed_target_ids, indent=2)
    return (
        f"OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - P3_FACT_AND_TARGET_SHIELDED):\n"
        f"AVAILABLE_EVIDENCE_IDS:\n{fact_ids_block}\n\n"
        f"AVAILABLE_TARGET_IDENTIFIERS:\n{target_ids_block}\n\n"
        f"Emit your evaluation strictly as a single JSON object with these fields:\n"
        f"{{\n"
        f'  "invariant": "Security invariant statement evaluated against target",\n'
        f'  "evidence_gap": "Missing observation or gap in evidence (null if none)",\n'
        f'  "affected_target": "Must be exactly one identifier selected from AVAILABLE_TARGET_IDENTIFIERS",\n'
        f'  "decision": "HYPOTHESIS" | "INSUFFICIENT_EVIDENCE" | "NO_RELEVANT_FUNCTIONALITY",\n'
        f'  "empirical_facts": ["FACT-xxx", ...],\n'
        f'  "methodology_references": ["CHK-xxx"],\n'
        f'  "attack_predicate": {{\n'
        f'    "subject": "Role/identity initiating attack",\n'
        f'    "operation": "Must match supplied deterministic experiment_action",\n'
        f'    "target": "Target endpoint, parameter, or resource identifier under test",\n'
        f'    "security_property": "Security property asserting breach",\n'
        f'    "expected_violation": "Brief statement of unauthorized condition"\n'
        f'  }} | null,\n'
        f'  "falsification_description": "Brief explanation of verification experiment (or null if none)"\n'
        f"}}\n\n"
        f"FIELD CONSTRAINTS & NAMESPACE RULES:\n"
        f"- 'empirical_facts': cite ONLY valid identifiers from AVAILABLE_EVIDENCE_IDS above. Inventing new fact IDs is strictly forbidden. Emit [] if abstaining.\n"
        f"- 'affected_target': select strictly from AVAILABLE_TARGET_IDENTIFIERS above. Free-form text or prose descriptions are strictly forbidden.\n"
        f"- 'methodology_references': cite ONLY valid CHK-* identifiers actually supplied. If none, emit [].\n"
        f"- For HYPOTHESIS: 'attack_predicate' is MANDATORY. 'attack_predicate.operation' MUST match supplied experiment_action.\n"
        f"- For INSUFFICIENT_EVIDENCE or NO_RELEVANT_FUNCTIONALITY: 'attack_predicate' must be null.\n"
        f"- Do NOT emit 'supporting_outcome' or 'disproving_outcome'. These are bound deterministically.\n"
        f"- NEVER emit CONFIRMED as the decision.\n"
        f"- Do NOT wrap output in markdown formatting or add extra keys."
    )


def get_inference_schema_for_condition(
    condition_id: str,
    allowed_fact_ids: Optional[List[str]] = None,
    allowed_target_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Returns Ollama constrained decoding JSON schema for P1, P2, or P3.
    """
    valid_props = sorted([e.value for e in SecurityPropertyDomain])
    valid_actions = sorted(list(VALID_ACTION_PREDICATES))

    # Base schema fields common to all conditions
    base_properties: Dict[str, Any] = {
        "invariant": {
            "type": "string",
            "description": "Security invariant statement evaluated against target",
        },
        "evidence_gap": {
            "type": ["string", "null"],
            "description": "Missing observation or gap in evidence",
        },
        "decision": {
            "type": "string",
            "enum": [
                "NO_RELEVANT_FUNCTIONALITY",
                "INSUFFICIENT_EVIDENCE",
                "HYPOTHESIS",
            ],
            "description": "One of NO_RELEVANT_FUNCTIONALITY, INSUFFICIENT_EVIDENCE, HYPOTHESIS",
        },
        "methodology_references": {
            "type": "array",
            "items": {
                "type": "string",
                "pattern": CHK_NAMESPACE_PATTERN,
            },
            "description": "Referenced VAPT methodology identifiers (^CHK-[A-Z0-9_-]+$)",
        },
        "attack_predicate": {
            "type": ["object", "null"],
            "properties": {
                "subject": {
                    "type": "string",
                    "description": "Acting entity role (e.g. UNAUTHORIZED_ACTOR, TENANT_B_USER)",
                },
                "operation": {
                    "type": "string",
                    "enum": valid_actions,
                    "description": "Must match supplied deterministic experiment_action",
                },
                "target": {
                    "type": "string",
                    "description": "Target endpoint, parameter, or resource identifier under test",
                },
                "security_property": {
                    "type": "string",
                    "enum": valid_props,
                    "description": "Security property domain asserted to be breached",
                },
                "expected_violation": {
                    "type": "string",
                    "description": "Brief description of the unauthorized condition resulting from execution",
                },
            },
            "required": ["subject", "operation", "target", "security_property", "expected_violation"],
        },
        "falsification_description": {
            "type": ["string", "null"],
            "description": "Brief description of verification experiment or falsification test",
        },
    }

    if condition_id == "P1":
        # P1: Unconstrained fact patterns and unconstrained target string
        base_properties["affected_target"] = {
            "type": "string",
            "description": "Target endpoint, asset ID, or parameter",
        }
        base_properties["empirical_facts"] = {
            "type": "array",
            "items": {
                "type": "string",
                "pattern": FACT_NAMESPACE_PATTERN,
            },
            "description": "Canonical observation fact IDs (^FACT-[A-Z0-9_-]+$)",
        }
    elif condition_id == "P2":
        # P2: Bounded fact IDs enum, unconstrained target string
        facts = allowed_fact_ids or ["FACT-00000001"]
        base_properties["affected_target"] = {
            "type": "string",
            "description": "Target endpoint, asset ID, or parameter",
        }
        base_properties["empirical_facts"] = {
            "type": "array",
            "items": {
                "type": "string",
                "enum": sorted(list(set(facts))),
            },
            "description": "Canonical observation fact IDs selected from allowed_fact_ids",
        }
    elif condition_id == "P3":
        # P3: Bounded fact IDs enum, bounded target IDs enum
        facts = allowed_fact_ids or ["FACT-00000001"]
        targets = allowed_target_ids or ["EP-DEFAULT"]
        base_properties["affected_target"] = {
            "type": "string",
            "enum": sorted(list(set(targets))),
            "description": "Target identifier strictly selected from allowed_target_ids",
        }
        base_properties["empirical_facts"] = {
            "type": "array",
            "items": {
                "type": "string",
                "enum": sorted(list(set(facts))),
            },
            "description": "Canonical observation fact IDs selected from allowed_fact_ids",
        }
    else:
        raise ValueError(f"Unknown condition_id: {condition_id}")

    return {
        "type": "object",
        "properties": base_properties,
        "required": [
            "decision",
            "empirical_facts",
            "affected_target",
            "invariant",
        ],
    }
