"""
Milestone M5 Phase 11.4: Output Protocol Contracts & Schemas for Property Alignment.

Defines prompt blocks, namespace instructions, and Ollama constrained decoding JSON schemas for:
- P3: Grounding-Shielded Control (bounded facts + bounded targets, global property domain enum)
- P4: Grounding + Security Property Shielded (bounded facts + bounded targets + category-bounded properties)
- P5: Identical to P4 protocol, evaluated with Track D context
"""

import json
from typing import Any, Dict, List, Optional

from src.engine.models import (
    CHK_NAMESPACE_PATTERN,
    FACT_NAMESPACE_PATTERN,
    VALID_ACTION_PREDICATES,
)
from src.eval.phase11_2_polarity.attack_predicate import SecurityPropertyDomain
from src.eval.phase11_3_grounding.grounding_protocol import (
    get_inference_schema_for_condition as get_p3_schema,
    render_p3_prompt_instruction,
)
from src.eval.phase11_4_property_alignment.property_registry import get_allowed_security_properties


def render_p4_prompt_instruction(
    allowed_fact_ids: List[str],
    allowed_target_ids: List[str],
    allowed_security_properties: List[str],
) -> str:
    """Renders P4 prompt instruction with bounded facts, targets, and security properties."""
    fact_ids_block = json.dumps(allowed_fact_ids, indent=2)
    target_ids_block = json.dumps(allowed_target_ids, indent=2)
    props_block = json.dumps(allowed_security_properties, indent=2)

    return (
        f"OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - P4_PROPERTY_SHIELDED):\n"
        f"AVAILABLE_EVIDENCE_IDS:\n{fact_ids_block}\n\n"
        f"AVAILABLE_TARGET_IDENTIFIERS:\n{target_ids_block}\n\n"
        f"AVAILABLE_SECURITY_PROPERTIES:\n{props_block}\n\n"
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
        f'    "security_property": "Must be selected strictly from AVAILABLE_SECURITY_PROPERTIES",\n'
        f'    "expected_violation": "Brief statement of unauthorized condition"\n'
        f'  }} | null,\n'
        f'  "falsification_description": "Brief explanation of verification experiment (or null if none)"\n'
        f"}}\n\n"
        f"FIELD CONSTRAINTS & NAMESPACE RULES:\n"
        f"- 'empirical_facts': cite ONLY valid identifiers from AVAILABLE_EVIDENCE_IDS above. Inventing new fact IDs is strictly forbidden. Emit [] if abstaining.\n"
        f"- 'affected_target': select strictly from AVAILABLE_TARGET_IDENTIFIERS above. Free-form text or prose descriptions are strictly forbidden.\n"
        f"- 'attack_predicate.security_property': select strictly from AVAILABLE_SECURITY_PROPERTIES above. Arbitrary properties are forbidden.\n"
        f"- 'attack_predicate.operation': MUST match supplied deterministic experiment_action.\n"
        f"- 'methodology_references': cite ONLY valid CHK-* identifiers actually supplied. If none, emit [].\n"
        f"- For HYPOTHESIS: 'attack_predicate' is MANDATORY.\n"
        f"- For INSUFFICIENT_EVIDENCE or NO_RELEVANT_FUNCTIONALITY: 'attack_predicate' must be null.\n"
        f"- Do NOT emit 'supporting_outcome' or 'disproving_outcome'. These are bound deterministically.\n"
        f"- NEVER emit CONFIRMED as the decision.\n"
        f"- Do NOT wrap output in markdown formatting or add extra keys."
    )


def get_p4_inference_schema(
    allowed_fact_ids: List[str],
    allowed_target_ids: List[str],
    allowed_security_properties: List[str],
) -> Dict[str, Any]:
    """
    Returns Ollama constrained decoding JSON schema for P4 / P5 with category-bound security property enum.
    """
    facts = sorted(list(set(allowed_fact_ids or ["FACT-00000001"])))
    targets = sorted(list(set(allowed_target_ids or ["EP-DEFAULT"])))
    props = sorted(list(set(allowed_security_properties or ["RESOURCE_OWNERSHIP_INTEGRITY"])))
    valid_actions = sorted(list(VALID_ACTION_PREDICATES))

    return {
        "type": "object",
        "properties": {
            "invariant": {
                "type": "string",
                "description": "Security invariant statement evaluated against target",
            },
            "evidence_gap": {
                "type": ["string", "null"],
                "description": "Missing observation or gap in evidence",
            },
            "affected_target": {
                "type": "string",
                "enum": targets,
                "description": "Target identifier strictly selected from allowed_target_ids",
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
            "empirical_facts": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": facts,
                },
                "description": "Canonical observation fact IDs selected from allowed_fact_ids",
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
                        "enum": props,
                        "description": "Category-bounded security property domain asserted to be breached",
                    },
                    "expected_violation": {
                        "type": "string",
                        "description": "Brief description of unauthorized condition resulting from execution",
                    },
                },
                "required": ["subject", "operation", "target", "security_property", "expected_violation"],
            },
            "falsification_description": {
                "type": ["string", "null"],
                "description": "Brief description of verification experiment or falsification test",
            },
        },
        "required": [
            "decision",
            "empirical_facts",
            "affected_target",
            "invariant",
        ],
    }
