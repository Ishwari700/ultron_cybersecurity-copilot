"""
Milestone M5 Phase 11.2: Output Protocol Contract for P1 Attack-Predicate Interface.

Defines P1BairJsonObject schema, prompt instructions, parser, and inference schema factory.
Under P1:
- The model emits 'attack_predicate' (typed) and 'falsification_description'.
- The model MUST NOT emit 'supporting_outcome' or 'disproving_outcome'.
- Downstream deterministic outcome binding populates the canonical outcomes.
"""

import json
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field, model_validator

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

P1_PROMPT_INSTRUCTION = """OUTPUT FORMAT (BOUNDED ANALYTICAL INFERENCE REPRESENTATION - P1_ATTACK_PREDICATE):
Emit your evaluation strictly as a single JSON object with these fields:
{
  "invariant": "Security invariant statement evaluated against target",
  "evidence_gap": "Missing observation or gap in evidence (null if none)",
  "affected_target": "Target endpoint, asset ID, or parameter",
  "decision": "HYPOTHESIS" | "INSUFFICIENT_EVIDENCE" | "NO_RELEVANT_FUNCTIONALITY",
  "empirical_facts": ["FACT-xxx", "FACT-yyy"],
  "methodology_references": ["CHK-xxx"],
  "attack_predicate": {
    "subject": "Role/identity initiating attack (e.g. UNAUTHORIZED_ACTOR, TENANT_B_USER, LOWER_ROLE_ACTOR, ANONYMOUS_CALLER)",
    "operation": "Must match supplied deterministic experiment_action",
    "target": "Target endpoint, parameter, or resource identifier under test",
    "security_property": "Security invariant asserted to be breached (e.g. RESOURCE_OWNERSHIP_INTEGRITY, TENANT_ISOLATION, STATE_TRANSITION_INTEGRITY, ROLE_BOUNDARY_ENFORCEMENT)",
    "expected_violation": "Brief statement of the specific unauthorized condition"
  } | null,
  "falsification_description": "Brief explanation of verification experiment (or null if none)"
}

FIELD CONSTRAINTS & NAMESPACE RULES:
- 'empirical_facts': cite ONLY valid FACT-xxx IDs from available target evidence.
- 'methodology_references': cite ONLY valid CHK-* identifiers actually supplied. If none, emit [].
- For HYPOTHESIS: 'attack_predicate' is MANDATORY. 'attack_predicate.operation' MUST match the supplied deterministic experiment_action.
- For INSUFFICIENT_EVIDENCE or NO_RELEVANT_FUNCTIONALITY: 'attack_predicate' must be null.
- Do NOT emit 'supporting_outcome' or 'disproving_outcome'. The deterministic engine maps outcomes automatically from your validated attack_predicate.
- NEVER emit CONFIRMED as the decision.
- Do NOT wrap output in markdown formatting or add extra keys."""


class P1BairJsonObject(BaseModel):
    """Structured response model for P1 Attack-Predicate protocol."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    invariant: Optional[str] = Field(
        default=None,
        description="Security invariant statement evaluated against target",
    )
    evidence_gap: Optional[str] = Field(
        default=None,
        description="Missing observation or gap in evidence",
    )
    affected_target: Optional[str] = Field(
        default=None,
        description="Target endpoint, asset ID, or parameter",
    )
    decision: HypothesisDecision = Field(
        ...,
        description="One of NO_RELEVANT_FUNCTIONALITY, INSUFFICIENT_EVIDENCE, HYPOTHESIS",
    )
    empirical_facts: List[str] = Field(
        default_factory=list,
        description="Canonical observation fact IDs (^FACT-[A-Z0-9_-]+$)",
    )
    methodology_references: List[str] = Field(
        default_factory=list,
        description="Referenced VAPT methodology identifiers (^CHK-[A-Z0-9_-]+$)",
    )
    attack_predicate: Optional[AttackPredicate] = Field(
        default=None,
        description="Typed attack predicate asserting the security violation under test",
    )
    falsification_description: Optional[str] = Field(
        default=None,
        description="Brief natural-language description of verification experiment",
    )

    @model_validator(mode="after")
    def validate_decision_consistency(self) -> "P1BairJsonObject":
        if self.decision == HypothesisDecision.HYPOTHESIS:
            if not self.attack_predicate:
                raise ValueError("Mandatory attack_predicate slot missing for HYPOTHESIS decision")
            if not self.invariant:
                raise ValueError("Mandatory invariant slot missing for HYPOTHESIS decision")
            if not self.affected_target:
                raise ValueError("Mandatory affected_target slot missing for HYPOTHESIS decision")
        elif self.decision in (HypothesisDecision.INSUFFICIENT_EVIDENCE, HypothesisDecision.NO_RELEVANT_FUNCTIONALITY):
            # For non-hypothesis, attack_predicate is optional/null
            pass
        return self

    @classmethod
    def get_inference_schema(cls) -> Dict[str, Any]:
        """JSON Schema suitable for Ollama native constrained decoding."""
        valid_props = sorted([e.value for e in SecurityPropertyDomain])
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
                    "description": "Target endpoint, asset ID, or parameter",
                },
                "decision": {
                    "type": "string",
                    "enum": [
                        "NO_RELEVANT_FUNCTIONALITY",
                        "INSUFFICIENT_EVIDENCE",
                        "HYPOTHESIS",
                    ],
                    "description": "One of NO_RELEVANT_FUNCTIONALITY, INSUFFICIENT_EVIDENCE, HYPOTHESIS (never CONFIRMED)",
                },
                "empirical_facts": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "pattern": FACT_NAMESPACE_PATTERN,
                    },
                    "description": "Canonical observation fact IDs (^FACT-[A-Z0-9_-]+$)",
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
                            "description": "Target endpoint or parameter",
                        },
                        "security_property": {
                            "type": "string",
                            "enum": valid_props,
                            "description": "Security invariant property asserted to be breached",
                        },
                        "expected_violation": {
                            "type": ["string", "null"],
                            "description": "Specific unauthorized condition asserted",
                        },
                    },
                    "required": ["subject", "operation", "target", "security_property"],
                },
                "falsification_description": {
                    "type": ["string", "null"],
                    "description": "Brief description of verification experiment",
                },
            },
            "required": [
                "invariant",
                "evidence_gap",
                "affected_target",
                "decision",
                "empirical_facts",
                "methodology_references",
                "attack_predicate",
                "falsification_description",
            ],
        }


def parse_p1_response(raw_text: str) -> Tuple[Optional[P1BairJsonObject], Optional[str]]:
    """
    Parses a raw response string into a P1BairJsonObject.
    Returns (parsed_object, error_message).
    """
    if not raw_text or not raw_text.strip():
        return None, "Empty response body"

    text = raw_text.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    try:
        data = json.loads(text)
    except Exception as exc:
        return None, f"JSON parsing failed: {exc}"

    if not isinstance(data, dict):
        return None, f"Parsed JSON is not an object: {type(data).__name__}"

    try:
        obj = P1BairJsonObject.model_validate(data)
        return obj, None
    except Exception as exc:
        return None, f"Schema validation failed: {exc}"
