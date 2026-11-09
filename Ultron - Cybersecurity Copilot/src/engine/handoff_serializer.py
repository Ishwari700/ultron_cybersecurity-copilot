"""
Intervention I6: Pure Invariant 3B Handoff Serializer.

Enforces a protected, deterministic boundary between the 3B triage stage
and the 7B reasoning stage:
- Serializes strictly verified Class-1 predicate booleans and exact EvidenceGapType.
- Suppresses subjective 3B category guesses and free-form triage rationale.
- Prohibits ground-truth leakage, secrets, tokens, confidence scores, and scope authority.
- Guaranteed byte-identical output for identical inputs with immutable descriptors.
"""

from __future__ import annotations

import hashlib
import json
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Union

from src.knowledge.models import EvidenceGapType
from src.evidence.cascade_models import (
    CascadeHandoffPacket,
    LosslessStructuralPack,
    RawTriageOutput,
    TriageMetadataPacket,
)


CANONICAL_CLASS1_PREDICATE_KEYS: tuple[str, ...] = (
    "auth_header_delta",
    "has_cross_identity_object_access_success",
    "has_cross_role_response_shape_delta",
    "has_evidence_parse_asymmetry",
    "has_numeric_path_identifier",
    "has_observed_contradictions",
    "has_privilege_level_delta",
    "has_unauthenticated_success",
    "has_unseen_endpoint_parameter",
    "status_code_changed_under_different_role",
)

PROHIBITED_KEYS: frozenset[str] = frozenset({
    # Hidden reasoning / CoT
    "cot",
    "chain_of_thought",
    "reasoning_trace",
    "thought",
    "thoughts",
    "internal_reasoning",
    # Free-form 3B reasoning
    "triage_rationale",
    "rationale",
    "free_text",
    "analysis",
    "notes",
    # Subjective category guesses
    "suspected_category",
    # Confidence / probabilities / scoring
    "confidence",
    "probability",
    "score",
    "cvss",
    "vulnerability_score",
    "risk_score",
    "certainty",
    # Ground truth / benchmark labels
    "is_vulnerable",
    "ground_truth",
    "gold_decision",
    "oracle_verdict",
    "oracle_vulnerability_status",
    "vulnerable_label",
    "control_label",
    "oracle_label",
    # Evaluation labels
    "evaluation_track",
    "track_id",
    "tp_label",
    "fp_label",
    "tn_label",
    "fn_label",
    "eval_label",
    "benchmark_label",
    "expected_outcome",
    "expected_decision",
    "expected_verdict",
    "gold_standard_hypothesis",
    "human_annotation",
    "reviewer_label",
    "study_label",
    # Secrets / credentials
    "cookie",
    "cookies",
    "authorization",
    "bearer",
    "token",
    "session_token",
    "jwt",
    "csrf_token",
    "api_key",
    "secret",
    "password",
    "signing_key",
    "credentials",
    # Scope authority
    "scope_authority",
    "scope_override",
    "in_scope_override",
    # Raw untrusted target payloads
    "raw_body_sample",
    "payload",
    "body_bytes",
})


class HandoffValidationError(ValueError):
    """Raised when handoff input fails deterministic validation or violates safety boundaries."""
    pass


class ProtectedHandoffDescriptor:
    """
    Immutable descriptor for a protected 3B -> 7B invariant handoff.
    
    Guarantees:
    - Immutable fields and mapping after creation.
    - Deterministic SHA-256 provenance hash of canonical JSON structure.
    - Formatted, delimited wire string for prompt Partition P3.
    """
    __slots__ = (
        "_schema_version",
        "_invariant",
        "_evidence_gap_type",
        "_class1_predicates",
        "_handoff_hash",
        "_serialized_handoff",
    )

    def __init__(
        self,
        schema_version: str,
        invariant: str,
        evidence_gap_type: EvidenceGapType,
        class1_predicates: Mapping[str, bool],
        handoff_hash: str,
        serialized_handoff: str,
    ) -> None:
        object.__setattr__(self, "_schema_version", schema_version)
        object.__setattr__(self, "_invariant", invariant)
        object.__setattr__(self, "_evidence_gap_type", evidence_gap_type)
        object.__setattr__(
            self,
            "_class1_predicates",
            MappingProxyType(dict(class1_predicates)),
        )
        object.__setattr__(self, "_handoff_hash", handoff_hash)
        object.__setattr__(self, "_serialized_handoff", serialized_handoff)

    @property
    def schema_version(self) -> str:
        return self._schema_version

    @property
    def invariant(self) -> str:
        return self._invariant

    @property
    def evidence_gap_type(self) -> EvidenceGapType:
        return self._evidence_gap_type

    @property
    def class1_predicates(self) -> Mapping[str, bool]:
        return self._class1_predicates

    @property
    def handoff_hash(self) -> str:
        return self._handoff_hash

    @property
    def serialized_handoff(self) -> str:
        return self._serialized_handoff

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError(f"ProtectedHandoffDescriptor is immutable; cannot modify attribute '{name}'")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"ProtectedHandoffDescriptor is immutable; cannot delete attribute '{name}'")

    def __repr__(self) -> str:
        return (
            f"ProtectedHandoffDescriptor(schema_version={self._schema_version!r}, "
            f"invariant={self._invariant!r}, evidence_gap_type={self._evidence_gap_type.value!r}, "
            f"handoff_hash={self._handoff_hash!r})"
        )

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ProtectedHandoffDescriptor):
            return False
        return (
            self._schema_version == other._schema_version
            and self._invariant == other._invariant
            and self._evidence_gap_type == other._evidence_gap_type
            and dict(self._class1_predicates) == dict(other._class1_predicates)
            and self._handoff_hash == other._handoff_hash
        )


class HandoffSerializer:
    """
    Deterministic serializer enforcing the I6 protected invariant handoff boundary.
    """

    SCHEMA_VERSION: str = "2.0.0"

    @classmethod
    def validate_inputs(
        cls,
        invariant: Any,
        evidence_gap_type: Any,
        class1_predicates: Any,
        strict_prohibited_check: Optional[Dict[str, Any]] = None,
    ) -> tuple[str, EvidenceGapType, Dict[str, bool]]:
        """
        Validates all inputs against canonical contracts.
        Fails closed on missing, malformed, or prohibited attributes.
        """
        # 1. Prohibited keys validation if raw dictionary supplied
        if strict_prohibited_check:
            for key in strict_prohibited_check:
                k_lower = key.lower()
                if k_lower in PROHIBITED_KEYS:
                    raise HandoffValidationError(
                        f"Prohibited field detected in handoff input: '{key}'. "
                        "Handoff must not carry reasoning traces, ground truth, secrets, or scores."
                    )

        # 2. Invariant validation
        if not invariant or not isinstance(invariant, str):
            raise HandoffValidationError("invariant must be a non-empty string")
        clean_invariant = invariant.strip()
        if not clean_invariant:
            raise HandoffValidationError("invariant must not be empty or whitespace-only")
        if clean_invariant.upper() in ("N/A", "TODO", "NONE", "UNKNOWN"):
            raise HandoffValidationError(f"invariant cannot be placeholder value: '{clean_invariant}'")

        # 3. EvidenceGapType validation
        if isinstance(evidence_gap_type, EvidenceGapType):
            validated_gap = evidence_gap_type
        elif isinstance(evidence_gap_type, str):
            try:
                validated_gap = EvidenceGapType(evidence_gap_type)
            except ValueError:
                raise HandoffValidationError(
                    f"Unsupported or malformed evidence_gap_type: '{evidence_gap_type}'. "
                    f"Must match closed enum: {[e.value for e in EvidenceGapType]}"
                )
        else:
            raise HandoffValidationError(
                f"evidence_gap_type must be an instance of EvidenceGapType or valid str, got {type(evidence_gap_type)}"
            )

        # 4. Class-1 Predicates validation
        clean_predicates: Dict[str, bool] = {}

        if isinstance(class1_predicates, LosslessStructuralPack):
            for k in CANONICAL_CLASS1_PREDICATE_KEYS:
                val = getattr(class1_predicates, k, False)
                clean_predicates[k] = bool(val)
        elif isinstance(class1_predicates, dict):
            # Check for unknown / prohibited keys in predicates dict
            for k, val in class1_predicates.items():
                k_lower = k.lower()
                if k_lower in PROHIBITED_KEYS:
                    raise HandoffValidationError(f"Prohibited key '{k}' found in predicates dict")
                if k not in CANONICAL_CLASS1_PREDICATE_KEYS:
                    raise HandoffValidationError(
                        f"Unknown predicate key '{k}'. Must be one of canonical Class-1 predicates: "
                        f"{CANONICAL_CLASS1_PREDICATE_KEYS}"
                    )
                if not isinstance(val, bool):
                    raise HandoffValidationError(
                        f"Predicate value for '{k}' must be bool, got {type(val)}: {val!r}"
                    )
            # Ensure all canonical Class-1 keys are populated
            for k in CANONICAL_CLASS1_PREDICATE_KEYS:
                clean_predicates[k] = bool(class1_predicates.get(k, False))
        elif class1_predicates is None:
            raise HandoffValidationError("class1_predicates must not be None")
        else:
            raise HandoffValidationError(
                f"class1_predicates must be LosslessStructuralPack or dict, got {type(class1_predicates)}"
            )

        return clean_invariant, validated_gap, clean_predicates

    @classmethod
    def serialize(
        cls,
        invariant: str,
        evidence_gap_type: Union[EvidenceGapType, str],
        class1_predicates: Union[LosslessStructuralPack, Dict[str, bool]],
        raw_input_context: Optional[Dict[str, Any]] = None,
    ) -> ProtectedHandoffDescriptor:
        """
        Serializes verified invariant and Class-1 predicates into a deterministic ProtectedHandoffDescriptor.
        """
        clean_invariant, validated_gap, clean_predicates = cls.validate_inputs(
            invariant=invariant,
            evidence_gap_type=evidence_gap_type,
            class1_predicates=class1_predicates,
            strict_prohibited_check=raw_input_context,
        )

        # 1. Deterministic canonical representation for cryptographic hashing
        canonical_dict = {
            "class1_predicates": {k: clean_predicates[k] for k in sorted(clean_predicates.keys())},
            "evidence_gap_type": validated_gap.value,
            "invariant": clean_invariant,
            "schema_version": cls.SCHEMA_VERSION,
        }
        canonical_bytes = json.dumps(
            canonical_dict,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        handoff_hash = hashlib.sha256(canonical_bytes).hexdigest()

        # 2. Canonical wire format for prompt Partition P3
        predicate_lines = [
            f"  {k}: {clean_predicates[k]}"
            for k in sorted(clean_predicates.keys())
        ]
        predicates_block = "\n".join(predicate_lines)

        serialized_text = (
            "=== PROTECTED 3B -> 7B INVARIANT HANDOFF (PARTITION P3) ===\n"
            "[AUTHORITATIVE STRUCTURED ANALYTICAL INPUT - NOT A CLAIM OF VULNERABILITY CONFIRMATION]\n"
            "[ADVISORY ONLY: NOT SCOPE AUTHORITY, NOT CONFIRMATION AUTHORITY, NOT EXECUTION AUTHORITY]\n"
            f"HANDOFF_SCHEMA_VERSION: {cls.SCHEMA_VERSION}\n"
            f"SECURITY_INVARIANT: {clean_invariant}\n"
            f"EVIDENCE_GAP_TYPE: {validated_gap.value}\n"
            "VERIFIED_CLASS1_PREDICATES:\n"
            f"{predicates_block}\n"
            f"HANDOFF_PROVENANCE_HASH: {handoff_hash}\n"
            "=== END PROTECTED HANDOFF ==="
        )

        return ProtectedHandoffDescriptor(
            schema_version=cls.SCHEMA_VERSION,
            invariant=clean_invariant,
            evidence_gap_type=validated_gap,
            class1_predicates=clean_predicates,
            handoff_hash=handoff_hash,
            serialized_handoff=serialized_text,
        )

    @classmethod
    def from_cascade_packet(
        cls,
        handoff_packet: CascadeHandoffPacket,
        evidence_gap_type: Union[EvidenceGapType, str],
        invariant: Optional[str] = None,
    ) -> ProtectedHandoffDescriptor:
        """
        Constructs a ProtectedHandoffDescriptor from an existing CascadeHandoffPacket.
        Extracts Class-1 predicates from channel_a_structural and suppresses any
        natural-language triage notes or subjective category assertions.
        """
        if not handoff_packet or not isinstance(handoff_packet, CascadeHandoffPacket):
            raise HandoffValidationError("handoff_packet must be a valid CascadeHandoffPacket")

        eff_invariant = invariant
        if not eff_invariant and handoff_packet.validated_triage:
            eff_invariant = handoff_packet.validated_triage.candidate_security_property

        if not eff_invariant:
            raise HandoffValidationError(
                "invariant is missing; must be provided explicitly or present in candidate_security_property"
            )

        return cls.serialize(
            invariant=eff_invariant,
            evidence_gap_type=evidence_gap_type,
            class1_predicates=handoff_packet.channel_a_structural,
        )

    @classmethod
    def from_3b_triage(
        cls,
        raw_triage: Union[RawTriageOutput, TriageMetadataPacket, Dict[str, Any]],
        channel_a: LosslessStructuralPack,
        evidence_gap_type: Union[EvidenceGapType, str],
        invariant: Optional[str] = None,
    ) -> ProtectedHandoffDescriptor:
        """
        Constructs a ProtectedHandoffDescriptor from raw 3B triage output and channel_a.
        Strips free-form 3B rationale, confidence, and subjective category assertions.
        """
        eff_invariant = invariant
        raw_dict: Optional[Dict[str, Any]] = None

        if isinstance(raw_triage, (RawTriageOutput, TriageMetadataPacket)):
            if not eff_invariant:
                eff_invariant = raw_triage.candidate_security_property
        elif isinstance(raw_triage, dict):
            raw_dict = raw_triage
            if not eff_invariant:
                eff_invariant = raw_triage.get("candidate_security_property") or raw_triage.get("invariant")

        if not eff_invariant:
            raise HandoffValidationError(
                "invariant is missing from 3B triage output; must be provided explicitly"
            )

        return cls.serialize(
            invariant=eff_invariant,
            evidence_gap_type=evidence_gap_type,
            class1_predicates=channel_a,
            raw_input_context=raw_dict,
        )
