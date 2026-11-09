"""Centralized Canonical Provenance Serialization and Hashing Module.

Contract Specification (Addendum E):
    - Format: JSON
    - Encoding: UTF-8
    - Key ordering: sort_keys=True
    - Delimiters: separators=(",", ":") with no extraneous whitespace
    - ASCII escaping: ensure_ascii=False
    - Float/Numeric: deterministic string or standard json serialization without precision ambiguity
    - List ordering: Semantic insertion order MUST be preserved.
      * gate_triggers ordering MUST be deterministic.
      * audit_event_ids ordering MUST be deterministic.
      * reasons ordering MUST be deterministic.
      * Ordered lists MUST NOT be converted to sets merely to stabilize hashing.
    - Binding: CascadeHandoffPacket.provenance_hash cryptographically binds:
          Channel A (LosslessStructuralPack)
          +
          GateValidationResult
          +
          DeterministicRoutingDecision
"""

import hashlib
import json
from typing import Any, Dict
from pydantic import BaseModel

from src.evidence.cascade_models import (
    DeterministicRoutingDecision,
    GateValidationResult,
    LosslessStructuralPack,
)


def normalize_for_serialization(val: Any) -> Any:
    """
    Recursively normalize an object into primitives suitable for canonical JSON.
    Preserves list order; converts pydantic models and dictionaries recursively.
    Does NOT convert lists to sets.
    """
    if isinstance(val, BaseModel):
        return normalize_for_serialization(val.model_dump())
    elif isinstance(val, dict):
        return {k: normalize_for_serialization(v) for k, v in val.items()}
    elif isinstance(val, (list, tuple)):
        return [normalize_for_serialization(item) for item in val]
    elif val is None or isinstance(val, (str, int, float, bool)):
        return val
    else:
        return str(val)


def canonical_json_serialize(obj: Any) -> bytes:
    """
    Serialize an object into byte-exact canonical JSON representation.
    Guarantees deterministic output across platforms and dictionary key orderings.
    """
    normalized = normalize_for_serialization(obj)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_canonical_sha256(obj: Any) -> str:
    """Compute SHA-256 hex digest over canonical serialized bytes of obj."""
    return hashlib.sha256(canonical_json_serialize(obj)).hexdigest()


def compute_provenance_hash(
    channel_a: LosslessStructuralPack,
    gate_result: GateValidationResult,
    routing_decision: DeterministicRoutingDecision,
) -> str:
    """
    Compute the canonical provenance hash binding:
        Channel A (LosslessStructuralPack)
        +
        GateValidationResult
        +
        DeterministicRoutingDecision

    Produces a deterministic SHA-256 digest over the canonical byte representation
    of the composite dictionary.
    """
    composite = {
        "channel_a": normalize_for_serialization(channel_a),
        "gate_result": normalize_for_serialization(gate_result),
        "routing_decision": normalize_for_serialization(routing_decision),
    }
    return compute_canonical_sha256(composite)
