"""Canonical Evidence data models and representations."""

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EpistemicCertainty(str, Enum):
    OBSERVED = "OBSERVED"
    DOCUMENTED = "DOCUMENTED"
    DETERMINISTIC_DERIVATION = "DETERMINISTIC_DERIVATION"


class EvidenceTrust(str, Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"


class CanonicalParameter(BaseModel):
    """Canonical representation of an extracted HTTP parameter."""
    param_id: str
    asset_id: str
    param_name: str
    location: str # query, path, body, header, cookie
    content_type: Optional[str] = None
    param_type: Optional[str] = None
    is_server_volatile: bool = False

    @classmethod
    def compute_param_id(cls, asset_id: str, param_name: str, location: str) -> str:
        raw = f"{asset_id}:{param_name}:{location}".lower()
        return f"PARAM-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12].upper()}"

    @classmethod
    def create(
        cls,
        asset_id: str,
        param_name: str,
        location: str,
        content_type: Optional[str] = None,
        param_type: Optional[str] = None,
        is_server_volatile: bool = False,
    ) -> "CanonicalParameter":
        param_id = cls.compute_param_id(asset_id, param_name, location)
        return cls(
            param_id=param_id,
            asset_id=asset_id,
            param_name=param_name,
            location=location,
            content_type=content_type,
            param_type=param_type,
            is_server_volatile=is_server_volatile,
        )


class CanonicalEvidence(BaseModel):
    """
    Tool-independent Canonical Evidence object capturing all normalized observation details.
    """
    fact_id: str
    certainty: EpistemicCertainty
    statement: str
    source_tool: str
    source_version: Optional[str] = None
    trust: EvidenceTrust = EvidenceTrust.UNTRUSTED
    scope_decision_id: Optional[str] = None

    # Endpoint & Asset Association
    asset_id: str
    http_method: str
    host: str
    raw_path: str
    normalized_path: str
    normalization_confidence: float = 1.0
    application_mutability: str = "UNKNOWN"
    liveness: str = "SHADOW_ACTIVE"

    # Extracted Parameters & Data
    parameters: List[CanonicalParameter] = Field(default_factory=list)
    identity_context: Optional[str] = None
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body_summary: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body_summary: Optional[str] = None
    raw_evidence_ref: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def compute_asset_id(cls, method: str, host: str, normalized_path: str) -> str:
        """Derive canonical asset ID: sha256(METHOD + host + normalized_path)."""
        raw = f"{method.upper()}:{host.lower().strip()}:{normalized_path.strip()}".strip()
        return f"ASSET-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12].upper()}"

    @classmethod
    def compute_fact_id(cls, source_tool: str, statement: str, timestamp: Optional[str] = None) -> str:
        """Derive canonical fact ID."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        raw = f"{source_tool}:{statement}:{ts}"
        return f"FACT-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12].upper()}"
