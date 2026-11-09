"""Evidence ingestion data models and result contracts."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IngestionSourceType(str, Enum):
    HAR = "har"
    RAW_HTTP = "raw_http"
    MANUAL = "manual"
    BURP = "burp"


class RawTransactionRecord(BaseModel):
    """Raw parsed HTTP transaction before normalization and scope checks."""
    method: str
    url: str
    host: str
    path: str
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    response_status: int = 200
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    timestamp: Optional[str] = None
    source_tool: str = "generic_http"
    source_artifact: str = ""
    researcher_note: Optional[str] = None


class InvestigationObservation(BaseModel):
    """Canonical target evidence observation persisted in an investigation."""
    id: str
    investigation_id: str
    fact_id: str
    asset_id: str
    http_method: str
    host: str
    raw_path: str
    normalized_path: str
    response_status: int
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    statement: str
    source_type: str
    source_artifact: Optional[str] = None
    researcher_note: Optional[str] = None
    transaction_digest: str
    redacted_secret_count: int = 0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class IngestionResult(BaseModel):
    """Structured summary of evidence ingestion operation."""
    imported_count: int = 0
    accepted_count: int = 0
    duplicate_count: int = 0
    out_of_scope_count: int = 0
    redacted_secret_count: int = 0
    parsing_failures: int = 0
    errors: List[str] = Field(default_factory=list)
    accepted_observations: List[InvestigationObservation] = Field(default_factory=list)

    # Structured details for auditability & explicit scope transparency
    observations_added: int = 0
    duplicates: int = 0
    out_of_scope: List[Dict[str, Any]] = Field(default_factory=list)
    parse_errors: List[str] = Field(default_factory=list)
