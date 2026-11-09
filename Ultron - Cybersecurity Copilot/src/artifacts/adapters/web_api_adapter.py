"""Web and API Artifact Ingestion and Observation Normalization Adapter.

Enforces:
- Normalization into canonical observation types (HTTP_REQUEST, HTTP_RESPONSE, API_ENDPOINT, etc.)
- Deep secret redaction of tokens and cookies prior to evidence recording
- Protection of raw original payload
"""

import json
from typing import Any, Dict, List, Optional, Tuple

from src.artifacts.metadata import ArtifactRecord, ArtifactType
from src.assessment.models import (
    AssessmentScopeStatus,
    CanonicalObservation,
    ObservationType,
)
from src.assessment.secrets import SecretRedactor


class WebApiArtifactAdapter:
    """Extracts, redacts, and normalizes Web and API artifacts into canonical observations."""

    @classmethod
    def process_artifact(
        cls,
        record: ArtifactRecord,
        raw_bytes: bytes,
        scope_gate: Optional[Any] = None,
    ) -> List[CanonicalObservation]:
        """Parses Web/API artifact into normalized, secret-redacted canonical observations."""
        observations: List[CanonicalObservation] = []

        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text = raw_bytes.decode("latin-1", errors="replace")

        # 1. HAR Files
        if record.artifact_type == ArtifactType.HAR or "log" in text[:200]:
            try:
                data = json.loads(text)
                entries = data.get("log", {}).get("entries", [])
                for idx, entry in enumerate(entries):
                    req = entry.get("request", {})
                    resp = entry.get("response", {})
                    url = req.get("url", "")
                    method = req.get("method", "GET")
                    status_code = resp.get("status", 200)

                    # Secret redaction on headers and body
                    redacted_headers = []
                    for h in req.get("headers", []):
                        if isinstance(h, dict):
                            h_name = h.get("name", "")
                            h_val = h.get("value", "")
                            if any(s in h_name.lower() for s in ("auth", "token", "key", "cookie", "secret", "password")):
                                h_val = "SECRET_REDACTED"
                            else:
                                h_val, _ = SecretRedactor.redact_text(h_val)
                            redacted_headers.append({"name": h_name, "value": h_val})

                    raw_body = req.get("postData", {}).get("text", "")
                    redacted_body, _ = SecretRedactor.redact_text(raw_body)

                    scope_status = AssessmentScopeStatus.IN_SCOPE
                    if scope_gate and url:
                        res = scope_gate.evaluate_extended_scope(url)
                        scope_status = res.scope_status

                    norm_data = {
                        "target_identifier": url,
                        "url": url,
                        "method": method,
                        "status_code": status_code,
                        "headers": redacted_headers,
                        "body": redacted_body,
                        "source_artifact": record.artifact_id,
                        "entry_index": idx,
                    }

                    obs = CanonicalObservation.create(
                        assessment_id=record.assessment_id,
                        asset_id=url,
                        observation_type=ObservationType.HTTP_RESPONSE,
                        source="HAR_ARTIFACT",
                        normalized_data=norm_data,
                        scope_decision=scope_status,
                        raw_reference=f"{record.artifact_id}#entry-{idx}",
                        provenance={"artifact_id": record.artifact_id, "sha256": record.sha256},
                    )
                    observations.append(obs)
            except Exception:
                pass

        # 2. OpenAPI / Swagger Specs
        elif "openapi" in text[:300] or "swagger" in text[:300]:
            try:
                data = json.loads(text)
                paths = data.get("paths", {})
                for path_key, methods in paths.items():
                    if isinstance(methods, dict):
                        for m_key, m_val in methods.items():
                            if m_key.lower() in ("get", "post", "put", "delete", "patch"):
                                norm_data = {
                                    "endpoint": path_key,
                                    "method": m_key.upper(),
                                    "summary": m_val.get("summary", ""),
                                    "parameters": m_val.get("parameters", []),
                                    "source_artifact": record.artifact_id,
                                }
                                obs = CanonicalObservation.create(
                                    assessment_id=record.assessment_id,
                                    asset_id=path_key,
                                    observation_type=ObservationType.API_ENDPOINT,
                                    source="OPENAPI_SPEC",
                                    normalized_data=norm_data,
                                    scope_decision=AssessmentScopeStatus.IN_SCOPE,
                                    raw_reference=record.artifact_id,
                                    provenance={"artifact_id": record.artifact_id, "sha256": record.sha256},
                                )
                                observations.append(obs)
            except Exception:
                pass

        # 3. JSON API Captures / GraphQL
        elif record.artifact_type == ArtifactType.JSON:
            try:
                data = json.loads(text)
                redacted_data = SecretRedactor.redact_dict(data)

                # Check for GraphQL query
                if "query" in data and ("mutation" in data.get("query", "") or "{" in data.get("query", "")):
                    obs_type = ObservationType.API_ENDPOINT
                    source = "GRAPHQL_CAPTURE"
                else:
                    obs_type = ObservationType.HTTP_RESPONSE
                    source = "JSON_API_CAPTURE"

                norm_data = {
                    "payload": redacted_data,
                    "source_artifact": record.artifact_id,
                }
                obs = CanonicalObservation.create(
                    assessment_id=record.assessment_id,
                    asset_id=record.filename,
                    observation_type=obs_type,
                    source=source,
                    normalized_data=norm_data,
                    scope_decision=AssessmentScopeStatus.IN_SCOPE,
                    raw_reference=record.artifact_id,
                    provenance={"artifact_id": record.artifact_id, "sha256": record.sha256},
                )
                observations.append(obs)
            except Exception:
                pass

        return observations
