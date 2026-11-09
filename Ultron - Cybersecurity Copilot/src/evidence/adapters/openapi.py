"""OpenAPI / Swagger documentation adapter producing DOCUMENTED canonical facts."""

import json
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional
import yaml

from src.evidence.adapters.base import BaseObservationAdapter
from src.evidence.models import CanonicalEvidence, CanonicalParameter, EpistemicCertainty, EvidenceTrust


class OpenApiAdapter(BaseObservationAdapter):
    """
    Parses OpenAPI 3.x and Swagger 2.0 specs into DOCUMENTED CanonicalEvidence.
    Extracts methods, paths, parameters, schemas, and security requirements.
    """

    def ingest(self, raw_data: Any, scope_decision_id: Optional[str] = None) -> List[CanonicalEvidence]:
        """
        Accepts raw spec as dict, YAML string, or JSON string.
        """
        spec: Dict[str, Any] = {}
        if isinstance(raw_data, str):
            try:
                spec = json.loads(raw_data)
            except (json.JSONDecodeError, ValueError):
                spec = yaml.safe_load(raw_data) or {}
        elif isinstance(raw_data, dict):
            spec = raw_data

        # Determine host
        host = "api.target.com"
        if "servers" in spec and spec["servers"]:
            server_url = spec["servers"][0].get("url", "")
            parsed = urlparse(server_url if "://" in server_url else f"https://{server_url}")
            if parsed.hostname:
                host = parsed.hostname
        elif "host" in spec:
            host = spec["host"]

        results: List[CanonicalEvidence] = []
        paths = spec.get("paths", {})

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            normalized_path, confidence = self.normalizer.normalize_path(path_str)

            for method_str, op in path_item.items():
                if method_str.lower() not in ("get", "post", "put", "delete", "patch", "options", "head"):
                    continue

                method = method_str.upper()
                asset_id = CanonicalEvidence.compute_asset_id(method, host, normalized_path)
                mutability = self.normalizer.classify_mutability(method)

                # Extract parameters
                params: List[CanonicalParameter] = []
                # Combine path-level and operation-level parameters
                all_params = path_item.get("parameters", []) + op.get("parameters", [])
                for p in all_params:
                    if not isinstance(p, dict) or "name" not in p:
                        continue
                    p_name = p["name"]
                    p_loc = p.get("in", "query")
                    if p_loc not in ("query", "path", "body", "header", "cookie"):
                        p_loc = "query"
                    schema = p.get("schema", {})
                    p_type = schema.get("type", "string") if isinstance(schema, dict) else "string"

                    params.append(
                        CanonicalParameter.create(
                            asset_id=asset_id,
                            param_name=p_name,
                            location=p_loc,
                            param_type=p_type,
                        )
                    )

                # Security schemes
                security = op.get("security") or spec.get("security", [])
                sec_desc = "unauthenticated" if not security else f"auth_required: {security}"

                summary = op.get("summary") or op.get("description") or ""
                statement = f"Documented endpoint {method} {path_str} ({sec_desc}). {summary}".strip()
                fact_id = CanonicalEvidence.compute_fact_id("openapi", statement)

                evidence = CanonicalEvidence(
                    fact_id=fact_id,
                    certainty=EpistemicCertainty.DOCUMENTED, # Hard requirement: DOCUMENTED certainty
                    statement=statement,
                    source_tool="openapi",
                    source_version=spec.get("openapi") or spec.get("swagger", "3.0"),
                    trust=EvidenceTrust.UNTRUSTED, # Spec comes from target, treat as untrusted data
                    scope_decision_id=scope_decision_id,
                    asset_id=asset_id,
                    http_method=method,
                    host=host,
                    raw_path=path_str,
                    normalized_path=normalized_path,
                    normalization_confidence=confidence,
                    application_mutability=mutability,
                    liveness="LIVE_DOCUMENTED",
                    parameters=params,
                    request_body_summary=self.compressor.compress(json.dumps(op.get("requestBody", {}))),
                    response_status=200,
                    response_body_summary=self.compressor.compress(json.dumps(op.get("responses", {}))),
                )
                results.append(evidence)

        return results
