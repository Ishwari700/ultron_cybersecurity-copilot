"""Generic HTTP observation adapter for request/response captures."""

from urllib.parse import parse_qs, urlparse
from typing import Any, Dict, List, Optional
from src.evidence.adapters.base import BaseObservationAdapter
from src.evidence.models import CanonicalEvidence, CanonicalParameter, EpistemicCertainty, EvidenceTrust


class GenericHttpAdapter(BaseObservationAdapter):
    """Ingests generic HTTP request/response interactions into CanonicalEvidence."""

    def ingest(self, raw_data: Any, scope_decision_id: Optional[str] = None) -> List[CanonicalEvidence]:
        """
        raw_data can be a single interaction dict or a list of interaction dicts:
        {
            "method": "GET",
            "url": "https://api.target.com/v1/users/42?include=profile",
            "request_headers": {"Authorization": "Bearer ..."},
            "request_body": "...",
            "response_status": 200,
            "response_headers": {"Content-Type": "application/json"},
            "response_body": "...",
            "source_tool": "httpx",
            "source_version": "1.0",
        }
        """
        items = raw_data if isinstance(raw_data, list) else [raw_data]
        results: List[CanonicalEvidence] = []

        for item in items:
            method = item.get("method", "GET").upper()
            raw_url = item.get("url", "")
            parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
            host = parsed.hostname or "unknown-host"
            raw_path = parsed.path or "/"

            normalized_path, confidence = self.normalizer.normalize_path(raw_path)
            asset_id = CanonicalEvidence.compute_asset_id(method, host, normalized_path)
            mutability = self.normalizer.classify_mutability(method)

            # Redact headers
            req_headers = self.vault.redact_dict(item.get("request_headers", {}))
            resp_headers = self.vault.redact_dict(item.get("response_headers", {}))

            # Redact & compress bodies
            req_body_raw = self.vault.redact_text(str(item.get("request_body", "")))
            resp_body_raw = self.vault.redact_text(str(item.get("response_body", "")))

            req_summary = self.compressor.compress(req_body_raw, req_headers.get("content-type"))
            resp_summary = self.compressor.compress(resp_body_raw, resp_headers.get("content-type"))

            # Extract parameters
            params: List[CanonicalParameter] = []
            # 1. Query parameters
            query_params = parse_qs(parsed.query)
            for q_name in query_params:
                params.append(
                    CanonicalParameter.create(
                        asset_id=asset_id,
                        param_name=q_name,
                        location="query",
                        param_type="string",
                    )
                )

            # 2. Path template parameters
            for part in normalized_path.split("/"):
                if part.startswith("{") and part.endswith("}"):
                    p_name = part[1:-1]
                    params.append(
                        CanonicalParameter.create(
                            asset_id=asset_id,
                            param_name=p_name,
                            location="path",
                            param_type="identifier",
                        )
                    )

            # Statement
            resp_status = item.get("response_status", 200)
            statement = f"{method} {raw_url} returned HTTP {resp_status}"
            source_tool = item.get("source_tool", "generic_http")
            fact_id = CanonicalEvidence.compute_fact_id(source_tool, statement)

            evidence = CanonicalEvidence(
                fact_id=fact_id,
                certainty=EpistemicCertainty.OBSERVED,
                statement=statement,
                source_tool=source_tool,
                source_version=item.get("source_version"),
                trust=EvidenceTrust.UNTRUSTED, # live target traffic is untrusted
                scope_decision_id=scope_decision_id,
                asset_id=asset_id,
                http_method=method,
                host=host,
                raw_path=raw_path,
                normalized_path=normalized_path,
                normalization_confidence=confidence,
                application_mutability=mutability,
                liveness="SHADOW_ACTIVE" if resp_status != 404 else "ZOMBIE_STALE",
                parameters=params,
                identity_context=item.get("identity_context"),
                request_headers=req_headers,
                request_body_summary=req_summary,
                response_status=resp_status,
                response_headers=resp_headers,
                response_body_summary=resp_summary,
                raw_evidence_ref=item.get("raw_evidence_ref"),
            )
            results.append(evidence)

        return results
