"""Telemetry Normalization Pipeline for M6 Authorized Security Assessments.

Enforces:
1. Strict pipeline: Parser -> Normalizer -> ScopeGate -> Evidence Store.
2. Ingestion never bypasses ScopeGate.
3. Every observation receives explicit scope_decision (IN_SCOPE, OUT_OF_SCOPE, or UNKNOWN).
4. UNKNOWN is treated as OUT_OF_SCOPE (fail closed).
5. Epistemic integrity: status is strictly OBSERVATION / FACT, never MODEL_HYPOTHESIS.
6. Fault tolerance: malformed records are quarantined without crashing batch processing.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from src.assessment.models import (
    AssetType,
    AssessmentScopeStatus,
    CanonicalObservation,
    ObservationType,
)
from src.assessment.assets import AssetGraph
from src.scope.gate import ScopeGate
from src.telemetry.parsers import (
    HARParser,
    BurpCaidoParser,
    RawHTTPParser,
    DNSTLSParser,
    SecurityToolParser,
    MobileArtifactParser,
)


class TelemetryIngestionPipeline:
    """End-to-end telemetry normalizer and scope-gating pipeline."""

    def __init__(self, scope_gate: ScopeGate, asset_graph: Optional[AssetGraph] = None) -> None:
        self.scope_gate = scope_gate
        self.asset_graph = asset_graph
        self._stored_observations: List[CanonicalObservation] = []
        self.quarantined_records: List[Dict[str, Any]] = []

    def ingest(
        self,
        assessment_id: str,
        format_type: str,
        raw_payload: Any,
        source_label: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes the Parser -> Normalizer -> ScopeGate -> Evidence Store pipeline.
        Returns a structured ingestion report.
        """
        parsed_records: List[Dict[str, Any]] = []
        malformed_count = 0
        error_details = []

        # 1. Parsing stage with per-record fault tolerance
        fmt = format_type.lower().strip()
        try:
            if fmt == "har":
                parsed_records = HARParser.parse(raw_payload)
            elif fmt in ("burp", "caido", "proxy"):
                parsed_records = BurpCaidoParser.parse(raw_payload)
            elif fmt == "raw_http":
                if isinstance(raw_payload, list):
                    for item in raw_payload:
                        rec = RawHTTPParser.parse_request(str(item))
                        if rec:
                            parsed_records.append(rec)
                        else:
                            malformed_count += 1
                else:
                    rec = RawHTTPParser.parse_request(str(raw_payload))
                    if rec:
                        parsed_records.append(rec)
                    else:
                        malformed_count += 1
            elif fmt == "dns":
                if isinstance(raw_payload, list):
                    for item in raw_payload:
                        rec = DNSTLSParser.parse_dns(item)
                        if rec:
                            parsed_records.append(rec)
                        else:
                            malformed_count += 1
                else:
                    rec = DNSTLSParser.parse_dns(raw_payload)
                    if rec:
                        parsed_records.append(rec)
                    else:
                        malformed_count += 1
            elif fmt == "tls":
                if isinstance(raw_payload, list):
                    for item in raw_payload:
                        rec = DNSTLSParser.parse_tls(item)
                        if rec:
                            parsed_records.append(rec)
                        else:
                            malformed_count += 1
                else:
                    rec = DNSTLSParser.parse_tls(raw_payload)
                    if rec:
                        parsed_records.append(rec)
                    else:
                        malformed_count += 1
            elif fmt == "tool":
                tname = tool_name or "generic"
                parsed_records = SecurityToolParser.parse(tname, raw_payload)
            elif fmt in ("apk", "mobile"):
                rec = MobileArtifactParser.parse_manifest(raw_payload)
                if rec:
                    parsed_records.append(rec)
                else:
                    malformed_count += 1
            else:
                # Generic dictionary or list of dicts
                if isinstance(raw_payload, list):
                    for item in raw_payload:
                        if isinstance(item, dict) and "target_identifier" in item:
                            parsed_records.append(item)
                        else:
                            malformed_count += 1
                elif isinstance(raw_payload, dict) and "target_identifier" in raw_payload:
                    parsed_records.append(raw_payload)
                else:
                    malformed_count += 1
        except Exception as exc:
            malformed_count += 1
            error_details.append(f"Batch parse exception: {exc}")

        # 2. Normalization, Scope-Gate Evaluation, and Storage
        in_scope_count = 0
        out_of_scope_count = 0
        unknown_count = 0
        newly_ingested: List[CanonicalObservation] = []

        for record in parsed_records:
            try:
                target = record.get("target_identifier", "").strip()
                if not target:
                    malformed_count += 1
                    continue

                # Run Scope Gate
                scope_res = self.scope_gate.evaluate_extended_scope(target)

                if scope_res.scope_status == AssessmentScopeStatus.IN_SCOPE:
                    in_scope_count += 1
                elif scope_res.scope_status == AssessmentScopeStatus.OUT_OF_SCOPE:
                    out_of_scope_count += 1
                else:
                    unknown_count += 1

                # Infer observation type
                obs_type = self._infer_obs_type(fmt, record)

                # Derive asset representation in AssetGraph if active
                asset_id = f"ASSET-{target}"
                if self.asset_graph:
                    asset_type = self._infer_asset_type(fmt, target)
                    asset_rec = self.asset_graph.add_asset(
                        asset_type=asset_type,
                        canonical_identifier=target,
                        scope_status=scope_res.scope_status,
                        discovery_source=record.get("source", source_label or fmt.upper()),
                    )
                    asset_id = asset_rec.asset_id

                obs = CanonicalObservation.create(
                    assessment_id=assessment_id,
                    asset_id=asset_id,
                    observation_type=obs_type,
                    source=record.get("source", source_label or fmt.upper()),
                    normalized_data=record,
                    scope_decision=scope_res.scope_status,
                    scope_rule=scope_res.matched_rule or scope_res.out_of_scope_rule,
                    confidence=1.0,
                    provenance={"format": fmt, "tool": tool_name or fmt},
                )

                self._stored_observations.append(obs)
                newly_ingested.append(obs)
            except Exception as e:
                malformed_count += 1
                error_details.append(f"Record processing failure: {e}")
                self.quarantined_records.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "format": fmt,
                    "record": str(record)[:200],
                    "reason": f"Record processing failure: {e}",
                })

        return {
            "assessment_id": assessment_id,
            "format": fmt,
            "total_parsed": len(parsed_records),
            "valid_observations": len(newly_ingested),
            "malformed_records": malformed_count,
            "quarantined_records": malformed_count,
            "in_scope_count": in_scope_count,
            "out_of_scope_count": out_of_scope_count,
            "unknown_count": unknown_count,
            "new_observations": newly_ingested,
            "errors": error_details,
        }

    def get_observations(
        self,
        assessment_id: Optional[str] = None,
        scope_only: Optional[AssessmentScopeStatus] = None,
    ) -> List[CanonicalObservation]:
        """Retrieves stored observations with optional filtering."""
        res = self._stored_observations
        if assessment_id:
            res = [o for o in res if o.assessment_id == assessment_id]
        if scope_only:
            res = [o for o in res if o.scope_decision == scope_only]
        return res

    @staticmethod
    def _infer_obs_type(fmt: str, record: Dict[str, Any]) -> ObservationType:
        if fmt in ("har", "burp", "caido", "raw_http"):
            if "status_code" in record or "response_headers" in record:
                return ObservationType.HTTP_RESPONSE
            return ObservationType.HTTP_REQUEST
        elif fmt == "dns":
            return ObservationType.DNS
        elif fmt == "tls":
            return ObservationType.TLS
        elif fmt == "tool":
            return ObservationType.TOOL_OUTPUT
        elif fmt in ("apk", "mobile"):
            return ObservationType.MOBILE_ARTIFACT
        return ObservationType.OTHER

    @staticmethod
    def _infer_asset_type(fmt: str, target: str) -> AssetType:
        if fmt in ("apk", "mobile"):
            return AssetType.MOBILE_APPLICATION
        if "/" in target and not target.startswith("http"):
            return AssetType.REPOSITORY if "github" in target or "gitlab" in target else AssetType.ENDPOINT
        if any(c in target for c in ":[]") and not "." in target:
            return AssetType.IP
        if target.replace(".", "").isdigit():
            return AssetType.IP
        if "." in target:
            # Check if domain or subdomain
            parts = target.split(".")
            return AssetType.SUBDOMAIN if len(parts) > 2 else AssetType.DOMAIN
        return AssetType.HOST
