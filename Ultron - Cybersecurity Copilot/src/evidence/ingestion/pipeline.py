"""Canonical Evidence Ingestion Pipeline enforcing normalization, scope, redaction, and deduplication."""

from datetime import datetime, timezone
import hashlib
import re
import secrets
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from src.core.logging import AuditLogger, get_logger
from src.database.manager import DatabaseManager
from src.evidence.compressor import SemanticCompressor
from src.evidence.ingestion.importers import BurpImporter, EvidenceImporter, HarImporter, RawHttpImporter
from src.evidence.ingestion.models import (
    IngestionResult,
    IngestionSourceType,
    InvestigationObservation,
    RawTransactionRecord,
)
from src.evidence.models import CanonicalEvidence, CanonicalParameter, EpistemicCertainty, EvidenceTrust
from src.evidence.normalizer import PathNormalizer
from src.evidence.vault import RedactionVault
from src.scope.gate import ScopeGate, canonicalize_host
from src.scope.models import ScopePolicy, ScopeDecision

import json

logger = get_logger("EvidenceIngestionPipeline")


def canonicalize_headers(headers: Optional[Any]) -> List[List[str]]:
    """Deterministically normalizes HTTP headers for canonical evidence digest.
    Converts keys to lowercase, trims whitespace, and sorts alphabetically by header name.
    Preserves multiple headers deterministically. Returns a sorted list of [key, value] pairs.
    """
    if not headers:
        return []
    if isinstance(headers, str):
        try:
            parsed = json.loads(headers)
            if isinstance(parsed, dict):
                headers = parsed
            elif isinstance(parsed, list):
                headers = parsed
            else:
                return []
        except Exception:
            return []

    normalized_pairs: List[List[str]] = []
    if isinstance(headers, dict):
        for k, v in headers.items():
            clean_k = str(k).strip().lower()
            clean_v = str(v).strip() if v is not None else ""
            normalized_pairs.append([clean_k, clean_v])
    elif isinstance(headers, list):
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                clean_k = str(item[0]).strip().lower()
                clean_v = str(item[1]).strip() if item[1] is not None else ""
                normalized_pairs.append([clean_k, clean_v])
            elif isinstance(item, dict) and "name" in item and "value" in item:
                clean_k = str(item["name"]).strip().lower()
                clean_v = str(item["value"]).strip() if item["value"] is not None else ""
                normalized_pairs.append([clean_k, clean_v])

    # Sort deterministically by header name, then value
    normalized_pairs.sort(key=lambda pair: (pair[0], pair[1]))
    return normalized_pairs


def compute_canonical_transaction_digest(
    method: str,
    host: str,
    path: str,
    response_status: int,
    request_body: str = "",
    response_body: str = "",
    request_headers: Optional[Any] = None,
    response_headers: Optional[Any] = None,
) -> str:
    """Computes deterministic canonical SHA-256 digest over semantically relevant observation fields.
    Guarantees tamper-evidence: any modification to method, host, path, status, headers, or payload yields a distinct digest.
    """
    req_b_hash = hashlib.sha256((request_body or "").encode("utf-8")).hexdigest()
    resp_b_hash = hashlib.sha256((response_body or "").encode("utf-8")).hexdigest()
    req_h_hash = hashlib.sha256(
        json.dumps(canonicalize_headers(request_headers), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    resp_h_hash = hashlib.sha256(
        json.dumps(canonicalize_headers(response_headers), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    canonical_payload = {
        "host": (host or "").lower().strip(),
        "method": (method or "").upper().strip(),
        "path": (path or "/").strip(),
        "request_body_sha256": req_b_hash,
        "request_headers_sha256": req_h_hash,
        "response_body_sha256": resp_b_hash,
        "response_headers_sha256": resp_h_hash,
        "response_status": int(response_status),
    }
    raw = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def verify_observation_digest(observation: Dict[str, Any]) -> bool:
    """Deterministic verification of observation integrity. Detects in-place tampering."""
    expected = observation.get("transaction_digest")
    if not expected:
        return False
    computed = compute_canonical_transaction_digest(
        method=observation.get("http_method") or observation.get("method", ""),
        host=observation.get("host", ""),
        path=observation.get("raw_path") or observation.get("path", "/"),
        response_status=int(observation.get("response_status") or observation.get("status_code", 0)),
        request_body=observation.get("request_body") or "",
        response_body=observation.get("response_body") or "",
        request_headers=observation.get("request_headers"),
        response_headers=observation.get("response_headers"),
    )
    return computed == expected


class EvidenceIngestionPipeline:
    """
    Ingestion Pipeline implementing:
    Raw Import -> Parser -> Structural Normalization -> Secret Detection/Redaction ->
    Deterministic Scope Validation -> Duplicate Detection -> Evidence Preservation Gate ->
    Canonical Evidence -> Evidence Store.
    """

    VALID_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}

    def __init__(
        self,
        db_manager: DatabaseManager,
        vault: Optional[RedactionVault] = None,
        scope_gate: Optional[ScopeGate] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.db = db_manager
        self.vault = vault or RedactionVault()
        self.scope_gate = scope_gate or ScopeGate(
            policy=ScopePolicy(
                program_name="EvidenceIngestionFallback",
                platform="LOCAL",
                in_scope=[],
            )
        )
        self.audit_logger = audit_logger
        self.normalizer = PathNormalizer()
        self.compressor = SemanticCompressor()

    def get_importer(self, format_type: str) -> EvidenceImporter:
        """Resolve format adapter by name."""
        fmt = (format_type or "").lower().strip()
        if fmt == "har":
            return HarImporter()
        elif fmt in ("raw_http", "raw", "http"):
            return RawHttpImporter()
        elif fmt == "burp":
            return BurpImporter()
        else:
            # Fallback heuristic: check if JSON vs raw text
            return RawHttpImporter()

    def ingest_raw(
        self,
        investigation_id: str,
        target_host: str,
        raw_content: str,
        format_type: str,
        source_artifact: str = "",
    ) -> IngestionResult:
        """Parse raw imported text/file and process transactions through the ingestion pipeline."""
        importer = self.get_importer(format_type)
        records, parse_errors = importer.parse(raw_content, source_artifact=source_artifact)
        return self.process_records(
            investigation_id=investigation_id,
            target_host=target_host,
            records=records,
            source_type=format_type.lower(),
            source_artifact=source_artifact,
            parse_errors=parse_errors,
        )

    def add_manual_observation(
        self,
        investigation_id: str,
        target_host: str,
        data: Dict[str, Any],
    ) -> IngestionResult:
        """Convert a researcher's manual observation into a transaction record and run through pipeline."""
        method = (data.get("method") or "GET").upper().strip()
        host = (data.get("host") or target_host).strip().lower()
        path = (data.get("path") or "/").strip()
        if not path.startswith("/"):
            path = "/" + path

        url = f"https://{host}{path}"
        status_code = int(data.get("status_code", 200))
        req_headers = data.get("request_headers", {})
        if not isinstance(req_headers, dict):
            req_headers = {}
        req_body = str(data.get("request_body", "") or "")
        resp_headers = data.get("response_headers", {})
        if not isinstance(resp_headers, dict):
            resp_headers = {}
        resp_body = str(data.get("response_body", "") or "")
        researcher_note = data.get("researcher_note")

        record = RawTransactionRecord(
            method=method,
            url=url,
            host=host,
            path=path,
            request_headers=req_headers,
            request_body=req_body,
            response_status=status_code,
            response_headers=resp_headers,
            response_body=resp_body,
            source_tool="manual_observation",
            source_artifact="manual_entry",
            researcher_note=researcher_note,
        )

        return self.process_records(
            investigation_id=investigation_id,
            target_host=target_host,
            records=[record],
            source_type="manual",
            source_artifact="manual_entry",
            parse_errors=[],
        )

    def process_records(
        self,
        investigation_id: str,
        target_host: str,
        records: List[RawTransactionRecord],
        source_type: str,
        source_artifact: str = "",
        parse_errors: Optional[List[str]] = None,
    ) -> IngestionResult:
        """
        Process a list of RawTransactionRecords through normalization, secret redaction,
        deterministic scope validation, duplicate detection, and canonical persistence.
        """
        result = IngestionResult(
            imported_count=len(records) + len(parse_errors or []),
            parsing_failures=len(parse_errors or []),
            errors=list(parse_errors or []),
            parse_errors=list(parse_errors or []),
        )

        canonical_target = canonicalize_host(target_host) if target_host else None
        batch_digests: Set[str] = set()

        for idx, record in enumerate(records):
            try:
                # 1. Structural Validation
                method = record.method.upper().strip()
                if method not in self.VALID_HTTP_METHODS:
                    result.parsing_failures += 1
                    err_msg = f"Record {idx + 1}: Unsupported HTTP method '{method}'"
                    result.errors.append(err_msg)
                    result.parse_errors.append(err_msg)
                    continue

                raw_path = record.path.strip() if record.path else "/"
                if not raw_path.startswith("/"):
                    raw_path = "/" + raw_path

                # Extract and canonicalize transaction host
                c_host = canonicalize_host(record.host)
                c_url_host = canonicalize_host(record.url) if record.url else None

                # Check for host header vs URL host injection/mismatch
                if c_host and c_url_host and c_host != c_url_host:
                    result.out_of_scope_count += 1
                    result.out_of_scope.append({
                        "transaction": idx + 1,
                        "host": c_host,
                        "reason": f"Host header '{c_host}' does not match URL host '{c_url_host}'",
                    })
                    continue

                tx_host = c_host or c_url_host
                if not tx_host:
                    result.out_of_scope_count += 1
                    result.out_of_scope.append({
                        "transaction": idx + 1,
                        "host": "unknown",
                        "reason": "Missing or malformed transaction host",
                    })
                    continue

                # Build canonical evaluation URL
                eval_url = record.url if "://" in record.url else f"https://{tx_host}{raw_path}"

                # 2. Authoritative ScopeGate Evaluation (Fail-Closed, Passive)
                # Scope decision is deterministic, code-enforced, and evaluated BEFORE any persistence
                scope_decision = self.scope_gate.evaluate(
                    requested_url=eval_url,
                    tool_name=source_type,
                    allow_passive=True,
                    target_scope=target_host if target_host else None,
                )

                if scope_decision.decision.value not in ("ALLOW", "ALLOWED"):
                    result.out_of_scope_count += 1
                    result.out_of_scope.append({
                        "transaction": idx + 1,
                        "host": tx_host,
                        "reason": scope_decision.reason,
                    })
                    continue

                # 3. Secret Detection & Redaction via RedactionVault
                redacted_req_headers, secrets_req_h = self._redact_headers(record.request_headers)
                redacted_resp_headers, secrets_resp_h = self._redact_headers(record.response_headers)

                redacted_req_body, secrets_req_b = self._redact_body(record.request_body)
                redacted_resp_body, secrets_resp_b = self._redact_body(record.response_body)

                total_redacted = secrets_req_h + secrets_resp_h + secrets_req_b + secrets_resp_b
                result.redacted_secret_count += total_redacted

                # 4. Duplicate Detection & Canonical Tamper-Evident Digest Construction
                tx_digest = compute_canonical_transaction_digest(
                    method=method,
                    host=tx_host,
                    path=raw_path,
                    response_status=record.response_status,
                    request_body=redacted_req_body,
                    response_body=redacted_resp_body,
                    request_headers=redacted_req_headers,
                    response_headers=redacted_resp_headers,
                )

                # Check for duplicates against existing DB records and current batch
                if self.db.has_observation_digest(investigation_id, tx_digest) or tx_digest in batch_digests:
                    result.duplicate_count += 1
                    result.duplicates += 1
                    continue

                batch_digests.add(tx_digest)

                # 5. Normalization & Canonical Modeling
                normalized_path, norm_conf = self.normalizer.normalize_path(raw_path)
                asset_id = CanonicalEvidence.compute_asset_id(method, tx_host, normalized_path)
                mutability = self.normalizer.classify_mutability(method)

                # Statement
                statement = f"{method} {raw_path} returned HTTP {record.response_status}"
                fact_id = CanonicalEvidence.compute_fact_id(source_tool=source_type, statement=statement)
                obs_id = f"OBS-{secrets.token_hex(4).upper()}"

                # 6. Database Persistence (Only after scope validation passed)
                obs_dict = {
                    "id": obs_id,
                    "investigation_id": investigation_id,
                    "fact_id": fact_id,
                    "asset_id": asset_id,
                    "http_method": method,
                    "host": tx_host,
                    "raw_path": raw_path,
                    "normalized_path": normalized_path,
                    "response_status": record.response_status,
                    "request_headers": redacted_req_headers,
                    "request_body": redacted_req_body,
                    "response_headers": redacted_resp_headers,
                    "response_body": redacted_resp_body,
                    "statement": statement,
                    "source_type": source_type,
                    "source_artifact": source_artifact or record.source_artifact,
                    "researcher_note": record.researcher_note,
                    "transaction_digest": tx_digest,
                    "redacted_secret_count": total_redacted,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }

                self.db.insert_investigation_observation(obs_dict)

                # Also ensure asset and canonical evidence_items are registered
                self.db.insert_asset({
                    "asset_id": asset_id,
                    "method": method,
                    "host": tx_host,
                    "raw_path": raw_path,
                    "normalized_path": normalized_path,
                    "normalization_confidence": norm_conf,
                    "http_semantics": method,
                    "application_mutability": mutability,
                    "liveness": "SHADOW_ACTIVE" if record.response_status != 404 else "ZOMBIE_STALE",
                })

                self.db.insert_evidence_item({
                    "fact_id": fact_id,
                    "certainty": EpistemicCertainty.OBSERVED.value,
                    "statement": statement,
                    "source_tool": source_type,
                    "source_version": "1.0",
                    "trust": EvidenceTrust.UNTRUSTED.value,
                    "raw_evidence_ref": obs_id,
                })

                obs_obj = InvestigationObservation(**obs_dict)
                result.accepted_observations.append(obs_obj)
                result.accepted_count += 1
                result.observations_added += 1

            except Exception as e:
                logger.error("Transaction %d processing error: %s", idx + 1, e, exc_info=True)
                err_msg = f"Record {idx + 1} processing error: {str(e)}"
                result.parsing_failures += 1
                result.errors.append(err_msg)
                result.parse_errors.append(err_msg)

        # Audit logging for the ingestion operation
        if self.audit_logger and (result.accepted_count > 0 or result.duplicate_count > 0 or result.out_of_scope_count > 0):
            self.audit_logger.log_event(
                event_type="EVIDENCE_INGESTED",
                actor="local_researcher",
                subject_id=investigation_id,
                details={
                    "source_type": source_type,
                    "source_artifact": source_artifact,
                    "imported_count": result.imported_count,
                    "accepted_count": result.accepted_count,
                    "observations_added": result.observations_added,
                    "duplicate_count": result.duplicate_count,
                    "duplicates": result.duplicates,
                    "out_of_scope_count": result.out_of_scope_count,
                    "out_of_scope": result.out_of_scope,
                    "redacted_secret_count": result.redacted_secret_count,
                    "parsing_failures": result.parsing_failures,
                    "parse_errors": result.parse_errors,
                },
            )

        return result

    def _redact_headers(self, headers: Dict[str, str]) -> Tuple[Dict[str, str], int]:
        """Redact sensitive headers and return count of redacted tokens."""
        if not headers:
            return {}, 0
        clean: Dict[str, str] = {}
        count = 0
        sensitive_header_re = re.compile(
            r"(auth|token|key|secret|credential|session|cookie|password|jwt)", re.IGNORECASE
        )

        for k, v in headers.items():
            if not isinstance(v, str):
                clean[k] = v
                continue

            k_lower = k.lower().strip()
            # 1. Cookie headers
            if k_lower in ("cookie", "set-cookie"):
                redacted_cookie_str = self.vault.redact_text(f"Cookie: {v}")
                if redacted_cookie_str.lower().startswith("cookie: "):
                    redacted_val = redacted_cookie_str[8:]
                else:
                    redacted_val = redacted_cookie_str
                clean[k] = redacted_val
            # 2. Authorization / API Keys / Session / Secret headers
            elif sensitive_header_re.search(k_lower) or k_lower in ("authorization", "x-api-key"):
                redacted_val = self.vault.redact_text(v)
                if redacted_val == v and len(v.strip()) > 0:
                    redacted_val = self.vault._get_or_create_placeholder(v, "SECRET")
                clean[k] = redacted_val
            else:
                clean[k] = self.vault.redact_text(v)

            count += len(re.findall(r"\[REDACTED_[A-Z0-9_]+\]", str(clean[k])))

        return clean, count

    def _redact_body(self, body: str) -> Tuple[str, int]:
        """Redact sensitive content in body and return count of redacted tokens."""
        if not body:
            return "", 0
        redacted = self.vault.redact_text(body)
        count = len(re.findall(r"\[REDACTED_[A-Z0-9_]+\]", redacted))
        return redacted, count
