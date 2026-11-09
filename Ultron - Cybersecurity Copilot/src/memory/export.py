"""Export and Import Engine for Memory Subsystem.

Guarantees:
1. Export passes all content through RedactionVault.
2. Imported memory enters as UNTRUSTED_DATA and must pass admission validation.
3. Rule M12-24: Memory import cannot execute instructions contained inside imported data.
4. Mandatory receiving context: importing serialized memory without an authorized receiving context fails closed.
5. Authorization-aware export privacy: export requires an authorized caller context and scrubs private metadata.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from src.evidence.vault import RedactionVault
from src.memory.enums import EpistemicStatus, MemoryAuthority, MemoryNamespace, MemorySourceType
from src.memory.models import MemoryAccessContext, MemoryItem
from src.memory.namespaces import NamespaceValidator


class MemoryExportEngine:
    """
    Manages safe JSON serialization and untrusted deserialization of memory items.
    Enforces authorization-aware export disclosure and context rebinding on import.
    """

    def __init__(self) -> None:
        self.vault = RedactionVault()

    def export_items(
        self,
        items: List[MemoryItem],
        caller_context: MemoryAccessContext,
    ) -> str:
        """
        Serializes memory items to structured JSON with mandatory secret redaction
        and authorization-aware metadata allowlisting.
        Fails closed if caller_context is missing or invalid.
        """
        if not caller_context or not isinstance(caller_context, MemoryAccessContext):
            raise ValueError("EXPORT_CONTEXT_REQUIRED: Exporting memory items requires an authorized caller context.")

        payloads: List[Dict[str, Any]] = []
        for item in items:
            # 1. Enforce export authorization boundary
            if not caller_context.is_admin and item.tenant_id != caller_context.tenant_id:
                # Never export records belonging to a different tenant unless strictly public GLOBAL_KNOWLEDGE
                if item.namespace != MemoryNamespace.GLOBAL_KNOWLEDGE:
                    continue

            if caller_context.assessment_id:
                policy = NamespaceValidator.get_policy(item.namespace)
                if not policy.cross_assessment_readable and item.assessment_id != caller_context.assessment_id:
                    # Never export private assessment records to a different assessment
                    continue

            redacted_content = self.vault.redact_text(item.content)
            redacted_summary = self.vault.redact_text(item.summary)
            redacted_title = self.vault.redact_text(item.title)

            # 2. Metadata allowlist (sanitizes private internal identifiers for non-admins)
            tenant_disp = item.tenant_id if (caller_context.is_admin or item.tenant_id == caller_context.tenant_id) else "redacted_tenant"
            owner_disp = item.owner_id if (caller_context.is_admin or item.owner_id == caller_context.user_id) else "anonymized_researcher"
            assessment_disp = item.assessment_id if (caller_context.is_admin or item.assessment_id == caller_context.assessment_id) else "redacted_assessment"

            # Strip private evidence pointers if the caller does not have assessment access
            evidence_refs = item.evidence_references if (caller_context.is_admin or item.assessment_id == caller_context.assessment_id) else []

            payloads.append({
                "memory_id": item.memory_id,
                "namespace": item.namespace.value,
                "owner_id": owner_disp,
                "tenant_id": tenant_disp,
                "assessment_id": assessment_disp,
                "source_type": item.source_type.value,
                "epistemic_status": item.epistemic_status.value,
                "authority_level": item.authority_level.value,
                "content": redacted_content,
                "title": redacted_title,
                "summary": redacted_summary,
                "confidence": item.confidence,
                "created_at": item.created_at,
                "updated_at": item.updated_at,
                "provenance_references": [self.vault.redact_text(p) for p in item.provenance_references],
                "evidence_references": evidence_refs,
                "content_hash": item.content_hash,
                "version": item.version,
                "sensitivity_classification": item.sensitivity_classification.value,
                "export_timestamp": datetime.now(timezone.utc).isoformat(),
            })

        return json.dumps({"version": "1.0", "items": payloads}, indent=2)

    def parse_imported_payload(
        self,
        raw_json: str,
        receiving_context: MemoryAccessContext,
    ) -> List[MemoryItem]:
        """
        Parses imported JSON into candidate MemoryItems marked as UNTRUSTED import.
        Rebinds tenant and assessment context strictly to receiving_context.
        Untrusted metadata can NEVER override the receiving context (M12-24).
        Fails closed and raises ValueError if receiving_context is missing or invalid.
        """
        if not receiving_context or not isinstance(receiving_context, MemoryAccessContext):
            raise ValueError("RECEIVING_CONTEXT_REQUIRED: Importing serialized memory requires an authorized receiving context.")

        if not receiving_context.tenant_id or not receiving_context.tenant_id.strip():
            raise ValueError("RECEIVING_CONTEXT_INVALID: receiving_context must specify a non-empty tenant_id.")

        if not receiving_context.user_id or not receiving_context.user_id.strip():
            raise ValueError("RECEIVING_CONTEXT_INVALID: receiving_context must specify a non-empty user_id.")

        if not raw_json or not raw_json.strip():
            return []

        data = json.loads(raw_json)
        raw_items = data.get("items", [])
        candidates: List[MemoryItem] = []

        effective_tenant = receiving_context.tenant_id.strip()
        effective_assessment = receiving_context.assessment_id.strip() if receiving_context.assessment_id else None
        effective_owner = receiving_context.user_id.strip()

        for raw in raw_items:
            # Parse namespace safely
            raw_ns = raw.get("namespace", MemoryNamespace.ASSESSMENT_LOCAL.value)
            try:
                ns = MemoryNamespace(raw_ns)
            except ValueError:
                ns = MemoryNamespace.ASSESSMENT_LOCAL

            # Force untrusted import status on entry
            item = MemoryItem(
                memory_id=raw.get("memory_id", ""),
                namespace=ns,
                owner_id=effective_owner,
                tenant_id=effective_tenant,
                assessment_id=effective_assessment,
                source_type=MemorySourceType.IMPORT,
                epistemic_status=EpistemicStatus.UNVERIFIED_CLAIM,  # Forced to UNVERIFIED_CLAIM
                authority_level=MemoryAuthority.UNVERIFIED,  # Enforce UNVERIFIED for external imports
                content=raw.get("content", ""),
                title=raw.get("title", ""),
                summary=raw.get("summary", ""),
                confidence=float(raw.get("confidence", 0.5)),
                created_at=raw.get("created_at", datetime.now(timezone.utc).isoformat()),
                provenance_references=raw.get("provenance_references", []) + ["source:untrusted_import"],
                evidence_references=raw.get("evidence_references", []),
            )
            candidates.append(item)

        return candidates
