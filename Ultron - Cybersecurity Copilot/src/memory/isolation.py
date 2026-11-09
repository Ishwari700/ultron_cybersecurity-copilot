"""Assessment and Multi-Tenant Isolation Engine for Memory Subsystem.

NON-NEGOTIABLE TENET:
Assessment A must NEVER retrieve raw assessment-private memory from Assessment B.
Isolation must happen BEFORE candidate generation and ranking.
Never rely solely on post-retrieval filtering.
"""

from typing import Any, Dict, List, Optional
from src.memory.enums import MemoryNamespace
from src.memory.errors import (
    AssessmentIsolationViolationError,
    MemoryAccessDeniedError,
)
from src.memory.models import MemoryAccessContext, MemoryItem
from src.memory.namespaces import NamespaceValidator


class MemoryIsolationEngine:
    """
    Enforces multi-tenant and per-assessment boundaries on memory queries and modifications.
    """

    @staticmethod
    def validate_access_context(context: Optional[MemoryAccessContext]) -> MemoryAccessContext:
        """
        Validates security context. Fails closed if missing or incomplete.
        """
        if context is None:
            raise MemoryAccessDeniedError("MemoryAccessContext is missing: access fails closed.")
        if not context.tenant_id or not context.user_id:
            raise MemoryAccessDeniedError("MemoryAccessContext has invalid tenant_id or user_id.")
        return context

    @classmethod
    def filter_authorized_candidates(
        cls,
        context: MemoryAccessContext,
        candidates: List[MemoryItem],
    ) -> List[MemoryItem]:
        """
        Filters a list of candidate memory items against the security context
        BEFORE scoring or ranking.
        """
        cls.validate_access_context(context)
        authorized: List[MemoryItem] = []

        for item in candidates:
            # 1. Tenant boundary
            if item.tenant_id != context.tenant_id and not context.is_admin:
                continue

            # 2. Namespace authorization
            if item.namespace not in context.allowed_namespaces:
                continue

            policy = NamespaceValidator.get_policy(item.namespace)

            # 3. Assessment isolation boundary
            if not policy.cross_assessment_readable:
                if not context.assessment_id or item.assessment_id != context.assessment_id:
                    # Drop candidate completely: never expose cross-assessment private memory
                    continue

            # 4. Tombstone/deleted check
            if item.is_tombstone or item.lifecycle_state.value == "DELETED":
                continue

            authorized.append(item)

        return authorized

    @classmethod
    def build_query_filter_sql(cls, context: MemoryAccessContext) -> Dict[str, Any]:
        """
        Builds SQL WHERE clauses and parameters that guarantee cross-assessment and
        cross-tenant isolation directly at the database query level.
        """
        cls.validate_access_context(context)

        clauses = ["is_tombstone = 0", "lifecycle_state != 'DELETED'"]
        params: List[Any] = []

        # Tenant filter
        if not context.is_admin:
            clauses.append("tenant_id = ?")
            params.append(context.tenant_id)

        # Namespace and assessment filter
        # Allowed: (namespace IN shared_namespaces) OR (namespace = 'ASSESSMENT_LOCAL' AND assessment_id = ?)
        shared_ns = [
            ns.value for ns in context.allowed_namespaces
            if NamespaceValidator.get_policy(ns).cross_assessment_readable
        ]
        
        ns_conditions = []
        if shared_ns:
            placeholders = ",".join("?" for _ in shared_ns)
            ns_conditions.append(f"namespace IN ({placeholders})")
            params.extend(shared_ns)

        if context.assessment_id and MemoryNamespace.ASSESSMENT_LOCAL in context.allowed_namespaces:
            ns_conditions.append("(namespace = ? AND assessment_id = ?)")
            params.extend([MemoryNamespace.ASSESSMENT_LOCAL.value, context.assessment_id])

        if context.assessment_id and MemoryNamespace.TARGET_EVIDENCE_POINTER in context.allowed_namespaces:
            ns_conditions.append("(namespace = ? AND assessment_id = ?)")
            params.extend([MemoryNamespace.TARGET_EVIDENCE_POINTER.value, context.assessment_id])

        if ns_conditions:
            clauses.append(f"({' OR '.join(ns_conditions)})")
        else:
            # No valid namespace permitted
            clauses.append("1 = 0")

        return {
            "where_clause": " AND ".join(clauses),
            "params": params,
        }
