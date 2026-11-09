"""Permission checks and non-authority guards for Memory Subsystem."""

from typing import Optional
from src.memory.enums import MemoryNamespace
from src.memory.errors import MemoryAccessDeniedError
from src.memory.models import MemoryAccessContext, MemoryItem


class MemoryPermissionGate:
    """
    Guards memory operations and prevents memory from exerting execution or scope authority.
    """

    @staticmethod
    def check_can_read(context: MemoryAccessContext, item: MemoryItem) -> bool:
        """Verifies if context is authorized to read the given memory item."""
        if item.tenant_id != context.tenant_id and not context.is_admin:
            raise MemoryAccessDeniedError(f"Cross-tenant read denied for item {item.memory_id}")

        if item.namespace not in context.allowed_namespaces:
            raise MemoryAccessDeniedError(f"Namespace {item.namespace.value} read denied")

        if item.namespace in (MemoryNamespace.ASSESSMENT_LOCAL, MemoryNamespace.TARGET_EVIDENCE_POINTER):
            if not context.assessment_id or context.assessment_id != item.assessment_id:
                raise MemoryAccessDeniedError(
                    f"Assessment isolation: context {context.assessment_id} cannot read {item.assessment_id}"
                )

        return True

    @staticmethod
    def check_can_write(context: MemoryAccessContext, namespace: MemoryNamespace, assessment_id: Optional[str] = None) -> bool:
        """Verifies if context is authorized to write into the given namespace."""
        if namespace not in context.allowed_namespaces:
            raise MemoryAccessDeniedError(f"Namespace {namespace.value} write not permitted")

        if namespace in (MemoryNamespace.ASSESSMENT_LOCAL, MemoryNamespace.TARGET_EVIDENCE_POINTER):
            if not context.assessment_id or (assessment_id and context.assessment_id != assessment_id):
                raise MemoryAccessDeniedError("Writing to local namespace requires matching active assessment_id")

        if namespace in (MemoryNamespace.SHARED_RESEARCH, MemoryNamespace.VERIFIED_PATTERN, MemoryNamespace.GLOBAL_KNOWLEDGE):
            # Direct write to shared/global namespaces without promotion workflow is restricted
            if not context.is_admin:
                raise MemoryAccessDeniedError(
                    f"Direct write to {namespace.value} forbidden; requires promotion workflow"
                )

        return True

    @staticmethod
    def check_can_delete(context: MemoryAccessContext, item: MemoryItem) -> bool:
        """Verifies if context is authorized to delete/tombstone the given memory item."""
        if item.tenant_id != context.tenant_id and not context.is_admin:
            raise MemoryAccessDeniedError("Cross-tenant deletion forbidden")

        if item.namespace == MemoryNamespace.ASSESSMENT_LOCAL:
            if context.assessment_id != item.assessment_id and not context.is_admin:
                raise MemoryAccessDeniedError("Cannot delete memory belonging to another assessment")

        return True
