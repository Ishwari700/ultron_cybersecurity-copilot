"""Namespace policies and validation rules for M12 Security Research Memory.

Defines access rules, scope constraints, and permission checks for each
of the logical memory namespaces.
"""

from typing import Dict, List, Optional
from src.memory.enums import (
    MemoryAuthority,
    MemoryNamespace,
    PromotionStatus,
    SensitivityClassification,
)
from src.memory.errors import (
    AssessmentIsolationViolationError,
    MemoryAccessDeniedError,
)
from src.memory.models import MemoryAccessContext, MemoryItem


class NamespacePolicy:
    """Policy rules governing a specific memory namespace."""

    def __init__(
        self,
        namespace: MemoryNamespace,
        requires_assessment: bool,
        cross_assessment_readable: bool,
        allows_raw_target_data: bool,
        minimum_authority: MemoryAuthority,
        requires_human_promotion: bool,
        max_sensitivity: SensitivityClassification,
    ) -> None:
        self.namespace = namespace
        self.requires_assessment = requires_assessment
        self.cross_assessment_readable = cross_assessment_readable
        self.allows_raw_target_data = allows_raw_target_data
        self.minimum_authority = minimum_authority
        self.requires_human_promotion = requires_human_promotion
        self.max_sensitivity = max_sensitivity


# Deterministic namespace policy registry
NAMESPACE_POLICIES: Dict[MemoryNamespace, NamespacePolicy] = {
    MemoryNamespace.GLOBAL_KNOWLEDGE: NamespacePolicy(
        namespace=MemoryNamespace.GLOBAL_KNOWLEDGE,
        requires_assessment=False,
        cross_assessment_readable=True,
        allows_raw_target_data=False,
        minimum_authority=MemoryAuthority.AUTHORITATIVE_EXTERNAL,
        requires_human_promotion=False,
        max_sensitivity=SensitivityClassification.PUBLIC,
    ),
    MemoryNamespace.USER_RESEARCH: NamespacePolicy(
        namespace=MemoryNamespace.USER_RESEARCH,
        requires_assessment=False,
        cross_assessment_readable=True,
        allows_raw_target_data=False,
        minimum_authority=MemoryAuthority.USER_PROVIDED,
        requires_human_promotion=False,
        max_sensitivity=SensitivityClassification.INTERNAL,
    ),
    MemoryNamespace.SHARED_RESEARCH: NamespacePolicy(
        namespace=MemoryNamespace.SHARED_RESEARCH,
        requires_assessment=False,
        cross_assessment_readable=True,
        allows_raw_target_data=False,
        minimum_authority=MemoryAuthority.CURATED_RESEARCH,
        requires_human_promotion=True,
        max_sensitivity=SensitivityClassification.INTERNAL,
    ),
    MemoryNamespace.ASSESSMENT_LOCAL: NamespacePolicy(
        namespace=MemoryNamespace.ASSESSMENT_LOCAL,
        requires_assessment=True,
        cross_assessment_readable=False,
        allows_raw_target_data=True,
        minimum_authority=MemoryAuthority.UNVERIFIED,
        requires_human_promotion=False,
        max_sensitivity=SensitivityClassification.CRITICAL_CONFIDENTIAL,
    ),
    MemoryNamespace.VERIFIED_PATTERN: NamespacePolicy(
        namespace=MemoryNamespace.VERIFIED_PATTERN,
        requires_assessment=False,
        cross_assessment_readable=True,
        allows_raw_target_data=False,
        minimum_authority=MemoryAuthority.HUMAN_VERIFIED,
        requires_human_promotion=True,
        max_sensitivity=SensitivityClassification.INTERNAL,
    ),
    MemoryNamespace.TARGET_EVIDENCE_POINTER: NamespacePolicy(
        namespace=MemoryNamespace.TARGET_EVIDENCE_POINTER,
        requires_assessment=True,
        cross_assessment_readable=False,
        allows_raw_target_data=False,  # Must be pointer only, no raw payload
        minimum_authority=MemoryAuthority.CANONICAL_OBSERVATION,
        requires_human_promotion=False,
        max_sensitivity=SensitivityClassification.RESTRICTED,
    ),
}


class NamespaceValidator:
    """Validates read and write operations against deterministic namespace policies."""

    @staticmethod
    def get_policy(namespace: MemoryNamespace) -> NamespacePolicy:
        if namespace not in NAMESPACE_POLICIES:
            raise MemoryAccessDeniedError(f"Unknown or unmanaged namespace: {namespace}")
        return NAMESPACE_POLICIES[namespace]

    @classmethod
    def validate_admission(cls, item: MemoryItem) -> None:
        """
        Validates that a candidate memory item satisfies the admission rules
        for its designated namespace.
        """
        policy = cls.get_policy(item.namespace)

        # 1. Assessment requirement
        if policy.requires_assessment and not item.assessment_id:
            raise MemoryAccessDeniedError(
                f"Namespace {item.namespace.value} strictly requires an associated assessment_id"
            )

        # 2. Shared namespaces must not contain raw target data or critical secrets
        if not policy.allows_raw_target_data:
            if item.sensitivity_classification == SensitivityClassification.CRITICAL_CONFIDENTIAL:
                raise MemoryAccessDeniedError(
                    f"Namespace {item.namespace.value} forbids CRITICAL_CONFIDENTIAL raw target data"
                )

        # 3. Promotion requirements for shared patterns
        if policy.requires_human_promotion:
            if item.promotion_status != PromotionStatus.PROMOTED:
                raise MemoryAccessDeniedError(
                    f"Namespace {item.namespace.value} requires explicit HUMAN PROMOTION (status={item.promotion_status.value})"
                )

    @classmethod
    def authorize_read(
        cls,
        context: MemoryAccessContext,
        target_namespace: MemoryNamespace,
        target_assessment_id: Optional[str] = None,
        target_tenant_id: str = "default_tenant",
    ) -> bool:
        """
        Enforces tenant and assessment isolation BEFORE any candidate is retrieved.
        Fails closed.
        """
        # Tenant isolation
        if context.tenant_id != target_tenant_id and not context.is_admin:
            raise MemoryAccessDeniedError(
                f"Cross-tenant memory access forbidden: context tenant '{context.tenant_id}' != target tenant '{target_tenant_id}'"
            )

        # Namespace allowance in context
        if target_namespace not in context.allowed_namespaces:
            raise MemoryAccessDeniedError(
                f"Namespace '{target_namespace.value}' is not permitted for current access context"
            )

        policy = cls.get_policy(target_namespace)

        # Assessment isolation
        if not policy.cross_assessment_readable:
            # Must have an active assessment context and match target exactly
            if not context.assessment_id:
                raise AssessmentIsolationViolationError(
                    f"Accessing isolated namespace '{target_namespace.value}' requires an active assessment_id"
                )
            if context.assessment_id != target_assessment_id:
                raise AssessmentIsolationViolationError(
                    f"Assessment '{context.assessment_id}' cannot access private memory of assessment '{target_assessment_id}'"
                )

        return True
