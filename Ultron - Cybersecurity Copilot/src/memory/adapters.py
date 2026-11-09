"""Adapters converting M11 controlled experiments, falsifications, and review events into research memory items."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from src.memory.enums import (
    EpistemicStatus,
    MemoryAuthority,
    MemoryNamespace,
    MemorySourceType,
    PromotionStatus,
    SensitivityClassification,
)
from src.memory.models import EvidencePointer, MemoryItem


class EpisodicMemoryAdapters:
    """
    Constructs well-formed candidate MemoryItems from domain artifacts,
    preserving epistemic status and creating evidence pointers.
    """

    @staticmethod
    def from_controlled_experiment(
        experiment_id: str,
        assessment_id: str,
        hypothesis: str,
        experiment_type: str,
        outcome: str,
        falsified: bool,
        evidence_digest: str,
        limitations: Optional[str] = None,
        tenant_id: str = "default_tenant",
        researcher_id: str = "researcher",
    ) -> MemoryItem:
        """
        Adapts a completed controlled experiment into an ASSESSMENT_LOCAL memory item.
        Preserves original hypothesis/observation epistemic status; never declares
        unauthorized finding confirmation.
        """
        status_text = "FALSIFIED (Hypothesis refuting condition observed)" if falsified else f"Outcome: {outcome}"
        content = (
            f"Controlled Experiment [{experiment_type}]: {hypothesis}\n"
            f"Execution Outcome: {status_text}\n"
            f"Empirical Limitations: {limitations or 'Standard local sandbox bounds'}"
        )

        pointer = EvidencePointer(
            pointer_id=f"PTR-{uuid.uuid4().hex[:8]}",
            memory_id="",  # Bound upon creation
            target_evidence_id=experiment_id,
            assessment_id=assessment_id,
            evidence_type="controlled_experiment",
            evidence_digest=evidence_digest,
        )

        item = MemoryItem(
            memory_id=f"MEM-EXP-{uuid.uuid4().hex[:8]}",
            namespace=MemoryNamespace.ASSESSMENT_LOCAL,
            owner_id=researcher_id,
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            source_type=MemorySourceType.CONTROLLED_EXPERIMENT,
            epistemic_status=EpistemicStatus.OBSERVATION,
            authority_level=MemoryAuthority.CANONICAL_OBSERVATION,
            content=content,
            title=f"Experiment: {hypothesis[:60]}...",
            summary=f"Experiment {experiment_id} outcome: {outcome}",
            provenance_references=[f"experiment_id:{experiment_id}", f"evidence_digest:{evidence_digest}"],
            evidence_references=[evidence_digest],
            evidence_pointers=[pointer],
            sensitivity_classification=SensitivityClassification.INTERNAL,
        )
        pointer.memory_id = item.memory_id
        return item

    @staticmethod
    def from_negative_control(
        assessment_id: str,
        tested_hypothesis: str,
        benign_explanation: str,
        control_artifact_digest: str,
        tenant_id: str = "default_tenant",
        researcher_id: str = "researcher",
    ) -> MemoryItem:
        """
        Adapts a negative control result into a high-value reusable memory lesson.
        Preserves refuting condition to prevent future false positive chasing.
        """
        content = (
            f"Negative Control Lesson: Hypothesis '{tested_hypothesis}' was refuted.\n"
            f"Benign Root Cause: {benign_explanation}\n"
            f"Relevance: Check for this benign factor when evaluating similar response signals."
        )

        pointer = EvidencePointer(
            pointer_id=f"PTR-{uuid.uuid4().hex[:8]}",
            memory_id="",
            target_evidence_id=control_artifact_digest,
            assessment_id=assessment_id,
            evidence_type="negative_control",
            evidence_digest=control_artifact_digest,
        )

        item = MemoryItem(
            memory_id=f"MEM-NEG-{uuid.uuid4().hex[:8]}",
            namespace=MemoryNamespace.USER_RESEARCH,  # Reusable negative lessons across research
            owner_id=researcher_id,
            tenant_id=tenant_id,
            assessment_id=None,  # Abstracted reusable lesson
            source_type=MemorySourceType.NEGATIVE_CONTROL,
            epistemic_status=EpistemicStatus.OBSERVATION,
            authority_level=MemoryAuthority.CURATED_RESEARCH,
            content=content,
            title=f"Negative Control: {tested_hypothesis[:50]}...",
            summary=f"Refuted via negative control: {benign_explanation}",
            provenance_references=[f"origin_assessment:{assessment_id}", f"control_digest:{control_artifact_digest}"],
            evidence_references=[control_artifact_digest],
            evidence_pointers=[pointer],
            sensitivity_classification=SensitivityClassification.INTERNAL,
        )
        pointer.memory_id = item.memory_id
        return item

    @staticmethod
    def from_verified_finding_reference(
        finding_id: str,
        assessment_id: str,
        vulnerability_type: str,
        abstracted_reproduction_pattern: str,
        finding_digest: str,
        tenant_id: str = "default_tenant",
        researcher_id: str = "researcher",
    ) -> MemoryItem:
        """
        Adapts an authoritative human-verified finding into a VERIFIED_PATTERN memory item.
        NEVER duplicates raw target evidence or confidential secrets into memory.
        """
        content = (
            f"Verified Vulnerability Pattern: {vulnerability_type}\n"
            f"Abstracted Mechanism: {abstracted_reproduction_pattern}\n"
            f"Authoritative Finding Pointer: {finding_id}"
        )

        pointer = EvidencePointer(
            pointer_id=f"PTR-{uuid.uuid4().hex[:8]}",
            memory_id="",
            target_evidence_id=finding_id,
            assessment_id=assessment_id,
            evidence_type="verified_finding",
            evidence_digest=finding_digest,
        )

        item = MemoryItem(
            memory_id=f"MEM-PAT-{uuid.uuid4().hex[:8]}",
            namespace=MemoryNamespace.VERIFIED_PATTERN,
            owner_id=researcher_id,
            tenant_id=tenant_id,
            assessment_id=None,  # Reusable pattern
            source_type=MemorySourceType.VERIFIED_FINDING_REF,
            epistemic_status=EpistemicStatus.HUMAN_VERIFIED_FINDING,
            authority_level=MemoryAuthority.HUMAN_VERIFIED,
            content=content,
            title=f"Verified Pattern: {vulnerability_type}",
            summary=f"Abstracted verification pattern for {vulnerability_type}",
            provenance_references=[f"finding_id:{finding_id}", f"finding_digest:{finding_digest}"],
            evidence_references=[finding_digest],
            evidence_pointers=[pointer],
            sensitivity_classification=SensitivityClassification.INTERNAL,
            promotion_status=PromotionStatus.PROMOTED,
        )
        pointer.memory_id = item.memory_id
        return item
