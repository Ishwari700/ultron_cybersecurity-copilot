"""Evidence Graph and Relational Entity Tracker (Milestone M5 Section 20).

Formalizes explicit relationships between investigation entities:
- Target, Asset, Endpoint, Observation, Evidence
- Hypothesis, EvidenceGap, Experiment, Finding
- KnowledgeChunk, ExternalClaim, ExternalSource

Preserves relational traceability without implementing GraphRAG.
"""

from enum import Enum
import hashlib
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class EntityType(str, Enum):
    """Core entity classifications in the investigation evidence graph."""
    TARGET = "TARGET"
    ASSET = "ASSET"
    ENDPOINT = "ENDPOINT"
    TRAFFIC = "TRAFFIC"
    OBSERVATION = "OBSERVATION"
    EVIDENCE = "EVIDENCE"
    HYPOTHESIS = "HYPOTHESIS"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    EXPERIMENT = "EXPERIMENT"
    FINDING = "FINDING"
    VULNERABILITY = "VULNERABILITY"
    SECURITY_INVARIANT = "SECURITY_INVARIANT"
    KNOWLEDGE_CHUNK = "KNOWLEDGE_CHUNK"
    EXTERNAL_CLAIM = "EXTERNAL_CLAIM"
    EXTERNAL_SOURCE = "EXTERNAL_SOURCE"
    RESEARCH_RUN = "RESEARCH_RUN"


class RelationshipType(str, Enum):
    """Authoritative semantic relationships connecting investigation entities."""
    OBSERVED_IN = "OBSERVED_IN"                  # Endpoint OBSERVED_IN Traffic
    HAS_OBSERVATION = "HAS_OBSERVATION"          # Endpoint HAS Observation
    SUPPORTS = "SUPPORTS"                        # Observation SUPPORTS Hypothesis
    CONTRADICTS = "CONTRADICTS"                  # Observation CONTRADICTS Hypothesis
    REQUIRES = "REQUIRES"                        # Hypothesis REQUIRES EvidenceGap
    ADDRESSED_BY = "ADDRESSED_BY"                # EvidenceGap ADDRESSED_BY Experiment
    PRODUCES = "PRODUCES"                        # Experiment PRODUCES Observation
    REFERENCES = "REFERENCES"                    # Hypothesis REFERENCES KnowledgeChunk
    MAPS_TO = "MAPS_TO"                          # Finding MAPS_TO Vulnerability
    SOURCED_FROM = "SOURCED_FROM"                # ExternalClaim SOURCED_FROM ExternalSource
    PART_OF_RUN = "PART_OF_RUN"                  # ExternalSource PART_OF_RUN ResearchRun


class EvidenceGraphEdge(BaseModel):
    """Directed relationship between two investigation entities."""
    edge_id: str
    investigation_id: str
    source_id: str
    source_type: EntityType
    relationship: RelationshipType
    target_id: str
    target_type: EntityType
    notes: Optional[str] = None


class InvestigationEvidenceGraph(BaseModel):
    """Lightweight relational container storing investigation entity edges."""
    investigation_id: str
    edges: List[EvidenceGraphEdge] = Field(default_factory=list)

    def add_edge(
        self,
        source_id: str,
        source_type: EntityType,
        relationship: RelationshipType,
        target_id: str,
        target_type: EntityType,
        notes: Optional[str] = None,
    ) -> EvidenceGraphEdge:
        """Adds a verified edge to the graph."""
        edge_id = f"EDGE-{hashlib.sha256((self.investigation_id + source_id + relationship.value + target_id).encode()).hexdigest()[:8]}"
        edge = EvidenceGraphEdge(
            edge_id=edge_id,
            investigation_id=self.investigation_id,
            source_id=source_id,
            source_type=source_type,
            relationship=relationship,
            target_id=target_id,
            target_type=target_type,
            notes=notes,
        )
        self.edges.append(edge)
        return edge

    def get_edges_for_entity(self, entity_id: str) -> List[EvidenceGraphEdge]:
        """Finds all edges incident to a specific entity."""
        return [e for e in self.edges if e.source_id == entity_id or e.target_id == entity_id]

    def get_supporting_evidence_for_hypothesis(self, hypothesis_id: str) -> List[str]:
        """Returns observation IDs that support a given hypothesis."""
        return [
            e.source_id for e in self.edges
            if e.target_id == hypothesis_id and e.relationship == RelationshipType.SUPPORTS
        ]

    def get_experiments_for_gap(self, gap_id: str) -> List[str]:
        """Returns experiment IDs addressing a specific evidence gap."""
        return [
            e.target_id for e in self.edges
            if e.source_id == gap_id and e.relationship == RelationshipType.ADDRESSED_BY
        ]
