"""Target and Asset Inventory Graph for M6 Authorized Security Assessments.

Enforces:
1. Canonical multi-tier asset hierarchy (Domain -> Subdomain -> IP -> Port -> Service -> App -> Endpoint).
2. Auditable parent-child relationships and discovery source provenance.
3. INVARIANT: Discovery != Vulnerability. Assets in the graph are neutral targets
   and never automatically classified as vulnerable without empirical proof and human verification.
"""

from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field
from src.assessment.models import (
    AssetRecord,
    AssetType,
    AssessmentScopeStatus,
    AttackSurfaceState,
)


class AssetGraph:
    """Directed acyclic asset relationship graph within an assessment."""

    def __init__(self, assessment_id: str) -> None:
        self.assessment_id = assessment_id
        self._assets: Dict[str, AssetRecord] = {}
        self._identifier_index: Dict[str, str] = {}  # canonical_identifier -> asset_id
        # Adjacency: parent_id -> set of child_ids
        self._children_map: Dict[str, Set[str]] = {}
        # Parent mapping: child_id -> set of parent_ids
        self._parents_map: Dict[str, Set[str]] = {}
        # Multi-target semantic relationships
        self._relationships: List[Any] = []

    def add_asset(
        self,
        asset_type: Any,
        canonical_identifier: Optional[str] = None,
        parent_asset_id: Optional[str] = None,
        scope_status: AssessmentScopeStatus = AssessmentScopeStatus.UNKNOWN,
        discovery_source: str = "PASSIVE_TELEMETRY",
        confidence: float = 1.0,
        tags: Optional[List[str]] = None,
        attack_surface_state: AttackSurfaceState = AttackSurfaceState.OBSERVED,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> AssetRecord:
        """Adds or updates an asset in the inventory graph."""
        if isinstance(asset_type, AssetRecord):
            record = asset_type
            self._assets[record.asset_id] = record
            self._identifier_index[record.canonical_identifier.strip()] = record.asset_id
            if record.parent_asset_id:
                self._link(record.parent_asset_id, record.asset_id)
            return record

        c_id = canonical_identifier.strip()
        existing_id = self._identifier_index.get(c_id)

        now_iso = datetime.now(timezone.utc).isoformat()
        if existing_id and existing_id in self._assets:
            existing = self._assets[existing_id]
            existing.last_seen = now_iso
            existing.confidence = max(existing.confidence, confidence)
            if parent_asset_id and not existing.parent_asset_id:
                existing.parent_asset_id = parent_asset_id
                self._link(parent_asset_id, existing.asset_id)
            if tags:
                for t in tags:
                    if t not in existing.tags:
                        existing.tags.append(t)
            return existing

        # Deterministic asset ID
        seed = f"{self.assessment_id}:{asset_type.value}:{c_id}"
        asset_id = f"ASSET-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:12].upper()}"

        record = AssetRecord(
            asset_id=asset_id,
            assessment_id=self.assessment_id,
            asset_type=asset_type,
            canonical_identifier=c_id,
            parent_asset_id=parent_asset_id,
            scope_status=scope_status,
            discovery_source=discovery_source,
            first_seen=now_iso,
            last_seen=now_iso,
            confidence=confidence,
            tags=tags or [],
            attack_surface_state=attack_surface_state,
            provenance=provenance or {"source": discovery_source},
        )

        self._assets[asset_id] = record
        self._identifier_index[c_id] = asset_id

        if parent_asset_id:
            self._link(parent_asset_id, asset_id)

        return record

    def _link(self, parent_id: str, child_id: str) -> None:
        """Internal helper to maintain parent-child adjacency."""
        if parent_id not in self._children_map:
            self._children_map[parent_id] = set()
        self._children_map[parent_id].add(child_id)

        if child_id not in self._parents_map:
            self._parents_map[child_id] = set()
        self._parents_map[child_id].add(parent_id)

    def get_asset(self, asset_id: str) -> Optional[AssetRecord]:
        """Retrieves asset by ID."""
        return self._assets.get(asset_id)

    def find_by_identifier(self, canonical_identifier: str) -> Optional[AssetRecord]:
        """Looks up asset by canonical identifier string."""
        aid = self._identifier_index.get(canonical_identifier.strip())
        return self._assets.get(aid) if aid else None

    def get_children(self, asset_id: str) -> List[AssetRecord]:
        """Returns direct children of an asset."""
        cids = self._children_map.get(asset_id, set())
        return [self._assets[cid] for cid in cids if cid in self._assets]

    def get_parents(self, asset_id: str) -> List[AssetRecord]:
        """Returns direct parents of an asset."""
        pids = self._parents_map.get(asset_id, set())
        return [self._assets[pid] for pid in pids if pid in self._assets]

    def get_lineage(self, asset_id: str) -> List[AssetRecord]:
        """Walks up the ancestry DAG to root parent assets."""
        lineage = []
        visited = set()
        queue = [asset_id]
        while queue:
            curr = queue.pop(0)
            if curr in visited or curr not in self._assets:
                continue
            visited.add(curr)
            record = self._assets[curr]
            lineage.append(record)
            parents = self._parents_map.get(curr, set())
            for p in parents:
                if p not in visited:
                    queue.append(p)
        return lineage

    def get_all_assets(self) -> List[AssetRecord]:
        """Returns all registered assets in inventory."""
        return list(self._assets.values())

    def add_relationship(
        self,
        source_asset_id: Any,
        target_asset_id: Optional[str] = None,
        relationship_type: Optional["AssetRelationshipType"] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> "AssetRelationship":
        """
        Adds a semantic relationship between assets.
        INVARIANT: Relationships do NOT expand authorization scope (INV-SEC-02, INV-M8-02).
        """
        if isinstance(source_asset_id, AssetRelationship):
            self._relationships.append(source_asset_id)
            return source_asset_id

        if source_asset_id not in self._assets:
            raise KeyError(f"Source asset '{source_asset_id}' not found.")
        if target_asset_id not in self._assets:
            raise KeyError(f"Target asset '{target_asset_id}' not found.")

        raw_seed = f"{self.assessment_id}:{source_asset_id}:{target_asset_id}:{relationship_type.value}"
        rel_id = f"REL-{hashlib.sha256(raw_seed.encode()).hexdigest()[:12].upper()}"

        rel = AssetRelationship(
            relationship_id=rel_id,
            assessment_id=self.assessment_id,
            source_asset_id=source_asset_id,
            target_asset_id=target_asset_id,
            relationship_type=relationship_type,
            provenance=provenance or {"source": "CROSS_ASSET_ANALYSIS"},
        )
        self._relationships.append(rel)
        return rel

    def get_relationships(self, asset_id: Optional[str] = None) -> List["AssetRelationship"]:
        """Returns all relationships, or those involving a specific asset."""
        if not asset_id:
            return list(self._relationships)
        return [r for r in self._relationships if r.source_asset_id == asset_id or r.target_asset_id == asset_id]

    def evaluate_asset_scope_independent(self, asset_id: str, scope_gate: Any) -> AssessmentScopeStatus:
        """
        Evaluates scope independently for an asset.
        Proves relationships do NOT inherit or expand authorization scope.
        """
        asset = self.get_asset(asset_id)
        if not asset:
            raise KeyError(f"Asset '{asset_id}' not found.")
        if not scope_gate:
            return AssessmentScopeStatus.UNKNOWN
        res = scope_gate.evaluate_extended_scope(asset.canonical_identifier)
        return res.scope_status

    def export_graph(self) -> Dict[str, Any]:
        """Serializes complete asset hierarchy for audit and dashboard visualization."""
        nodes = [a.model_dump() for a in self._assets.values()]
        edges = []
        for p_id, c_set in self._children_map.items():
            for c_id in c_set:
                edges.append({"source": p_id, "target": c_id, "relationship": "CONTAINS"})
        for rel in self._relationships:
            edges.append({
                "source": rel.source_asset_id,
                "target": rel.target_asset_id,
                "relationship": rel.relationship_type.value,
            })
        return {
            "assessment_id": self.assessment_id,
            "total_assets": len(nodes),
            "nodes": nodes,
            "edges": edges,
        }


class AssetRelationshipType(str, Enum):
    """Semantic relationship types between multi-target assessment assets."""
    DEPENDS_ON = "DEPENDS_ON"
    CALLS = "CALLS"
    AUTHENTICATES_TO = "AUTHENTICATES_TO"
    SERVES = "SERVES"
    RESOLVES_TO = "RESOLVES_TO"
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    EMBEDS = "EMBEDS"
    SHARES_IDENTITY_WITH = "SHARES_IDENTITY_WITH"
    CONTAINS = "CONTAINS"


class AssetRelationship(BaseModel):
    """Auditable cross-asset relationship record."""
    relationship_id: str
    assessment_id: str
    source_asset_id: str
    target_asset_id: str
    relationship_type: AssetRelationshipType
    provenance: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# Type Aliases and Functions for M8 Specification Parity
AssessmentAssetGraph = AssetGraph
AssetNode = AssetRecord


def evaluate_asset_scope_independent(asset: Any, scope_gate: Any) -> AssessmentScopeStatus:
    """Standalone helper evaluating scope independently for an asset or asset identifier."""
    if not scope_gate:
        return AssessmentScopeStatus.UNKNOWN
    c_id = getattr(asset, "canonical_identifier", None)
    if not c_id and isinstance(asset, str):
        c_id = asset
    if not c_id:
        return AssessmentScopeStatus.UNKNOWN
    res = scope_gate.evaluate_extended_scope(c_id)
    return res.scope_status

