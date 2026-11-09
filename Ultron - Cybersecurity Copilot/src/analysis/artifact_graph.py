"""Unified Multi-Layer Artifact Graph and Cross-Artifact Reasoning Engine for M10.

Connects static evidence layers:
APK -> Manifest -> Component -> DEX Class -> Method -> Smali -> Native Library -> Function -> Sink
and:
Android Component -> Deep Link -> URL -> API Endpoint

Preserves epistemic boundaries:
- OBSERVED_RELATION: Direct static proof
- INFERRED_RELATION: Pattern/name-matched connection
- UNRESOLVED_RELATION: Dynamic/reflective call without resolved target (INV-M10-06)
- MODEL_HYPOTHESIS: Predictive reasoning candidate
- CONTRADICTION: Preserves competing/conflicting evidence without silent selection (INV-M10-05).
"""

from collections import deque
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from src.artifacts.metadata import ArtifactRecord


class RelationType(str, Enum):
    OBSERVED_RELATION = "OBSERVED_RELATION"
    INFERRED_RELATION = "INFERRED_RELATION"
    UNRESOLVED_RELATION = "UNRESOLVED_RELATION"
    MODEL_HYPOTHESIS = "MODEL_HYPOTHESIS"


class ArtifactNode(BaseModel):
    node_id: str
    node_type: str  # APK, MANIFEST, COMPONENT, DEX_CLASS, METHOD, SMALI, NATIVE_LIB, FUNCTION, SINK, DEEP_LINK, URL, API_ENDPOINT
    label: str
    artifact_id: Optional[str] = None
    source_layer: str = "STATIC"
    properties: Dict[str, Any] = Field(default_factory=dict)


class ArtifactEdge(BaseModel):
    source_id: str
    target_id: str
    relation_type: RelationType = RelationType.OBSERVED_RELATION
    label: str = "CONNECTS_TO"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ContradictionRecord(BaseModel):
    contradiction_id: str
    topic: str
    claim_a: str
    source_a: str
    claim_b: str
    source_b: str
    status: str = "UNRESOLVED_CONTRADICTION"
    description: str = ""


class AndroidArtifactGraph:
    """Unified graph connecting Android and Native binary evidence layers."""

    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id
        self.nodes: Dict[str, ArtifactNode] = {}
        self.edges: List[ArtifactEdge] = []
        self._adj: Dict[str, List[ArtifactEdge]] = {}
        self.contradictions: List[ContradictionRecord] = []

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        artifact_id: Optional[str] = None,
        source_layer: str = "STATIC",
        properties: Optional[Dict[str, Any]] = None,
    ) -> ArtifactNode:
        """Adds a verified artifact node."""
        node = ArtifactNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            artifact_id=artifact_id,
            source_layer=source_layer,
            properties=properties or {},
        )
        self.nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType = RelationType.OBSERVED_RELATION,
        label: str = "CONNECTS_TO",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ArtifactEdge:
        """Adds a typed relationship edge."""
        edge = ArtifactEdge(
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            label=label,
            metadata=metadata or {},
        )
        self.edges.append(edge)
        self._adj.setdefault(source_id, []).append(edge)
        return edge

    def record_contradiction(
        self,
        topic: str,
        claim_a: str,
        source_a: str,
        claim_b: str,
        source_b: str,
        description: str = "",
    ) -> ContradictionRecord:
        """
        Records competing or conflicting evidence between artifacts without
        silently choosing one (INV-M10-05).
        """
        cid = f"CONTRA-{len(self.contradictions) + 1:03d}"
        rec = ContradictionRecord(
            contradiction_id=cid,
            topic=topic,
            claim_a=claim_a,
            source_a=source_a,
            claim_b=claim_b,
            source_b=source_b,
            description=description or f"Competing claims regarding '{topic}' between {source_a} and {source_b}",
        )
        self.contradictions.append(rec)
        return rec

    def correlate_manifest_to_dex(
        self,
        component_name: str,
        dex_class_name: str,
    ) -> None:
        """Correlates an Android component from manifest with its DEX implementation class."""
        c_node_id = f"COMP:{component_name}"
        d_node_id = f"CLASS:{dex_class_name}"
        if c_node_id in self.nodes and d_node_id in self.nodes:
            self.add_edge(
                source_id=c_node_id,
                target_id=d_node_id,
                relation_type=RelationType.OBSERVED_RELATION,
                label="IMPLEMENTED_BY",
            )

    def correlate_jni_native_method(
        self,
        dex_method_id: str,
        native_function_name: str,
        native_library_name: str,
    ) -> None:
        """
        Correlates a Java/Kotlin native method declaration to its compiled C/C++
        JNI function symbol inside a native library (.so).
        """
        m_node_id = f"METHOD:{dex_method_id}"
        fn_node_id = f"FUNC:{native_library_name}:{native_function_name}"

        # JNI naming convention check: Java_package_Class_method
        clean_class = dex_method_id.split("->")[0].replace("/", "_").replace(";", "").replace("L", "")
        clean_method = dex_method_id.split("->")[1].split("(")[0]
        expected_jni_symbol = f"Java_{clean_class}_{clean_method}"

        rel_type = (
            RelationType.OBSERVED_RELATION
            if native_function_name == expected_jni_symbol
            else RelationType.INFERRED_RELATION
        )

        self.add_edge(
            source_id=m_node_id,
            target_id=fn_node_id,
            relation_type=rel_type,
            label="CALLS_JNI_NATIVE",
            metadata={"expected_jni_symbol": expected_jni_symbol, "actual_symbol": native_function_name},
        )

    def find_path_to_sink(
        self,
        start_node_id: str,
        target_sink_id: str,
    ) -> Tuple[bool, List[str], List[str]]:
        """
        Finds path from entry node to target sink, capturing unresolved relationships.
        Returns: (path_exists: bool, path_nodes: List[str], unresolved_steps: List[str])
        """
        if start_node_id == target_sink_id:
            return True, [start_node_id], []

        queue = deque([(start_node_id, [start_node_id], [])])
        visited: Set[str] = {start_node_id}

        while queue:
            curr, path, unres = queue.popleft()
            for edge in self._adj.get(curr, []):
                new_unres = list(unres)
                if edge.relation_type == RelationType.UNRESOLVED_RELATION:
                    new_unres.append(f"{edge.source_id} -> {edge.target_id}")

                if edge.target_id == target_sink_id:
                    return True, path + [edge.target_id], new_unres

                if edge.target_id not in visited:
                    visited.add(edge.target_id)
                    queue.append((edge.target_id, path + [edge.target_id], new_unres))

        return False, [], []
