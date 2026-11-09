"""Binary Evidence Adapter for Reverse Engineering in M7.

Transforms function summaries, decompiled sinks, and reachability proofs
into CanonicalObservation records backed by cryptographic audit hashes.
"""

from typing import Any, Dict, List, Optional, Tuple
from src.assessment.models import (
    AssessmentScopeStatus,
    CanonicalObservation,
    ObservationType,
)
from src.binary.artifacts import (
    BinaryArtifact,
    CallRelationship,
    FunctionArtifact,
    SuspiciousSink,
)
from src.binary.functions import FunctionAnalyzer
from src.binary.relationships import CallGraphAnalyzer


class BinaryEvidenceAdapter:
    """Bridges decompiled binary intelligence into canonical assessment observations."""

    @staticmethod
    def process_binary_analysis(
        assessment_id: str,
        binary_name: str,
        architecture: str = "x86_64",
        format_type: str = "ELF",
        raw_functions: Optional[List[Dict[str, Any]]] = None,
        raw_call_graph: Optional[List[Dict[str, str]]] = None,
        imports: Optional[List[str]] = None,
        exports: Optional[List[str]] = None,
    ) -> Tuple[BinaryArtifact, CanonicalObservation]:
        functions: List[FunctionArtifact] = []
        sinks: List[SuspiciousSink] = []

        if raw_functions:
            functions, sinks = FunctionAnalyzer.analyze_functions(raw_functions)

        call_relationships: List[CallRelationship] = []
        if raw_call_graph:
            for rel in raw_call_graph:
                call_relationships.append(CallRelationship(
                    caller=rel.get("caller", ""),
                    callee=rel.get("callee", ""),
                ))

        artifact = BinaryArtifact(
            binary_name=binary_name,
            architecture=architecture,
            format=format_type,
            functions=functions,
            call_graph=call_relationships,
            sinks=sinks,
            imports=imports or [],
            exports=exports or [],
        )
        c_hash = artifact.compute_hash()

        # Build CanonicalObservation
        obs = CanonicalObservation.create(
            assessment_id=assessment_id,
            asset_id=f"ASSET-{binary_name}",
            observation_type=ObservationType.SOURCE_CODE,  # Decompiled / Disassembled code
            source="BINARY_REVERSE_ENGINEERING_ADAPTER",
            normalized_data={
                "binary_name": binary_name,
                "architecture": architecture,
                "format": format_type,
                "function_count": len(functions),
                "suspicious_sinks": [s.instruction_or_call for s in sinks],
                "exports": exports or [],
            },
            scope_decision=AssessmentScopeStatus.IN_SCOPE,
            confidence=1.0,
            provenance={
                "tool": "binary_evidence_adapter",
                "binary_name": binary_name,
                "content_hash": c_hash,
            },
        )

        return artifact, obs
