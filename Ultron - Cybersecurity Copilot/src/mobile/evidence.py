"""Evidence Adapter for Mobile Android Artifacts.

Transforms static manifest, DEX, and smali evidence into CanonicalObservation
records backed by cryptographic provenance hashes.
"""

import hashlib
from typing import Any, Dict, List, Optional, Tuple
from src.assessment.models import (
    AssessmentScopeStatus,
    CanonicalObservation,
    ObservationType,
)
from src.mobile.artifacts import MobileArtifact
from src.mobile.manifest import ManifestAnalyzer
from src.mobile.dex import DexAnalyzer
from src.mobile.smali import SmaliAnalyzer


class MobileEvidenceAdapter:
    """Bridges Android analysis pipelines into the canonical assessment evidence store."""

    @staticmethod
    def process_android_package(
        assessment_id: str,
        package_name: str,
        manifest_xml: Optional[str] = None,
        dex_metadata: Optional[Dict[str, Any]] = None,
        smali_snippets: Optional[List[str]] = None,
    ) -> Tuple[MobileArtifact, CanonicalObservation]:
        layers = []
        components = []
        permissions = []
        deep_links = []

        if manifest_xml:
            layers.append("MANIFEST")
            m_res = ManifestAnalyzer.parse_manifest_xml(manifest_xml)
            components.extend(m_res["components"])
            permissions.extend(m_res["permissions"])
            deep_links.extend(m_res["deep_links"])

        dex_res = {}
        if dex_metadata:
            layers.append("DEX")
            dex_res = DexAnalyzer.analyze_dex_metadata(dex_metadata)

        smali_findings = []
        if smali_snippets:
            layers.append("SMALI")
            for snippet in smali_snippets:
                s_res = SmaliAnalyzer.analyze_smali_block(snippet)
                smali_findings.extend(s_res["findings"])

        artifact = MobileArtifact(
            package_name=package_name,
            components=components,
            permissions=permissions,
            deep_links=deep_links,
            embedded_urls=dex_res.get("embedded_urls", []),
            evidence_layers_analyzed=layers,
        )
        c_hash = artifact.compute_hash()

        # Build CanonicalObservation
        obs = CanonicalObservation.create(
            assessment_id=assessment_id,
            asset_id=f"ASSET-{package_name}",
            observation_type=ObservationType.MOBILE_ARTIFACT,
            source="ANDROID_STATIC_ANALYZER",
            normalized_data={
                "package_name": package_name,
                "exported_components": [c.name for c in components if c.is_exported],
                "deep_links": [d.scheme for d in deep_links],
                "layers_analyzed": layers,
                "smali_findings": smali_findings,
            },
            scope_decision=AssessmentScopeStatus.IN_SCOPE,
            confidence=1.0,
            provenance={
                "tool": "mobile_evidence_adapter",
                "package": package_name,
                "content_hash": c_hash,
            },
        )

        return artifact, obs

    @classmethod
    def create_mobile_observation(
        cls,
        assessment_id: str,
        target_asset: str,
        layer: str,
        data: Dict[str, Any],
    ) -> CanonicalObservation:
        """Convenience factory creating a typed mobile CanonicalObservation."""
        manifest_xml = None
        dex_meta = None
        smali_snips = None

        if layer == "MANIFEST":
            if isinstance(data, str):
                manifest_xml = data
            else:
                norm_data = {
                    "package_name": data.get("package_name", target_asset),
                    "exported_components": [c.name for c in data.get("components", []) if getattr(c, "is_exported", False)],
                    "deep_links": [getattr(d, "scheme", str(d)) for d in data.get("deep_links", [])],
                    "layers_analyzed": [layer],
                }
                c_hash = f"sha256:{hashlib.sha256(str(norm_data).encode()).hexdigest()}"
                return CanonicalObservation.create(
                    assessment_id=assessment_id,
                    asset_id=f"ASSET-{target_asset}",
                    observation_type=ObservationType.MOBILE_ARTIFACT,
                    source="ANDROID_STATIC_ANALYZER",
                    normalized_data=norm_data,
                    scope_decision=AssessmentScopeStatus.IN_SCOPE,
                    confidence=1.0,
                    provenance={"tool": "mobile_evidence_adapter", "layer": layer, "data_hash": c_hash},
                )
        elif layer == "DEX":
            dex_meta = data
        elif layer == "SMALI":
            norm_data = {
                "package_name": target_asset,
                "layers_analyzed": [layer],
                "smali_findings": data.get("findings", []),
            }
            c_hash = f"sha256:{hashlib.sha256(str(norm_data).encode()).hexdigest()}"
            return CanonicalObservation.create(
                assessment_id=assessment_id,
                asset_id=f"ASSET-{target_asset}",
                observation_type=ObservationType.MOBILE_ARTIFACT,
                source="ANDROID_STATIC_ANALYZER",
                normalized_data=norm_data,
                scope_decision=AssessmentScopeStatus.IN_SCOPE,
                confidence=1.0,
                provenance={"tool": "mobile_evidence_adapter", "layer": layer, "data_hash": c_hash},
            )

        _, obs = cls.process_android_package(
            assessment_id=assessment_id,
            package_name=target_asset,
            manifest_xml=manifest_xml,
            dex_metadata=dex_meta,
            smali_snippets=smali_snips,
        )
        return obs
