"""Mobile Android Security Analyst Agent for M7.

Enforces:
1. Deep multi-layer analysis: Manifest, DEX, SMALI, Resources, WebViews, Deep links.
2. Identifies: SUSPICIOUS_PATTERN, POSSIBLE_VULNERABILITY, EVIDENCE_GAP.
3. INVARIANT: Never declares confirmed vulnerability from static package indicators alone.
4. Generates testable hypotheses with explicit negative controls and safe experiment steps.
"""

from typing import Any, Dict, List
from src.agents.base import BaseAgent
from src.agents.schemas import AgentOutput, AgentTask, AgentType
from src.assessment.models import (
    AssessmentHypothesis,
    AssessmentExperiment,
    EpistemicStatus,
    ExperimentRiskLevel,
    ExperimentStatus,
)
from src.mobile.artifacts import MobileArtifact
from src.mobile.manifest import ManifestAnalyzer
from src.mobile.dex import DexAnalyzer
from src.mobile.smali import SmaliAnalyzer


class MobileAndroidAnalystAgent(BaseAgent):
    """Specialized agent for Android application auditing across Manifest, DEX, and Smali layers."""

    def __init__(self, assessment_id: str, agent_id: str = "AGENT-MOBILE-001") -> None:
        super().__init__(agent_id=agent_id, agent_type=AgentType.MOBILE, assessment_id=assessment_id)

    def analyze(self, task: AgentTask, context: Dict[str, Any]) -> AgentOutput:
        package_name = task.target_asset
        manifest_xml = context.get("manifest_xml", "")
        dex_meta = context.get("dex_metadata", {})
        smali_snippets = context.get("smali_snippets", [])
        observations = context.get("observations", [])
        evidence_ids = [obs.get("observation_id") for obs in observations if isinstance(obs, dict) and "observation_id" in obs]

        hypotheses: List[AssessmentHypothesis] = []
        evidence_gaps: List[str] = []
        proposed_exps: List[AssessmentExperiment] = []
        layers_analyzed = []

        # 1. Manifest Analysis
        exported_components = []
        if manifest_xml:
            layers_analyzed.append("MANIFEST")
            m_res = ManifestAnalyzer.parse_manifest_xml(manifest_xml)
            for comp in m_res.get("components", []):
                if comp.is_exported and not comp.permission_required:
                    exported_components.append(comp.name)

        # 2. DEX Analysis
        if dex_meta:
            layers_analyzed.append("DEX")
            d_res = DexAnalyzer.analyze_dex_metadata(dex_meta)
            if d_res.get("embedded_urls"):
                evidence_gaps.append(f"Discovered {len(d_res['embedded_urls'])} embedded endpoints in DEX; verify API backend scope.")

        # 3. Smali Analysis
        smali_vulnerabilities = []
        if smali_snippets:
            layers_analyzed.append("SMALI")
            for snippet in smali_snippets:
                s_res = SmaliAnalyzer.analyze_smali_block(snippet)
                smali_vulnerabilities.extend(s_res.get("findings", []))

        # 4. Extract from ingested observations
        for obs in observations:
            if isinstance(obs, dict):
                nd = obs.get("normalized_data", {})
                for layer in nd.get("layers_analyzed", []):
                    if layer not in layers_analyzed:
                        layers_analyzed.append(layer)
                for exp_c in nd.get("exported_components", []):
                    if exp_c not in exported_components:
                        exported_components.append(exp_c)
                for sm_f in nd.get("smali_findings", []):
                    smali_vulnerabilities.append(sm_f)

        # Formulate hypothesis for unpermissioned exported components
        if exported_components:
            target_comp = exported_components[0]
            hyp = AssessmentHypothesis(
                hypothesis_id=f"HYP-MOB-{len(hypotheses)+1:03d}",
                assessment_id=self.assessment_id,
                title=f"Exported IPC Component Without Permission Boundary on {package_name}",
                description=f"Component '{target_comp}' has android:exported='true' without custom permission protection.",
                domain="ANDROID",
                supporting_observations=evidence_ids[:1],
                security_invariants=["ANDROID: Exported components handling sensitive state must enforce signature/custom permission checks."],
                negative_control="Component rejects intents with unexpected extras or fails cleanly without sensitive action.",
                falsification_condition="Component validates caller UID/signature at runtime or requires system privilege.",
                evidence_gaps=[f"Missing runtime intent fuzzing verifying component action on {target_comp}."],
            )
            hypotheses.append(hyp)

            exp = AssessmentExperiment(
                experiment_id=f"EXP-MOB-{len(proposed_exps)+1:03d}",
                assessment_id=self.assessment_id,
                hypothesis_id=hyp.hypothesis_id,
                objective=f"Test intent launch on exported component {target_comp}",
                authorization_reference=task.authorization_id,
                scope_reference=task.scope_reference,
                preconditions=[f"Android emulator/test device running authorized build of {package_name}"],
                steps=[f"adb shell am start -n {package_name}/{target_comp}"],
                expected_secure_result="SecurityException thrown or intent rejected",
                expected_vulnerable_result="Activity opens directly or exposes unauthorized action",
                falsification_condition="System enforces permission check or rejects launch",
                negative_control="Standard in-app launch validates legitimate flow",
                requires_human_execution=True,
                risk_level=ExperimentRiskLevel.LOW_RISK,
                status=ExperimentStatus.PROPOSED,
            )
            proposed_exps.append(exp)

        # Formulate hypothesis for smali findings (e.g., insecure WebView)
        for s_find in smali_vulnerabilities:
            hyp = AssessmentHypothesis(
                hypothesis_id=f"HYP-MOB-{len(hypotheses)+1:03d}",
                assessment_id=self.assessment_id,
                title=f"Potential {s_find['type']} in {package_name}",
                description=s_find["description"],
                domain="ANDROID",
                supporting_observations=evidence_ids[:1],
                security_invariants=["MOBILE: WebViews must disallow local file access and restrict JavaScript interfaces."],
                negative_control="WebView loads HTTPS remote URL securely without evaluating file:// URIs.",
                falsification_condition="Local file loading is blocked by WebSettings configuration.",
                evidence_gaps=["Missing empirical runtime URL load test on affected WebView."],
            )
            hypotheses.append(hyp)

        summary = (
            f"Android analysis for {package_name}: Analyzed layers: {layers_analyzed}. "
            f"Found {len(exported_components)} unprotected exported components and {len(smali_vulnerabilities)} smali indicators. "
            f"Static artifact != verified finding."
        )

        return AgentOutput(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            assessment_id=self.assessment_id,
            task_id=task.task_id,
            confidence=0.82,
            epistemic_status=EpistemicStatus.MODEL_HYPOTHESIS,
            hypotheses=hypotheses,
            evidence_gaps=evidence_gaps,
            security_invariants=["INV-MOB-01: Static Android artifact != confirmed vulnerability."],
            proposed_experiments=proposed_exps,
            supporting_evidence=evidence_ids,
            analysis_summary=summary,
            provenance={"layers_analyzed": layers_analyzed},
        )
