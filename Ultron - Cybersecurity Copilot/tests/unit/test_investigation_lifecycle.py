"""Unit Tests for Investigation Lifecycle, Hypothesis Governance, and Human Gate (Milestone M5)."""

import pytest
from src.investigation.graph import (
    EntityType,
    InvestigationEvidenceGraph,
    RelationshipType,
)
from src.investigation.lifecycle import LifecycleManager
from src.investigation.models import (
    EvidenceGapStatus,
    HypothesisStatus,
    InvestigationWorkspace,
    ObservationEntity,
    SeverityLevel,
)
from src.investigation.summary import InvestigationSummaryGenerator


def _create_workspace(inv_id: str = "INV-001", target: str = "target.corp.local") -> InvestigationWorkspace:
    return InvestigationWorkspace(
        investigation_id=inv_id,
        title="Test Security Investigation",
        target_host=target,
    )


def test_investigation_isolation_and_contamination_rejection():
    """Verify cross-investigation evidence contamination is rejected."""
    ws1 = _create_workspace("INV-001")
    ws2 = _create_workspace("INV-002")

    obs1 = LifecycleManager.record_observation(ws1, "/api/v1/users", "Observed user profile endpoint")
    obs2 = LifecycleManager.record_observation(ws2, "/admin/dashboard", "Observed admin console")

    assert obs1.investigation_id == "INV-001"
    assert obs2.investigation_id == "INV-002"

    # Workspace 1 assertion succeeds
    ws1.assert_isolation("INV-002")

    # Infiltrate workspace 1 with foreign observation from workspace 2
    ws1.observations.append(obs2)
    with pytest.raises(ValueError, match="Cross-investigation contamination detected"):
        ws1.assert_isolation("INV-002")


def test_hypothesis_lifecycle_progression():
    """Verify formal progression: PROPOSED -> NEEDS_EVIDENCE -> TESTABLE -> SUPPORTED."""
    ws = _create_workspace("INV-001")
    obs = LifecycleManager.record_observation(ws, "/api/v1/invoices/100", "Returned invoice data for tenant A")

    # 1. Propose hypothesis
    hyp = LifecycleManager.propose_hypothesis(
        workspace=ws,
        statement="Tenant B can access Tenant A invoices (BOLA)",
        domain="API_SECURITY",
        supporting_fact_ids=[obs.observation_id],
        falsification_condition="Access denied with HTTP 403 when requesting Tenant A invoice using Tenant B token",
    )
    assert hyp.status == HypothesisStatus.PROPOSED

    # 2. Add evidence gap -> transitions to NEEDS_EVIDENCE
    gap = LifecycleManager.add_evidence_gap(
        workspace=ws,
        hypothesis_id=hyp.hypothesis_id,
        description="Missing observation with Tenant B token",
        required_evidence="HTTP request to /api/v1/invoices/100 signed with Tenant B token",
    )
    assert gap.status == EvidenceGapStatus.OPEN
    assert hyp.status == HypothesisStatus.NEEDS_EVIDENCE

    # 3. Propose experiment -> transitions to TESTABLE
    exp = LifecycleManager.propose_experiment(
        workspace=ws,
        hypothesis_id=hyp.hypothesis_id,
        objective="Verify cross-tenant authorization boundary",
        steps=["Generate Tenant B token", "Request /api/v1/invoices/100", "Check response status code"],
        expected_secure="HTTP 403 Forbidden",
        expected_vulnerable="HTTP 200 OK with Tenant A invoice body",
        falsification="Server returns 403 or 404",
        negative_control="Access public tenant directory",
    )
    assert exp.experiment_id.startswith("EXP-")
    assert hyp.status == HypothesisStatus.TESTABLE

    # 4. Resolve evidence gap
    LifecycleManager.resolve_evidence_gap(
        workspace=ws,
        gap_id=gap.gap_id,
        status=EvidenceGapStatus.SATISFIED,
        resolution_notes="Observed differential request result",
    )
    assert gap.status == EvidenceGapStatus.SATISFIED

    # 5. Transition hypothesis to SUPPORTED
    LifecycleManager.update_hypothesis_status(
        workspace=ws,
        hypothesis_id=hyp.hypothesis_id,
        new_status=HypothesisStatus.SUPPORTED,
    )
    assert hyp.status == HypothesisStatus.SUPPORTED
    assert hyp.human_verified is False


def test_human_verification_gate_mandatory_for_finding():
    """Verify that SUPPORTED != HUMAN_VERIFIED and automated promotion fails closed."""
    ws = _create_workspace("INV-001")
    obs = LifecycleManager.record_observation(ws, "/api/v1/items/42", "Observed item details")
    hyp = LifecycleManager.propose_hypothesis(
        ws, "IDOR on item update", "API_SECURITY", [obs.observation_id], "403 when not item owner"
    )

    # Automated logic cannot promote directly to HUMAN_VERIFIED
    with pytest.raises(PermissionError, match="Automated logic cannot set status to HUMAN_VERIFIED"):
        LifecycleManager.update_hypothesis_status(ws, hyp.hypothesis_id, HypothesisStatus.HUMAN_VERIFIED)

    # Empty or automated verifier fails closed
    with pytest.raises(PermissionError, match="Human verification gate requires an authentic human researcher identity"):
        LifecycleManager.verify_hypothesis_by_human(ws, hyp.hypothesis_id, human_verifier="system", notes="Auto confirmed")

    with pytest.raises(PermissionError, match="Human verification gate requires an authentic human researcher identity"):
        LifecycleManager.verify_hypothesis_by_human(ws, hyp.hypothesis_id, human_verifier="", notes="Empty")

    # Authentic human verification succeeds
    finding = LifecycleManager.verify_hypothesis_by_human(
        ws,
        hyp.hypothesis_id,
        human_verifier="alice_security_lead",
        notes="Independently reproduced via curl; cross-tenant invoice leaked.",
        severity=SeverityLevel.HIGH,
    )
    assert finding.finding_id.startswith("FIND-")
    assert finding.human_verifier == "alice_security_lead"
    assert hyp.status == HypothesisStatus.HUMAN_VERIFIED
    assert hyp.human_verified is True


def test_report_drafting_requires_human_verification():
    """Verify reports are explicitly marked DRAFT / UNVERIFIED until human verification."""
    ws = _create_workspace("INV-001")
    obs = LifecycleManager.record_observation(ws, "/api/v1/docs", "Doc endpoint")
    hyp = LifecycleManager.propose_hypothesis(ws, "Docs leak internal keys", "API_SECURITY", [obs.observation_id], "403 on internal docs")

    # Draft report before human verification
    draft_unverified = LifecycleManager.draft_report(ws, hyp.hypothesis_id)
    assert draft_unverified.status_label == "DRAFT / UNVERIFIED"
    assert draft_unverified.human_verified is False

    # Perform human verification
    LifecycleManager.verify_hypothesis_by_human(ws, hyp.hypothesis_id, "bob_auditor", "Verified leak")

    # Draft report after human verification
    verified_report = LifecycleManager.draft_report(ws, hyp.hypothesis_id)
    assert verified_report.status_label == "HUMAN_VERIFIED"
    assert verified_report.human_verified is True


def test_evidence_graph_linking():
    """Verify Evidence Graph tracks entity relationships per Section 20."""
    graph = InvestigationEvidenceGraph(investigation_id="INV-001")

    # Add edges
    e1 = graph.add_edge(
        source_id="END-01",
        source_type=EntityType.ENDPOINT,
        relationship=RelationshipType.OBSERVED_IN,
        target_id="TRF-01",
        target_type=EntityType.TRAFFIC,
    )
    e2 = graph.add_edge(
        source_id="FACT-01",
        source_type=EntityType.OBSERVATION,
        relationship=RelationshipType.SUPPORTS,
        target_id="HYP-01",
        target_type=EntityType.HYPOTHESIS,
    )
    e3 = graph.add_edge(
        source_id="GAP-01",
        source_type=EntityType.EVIDENCE_GAP,
        relationship=RelationshipType.ADDRESSED_BY,
        target_id="EXP-01",
        target_type=EntityType.EXPERIMENT,
    )

    assert len(graph.edges) == 3
    assert graph.get_supporting_evidence_for_hypothesis("HYP-01") == ["FACT-01"]
    assert graph.get_experiments_for_gap("GAP-01") == ["EXP-01"]


def test_investigation_summary_generation():
    """Verify deterministic summary generator computes accurate metrics."""
    ws = _create_workspace("INV-001")
    obs = LifecycleManager.record_observation(ws, "/api/data", "Data access")
    hyp = LifecycleManager.propose_hypothesis(ws, "Data leak", "API_SECURITY", [obs.observation_id], "falsification")
    LifecycleManager.add_evidence_gap(ws, hyp.hypothesis_id, "Gap description", "Required evidence")
    LifecycleManager.propose_experiment(ws, hyp.hypothesis_id, "Exp objective", ["step 1"], "sec", "vuln", "fals", "neg")

    summary = InvestigationSummaryGenerator.generate_summary(ws)
    assert summary.total_observations == 1
    assert summary.total_hypotheses == 1
    assert summary.open_evidence_gaps == 1
    assert summary.recommended_experiments == 1
    assert summary.human_verified_findings == 0
    assert summary.primary_domain == "API_SECURITY"

    rendered_text = summary.format_text_summary()
    assert "INV-001" in rendered_text
    assert "1 observations" in rendered_text
    assert "0 human-verified findings" in rendered_text
