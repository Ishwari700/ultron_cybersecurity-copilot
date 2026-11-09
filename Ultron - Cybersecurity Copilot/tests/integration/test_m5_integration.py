"""End-to-End Integration Tests for Milestone M5 Copilot (Milestone M5 Section 46).

Tests:
- Test A — Simple Q&A (no unnecessary investigation, local sufficient)
- Test B — Local VAPT investigation (local retrieval, 3B triage, 7B reasoning if needed, no unnecessary search)
- Test C — Knowledge gap (unsupported domain produces KNOWLEDGE_GAP and external research)
- Test D — Multi-domain question (API + OAuth + TLS cross-domain routing)
- Test E — False positive / Negative-control analysis (benign endpoint, counterfactual checks)
- Test F — Conflicting sources (version/temporal conflict preserved, no silent resolution)
- Test G — Human verification gate (hypothesis cannot become finding until explicit human action)
"""

import pytest
from src.copilot.domain import DomainRouter, SecurityDomain
from src.copilot.intent import CopilotMode, CopilotTaskType, IntentRouter
from src.copilot.orchestration import ComplexityTier, CopilotOrchestrator
from src.copilot.registry import CoverageLevel, DomainKnowledgeRegistry
from src.copilot.sufficiency import KnowledgeSufficiencyEngine, SufficiencyStatus
from src.investigation.lifecycle import LifecycleManager
from src.investigation.models import (
    HypothesisStatus,
    InvestigationWorkspace,
    ObservationEntity,
    SeverityLevel,
)
from src.research.conflicts import ConflictCategory, ConflictDetector
from src.research.models import (
    ClaimEpistemicStatus,
    ClaimType,
    ExternalClaim,
)
from src.research.negative_control import NegativeControlEngine


def test_m5_integration_a_simple_qa():
    """Test A — Simple Q&A: normal answer, no unnecessary investigation, no external search."""
    query = "What is the difference between symmetric and asymmetric encryption?"

    intent_res = IntentRouter.classify_intent(query)
    domain_res = DomainRouter.classify_domain(query)
    suff_res = KnowledgeSufficiencyEngine.evaluate_sufficiency(
        query=query,
        domain=domain_res.primary_domain,
        task=intent_res.primary_task,
        mode=intent_res.mode,
    )

    response = CopilotOrchestrator.process_query(user_query=query)

    assert intent_res.mode == CopilotMode.GENERAL_QA
    assert intent_res.primary_task in (CopilotTaskType.COMPARE, CopilotTaskType.EXPLAIN)
    assert domain_res.primary_domain == SecurityDomain.CRYPTOGRAPHY
    assert suff_res.status == SufficiencyStatus.LOCAL_SUFFICIENT
    assert suff_res.escalate_to_external_research is False
    assert response.complexity == ComplexityTier.LOW_COMPLEXITY
    assert response.escalated_to_7b is False
    assert len(response.hypotheses) == 0
    assert len(response.experiments) == 0


def test_m5_integration_b_local_vapt_investigation():
    """Test B — Local VAPT investigation: local retrieval, 3B triage, 7B reasoning, no unnecessary external research."""
    workspace = InvestigationWorkspace(
        investigation_id="INV-INT-002",
        title="BOLA Investigation",
        target_host="api.corp.internal",
    )
    obs = LifecycleManager.record_observation(
        workspace=workspace,
        endpoint="/api/v1/invoices/100",
        summary="Returned full invoice details for user 100",
    )

    query = "Investigate potential BOLA on invoice endpoints"

    intent_res = IntentRouter.classify_intent(query, has_active_evidence=True)
    domain_res = DomainRouter.classify_domain(query)
    suff_res = KnowledgeSufficiencyEngine.evaluate_sufficiency(
        query=query,
        domain=domain_res.primary_domain,
        task=intent_res.primary_task,
        mode=intent_res.mode,
    )

    response = CopilotOrchestrator.process_query(user_query=query, workspace=workspace)

    assert intent_res.mode == CopilotMode.INVESTIGATION
    assert domain_res.primary_domain in (SecurityDomain.API_SECURITY, SecurityDomain.AUTHORIZATION)
    assert suff_res.status == SufficiencyStatus.LOCAL_SUFFICIENT
    assert suff_res.escalate_to_external_research is False
    # Empirical observation triggers escalation to 7B
    assert response.escalated_to_7b is True
    assert response.complexity in (ComplexityTier.MEDIUM_COMPLEXITY, ComplexityTier.HIGH_COMPLEXITY)


def test_m5_integration_c_knowledge_gap():
    """Test C — Knowledge gap: domain with limited/unsupported local corpus produces KNOWLEDGE_GAP and external research."""
    query = "Investigate digital forensics volshell memory extraction procedures"

    domain_res = DomainRouter.classify_domain(query)
    assert domain_res.primary_domain == SecurityDomain.DIGITAL_FORENSICS

    cov = DomainKnowledgeRegistry.get_coverage(domain_res.primary_domain)
    assert cov == CoverageLevel.LIMITED

    suff_res = KnowledgeSufficiencyEngine.evaluate_sufficiency(
        query=query,
        domain=domain_res.primary_domain,
        task=CopilotTaskType.INVESTIGATE,
        mode=CopilotMode.INVESTIGATION,
    )

    assert suff_res.status == SufficiencyStatus.KNOWLEDGE_GAP
    assert suff_res.escalate_to_external_research is True
    assert suff_res.sanitized_external_query is not None


def test_m5_integration_d_multi_domain_question():
    """Test D — Multi-domain question: API + OAuth + TLS cross-domain routing."""
    query = "Explain how to secure an OAuth 2.0 PKCE flow for an API with TLS 1.3 certificates"

    domain_res = DomainRouter.classify_domain(query)
    all_domains = [domain_res.primary_domain] + domain_res.secondary_domains

    assert len(all_domains) >= 2
    assert any(d in (SecurityDomain.AUTHENTICATION, SecurityDomain.AUTHORIZATION) for d in all_domains)
    assert any(d in (SecurityDomain.API_SECURITY, SecurityDomain.TLS_SECURITY, SecurityDomain.NETWORK_SECURITY) for d in all_domains)

    response = CopilotOrchestrator.process_query(user_query=query)
    assert response.primary_domain in all_domains
    assert len(response.secondary_domains) > 0


def test_m5_integration_e_false_positive():
    """Test E — False positive: benign public endpoint, counterfactual checks, no unsupported vuln conclusion."""
    query = "Endpoint /health returns HTTP 200 without authentication. Is this an unauthenticated access vulnerability?"

    nc_guidance = NegativeControlEngine.get_guidance(query, domain=SecurityDomain.API_SECURITY)
    assert len(nc_guidance) > 0

    guidance = nc_guidance[0]
    assert len(guidance.legitimate_explanations) > 0
    assert len(guidance.falsification_conditions) > 0

    response = CopilotOrchestrator.process_query(user_query=query)
    # Must not claim critical confirmed vulnerability
    assert response.human_verified_findings_count == 0
    assert "critical confirmed vulnerability" not in response.content.lower()


def test_m5_integration_f_conflicting_sources():
    """Test F — Conflicting sources: version/temporal conflict preserved, no silent resolution."""
    c1 = ExternalClaim(
        claim_id="CLM-OAUTH-01",
        source_id="SRC-RFC-6749",
        statement="PKCE is optional for confidential clients in OAuth 2.0.",
        claim_type=ClaimType.SECURITY_INVARIANT,
    )
    c2 = ExternalClaim(
        claim_id="CLM-OAUTH-02",
        source_id="SRC-RFC-OAuth21",
        statement="PKCE is required for all clients in OAuth 2.1.",
        claim_type=ClaimType.SECURITY_INVARIANT,
    )

    conflicts, updated_claims = ConflictDetector.detect_conflicts([c1, c2])

    assert len(conflicts) == 1
    conf = conflicts[0]
    assert conf.category == ConflictCategory.TEMPORAL_CHANGE
    assert "OAuth 2.1" in str(conf.version_conditions) or "OAuth 2.0" in str(conf.version_conditions)
    assert "supersedes" in conf.preferred_interpretation.lower()

    # Verify both claims are marked EXTERNAL_CONFLICTED
    assert c1.epistemic_status == ClaimEpistemicStatus.EXTERNAL_CONFLICTED
    assert c2.epistemic_status == ClaimEpistemicStatus.EXTERNAL_CONFLICTED

    # Ingest into orchestrator response
    response = CopilotOrchestrator.process_query(
        user_query="Does OAuth require PKCE?",
        external_claims=updated_claims,
        conflicts=conflicts,
    )
    assert len(response.conflicts) == 1
    assert "TEMPORAL_CHANGE" in response.content


def test_m5_integration_g_human_verification():
    """Test G — Human verification: hypothesis cannot become finding until explicit human action."""
    workspace = InvestigationWorkspace(
        investigation_id="INV-INT-007",
        title="Human Gate Verification Test",
        target_host="api.target.internal",
    )
    obs = LifecycleManager.record_observation(
        workspace=workspace,
        endpoint="/api/v1/admin/export",
        summary="Export returned HTTP 200 with tenant dump",
    )

    hyp = LifecycleManager.propose_hypothesis(
        workspace=workspace,
        statement="Tenant isolation failure on export endpoint",
        domain=SecurityDomain.AUTHORIZATION.value,
        supporting_fact_ids=[obs.observation_id],
        falsification_condition="Access denied HTTP 403 on tenant B export",
    )

    # 1. Automated direct promotion is blocked
    with pytest.raises(PermissionError):
        LifecycleManager.update_hypothesis_status(
            workspace,
            hyp.hypothesis_id,
            HypothesisStatus.HUMAN_VERIFIED,
        )

    # 2. Report drafted prior to verification is unverified draft
    draft_pre = LifecycleManager.draft_report(workspace, hyp.hypothesis_id)
    assert draft_pre.status_label == "DRAFT / UNVERIFIED"
    assert draft_pre.human_verified is False

    # 3. Explicit human verification executes
    finding = LifecycleManager.verify_hypothesis_by_human(
        workspace=workspace,
        hypothesis_id=hyp.hypothesis_id,
        human_verifier="alice_security_researcher",
        notes="Manually verified tenant B token accessed tenant A export with identical payload.",
        severity=SeverityLevel.HIGH,
    )

    assert finding.human_verifier == "alice_security_researcher"
    assert len(workspace.findings) == 1
    assert hyp.status == HypothesisStatus.HUMAN_VERIFIED
    assert hyp.human_verified is True

    # 4. Report drafted post-verification is HUMAN_VERIFIED
    draft_post = LifecycleManager.draft_report(workspace, hyp.hypothesis_id)
    assert draft_post.status_label == "HUMAN_VERIFIED"
    assert draft_post.human_verified is True
