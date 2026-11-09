# M13 — Full Security Assessment Workspace: Implementation Plan

## Milestone Overview
- **Milestone**: M13 — Full Security Assessment Workspace
- **Subphases**: M13.1 through M13.10
- **Verified Baseline**: Commit `b6e4d28`, Tag `v12.0.0-security-research-memory` (1,531 passed, 1 skipped, 0 failed)
- **Primary Objective**: Unify completed research subsystems (M0–M12) into a cohesive, auditable, and production-grade security assessment workspace spanning assessment lifecycle, scope enforcement, asset graph, artifact analysis, evidence lineage, controlled experiments, human review, findings validation, reporting, and audit timeline.
- **Core Axiom**: **THE WORKSPACE IS A CONTEXT INTERFACE, NOT AN AUTHORITY.** System Security Policy > ScopeGate & Authorization > Canonical Evidence > Human-Verified Findings > Research Memory > Analytical Hypotheses > LLM Reasoning.

---

## 1. Subphase Architecture & Module Mapping

### M13.1 — Workspace Architecture & Domain Model
- **Existing Modules**:
  - `src/assessment/models.py`: Canonical `AssessmentRecord`, `AuthorizationRecord`, `AssetRecord`, `CanonicalObservation`, `AssessmentHypothesis`, `AssessmentExperiment`, `AssessmentFinding`, `AssessmentAuditRecord`.
  - `src/assessment/manager.py`: `AssessmentManager`, `AssessmentContainer`.
  - `src/dashboard/models.py`: API request/response models.
- **Required Additions**:
  - `src/workspace/models.py`: `WorkspaceOverview`, `AssessmentSection`, `WorkspaceViewState`, `AssessmentNavigationState`, `AssessmentSummary`.
  - `docs/M13_WORKSPACE_ARCHITECTURE.md`, `docs/M13_DOMAIN_MODEL.md`.
- **Acceptance Criteria**: Strongly typed models unifying assessment state across backend and frontend, persisting state without creating parallel authorization records.

---

### M13.2 — Unified Workspace Shell & Navigation
- **Existing Modules**:
  - `frontend/src/App.tsx`: Main React component.
  - `frontend/src/components/Sidebar.tsx`, `frontend/src/components/InvestigationHeader.tsx`, `frontend/src/components/ContextDrawer.tsx`.
- **Required Additions**:
  - `frontend/src/components/workspace/WorkspaceShell.tsx`: Navigation bar (Dashboard/Assessments, Knowledge, Artifacts, Reports, Settings).
  - `frontend/src/components/workspace/AssessmentWorkspace.tsx`: 12-section tabbed assessment view (Overview, Scope & Assets, Attack Surface, Artifacts, Research, Hypotheses & Gaps, Evidence, Experiments, Findings & Review, Reports, Memory & Knowledge, Activity & Audit).
  - `frontend/src/components/workspace/AssessmentList.tsx`: Search, filtering, status badges, pagination, empty/loading/error states.
  - `frontend/src/components/workspace/WorkspaceHeader.tsx`: Lifecycle state, authoritative authorization badge, last activity, scope status.
- **Acceptance Criteria**: Responsive UI matching existing dark aesthetic, smooth section switching, persistence of active tab.

---

### M13.3 — Assessment Lifecycle, Scope & Asset Graph
- **Existing Modules**:
  - `src/assessment/lifecycle.py`: `AssessmentLifecycleEngine` (DRAFT, AUTHORIZATION_PENDING, AUTHORIZED, SCOPE_DEFINED, ASSESSMENT_ACTIVE, VALIDATION_PENDING, HUMAN_REVIEW, COMPLETED, ARCHIVED).
  - `src/assessment/authorization.py`: `AuthorizationValidator`.
  - `src/scope/gate.py`: `ScopeGate`.
  - `src/assessment/assets.py`: `AssetGraph`.
  - `src/assessment/attack_surface.py`: `AttackSurfaceMap`.
- **Required Additions**:
  - Extended REST endpoints in `src/dashboard/app.py`: `/api/assessments/{id}/workspace`, `/overview`, `/lifecycle/transition`, `/scope/validate`, `/attack-surface`.
  - `frontend/src/components/workspace/ScopeAndAssetsTab.tsx`: Scope policy inspector, in-scope vs out-of-scope lists, asset inventory table.
  - `frontend/src/components/workspace/AttackSurfaceTab.tsx`: Structured attack surface node & relationship viewer.
  - `frontend/src/components/workspace/NewAssessmentModal.tsx`: Wizard for assessment creation, authorization evidence, and initial scope.
- **Acceptance Criteria**: Strict state machine transitions, immutable audit events, UI cannot grant authorization or expand scope.

---

### M13.4 — Artifacts, Observations & Evidence Workspace
- **Existing Modules**:
  - `src/artifacts/registry.py`: `ArtifactRegistry` (APK, DEX, ELF, PE, Source, HAR, OpenAPI, PCAP, logs).
  - `src/evidence/ingestion/pipeline.py`: `EvidenceIngestionPipeline`.
  - `src/assessment/lineage.py`: `EvidenceLineageGraph`.
- **Required Additions**:
  - Endpoints in `src/dashboard/app.py`: `/api/assessments/{id}/artifacts`, `/api/assessments/{id}/lineage`, `/api/assessments/{id}/evidence`.
  - `frontend/src/components/workspace/ArtifactsTab.tsx`: Artifact upload, digest check, quarantine status, extracted observations.
  - `frontend/src/components/workspace/EvidenceTab.tsx`: Evidence explorer, filter by asset/type/review status.
  - `frontend/src/components/workspace/LineageModal.tsx`: Visual/structured evidence lineage graph (Artifact -> Observation -> Hypothesis -> Experiment -> Finding).
- **Acceptance Criteria**: Zero duplication of canonical evidence, strict assessment isolation, secret redaction on display.

---

### M13.5 — Integrated Research Workflow
- **Existing Modules**:
  - `src/copilot/orchestration.py`: `CopilotOrchestrator` (M9 Knowledge RAG).
  - `src/memory/retrieval.py`: `HybridMemoryRetriever` (M12 Research Memory).
  - `src/agents/`: M7 specialized analytical agents.
  - `src/hypothesis/state_machine.py`: `HypothesisStateMachine`.
- **Required Additions**:
  - Endpoints in `src/dashboard/app.py`: `/api/assessments/{id}/research/query`, `/api/assessments/{id}/agents/run`.
  - `frontend/src/components/workspace/ResearchTab.tsx`: Integrated conversational research copilot with M9 RAG & M12 memory context.
  - `frontend/src/components/workspace/HypothesesTab.tsx`: Hypotheses list, evidence gaps, falsification criteria.
  - `frontend/src/components/workspace/ContextInspector.tsx`: Transparent attribution drawer showing citation provenance (Global Knowledge vs Research Memory vs Target Evidence).
- **Acceptance Criteria**: Clear separation of logical planes, no CoT leaks, epistemic badges visible on all answers.

---

### M13.6 — Controlled Experiments & Reproducibility
- **Existing Modules**:
  - `src/experiment/`: M11 Safe PoC Engine, deterministic execution engine, safe simulation.
  - `src/assessment/experiments.py`: `SafeExperimentEngine`.
- **Required Additions**:
  - Endpoints in `src/dashboard/app.py`: `/api/assessments/{id}/experiments/plan`, `/api/experiments/{id}/preflight`.
  - `frontend/src/components/workspace/ExperimentsTab.tsx`: Experiment list, risk levels, preflight validation indicators, Plane A lab approval button, Plane B manual reproduction steps.
- **Acceptance Criteria**: Plane A requires human approval and deterministic preflight; Plane B forbids autonomous execution; negative controls recorded as research lessons.

---

### M13.7 — Human Review, Findings & Reporting
- **Existing Modules**:
  - `src/assessment/review.py`: `HumanReviewWorkspace`.
  - `src/assessment/validation.py`: `FindingValidator`.
  - `src/reporting/builder.py`: Report generator (Markdown, HTML, PDF, SARIF, ASVS, BugBounty).
- **Required Additions**:
  - Endpoints in `src/dashboard/app.py`: `/api/assessments/{id}/findings`, `/api/findings/{id}/review`, `/api/assessments/{id}/reports/generate`, `/api/assessments/{id}/reports/export`.
  - `frontend/src/components/workspace/FindingsTab.tsx`: Finding pipeline (Candidate -> Under Review -> Human Verified), severity, affected asset.
  - `frontend/src/components/workspace/HumanReviewModal.tsx`: Review interface displaying supporting/contradicting evidence and human decision buttons.
  - `frontend/src/components/workspace/ReportsTab.tsx`: Report preview, export controls, format selector (Markdown, HTML, PDF, SARIF, ASVS, BugBounty).
- **Acceptance Criteria**: UI cannot set `HUMAN_VERIFIED` directly; must invoke `FindingValidator`; unverified findings cannot masquerade as confirmed.

---

### M13.8 — Assessment Timeline, Audit & Workspace API
- **Existing Modules**:
  - `src/core/logging.py`: `AuditLogger`, cryptographic hash verification.
  - `src/assessment/observability.py`: `AssessmentAuditLogger`.
- **Required Additions**:
  - Endpoints in `src/dashboard/app.py`: `/api/assessments/{id}/activity`, `/api/assessments/{id}/audit/verify`.
  - `frontend/src/components/workspace/ActivityTab.tsx`: Activity timeline derived from real audit events (no synthetic filler).
  - API schemas and response structures in `src/dashboard/models.py`.
- **Acceptance Criteria**: Cryptographically verifiable audit trail; zero raw secrets in logs; fail-closed access control.

---

### M13.9 — Product Quality-of-Life Features
- **Existing Modules**:
  - `src/response/generator.py`: `LongResponseEngine` (M11.5).
  - `frontend/src/components/LargeResponseView.tsx`.
- **Required Additions**:
  - Global Search endpoint: `/api/workspace/search` across accessible assessments, assets, findings, and evidence.
  - `frontend/src/components/workspace/GlobalSearchModal.tsx`.
  - Cross-panel navigation shortcuts (e.g. Asset -> Artifact -> Evidence -> Finding).
  - Error boundaries, empty states, and responsive layout polish.
- **Acceptance Criteria**: Global search respects assessment isolation; seamless navigation between linked artifacts.

---

### M13.10 — Integration, Migration & Evaluation
- **Benchmark & Testing Deliverables**:
  - `src/eval/m13_dataset.py`: >= 350 structured workflow cases across all 24 required categories.
  - `src/eval/m13_evaluator.py`: Benchmark evaluation runner and metrics generator.
  - `tests/unit/test_m13_security_invariants.py`: Dedicated tests for all 35 M13 security invariants (M13-01 to M13-35).
  - `tests/integration/test_m13_workspace_pipeline.py`: Comprehensive end-to-end integration test suite.
  - `tests/unit/test_m13_eval_benchmark.py`: Benchmark runner unit test.
- **Documentation Deliverables**:
  - `docs/M13_WORKSPACE_ARCHITECTURE.md`
  - `docs/M13_DOMAIN_MODEL.md`
  - `docs/M13_ASSESSMENT_WORKFLOW.md`
  - `docs/M13_SCOPE_AND_ASSETS.md`
  - `docs/M13_EVIDENCE_AND_PROVENANCE.md`
  - `docs/M13_RESEARCH_INTEGRATION.md`
  - `docs/M13_EXPERIMENT_WORKFLOW.md`
  - `docs/M13_FINDING_REVIEW_AND_REPORTING.md`
  - `docs/M13_API.md`
  - `docs/M13_SECURITY.md`
  - `docs/M13_TESTING.md`
  - `reports/M13_FINAL_REPORT.md`

---

## 2. Hard Security Invariants (M13-01 through M13-35)
1. M13-01: Workspace navigation cannot create authorization.
2. M13-02: A listed asset is not automatically an authorized asset.
3. M13-03: No workspace operation can silently expand scope.
4. M13-04: Invalid authorization blocks protected actions.
5. M13-05: Cross-assessment data access is denied.
6. M13-06: Cross-tenant data access is denied where tenancy is supported.
7. M13-07: Model hypotheses remain separate from observations.
8. M13-08: External knowledge cannot become target evidence automatically.
9. M13-09: Research memory cannot become authorization.
10. M13-10: Research memory cannot silently become global knowledge.
11. M13-11: Research memory cannot silently become canonical target evidence.
12. M13-12: Imported artifacts remain untrusted until appropriately processed.
13. M13-13: Imported content cannot execute instructions against application policy.
14. M13-14: Artifact identity and evidence provenance cannot be changed through client-side ID substitution.
15. M13-15: Agent recommendations cannot mark findings verified.
16. M13-16: Only the authoritative human-review workflow can establish verification.
17. M13-17: Finding verification cannot bypass FindingValidator.
18. M13-18: Evidence records cannot be silently fabricated or overwritten.
19. M13-19: Experiment observations must originate from actual observation path or be explicitly labeled user-provided.
20. M13-20: Plane A execution requires all existing safety gates.
21. M13-21: Plane B cannot invoke autonomous target-affecting execution.
22. M13-22: Experiment success does not automatically confirm a vulnerability.
23. M13-23: Reports cannot silently include unverified findings as confirmed vulnerabilities.
24. M13-24: Report exports use existing redaction and authorization policies.
25. M13-25: Long-response continuation cannot alter assessment authorization.
26. M13-26: Memory permissions are enforced by the memory subsystem.
27. M13-27: Deleted or superseded memory cannot appear as current merely through a stale index.
28. M13-28: Sensitive operations remain auditable.
29. M13-29: Audit events cannot be fabricated to represent successful operations.
30. M13-30: Invalid lifecycle transitions are rejected.
31. M13-31: UI visibility is not treated as a security boundary.
32. M13-32: Error handling cannot leak secrets or inaccessible assessment data.
33. M13-33: Archived assessments remain subject to existing access controls.
34. M13-34: User cancellation cannot cause partial state to be marked as successful.
35. M13-35: Workspace integration cannot bypass any M0–M12 security invariant.

---

## 3. Step-by-Step Implementation Sequence
1. **Phase 1: Backend Domain Models & Workspace Service Extensions**
   - Create `src/workspace/models.py`.
   - Implement unified workspace aggregator methods in `src/dashboard/service.py` linking `AssessmentManager`, `DatabaseManager`, `ArtifactRegistry`, `FindingValidator`, `ReportGenerator`, `AuditLogger`, `MemoryPersistence`, and `LongResponseEngine`.
   - Expose all necessary REST routes in `src/dashboard/app.py`.
2. **Phase 2: Frontend Architecture & Workspace Components**
   - Implement API client functions in `frontend/src/api.ts`.
   - Build unified workspace shell, assessment switcher, and tabbed view.
   - Implement all 12 section components in `frontend/src/components/workspace/`.
   - Ensure build passes (`npm run build`, `npm run test`).
3. **Phase 3: Automated Testing & Security Verification**
   - Implement unit tests for all 35 invariants in `tests/unit/test_m13_security_invariants.py`.
   - Implement end-to-end integration tests in `tests/integration/test_m13_workspace_pipeline.py`.
4. **Phase 4: Benchmark Dataset & Evaluation Runner**
   - Create `src/eval/m13_dataset.py` with 360 structured cases across 24 categories.
   - Create `src/eval/m13_evaluator.py` and run benchmark via `tests/unit/test_m13_eval_benchmark.py`.
5. **Phase 5: Documentation & Git Release**
   - Write all 12 required markdown documents in `docs/` and `reports/M13_FINAL_REPORT.md`.
   - Execute full regression suite (`pytest -q` across all 1530+ tests).
   - Commit and tag `v13.0.0-full-security-assessment-workspace`.
