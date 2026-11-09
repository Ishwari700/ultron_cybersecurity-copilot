# M13 Security Architecture and Invariant Guarantees

## 1. Security Invariants (M13-01 through M13-35)

Milestone 13 establishes 35 formal security invariants covering all aspects of the integrated assessment workspace. All 35 invariants are covered with automated unit tests in `tests/unit/test_m13_security_invariants.py`.

### Table of M13 Security Invariants

| ID | Title | Enforcement Subsystem | Guarantee |
| :--- | :--- | :--- | :--- |
| **M13-01** | Navigation Cannot Create Authorization | UnifiedWorkspaceService | Navigating UI tabs cannot elevate a DRAFT assessment to AUTHORIZED. |
| **M13-02** | Listed Asset Is Not Automatically Authorized | AssetGraph / ScopeGate | Adding an asset to inventory does NOT authorize active probing. |
| **M13-03** | No Operation Silently Expands Scope | ScopeGate / Service | Scope validation queries are strictly read-only and never mutate policy. |
| **M13-04** | Invalid Authorization Blocks Protected Actions | AssessmentLifecycleEngine | Expired or missing authorization fails closed on active operations. |
| **M13-05** | Cross-Assessment Data Access Denied | UnifiedWorkspaceService | Queries specifying an assessment_id never return records from other assessments. |
| **M13-06** | Multi-Tenant Data Isolation | AssessmentManager | Separate client tenants are isolated across databases and memory stores. |
| **M13-07** | Hypotheses Separate From Observations | ReviewWorkspace | Model hypotheses cannot overwrite or masquerade as canonical observations. |
| **M13-08** | External Knowledge Cannot Become Target Evidence | ReviewWorkspace / Lineage | External CWE/CVE knowledge is context only, never empirical target evidence. |
| **M13-09** | Memory Cannot Become Authorization | MemoryEngine / Lifecycle | Memory items cannot authorize an engagement or substitute for human sign-off. |
| **M13-10** | Memory Not Silently Promoted to Global | MemoryEngine | Assessment-scoped memories remain strictly local unless formally promoted. |
| **M13-11** | Memory Cannot Become Canonical Target Evidence | TelemetryPipeline | Memories can provide research context, never replace empirical telemetry. |
| **M13-12** | Imported Artifacts Remain Untrusted | ArtifactRegistry | Ingested files default to QUARANTINED until inspected and validated. |
| **M13-13** | Imported Content Cannot Execute Instructions | Telemetry / Importers | Payloads and captures are parsed strictly as passive data bytes. |
| **M13-14** | Artifact Identity Protected Against ID Substitution | ArtifactRegistry | Cryptographic SHA-256 hashes bind each artifact to its raw content. |
| **M13-15** | Agent Recommendations Cannot Verify Findings | ReviewWorkspace | Analytical agents provide advisory recommendations (`MODEL_REASONING`) only. |
| **M13-16** | Only Authoritative Human Review Establishes Verification | ReviewWorkspace | Only human researcher sign-off can transition findings to `HUMAN_VERIFIED`. |
| **M13-17** | Verification Cannot Bypass FindingValidator | FindingValidator | All 13 checklist validation criteria must deterministically pass. |
| **M13-18** | Evidence Records Immutable | EvidenceLineageGraph | Canonical observations are append-only and cannot be altered retroactively. |
| **M13-19** | Experiment Observations Originate from Actual Execution | TelemetryPipeline | Experiment results must be produced by real tests or explicit human entry. |
| **M13-20** | Plane A Execution Requires All Existing Safety Gates | SafeExperimentEngine | ScopeGate, active authorization, and non-destructive checks must all pass. |
| **M13-21** | Plane B Cannot Invoke Autonomous Execution | SafeExperimentEngine | Manual procedures generate instructions for humans; zero auto-execution. |
| **M13-22** | Experiment Success Does Not Auto-Confirm Vulnerability | ReviewWorkspace | Successful reproduction produces an observation, requiring human validation. |
| **M13-23** | Reports Cannot Silently Include Unverified Findings | ReportGenerator | Unverified items are strictly quarantined in a prominent disclaimer section. |
| **M13-24** | Report Exports Use Existing Redaction Policies | ReportGenerator | Sensitive secrets and credentials are redacted according to program rules. |
| **M13-25** | Response Continuation Cannot Alter Authorization | AssessmentLifecycleEngine | AI model responses or session loops cannot alter assessment authorization. |
| **M13-26** | Memory Permissions Enforced by Subsystem | MemoryEngine | Access control rules govern memory reads and writes across tiers. |
| **M13-27** | Deleted Memory Not Returned in Retrieval | MemoryPersistence | Tombstoned or deleted memories are instantly excluded from all queries. |
| **M13-28** | Sensitive Operations Audited | AssessmentAuditLogger | Telemetry imports, experiments, verifications, and exports are logged. |
| **M13-29** | Audit Events Read-Model Only | AssessmentAuditLogger | Audit events cannot be fabricated or injected through read models. |
| **M13-30** | Invalid Lifecycle Transitions Rejected | AssessmentLifecycleEngine | Only valid state transitions according to the legal DAG are allowed. |
| **M13-31** | Server-Side Enforcement (UI Not Security Boundary) | FastAPI Backend | All authorization and scope constraints are enforced on the server. |
| **M13-32** | Error Handling Fails Closed | Workspace Service | Unhandled exceptions return generic 500s without leaking sensitive data. |
| **M13-33** | Archived Assessments Read-Only | UnifiedWorkspaceService | Completed and archived assessments strictly reject all mutation operations. |
| **M13-34** | No Partial Success on Failure | AssessmentManager | Failed composite operations roll back completely with zero partial state. |
| **M13-35** | Workspace Integration Preserves All Prior Invariants | Whole System | Full backward compatibility with all M0–M12 security and safety controls. |

---

## 2. Threat Model & Mitigations

1. **Threat**: Malicious HTTP capture contains indirect prompt injection instructing AI to confirm high-severity vulnerability.
   - **Mitigation**: LLMs have zero confirmation authority (`M13-15`). Findings require human sign-off (`M13-16`) and deterministic checklist assertions (`M13-17`).
2. **Threat**: Researcher attempts to probe subdomains outside program scope.
   - **Mitigation**: `ScopeGate` rechecks every experiment target before proposal or execution (`M13-20`), failing closed on unknown targets (`M13-03`).
3. **Threat**: Client sends modified finding ID or artifact ID to gain access to another tenant's data.
   - **Mitigation**: Server-side tenant isolation (`M13-05`, `M13-06`, `M13-31`) verifies namespace ownership on all lookups.
