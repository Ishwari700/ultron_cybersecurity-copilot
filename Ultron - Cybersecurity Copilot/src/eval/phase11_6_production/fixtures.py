"""Deterministic local fixtures for Phase 11.6 production pipeline validation.

Defines 15 production fixtures covering:
1. BOLA (API-BOLA-001)
2. Cross-tenant isolation (API-CROSS-TENANT-001)
3. Role/function-level authorization (API-BFLA-002)
4. Lifecycle/state transition (API-STATE-001)
5. Multi-step authentication (API-MULTI-STEP-AUTH-001)
6. Mutation integrity (API-STATE-001)
7. Device BOLA (API-DEVICE-BOLA-001)
8. Authentication-required endpoint (API-BFLA-001)
9. Valid control / patched scenario (CONTROL-PATCHED)
10. Insufficient-evidence abstention (API-BOLA-001)
11. Out-of-scope destination (API-BOLA-001)
12. Provenance conflict (API-BOLA-001)
13. Stale evidence (API-BOLA-001)
14. Secret handling (API-BOLA-001)
15. Human-approval-required state-changing operation (API-BFLA-002)
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from src.evidence.cascade_models import LosslessStructuralPack, RawTriageOutput
from src.hypothesis.experiment import ExperimentProposal, ExpectedObservations, MutationClass, SafetyLevel
from src.engine.models import (
    ExperimentActionPredicate,
    HttpOutcomePredicate,
    HypothesisDecision,
    SemanticOutcomePredicate,
)


class ProductionFixture(BaseModel):
    """Encapsulates all inputs and expected invariants for a production pipeline scenario."""
    fixture_id: str
    category_id: str
    description: str
    target_url: str
    channel_a: LosslessStructuralPack
    raw_triage: Optional[RawTriageOutput]
    action: str
    supporting_outcome: str
    disproving_outcome: str
    expected_decision: str
    expected_escalate: bool
    expected_safety_level: SafetyLevel
    expected_execution_status: str
    mutation_class: MutationClass = MutationClass.CROSS_IDENTITY_REPLAY
    raw_secrets: Optional[Dict[str, str]] = None
    override_destination: Optional[str] = None
    is_state_changing: bool = False

    def build_experiment_proposal(self) -> ExperimentProposal:
        """Construct canonical ExperimentProposal for this fixture."""
        return ExperimentProposal(
            objective=f"Verify {self.category_id} boundary on {self.channel_a.endpoint_id}",
            target_asset_id=self.channel_a.asset_id,
            mutation_class=self.mutation_class,
            actor_identity_id="USER-ALICE",
            target_identity_id="USER-BOB",
            expected_observations=ExpectedObservations(
                supporting_observation=self.supporting_outcome,
                contradicting_observation=self.disproving_outcome,
            ),
            safety_level=self.expected_safety_level,
            required_token_references=["TOKEN-EXPIRED-01"] if self.fixture_id == "FIX-STALE-EVID-01" else [],
            required_test_data="Pre-seeded test tenant identifier TENANT-42",
            rollback_requirement="Revert object state" if self.is_state_changing else "No rollback needed for read-only operations",
        )


def get_validation_fixtures() -> List[ProductionFixture]:
    """Return the authoritative collection of 15 Phase 11.6 validation fixtures."""
    fixtures = [
        # 1. BOLA (API-BOLA-001)
        ProductionFixture(
            fixture_id="FIX-BOLA-01",
            category_id="API-BOLA-001",
            description="Object-level authorization boundary across user accounts",
            target_url="https://api.target.com/api/v1/orders/1001",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-ORDER-SVC",
                endpoint_id="EP-ORDER-001",
                route_template="/api/v1/orders/{order_id}",
                http_method="GET",
                application_mutability="READ_ONLY",
                has_cross_identity_object_access_success=True,
                parameter_lineage=[
                    {"param_id": "PARAM-ORDER-ID", "param_name": "order_id", "location": "path"}
                ],
                identity_matrix=[
                    {"identity_id": "USER-ALICE", "role": "buyer"},
                    {"identity_id": "USER-BOB", "role": "buyer"},
                ],
                observed_facts=[
                    {"fact_id": "FACT-ORDER-001", "statement": "User Alice accessed Order 1001 owned by Bob"},
                    {"fact_id": "FACT-ORDER-002", "statement": "HTTP GET returned status code 200 with complete order JSON"},
                ],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-BOLA-001",
                decision="SUSPECTED_VULNERABILITY",
                triage_rationale="Cross-identity object access succeeded without authorization check",
                suggested_experiment_class="ID_SWAP",
                cited_parameter_ids=["PARAM-ORDER-ID"],
                cited_fact_ids=["FACT-ORDER-001", "FACT-ORDER-002"],
            ),
            action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
            expected_decision=HypothesisDecision.HYPOTHESIS.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.READ_ONLY_SAFE,
            expected_execution_status="EXECUTED",
            mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        ),

        # 2. Cross-Tenant Isolation (API-CROSS-TENANT-001)
        ProductionFixture(
            fixture_id="FIX-CROSS-TENANT-01",
            category_id="API-CROSS-TENANT-001",
            description="Multi-tenant boundary verification between Tenant A and Tenant B",
            target_url="https://api.target.com/api/v1/tenants/tenant-b/data",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-TENANT-SVC",
                endpoint_id="EP-TENANT-001",
                route_template="/api/v1/tenants/{tenant_id}/data",
                http_method="GET",
                application_mutability="READ_ONLY",
                has_cross_identity_object_access_success=True,
                parameter_lineage=[
                    {"param_id": "PARAM-TENANT-ID", "param_name": "tenant_id", "location": "path"}
                ],
                identity_matrix=[
                    {"identity_id": "USER-TENANT-A", "role": "tenant_user"},
                    {"identity_id": "USER-TENANT-B", "role": "tenant_user"},
                ],
                observed_facts=[
                    {"fact_id": "FACT-TENANT-001", "statement": "Tenant A user queried Tenant B repository without 403 error"},
                ],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-CROSS-TENANT-001",
                decision="SUSPECTED_VULNERABILITY",
                triage_rationale="Cross-tenant access accessible across isolated tenant partitions",
                suggested_experiment_class="ID_SWAP",
                cited_parameter_ids=["PARAM-TENANT-ID"],
                cited_fact_ids=["FACT-TENANT-001"],
            ),
            action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
            expected_decision=HypothesisDecision.HYPOTHESIS.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.READ_ONLY_SAFE,
            expected_execution_status="EXECUTED",
            mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        ),

        # 3. Role/Function-Level Authorization (API-BFLA-002)
        ProductionFixture(
            fixture_id="FIX-BFLA-01",
            category_id="API-BFLA-002",
            description="Administrative function-level role boundary violation (state-changing)",
            target_url="https://api.target.com/api/v1/admin/users/user-123/role",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-ADMIN-SVC",
                endpoint_id="EP-ADMIN-002",
                route_template="/api/v1/admin/users/{user_id}/role",
                http_method="POST",
                application_mutability="STATE_CHANGING",
                has_privilege_level_delta=True,
                status_code_changed_under_different_role=True,
                parameter_lineage=[
                    {"param_id": "PARAM-USER-ID", "param_name": "user_id", "location": "path"},
                    {"param_id": "PARAM-ROLE", "param_name": "role", "location": "body"},
                ],
                identity_matrix=[
                    {"identity_id": "USER-REGULAR", "role": "member"},
                    {"identity_id": "USER-ADMIN", "role": "admin"},
                ],
                observed_facts=[
                    {"fact_id": "FACT-BFLA-001", "statement": "Regular user executed admin role change API endpoint successfully"},
                ],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-BFLA-002",
                decision="SUSPECTED_VULNERABILITY",
                triage_rationale="Member role invoked administrative state-changing role assignment",
                suggested_experiment_class="ROLE_SWAP",
                is_sensitive_category=True,
                cited_parameter_ids=["PARAM-USER-ID"],
                cited_fact_ids=["FACT-BFLA-001"],
            ),
            action=ExperimentActionPredicate.REPLAY_STEP_WITH_LOWER_ROLE.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
            expected_decision=HypothesisDecision.HYPOTHESIS.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL,
            expected_execution_status="EXECUTED",
            mutation_class=MutationClass.PRIVILEGE_ELEVATION,
            is_state_changing=True,
        ),

        # 4. Lifecycle / State Transition (API-STATE-001)
        ProductionFixture(
            fixture_id="FIX-STATE-01",
            category_id="API-STATE-001",
            description="Out-of-order state transition on order checkout lifecycle",
            target_url="https://api.target.com/api/v1/orders/1001/finalize",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-ORDER-SVC",
                endpoint_id="EP-ORDER-FINALIZE",
                route_template="/api/v1/orders/{order_id}/finalize",
                http_method="POST",
                application_mutability="STATE_CHANGING",
                parameter_lineage=[
                    {"param_id": "PARAM-ORDER-ID", "param_name": "order_id", "location": "path"}
                ],
                identity_matrix=[{"identity_id": "USER-ALICE", "role": "buyer"}],
                observed_facts=[
                    {"fact_id": "FACT-STATE-001", "statement": "Order finalized without prior payment capture step"},
                ],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-STATE-001",
                decision="SUSPECTED_VULNERABILITY",
                triage_rationale="State transition occurred out of declared workflow sequence",
                suggested_experiment_class="STEP_SKIP",
                cited_parameter_ids=["PARAM-ORDER-ID"],
                cited_fact_ids=["FACT-STATE-001"],
            ),
            action=ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_400_BAD_REQUEST.value,
            expected_decision=HypothesisDecision.HYPOTHESIS.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL,
            expected_execution_status="EXECUTED",
            mutation_class=MutationClass.STEP_SKIPPING,
            is_state_changing=True,
        ),

        # 5. Multi-Step Authentication (API-MULTI-STEP-AUTH-001)
        ProductionFixture(
            fixture_id="FIX-MULTI-STEP-01",
            category_id="API-MULTI-STEP-AUTH-001",
            description="Bypassing MFA verification step by direct transition to session exchange",
            target_url="https://api.target.com/api/v1/auth/mfa/complete",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-AUTH-SVC",
                endpoint_id="EP-AUTH-MFA",
                route_template="/api/v1/auth/mfa/complete",
                http_method="POST",
                application_mutability="STATE_CHANGING",
                parameter_lineage=[
                    {"param_id": "PARAM-CHALLENGE-ID", "param_name": "challenge_id", "location": "body"}
                ],
                identity_matrix=[{"identity_id": "USER-PENDING", "role": "pre_mfa"}],
                observed_facts=[
                    {"fact_id": "FACT-MFA-001", "statement": "MFA completion endpoint accepted challenge without OTP token"},
                ],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-MULTI-STEP-AUTH-001",
                decision="SUSPECTED_VULNERABILITY",
                triage_rationale="Authentication state bypassed second-factor verification step",
                suggested_experiment_class="STEP_SKIP",
                cited_parameter_ids=["PARAM-CHALLENGE-ID"],
                cited_fact_ids=["FACT-MFA-001"],
            ),
            action=ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_400_BAD_REQUEST.value,
            expected_decision=HypothesisDecision.HYPOTHESIS.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL,
            expected_execution_status="EXECUTED",
            mutation_class=MutationClass.STEP_SKIPPING,
            is_state_changing=True,
        ),

        # 6. Mutation Integrity (API-STATE-001)
        ProductionFixture(
            fixture_id="FIX-MUTATION-01",
            category_id="API-STATE-001",
            description="Unauthorized quantity and pricing modification in active checkout cart",
            target_url="https://api.target.com/api/v1/cart/items/55",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-CART-SVC",
                endpoint_id="EP-CART-ITEM",
                route_template="/api/v1/cart/items/{item_id}",
                http_method="PUT",
                application_mutability="STATE_CHANGING",
                parameter_lineage=[
                    {"param_id": "PARAM-ITEM-ID", "param_name": "item_id", "location": "path"}
                ],
                identity_matrix=[{"identity_id": "USER-ALICE", "role": "buyer"}],
                observed_facts=[
                    {"fact_id": "FACT-MUT-001", "statement": "State-changing PUT permitted price parameter alteration directly"},
                ],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-STATE-001",
                decision="SUSPECTED_VULNERABILITY",
                triage_rationale="State transition bypassed server-side cart pricing invariant",
                suggested_experiment_class="STEP_SKIP",
                cited_parameter_ids=["PARAM-ITEM-ID"],
                cited_fact_ids=["FACT-MUT-001"],
            ),
            action=ExperimentActionPredicate.EXECUTE_OUT_OF_ORDER_TRANSITION.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_400_BAD_REQUEST.value,
            expected_decision=HypothesisDecision.HYPOTHESIS.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL,
            expected_execution_status="EXECUTED",
            mutation_class=MutationClass.STEP_SKIPPING,
            is_state_changing=True,
        ),

        # 7. Device BOLA (API-DEVICE-BOLA-001)
        ProductionFixture(
            fixture_id="FIX-DEVICE-BOLA-01",
            category_id="API-DEVICE-BOLA-001",
            description="Cross-device telemetry access without asset-to-identity binding",
            target_url="https://api.target.com/api/v1/devices/dev-888/telemetry",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-IOT-SVC",
                endpoint_id="EP-DEVICE-001",
                route_template="/api/v1/devices/{device_id}/telemetry",
                http_method="GET",
                application_mutability="READ_ONLY",
                has_cross_identity_object_access_success=True,
                parameter_lineage=[
                    {"param_id": "PARAM-DEV-ID", "param_name": "device_id", "location": "path"}
                ],
                identity_matrix=[
                    {"identity_id": "USER-ALICE", "role": "device_owner"},
                    {"identity_id": "USER-BOB", "role": "device_owner"},
                ],
                observed_facts=[
                    {"fact_id": "FACT-DEV-001", "statement": "Device 888 telemetry stream accessible by unassociated user Alice"},
                ],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-DEVICE-BOLA-001",
                decision="SUSPECTED_VULNERABILITY",
                triage_rationale="Cross-identity device telemetry retrieval allowed",
                suggested_experiment_class="ID_SWAP",
                cited_parameter_ids=["PARAM-DEV-ID"],
                cited_fact_ids=["FACT-DEV-001"],
            ),
            action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
            expected_decision=HypothesisDecision.HYPOTHESIS.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.READ_ONLY_SAFE,
            expected_execution_status="EXECUTED",
            mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
        ),

        # 8. Authentication-Required Endpoint (API-BFLA-001)
        ProductionFixture(
            fixture_id="FIX-AUTH-REQ-01",
            category_id="API-BFLA-001",
            description="Internal configuration endpoint accessible unauthenticated",
            target_url="https://api.target.com/api/v1/internal/config",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-CONFIG-SVC",
                endpoint_id="EP-INTERNAL-CONFIG",
                route_template="/api/v1/internal/config",
                http_method="GET",
                application_mutability="READ_ONLY",
                has_unauthenticated_success=True,
                parameter_lineage=[],
                identity_matrix=[{"identity_id": "USER-ANONYMOUS", "role": "unauthenticated"}],
                observed_facts=[
                    {"fact_id": "FACT-CONF-001", "statement": "Internal config returned status 200 without Authorization header"},
                ],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-BFLA-001",
                decision="SUSPECTED_VULNERABILITY",
                triage_rationale="Endpoint failed to enforce mandatory authentication boundary",
                suggested_experiment_class="AUTH_DROP",
                cited_parameter_ids=[],
                cited_fact_ids=["FACT-CONF-001"],
            ),
            action=ExperimentActionPredicate.REPLAY_STEP_WITH_LOWER_ROLE.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_401_UNAUTHORIZED.value,
            expected_decision=HypothesisDecision.HYPOTHESIS.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.READ_ONLY_SAFE,
            expected_execution_status="EXECUTED",
            mutation_class=MutationClass.UNAUTHENTICATED_ACCESS,
        ),

        # 9. Valid Control / Patched Scenario (CONTROL-PATCHED)
        ProductionFixture(
            fixture_id="FIX-PATCHED-01",
            category_id="CONTROL-PATCHED",
            description="Patched public status healthcheck with zero mutable state or privileged assets",
            target_url="https://api.target.com/api/v1/public/ping",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-HEALTH-SVC",
                endpoint_id="EP-HEALTH-PING",
                route_template="/api/v1/public/ping",
                http_method="GET",
                application_mutability="READ_ONLY",
                parameter_lineage=[],
                identity_matrix=[{"identity_id": "USER-PUBLIC", "role": "anonymous"}],
                observed_facts=[
                    {"fact_id": "FACT-PING-001", "statement": "Public ping returns static pong response"},
                ],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category=None,
                decision="BENIGN_NO_ISSUE",
                triage_rationale="Static unauthenticated public diagnostic endpoint; no security property relevance",
                suggested_experiment_class=None,
                cited_parameter_ids=[],
                cited_fact_ids=["FACT-PING-001"],
            ),
            action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
            expected_decision=HypothesisDecision.NO_RELEVANT_FUNCTIONALITY.value,
            expected_escalate=False,
            expected_safety_level=SafetyLevel.READ_ONLY_SAFE,
            expected_execution_status="NOT_ESCALATED",
        ),

        # 10. Insufficient-Evidence Abstention (API-BOLA-001)
        ProductionFixture(
            fixture_id="FIX-ABSTAIN-01",
            category_id="API-BOLA-001",
            description="Target functionality is relevant but lacks discriminating observation facts",
            target_url="https://api.target.com/api/v1/accounts/acc-99/summary",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-ACCT-SVC",
                endpoint_id="EP-ACCT-SUMMARY",
                route_template="/api/v1/accounts/{id}/summary",
                http_method="GET",
                application_mutability="READ_ONLY",
                parameter_lineage=[
                    {"param_id": "PARAM-ACC-ID", "param_name": "id", "location": "path"}
                ],
                identity_matrix=[{"identity_id": "USER-ALICE", "role": "account_owner"}],
                observed_facts=[], # Zero observed empirical facts
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-BOLA-001",
                decision="INSUFFICIENT_EVIDENCE",
                triage_rationale="Account summary endpoint accepts identifier but no cross-identity evidence exists",
                suggested_experiment_class="ID_SWAP",
                is_sensitive_category=True,
                cited_parameter_ids=["PARAM-ACC-ID"],
                cited_fact_ids=[],
            ),
            action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
            expected_decision=HypothesisDecision.INSUFFICIENT_EVIDENCE.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.READ_ONLY_SAFE,
            expected_execution_status="ABSTAINED_INSUFFICIENT_EVIDENCE",
        ),

        # 11. Out-of-Scope Destination (API-BOLA-001)
        ProductionFixture(
            fixture_id="FIX-OUT-OF-SCOPE-01",
            category_id="API-BOLA-001",
            description="Target destination URL points to unauthorized third-party host",
            target_url="https://api.target.com/api/v1/orders/1001",
            override_destination="https://external-forbidden.com/api/v1/orders/1001",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-ORDER-SVC",
                endpoint_id="EP-ORDER-001",
                route_template="/api/v1/orders/{order_id}",
                http_method="GET",
                application_mutability="READ_ONLY",
                has_cross_identity_object_access_success=True,
                parameter_lineage=[{"param_id": "PARAM-ORDER-ID", "param_name": "order_id", "location": "path"}],
                identity_matrix=[{"identity_id": "USER-ALICE", "role": "buyer"}],
                observed_facts=[{"fact_id": "FACT-ORDER-001", "statement": "Order accessed"}],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-BOLA-001",
                decision="SUSPECTED_VULNERABILITY",
                triage_rationale="Candidate BOLA on out-of-scope host",
                suggested_experiment_class="ID_SWAP",
                cited_parameter_ids=["PARAM-ORDER-ID"],
                cited_fact_ids=["FACT-ORDER-001"],
            ),
            action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
            expected_decision=HypothesisDecision.HYPOTHESIS.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.READ_ONLY_SAFE,
            expected_execution_status="BLOCKED_SCOPE",
        ),

        # 12. Provenance Conflict (API-BOLA-001)
        ProductionFixture(
            fixture_id="FIX-PROV-CONFLICT-01",
            category_id="API-BOLA-001",
            description="Handoff packet has corrupted provenance hash",
            target_url="https://api.target.com/api/v1/orders/1001",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-ORDER-SVC",
                endpoint_id="EP-ORDER-001",
                route_template="/api/v1/orders/{order_id}",
                http_method="GET",
                application_mutability="READ_ONLY",
                has_cross_identity_object_access_success=True,
                parameter_lineage=[{"param_id": "PARAM-ORDER-ID", "param_name": "order_id", "location": "path"}],
                identity_matrix=[{"identity_id": "USER-ALICE", "role": "buyer"}],
                observed_facts=[{"fact_id": "FACT-ORDER-001", "statement": "Order accessed"}],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-BOLA-001",
                decision="SUSPECTED_VULNERABILITY",
                triage_rationale="BOLA candidate with corrupted provenance",
                suggested_experiment_class="ID_SWAP",
                cited_parameter_ids=["PARAM-ORDER-ID"],
                cited_fact_ids=["FACT-ORDER-001"],
            ),
            action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
            expected_decision=HypothesisDecision.HYPOTHESIS.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.READ_ONLY_SAFE,
            expected_execution_status="FAIL_CLOSED_PROVENANCE",
        ),

        # 13. Stale Evidence (API-BOLA-001)
        ProductionFixture(
            fixture_id="FIX-STALE-EVID-01",
            category_id="API-BOLA-001",
            description="Execution attempted with expired token or stale preflight TTL",
            target_url="https://api.target.com/api/v1/orders/1001",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-ORDER-SVC",
                endpoint_id="EP-ORDER-001",
                route_template="/api/v1/orders/{order_id}",
                http_method="GET",
                application_mutability="READ_ONLY",
                has_cross_identity_object_access_success=True,
                parameter_lineage=[{"param_id": "PARAM-ORDER-ID", "param_name": "order_id", "location": "path"}],
                identity_matrix=[{"identity_id": "USER-ALICE", "role": "buyer"}],
                observed_facts=[{"fact_id": "FACT-ORDER-001", "statement": "Order accessed"}],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-BOLA-001",
                decision="SUSPECTED_VULNERABILITY",
                triage_rationale="Candidate BOLA with expired token TTL",
                suggested_experiment_class="ID_SWAP",
                cited_parameter_ids=["PARAM-ORDER-ID"],
                cited_fact_ids=["FACT-ORDER-001"],
            ),
            action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
            expected_decision=HypothesisDecision.HYPOTHESIS.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.READ_ONLY_SAFE,
            expected_execution_status="BLOCKED_TTL",
        ),

        # 14. Secret Handling (API-BOLA-001)
        ProductionFixture(
            fixture_id="FIX-SECRET-LEAK-01",
            category_id="API-BOLA-001",
            description="Raw credentials and bearer JWTs are isolated and redacted from model context",
            target_url="https://api.target.com/api/v1/orders/1001",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-ORDER-SVC",
                endpoint_id="EP-ORDER-001",
                route_template="/api/v1/orders/{order_id}",
                http_method="GET",
                application_mutability="READ_ONLY",
                has_cross_identity_object_access_success=True,
                parameter_lineage=[{"param_id": "PARAM-ORDER-ID", "param_name": "order_id", "location": "path"}],
                identity_matrix=[{"identity_id": "USER-ALICE", "role": "buyer"}],
                observed_facts=[
                    {"fact_id": "FACT-ORDER-001", "statement": "Request header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}
                ],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-BOLA-001",
                decision="SUSPECTED_VULNERABILITY",
                triage_rationale="BOLA candidate with sensitive bearer token in facts",
                suggested_experiment_class="ID_SWAP",
                cited_parameter_ids=["PARAM-ORDER-ID"],
                cited_fact_ids=["FACT-ORDER-001"],
            ),
            action=ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
            expected_decision=HypothesisDecision.HYPOTHESIS.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.READ_ONLY_SAFE,
            expected_execution_status="EXECUTED",
            raw_secrets={
                "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "apikey": "AKIAIOSFODNN7EXAMPLE",
            },
        ),

        # 15. Human Approval Required (API-BFLA-002)
        ProductionFixture(
            fixture_id="FIX-APPROVAL-REQ-01",
            category_id="API-BFLA-002",
            description="State-changing admin role elevation requires cryptographic human approval",
            target_url="https://api.target.com/api/v1/admin/users/user-123/role",
            channel_a=LosslessStructuralPack(
                schema_version="2.0.0",
                asset_id="ASSET-ADMIN-SVC",
                endpoint_id="EP-ADMIN-002",
                route_template="/api/v1/admin/users/{user_id}/role",
                http_method="POST",
                application_mutability="STATE_CHANGING",
                has_privilege_level_delta=True,
                parameter_lineage=[{"param_id": "PARAM-USER-ID", "param_name": "user_id", "location": "path"}],
                identity_matrix=[{"identity_id": "USER-REGULAR", "role": "member"}],
                observed_facts=[{"fact_id": "FACT-BFLA-001", "statement": "Admin role elevation attempted"}],
            ),
            raw_triage=RawTriageOutput(
                schema_version="2.0.0",
                suspected_category="API-BFLA-002",
                decision="SUSPECTED_VULNERABILITY",
                triage_rationale="State-changing administrative privilege elevation",
                suggested_experiment_class="ROLE_SWAP",
                is_sensitive_category=True,
                cited_parameter_ids=["PARAM-USER-ID"],
                cited_fact_ids=["FACT-BFLA-001"],
            ),
            action=ExperimentActionPredicate.REPLAY_STEP_WITH_LOWER_ROLE.value,
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
            expected_decision=HypothesisDecision.HYPOTHESIS.value,
            expected_escalate=True,
            expected_safety_level=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL,
            expected_execution_status="EXECUTED",
            mutation_class=MutationClass.PRIVILEGE_ELEVATION,
            is_state_changing=True,
        ),
    ]
    return fixtures
