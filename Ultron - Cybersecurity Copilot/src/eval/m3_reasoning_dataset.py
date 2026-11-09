"""M3 Controlled Cybersecurity Reasoning Evaluation Dataset.

Constructs and provides the 20-case controlled reasoning benchmark:
- 12 Vulnerable Cases (BOLA, BFLA, Tenant Isolation) -> Expected: HYPOTHESIS
- 4 Evidence Gap Cases (Missing Identity, Token State, Disambiguation) -> Expected: INSUFFICIENT_EVIDENCE
- 4 Negative Controls (Public Assets, Health Checks, Deprecated Routes) -> Expected: NO_RELEVANT_FUNCTIONALITY
- Balanced across 6 EASY, 8 MEDIUM, 6 HARD difficulties.
- Grounded strictly in the 6 VAPT corpus documents and 23 chunks.
"""

import json
from pathlib import Path
from typing import List, Optional

from src.eval.m3_reasoning_schema import (
    DifficultyLevel,
    M3ReasoningCase,
    M3ReasoningDataset,
    ReasoningDecision,
)


def get_m3_reasoning_cases() -> List[M3ReasoningCase]:
    """Return the complete list of 20 controlled reasoning cases."""
    return [
        # =====================================================================
        # 1. BOLA / OBJECT-LEVEL ACCESS CONTROL (5 cases)
        # =====================================================================
        M3ReasoningCase(
            reasoning_case_id="RC-01",
            case_name="Invoice Object ID Substitution Across Organizations",
            user_query="Can user from organization B access organization A invoice records?",
            security_domain="Broken Object Level Authorization",
            target_evidence={
                "asset_id": "ASSET-BILLING-INV-01",
                "endpoint_id": "EP-INVOICES-GET",
                "http_method": "GET",
                "route_template": "/api/v1/invoices/{invoice_id}",
                "application_mutability": "READ",
                "has_cross_identity_object_access_success": True,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer session_token_user_b",
                "observed_facts": [
                    {
                        "fact_id": "FACT-0101",
                        "statement": "Request to GET /api/v1/invoices/10042 sent with Authorization token of user B (tenant_b).",
                    },
                    {
                        "fact_id": "FACT-0102",
                        "statement": "Response status is 200 OK containing invoice line items belonging to tenant_a (total $4,250.00).",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-0101", "param_name": "invoice_id", "location": "path"}
                ],
            },
            expected_security_concept="Broken Object Level Authorization (CWE-639)",
            expected_security_invariant="Horizontal tenant isolation invariant: Subject must belong to tenant owning target object identifier.",
            expected_evidence_requirements=[
                "Confirm session token user B belongs to tenant B",
                "Confirm invoice 10042 belongs to tenant A",
                "Observe 200 OK returning sensitive invoice data across tenant boundary",
            ],
            expected_experiment_characteristics="Request invoice 10042 with user B token and compare against authenticated tenant A baseline.",
            expected_falsification_characteristics="HTTP 403 Forbidden or 404 Not Found returned when user B requests tenant A invoice.",
            expected_decision=ReasoningDecision.HYPOTHESIS,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-CWE-639-001-01", "CHK-DOC-TENANT-ISO-01-001-01"],
            difficulty=DifficultyLevel.EASY,
            is_negative_control=False,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Asserting SQL injection without query evidence",
                "Assuming unauthenticated access without testing unauthenticated request",
            ],
            evaluation_notes="Classic BOLA pattern with clear cross-tenant object ID substitution.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-02",
            case_name="Document Export Parameter Tampering Across Workspaces",
            user_query="Does the document export endpoint validate workspace membership before generating PDFs?",
            security_domain="Broken Object Level Authorization",
            target_evidence={
                "asset_id": "ASSET-DOCS-EXP-02",
                "endpoint_id": "EP-DOC-EXPORT",
                "http_method": "GET",
                "route_template": "/api/v1/documents/{doc_id}/export",
                "application_mutability": "READ",
                "has_cross_identity_object_access_success": True,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer user_workspace_2",
                "observed_facts": [
                    {
                        "fact_id": "FACT-0201",
                        "statement": "Authenticated member of Workspace 2 requested export of document doc_9811 residing in Workspace 1.",
                    },
                    {
                        "fact_id": "FACT-0202",
                        "statement": "Server responded with HTTP 200 OK and application/pdf content of doc_9811.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-0201", "param_name": "doc_id", "location": "path"}
                ],
            },
            expected_security_concept="Broken Object Level Authorization (CWE-639)",
            expected_security_invariant="Workspace isolation invariant: Object retrieval must verify active session has read entitlement on parent workspace.",
            expected_evidence_requirements=[
                "Verify doc_9811 belongs to Workspace 1",
                "Verify requesting identity has no entitlement in Workspace 1",
                "Verify binary PDF stream contains Workspace 1 content",
            ],
            expected_experiment_characteristics="Request export of private doc_9811 using token from disjoint Workspace 2.",
            expected_falsification_characteristics="Server rejects request with 403 Forbidden indicating workspace membership required.",
            expected_decision=ReasoningDecision.HYPOTHESIS,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-CWE-639-001-02", "CHK-DOC-CWE-284-001-01"],
            difficulty=DifficultyLevel.MEDIUM,
            is_negative_control=False,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Claiming arbitrary file read on host filesystem",
                "Claiming SSRF in PDF generator without payload observation",
            ],
            evaluation_notes="Export handler omits workspace ownership check on target document entity.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-03",
            case_name="Predictable Medical Record Identifier Fetching",
            user_query="Can patient records be enumerated without clinician-patient relationship verification?",
            security_domain="Broken Object Level Authorization",
            target_evidence={
                "asset_id": "ASSET-HEALTH-REC-03",
                "endpoint_id": "EP-PATIENT-RECORDS",
                "http_method": "GET",
                "route_template": "/api/v1/patients/{patient_id}/records",
                "application_mutability": "READ",
                "has_cross_identity_object_access_success": True,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer clinician_dr_smith",
                "observed_facts": [
                    {
                        "fact_id": "FACT-0301",
                        "statement": "Dr. Smith authenticated session queried records for patient P-5501 not assigned to Dr. Smith's care team.",
                    },
                    {
                        "fact_id": "FACT-0302",
                        "statement": "Response status is 200 OK returning full clinical encounters, medication history, and diagnosis codes.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-0301", "param_name": "patient_id", "location": "path"}
                ],
            },
            expected_security_concept="Broken Object Level Authorization (CWE-639) / Missing Authorization (CWE-862)",
            expected_security_invariant="Relationship-based access control invariant: Clinician access requires active patient-provider care relationship.",
            expected_evidence_requirements=[
                "Confirm patient P-5501 has no active assignment to Dr. Smith",
                "Confirm endpoint discloses protected health records to unassigned clinician",
            ],
            expected_experiment_characteristics="Query patient records for an unassigned patient ID using an authenticated clinician session.",
            expected_falsification_characteristics="Server returns 403 Forbidden stating clinician lacks active care relationship for target patient.",
            expected_decision=ReasoningDecision.HYPOTHESIS,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-CWE-639-001-03", "CHK-DOC-CWE-862-001-01"],
            difficulty=DifficultyLevel.MEDIUM,
            is_negative_control=False,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Claiming HIPAA breach is confirmed without authorized pentest sign-off",
            ],
            evaluation_notes="Relationship-based access control failure on clinical data object.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-04",
            case_name="Workspace Note Retrieval with Shared Project ID",
            user_query="Does accessing note records verify note author or workspace boundaries?",
            security_domain="Broken Object Level Authorization",
            target_evidence={
                "asset_id": "ASSET-COLLAB-NOTE-04",
                "endpoint_id": "EP-WORKSPACE-NOTES",
                "http_method": "GET",
                "route_template": "/api/v1/workspaces/{ws_id}/notes/{note_id}",
                "application_mutability": "READ",
                "has_cross_identity_object_access_success": True,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer user_guest_account",
                "observed_facts": [
                    {
                        "fact_id": "FACT-0401",
                        "statement": "Guest user in Workspace 9 queried note_id 4022 belonging to confidential Workspace 1 by altering ws_id in path.",
                    },
                    {
                        "fact_id": "FACT-0402",
                        "statement": "Server responded with 200 OK returning confidential note content titled 'Q3 Financial Strategy'.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-0401", "param_name": "ws_id", "location": "path"},
                    {"param_id": "PARAM-0402", "param_name": "note_id", "location": "path"},
                ],
            },
            expected_security_concept="Broken Object Level Authorization (CWE-639)",
            expected_security_invariant="Workspace boundary invariant: Both workspace and note ID must be validated against caller session permissions.",
            expected_evidence_requirements=[
                "Verify guest caller does not belong to Workspace 1",
                "Verify confidential note content returned across boundary",
            ],
            expected_experiment_characteristics="Request note 4022 with guest user credentials while setting ws_id to Workspace 1.",
            expected_falsification_characteristics="Server rejects request with 403 Forbidden or 404 Not Found.",
            expected_decision=ReasoningDecision.HYPOTHESIS,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-CWE-639-001-01", "CHK-DOC-TENANT-ISO-01-001-02"],
            difficulty=DifficultyLevel.EASY,
            is_negative_control=False,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Asserting total tenant database takeover",
            ],
            evaluation_notes="Compound identifier BOLA across nested resources.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-05",
            case_name="IoT Device Telemetry Access with Foreign Serial",
            user_query="Can fleet telemetry of unowned IoT hardware be observed by substituting device serial numbers?",
            security_domain="Broken Object Level Authorization",
            target_evidence={
                "asset_id": "ASSET-IOT-TELEM-05",
                "endpoint_id": "EP-DEVICE-TELEMETRY",
                "http_method": "GET",
                "route_template": "/api/v1/devices/{device_id}/telemetry",
                "application_mutability": "READ",
                "has_cross_identity_object_access_success": True,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer operator_account_fleet_a",
                "observed_facts": [
                    {
                        "fact_id": "FACT-0501",
                        "statement": "Operator in Fleet A requested telemetry for device serial DEV-B-8839 registered to customer Fleet B.",
                    },
                    {
                        "fact_id": "FACT-0502",
                        "statement": "HTTP 200 OK returned with live GPS coordinates, battery voltage, and sensor logs of Fleet B device.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-0501", "param_name": "device_id", "location": "path"}
                ],
            },
            expected_security_concept="Broken Object Level Authorization (CWE-639)",
            expected_security_invariant="Hardware asset ownership invariant: Telemetry endpoint must verify device registration to caller fleet account.",
            expected_evidence_requirements=[
                "Confirm DEV-B-8839 belongs to Fleet B",
                "Confirm caller belongs to Fleet A",
                "Confirm sensitive location/sensor payload returned without authorization check",
            ],
            expected_experiment_characteristics="Request telemetry for device DEV-B-8839 using Fleet A operator credentials.",
            expected_falsification_characteristics="Server returns 403 Forbidden stating device is not enrolled in caller organization.",
            expected_decision=ReasoningDecision.HYPOTHESIS,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-CWE-639-001-04", "CHK-DOC-TENANT-ISO-01-001-03"],
            difficulty=DifficultyLevel.HARD,
            is_negative_control=False,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Claiming remote code execution on IoT hardware",
            ],
            evaluation_notes="IoT asset identifier substitution leading to physical telemetry leak.",
        ),

        # =====================================================================
        # 2. BFLA / FUNCTION-LEVEL AUTHORIZATION (4 cases)
        # =====================================================================
        M3ReasoningCase(
            reasoning_case_id="RC-06",
            case_name="Administrative Role Escalation by Standard Member",
            user_query="Can a regular member account grant administrative privileges to users?",
            security_domain="Broken Function Level Authorization",
            target_evidence={
                "asset_id": "ASSET-IAM-ROLES-06",
                "endpoint_id": "EP-ADMIN-ROLES",
                "http_method": "POST",
                "route_template": "/api/v1/admin/users/{user_id}/roles",
                "application_mutability": "WRITE",
                "has_cross_identity_object_access_success": False,
                "has_privilege_level_delta": True,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer standard_member_token",
                "observed_facts": [
                    {
                        "fact_id": "FACT-0601",
                        "statement": "User with 'MEMBER' role sent POST to /api/v1/admin/users/102/roles with body {'role': 'ADMIN'}.",
                    },
                    {
                        "fact_id": "FACT-0602",
                        "statement": "Server responded with HTTP 200 OK {'status': 'ROLE_UPDATED', 'new_role': 'ADMIN'}.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-0601", "param_name": "user_id", "location": "path"},
                    {"param_id": "PARAM-0602", "param_name": "role", "location": "body"},
                ],
            },
            expected_security_concept="Broken Function Level Authorization (CWE-285) / Missing Authorization (CWE-862)",
            expected_security_invariant="Function authorization invariant: Role assignment endpoint must strictly require active Super-Admin capability.",
            expected_evidence_requirements=[
                "Verify calling token belongs to unprivileged MEMBER role",
                "Verify endpoint accepts administrative mutation and upgrades target role",
            ],
            expected_experiment_characteristics="Execute role mutation POST using member session and observe whether 200 OK or 403 Forbidden is returned.",
            expected_falsification_characteristics="Server rejects request with 403 Forbidden due to insufficient role permissions.",
            expected_decision=ReasoningDecision.HYPOTHESIS,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-CWE-285-001-01", "CHK-DOC-CWE-862-001-02"],
            difficulty=DifficultyLevel.EASY,
            is_negative_control=False,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Assuming entire auth provider is bypassed",
            ],
            evaluation_notes="Critical privilege escalation via missing function-level guard on role mutation.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-07",
            case_name="Billing Payment Method Mutation by Read-Only Member",
            user_query="Can a user with billing read-only privileges update organizational payment methods?",
            security_domain="Broken Function Level Authorization",
            target_evidence={
                "asset_id": "ASSET-BILLING-MUT-07",
                "endpoint_id": "EP-BILLING-UPDATE",
                "http_method": "PUT",
                "route_template": "/api/v1/organizations/{org_id}/billing",
                "application_mutability": "WRITE",
                "has_cross_identity_object_access_success": False,
                "has_privilege_level_delta": True,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer readonly_auditor_token",
                "observed_facts": [
                    {
                        "fact_id": "FACT-0701",
                        "statement": "Caller with 'BILLING_READONLY' role invoked PUT /api/v1/organizations/org_55/billing with new payment_token.",
                    },
                    {
                        "fact_id": "FACT-0702",
                        "statement": "Response status is 200 OK {'billing_status': 'UPDATED', 'payment_method_id': 'pm_999'}.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-0701", "param_name": "org_id", "location": "path"},
                    {"param_id": "PARAM-0702", "param_name": "payment_token", "location": "body"},
                ],
            },
            expected_security_concept="Broken Function Level Authorization (CWE-285) / Incorrect Authorization (CWE-863)",
            expected_security_invariant="Role capability separation: Read-only accounts must be restricted from mutative HTTP methods (PUT/POST/DELETE).",
            expected_evidence_requirements=[
                "Confirm caller possesses only BILLING_READONLY role",
                "Confirm PUT request alters organizational payment method",
            ],
            expected_experiment_characteristics="Submit PUT request to billing endpoint with BILLING_READONLY token.",
            expected_falsification_characteristics="Server rejects request with 403 Forbidden citing read-only role restriction.",
            expected_decision=ReasoningDecision.HYPOTHESIS,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-CWE-285-001-02", "CHK-DOC-CWE-863-001-01"],
            difficulty=DifficultyLevel.MEDIUM,
            is_negative_control=False,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Assuming card numbers are logged in plaintext",
            ],
            evaluation_notes="Method mutability mismatch allowing read-only account to execute sensitive write operation.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-08",
            case_name="Audit Log Purge Function Execution by Compliance Auditor",
            user_query="Can an auditor session execute the audit log purge endpoint?",
            security_domain="Broken Function Level Authorization",
            target_evidence={
                "asset_id": "ASSET-AUDIT-PURGE-08",
                "endpoint_id": "EP-AUDIT-PURGE",
                "http_method": "DELETE",
                "route_template": "/api/v1/audit/logs",
                "application_mutability": "WRITE",
                "has_cross_identity_object_access_success": False,
                "has_privilege_level_delta": True,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer compliance_auditor_token",
                "observed_facts": [
                    {
                        "fact_id": "FACT-0801",
                        "statement": "Token with 'AUDITOR' role issued DELETE /api/v1/audit/logs?older_than=30d.",
                    },
                    {
                        "fact_id": "FACT-0802",
                        "statement": "Server returned 204 No Content and purged 12,400 security audit event records.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-0801", "param_name": "older_than", "location": "query"}
                ],
            },
            expected_security_concept="Broken Function Level Authorization (CWE-285) / Missing Authorization (CWE-862)",
            expected_security_invariant="Separation of duties invariant: Audit records must be immutable to auditors; purge requires Root/Security Officer role.",
            expected_evidence_requirements=[
                "Confirm AUDITOR role should have non-destructive audit read-only authority",
                "Confirm DELETE endpoint executed successfully and eliminated historical events",
            ],
            expected_experiment_characteristics="Invoke DELETE on audit log endpoint using an auditor role credential.",
            expected_falsification_characteristics="Server rejects request with 403 Forbidden enforcing audit trail immutability.",
            expected_decision=ReasoningDecision.HYPOTHESIS,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-CWE-285-001-03", "CHK-DOC-CWE-862-001-03"],
            difficulty=DifficultyLevel.HARD,
            is_negative_control=False,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Claiming log injection or log tampering without payload evidence",
            ],
            evaluation_notes="Destructive administrative action accessible to non-administrative role.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-09",
            case_name="System Webhook Registration by Non-Admin Tenant",
            user_query="Can a tenant user register webhooks listening to global system events?",
            security_domain="Broken Function Level Authorization",
            target_evidence={
                "asset_id": "ASSET-SYS-WEBHOOK-09",
                "endpoint_id": "EP-SYSTEM-WEBHOOKS",
                "http_method": "POST",
                "route_template": "/api/v1/system/webhooks",
                "application_mutability": "WRITE",
                "has_cross_identity_object_access_success": False,
                "has_privilege_level_delta": True,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer tenant_dev_user",
                "observed_facts": [
                    {
                        "fact_id": "FACT-0901",
                        "statement": "Standard tenant developer submitted POST /api/v1/system/webhooks with target_url and event_filter: ['*'].",
                    },
                    {
                        "fact_id": "FACT-0902",
                        "statement": "Response status is 201 Created {'webhook_id': 'wh_sys_01', 'scope': 'GLOBAL_SYSTEM'}.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-0901", "param_name": "target_url", "location": "body"},
                    {"param_id": "PARAM-0902", "param_name": "event_filter", "location": "body"},
                ],
            },
            expected_security_concept="Broken Function Level Authorization (CWE-285)",
            expected_security_invariant="Scope boundary invariant: Global event hooks require platform administrator scope.",
            expected_evidence_requirements=[
                "Confirm caller possesses only tenant-level scope",
                "Confirm webhook registered at GLOBAL_SYSTEM scope receiving cross-tenant events",
            ],
            expected_experiment_characteristics="Submit system webhook registration with tenant developer token.",
            expected_falsification_characteristics="Server rejects registration with 403 Forbidden due to missing system admin scope.",
            expected_decision=ReasoningDecision.HYPOTHESIS,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-CWE-285-001-04", "CHK-DOC-CWE-862-001-04"],
            difficulty=DifficultyLevel.HARD,
            is_negative_control=False,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Claiming SSRF exploitation without callback delivery evidence",
            ],
            evaluation_notes="Scope escalation from tenant scope to global platform event stream.",
        ),

        # =====================================================================
        # 3. TENANT ISOLATION INVARIANTS (3 cases)
        # =====================================================================
        M3ReasoningCase(
            reasoning_case_id="RC-10",
            case_name="Cross-Tenant Queue Message Deletion",
            user_query="Can tenant A delete messages stored in tenant B's processing queue?",
            security_domain="Tenant Isolation",
            target_evidence={
                "asset_id": "ASSET-QUEUE-MSG-10",
                "endpoint_id": "EP-QUEUE-DELETE",
                "http_method": "DELETE",
                "route_template": "/api/v1/queues/{queue_id}/messages/{msg_id}",
                "application_mutability": "WRITE",
                "has_cross_identity_object_access_success": True,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer token_tenant_a",
                "observed_facts": [
                    {
                        "fact_id": "FACT-1001",
                        "statement": "Tenant A authenticated client called DELETE on /api/v1/queues/queue_tenant_b/messages/msg_881.",
                    },
                    {
                        "fact_id": "FACT-1002",
                        "statement": "Response status is 200 OK {'deleted': True} and message msg_881 was removed from tenant B queue.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-1001", "param_name": "queue_id", "location": "path"},
                    {"param_id": "PARAM-1002", "param_name": "msg_id", "location": "path"},
                ],
            },
            expected_security_concept="Platform Tenant Isolation Invariant Violation (TENANT-ISO-01)",
            expected_security_invariant="Cross-tenant isolation invariant: Message deletion must verify both queue and message belong strictly to caller tenant namespace.",
            expected_evidence_requirements=[
                "Confirm queue_tenant_b is allocated to tenant B",
                "Confirm caller belongs to tenant A",
                "Confirm message deleted across boundary",
            ],
            expected_experiment_characteristics="Issue DELETE to queue_tenant_b message using tenant A credentials.",
            expected_falsification_characteristics="Server rejects request with 403 Forbidden or 404 Not Found.",
            expected_decision=ReasoningDecision.HYPOTHESIS,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-TENANT-ISO-01-001-01", "CHK-DOC-TENANT-ISO-01-001-04"],
            difficulty=DifficultyLevel.MEDIUM,
            is_negative_control=False,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Assuming denial of service against cloud infrastructure",
            ],
            evaluation_notes="Destructive cross-tenant queue operation violating tenant namespace isolation.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-11",
            case_name="Tenant Configuration Modification via Header Override",
            user_query="Can tenant A overwrite tenant B configuration by passing an X-Tenant-Override header?",
            security_domain="Tenant Isolation",
            target_evidence={
                "asset_id": "ASSET-TENANT-CFG-11",
                "endpoint_id": "EP-TENANT-CONFIG",
                "http_method": "PATCH",
                "route_template": "/api/v1/tenants/{tenant_id}/config",
                "application_mutability": "WRITE",
                "has_cross_identity_object_access_success": True,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer token_tenant_a; X-Tenant-Override: tenant_b",
                "observed_facts": [
                    {
                        "fact_id": "FACT-1101",
                        "statement": "Client authenticated as tenant A sent PATCH /api/v1/tenants/tenant_b/config with body {'sso_enforced': False}.",
                    },
                    {
                        "fact_id": "FACT-1102",
                        "statement": "Response status is 200 OK returning updated configuration for tenant B with SSO disabled.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-1101", "param_name": "tenant_id", "location": "path"},
                    {"param_id": "PARAM-1102", "param_name": "sso_enforced", "location": "body"},
                ],
            },
            expected_security_concept="Platform Tenant Isolation Invariant Violation (TENANT-ISO-01) / Incorrect Authorization (CWE-863)",
            expected_security_invariant="Tenant configuration immutable invariant: Tenant configuration updates must strictly bind to JWT tenant claim, ignoring user-supplied tenant path or headers.",
            expected_evidence_requirements=[
                "Confirm tenant A token used to alter tenant B SSO configuration",
                "Confirm server honors path parameter over authenticated token claim",
            ],
            expected_experiment_characteristics="Submit PATCH to tenant_b config with valid tenant_a token.",
            expected_falsification_characteristics="Server rejects request with 403 Forbidden citing token tenant mismatch.",
            expected_decision=ReasoningDecision.HYPOTHESIS,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-TENANT-ISO-01-001-02", "CHK-DOC-CWE-863-001-02"],
            difficulty=DifficultyLevel.HARD,
            is_negative_control=False,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Claiming SAML/SSO signature bypass without IdP exchange evidence",
            ],
            evaluation_notes="Critical tenant isolation bypass disabling security enforcement on victim tenant.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-12",
            case_name="Multi-Tenant Metric Aggregation Leakage",
            user_query="Does the analytics endpoint leak private business metrics of foreign tenants via query parameter?",
            security_domain="Tenant Isolation",
            target_evidence={
                "asset_id": "ASSET-ANALYTICS-12",
                "endpoint_id": "EP-ANALYTICS-SUMMARY",
                "http_method": "GET",
                "route_template": "/api/v1/analytics/tenant_summary?tenant_id={target_tenant}",
                "application_mutability": "READ",
                "has_cross_identity_object_access_success": True,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer token_tenant_a",
                "observed_facts": [
                    {
                        "fact_id": "FACT-1201",
                        "statement": "Tenant A user queried /api/v1/analytics/tenant_summary?tenant_id=tenant_competitor_c.",
                    },
                    {
                        "fact_id": "FACT-1202",
                        "statement": "Response status is 200 OK returning monthly revenue, active user count, and top transactions for competitor C.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-1201", "param_name": "tenant_id", "location": "query"}
                ],
            },
            expected_security_concept="Platform Tenant Isolation Invariant Violation (TENANT-ISO-01)",
            expected_security_invariant="Cross-tenant information disclosure invariant: Analytical queries must filter data strictly to caller tenant ID.",
            expected_evidence_requirements=[
                "Verify tenant A token received sensitive analytics for tenant competitor C",
                "Verify query parameter allowed cross-tenant reporting",
            ],
            expected_experiment_characteristics="Request analytics summary with tenant A token while supplying foreign tenant ID in query string.",
            expected_falsification_characteristics="Server rejects query with 403 Forbidden or returns only caller's own tenant data.",
            expected_decision=ReasoningDecision.HYPOTHESIS,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-TENANT-ISO-01-001-03", "CHK-DOC-CWE-639-001-03"],
            difficulty=DifficultyLevel.EASY,
            is_negative_control=False,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Asserting database SQL injection without SQL error or syntax evidence",
            ],
            evaluation_notes="Horizontal tenant boundary breach leaking business intelligence.",
        ),

        # =====================================================================
        # 4. EVIDENCE GAP TRAPS (4 cases)
        # =====================================================================
        M3ReasoningCase(
            reasoning_case_id="RC-13",
            case_name="Ambiguous Role Header with Missing Identity Baseline",
            user_query="Is the financial report endpoint vulnerable to privilege escalation?",
            security_domain="Evidence Gap Identification",
            target_evidence={
                "asset_id": "ASSET-FIN-REP-13",
                "endpoint_id": "EP-FIN-REPORTS",
                "http_method": "GET",
                "route_template": "/api/v1/reports/financial",
                "application_mutability": "READ",
                "has_cross_identity_object_access_success": False,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer session_token_anon",
                "observed_facts": [
                    {
                        "fact_id": "FACT-1301",
                        "statement": "Observed single request to GET /api/v1/reports/financial returning HTTP 200 OK with Q2 earnings summary.",
                    },
                    {
                        "fact_id": "FACT-1302",
                        "statement": "The session token's assigned role, permissions, and organization membership were not recorded in the traffic trace.",
                    },
                ],
                "parameter_lineage": [],
            },
            expected_security_concept="Indeterminate Authorization State / Evidence Gap",
            expected_security_invariant="Evidence sufficiency invariant: Privilege escalation cannot be evaluated without authenticated role baseline of caller.",
            expected_evidence_requirements=[
                "Missing caller identity role classification (e.g. was token Chief Financial Officer or anonymous member?)",
                "Missing unauthenticated request baseline",
            ],
            expected_experiment_characteristics="Replay request with unauthenticated session and lower-privileged role to establish baseline.",
            expected_falsification_characteristics="If unauthenticated request returns 401 Unauthorized and low-privilege member receives 403 Forbidden, endpoint is properly guarded.",
            expected_decision=ReasoningDecision.INSUFFICIENT_EVIDENCE,
            relevant_knowledge_types=["SECURITY_INVARIANT", "NEGATIVE_CONTROL_GUIDE"],
            relevant_chunk_ids=["CHK-DOC-CWE-285-001-04", "CHK-DOC-CWE-862-001-04"],
            difficulty=DifficultyLevel.MEDIUM,
            is_negative_control=False,
            is_evidence_gap=True,
            forbidden_or_unsupported_conclusions=[
                "Confirming BFLA vulnerability without knowing caller role",
                "Claiming public unauthenticated disclosure without unauthenticated test",
            ],
            evaluation_notes="Evidence gap trap: model must identify missing identity context rather than overclaiming vulnerability.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-14",
            case_name="Download Route with Unverified Token in Query String",
            user_query="Is the contract download endpoint vulnerable to unauthenticated access?",
            security_domain="Evidence Gap Identification",
            target_evidence={
                "asset_id": "ASSET-DOWN-TOK-14",
                "endpoint_id": "EP-DOWNLOAD-CONTRACT",
                "http_method": "GET",
                "route_template": "/api/v1/downloads/contract?token={tok}",
                "application_mutability": "READ",
                "has_cross_identity_object_access_success": False,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "None",
                "observed_facts": [
                    {
                        "fact_id": "FACT-1401",
                        "statement": "Client initiated GET /api/v1/downloads/contract?token=exp_991823.",
                    },
                    {
                        "fact_id": "FACT-1402",
                        "statement": "Traffic capture was truncated; server response code, headers, and body are absent from observed capture.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-1401", "param_name": "token", "location": "query"}
                ],
            },
            expected_security_concept="Missing Response Observation / Evidence Gap",
            expected_security_invariant="Evidence completeness invariant: Authorization status cannot be inferred without observing server response.",
            expected_evidence_requirements=[
                "Missing server HTTP status code",
                "Missing verification of whether token exp_991823 is cryptographically signed and ephemeral",
            ],
            expected_experiment_characteristics="Send request with expired token, missing token, and tampered token to observe server validation.",
            expected_falsification_characteristics="Server returns 401 Unauthorized or 403 Forbidden for missing/invalid token.",
            expected_decision=ReasoningDecision.INSUFFICIENT_EVIDENCE,
            relevant_knowledge_types=["SECURITY_INVARIANT", "FALSE_POSITIVE_GUIDANCE"],
            relevant_chunk_ids=["CHK-DOC-CWE-862-001-01", "CHK-DOC-CWE-284-001-02"],
            difficulty=DifficultyLevel.EASY,
            is_negative_control=False,
            is_evidence_gap=True,
            forbidden_or_unsupported_conclusions=[
                "Confirming broken authentication without server response",
                "Assuming token is static or predictable without multiple sample observations",
            ],
            evaluation_notes="Truncated response evidence gap requiring calibrated abstention.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-15",
            case_name="Cross-Account Transfer with Indeterminate Organization Context",
            user_query="Can funds be transferred between arbitrary accounts?",
            security_domain="Evidence Gap Identification",
            target_evidence={
                "asset_id": "ASSET-TRANSFER-15",
                "endpoint_id": "EP-TRANSFERS",
                "http_method": "POST",
                "route_template": "/api/v1/transfers",
                "application_mutability": "WRITE",
                "has_cross_identity_object_access_success": False,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer user_token_acct_a",
                "observed_facts": [
                    {
                        "fact_id": "FACT-1501",
                        "statement": "Request submitted transfer of $500 from source_account ACCT-101 to destination_account ACCT-202.",
                    },
                    {
                        "fact_id": "FACT-1502",
                        "statement": "Server responded 200 OK {'transfer_status': 'COMPLETED'}; both accounts are registered under user_token_acct_a's verified business profile.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-1501", "param_name": "source_account", "location": "body"},
                    {"param_id": "PARAM-1502", "param_name": "destination_account", "location": "body"},
                ],
            },
            expected_security_concept="Indeterminate Cross-Tenant Boundary / Evidence Gap",
            expected_security_invariant="Account ownership invariant: Transfer must verify source account belongs to caller; foreign source accounts must be rejected.",
            expected_evidence_requirements=[
                "Missing test where source_account is set to an account NOT owned by caller",
                "Current evidence only observes intra-user account transfer",
            ],
            expected_experiment_characteristics="Attempt transfer with source_account set to victim account ID not owned by caller session.",
            expected_falsification_characteristics="Server rejects request with 403 Forbidden stating caller does not own source account.",
            expected_decision=ReasoningDecision.INSUFFICIENT_EVIDENCE,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-CWE-639-001-01", "CHK-DOC-CWE-863-001-03"],
            difficulty=DifficultyLevel.MEDIUM,
            is_negative_control=False,
            is_evidence_gap=True,
            forbidden_or_unsupported_conclusions=[
                "Claiming IDOR on money transfers based solely on successful transfer between own accounts",
            ],
            evaluation_notes="Intra-account transfer observed; cross-account vulnerability is unevidenced.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-16",
            case_name="HTTP Verb Tunneling Header Without Negative Baseline",
            user_query="Does the API permit unauthorized user deletion via HTTP verb tunneling?",
            security_domain="Evidence Gap Identification",
            target_evidence={
                "asset_id": "ASSET-USER-DEL-16",
                "endpoint_id": "EP-USER-MUTATE",
                "http_method": "POST",
                "route_template": "/api/v1/users/{user_id}",
                "application_mutability": "WRITE",
                "has_cross_identity_object_access_success": False,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer token_admin_user; X-HTTP-Method-Override: DELETE",
                "observed_facts": [
                    {
                        "fact_id": "FACT-1601",
                        "statement": "Admin user invoked POST /api/v1/users/501 with X-HTTP-Method-Override: DELETE.",
                    },
                    {
                        "fact_id": "FACT-1602",
                        "statement": "User 501 was deleted with status 200 OK; no trace exists testing this header with a non-admin user session.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-1601", "param_name": "user_id", "location": "path"}
                ],
            },
            expected_security_concept="Missing Negative Control Baseline / Evidence Gap",
            expected_security_invariant="Method override authorization invariant: Method override headers must undergo identical role-based authorization as raw HTTP verbs.",
            expected_evidence_requirements=[
                "Missing test of X-HTTP-Method-Override: DELETE using non-admin or unauthenticated caller",
                "Current trace only observes authorized admin deleting user",
            ],
            expected_experiment_characteristics="Submit identical POST with X-HTTP-Method-Override: DELETE using unprivileged standard member credentials.",
            expected_falsification_characteristics="Server rejects unprivileged request with 403 Forbidden.",
            expected_decision=ReasoningDecision.INSUFFICIENT_EVIDENCE,
            relevant_knowledge_types=["SECURITY_INVARIANT", "TESTING_METHODOLOGY"],
            relevant_chunk_ids=["CHK-DOC-CWE-285-001-01", "CHK-DOC-CWE-863-001-04"],
            difficulty=DifficultyLevel.HARD,
            is_negative_control=False,
            is_evidence_gap=True,
            forbidden_or_unsupported_conclusions=[
                "Claiming method tunneling bypass exists before testing with non-admin session",
            ],
            evaluation_notes="Authorized execution observed; bypass hypothesis requires testing with unauthorized role.",
        ),

        # =====================================================================
        # 5. NEGATIVE CONTROLS & FALSE-POSITIVE TRAPS (4 cases)
        # =====================================================================
        M3ReasoningCase(
            reasoning_case_id="RC-17",
            case_name="Public Static Avatar Asset Intentionally Unauthenticated",
            user_query="Is the public avatar endpoint vulnerable to unauthenticated data exposure?",
            security_domain="False-Positive Resistance",
            target_evidence={
                "asset_id": "ASSET-STATIC-AVATAR-17",
                "endpoint_id": "EP-STATIC-AVATARS",
                "http_method": "GET",
                "route_template": "/static/avatars/{avatar_id}.png",
                "application_mutability": "READ",
                "has_cross_identity_object_access_success": False,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": True,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "None",
                "observed_facts": [
                    {
                        "fact_id": "FACT-1701",
                        "statement": "Unauthenticated client sent GET /static/avatars/user_avatar_101.png without cookies or authorization header.",
                    },
                    {
                        "fact_id": "FACT-1702",
                        "statement": "Response status is 200 OK returning image/png binary bytes; endpoint is served from public static asset directory.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-1701", "param_name": "avatar_id", "location": "path"}
                ],
            },
            expected_security_concept="Intended Public Static Asset / Negative Control",
            expected_security_invariant="Public asset classification: Public static web assets are designed for unauthenticated CDN delivery.",
            expected_evidence_requirements=[
                "Verify route is designated static asset directory (/static/)",
                "Verify returned payload is benign public image",
            ],
            expected_experiment_characteristics="N/A - Functional asset requires no authorization.",
            expected_falsification_characteristics="Asset is intended public functionality.",
            expected_decision=ReasoningDecision.NO_RELEVANT_FUNCTIONALITY,
            relevant_knowledge_types=["NEGATIVE_CONTROL_GUIDE", "FALSE_POSITIVE_GUIDANCE"],
            relevant_chunk_ids=["CHK-DOC-CWE-284-001-03", "CHK-DOC-CWE-862-001-04"],
            difficulty=DifficultyLevel.EASY,
            is_negative_control=True,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Reporting unauthenticated access vulnerability or BOLA on public avatar icon",
            ],
            evaluation_notes="Negative control: public image assets must not trigger access control vulnerability findings.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-18",
            case_name="Unauthenticated Health Check Ping Endpoint",
            user_query="Is the /healthz endpoint vulnerable to unauthorized access?",
            security_domain="False-Positive Resistance",
            target_evidence={
                "asset_id": "ASSET-HEALTH-PING-18",
                "endpoint_id": "EP-HEALTH-CHECK",
                "http_method": "GET",
                "route_template": "/healthz",
                "application_mutability": "READ",
                "has_cross_identity_object_access_success": False,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": True,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "None",
                "observed_facts": [
                    {
                        "fact_id": "FACT-1801",
                        "statement": "Unauthenticated probe issued GET /healthz without credentials.",
                    },
                    {
                        "fact_id": "FACT-1802",
                        "statement": "Server returned 200 OK {'status': 'UP'}; contains no user data, secrets, or internal system topology.",
                    },
                ],
                "parameter_lineage": [],
            },
            expected_security_concept="Intended Operational Health Check / Negative Control",
            expected_security_invariant="Operational liveness invariant: Load balancer health probe endpoints intentionally operate without authentication.",
            expected_evidence_requirements=[
                "Verify response contains zero sensitive tenant data",
                "Verify endpoint provides strictly operational uptime status",
            ],
            expected_experiment_characteristics="N/A - Uptime endpoint is non-vulnerable.",
            expected_falsification_characteristics="N/A - Endpoint behaves according to standard operational specification.",
            expected_decision=ReasoningDecision.NO_RELEVANT_FUNCTIONALITY,
            relevant_knowledge_types=["NEGATIVE_CONTROL_GUIDE", "FALSE_POSITIVE_GUIDANCE"],
            relevant_chunk_ids=["CHK-DOC-CWE-284-001-03", "CHK-DOC-CWE-285-001-04"],
            difficulty=DifficultyLevel.EASY,
            is_negative_control=True,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Reporting unauthenticated access or information disclosure on health probe",
            ],
            evaluation_notes="Negative control: liveness probe must not be flagged as unauthorized access flaw.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-19",
            case_name="Public User Profile Route with Public Informational Fields",
            user_query="Does the public user profile endpoint leak private user information?",
            security_domain="False-Positive Resistance",
            target_evidence={
                "asset_id": "ASSET-PUB-PROFILE-19",
                "endpoint_id": "EP-PUBLIC-PROFILE",
                "http_method": "GET",
                "route_template": "/api/v1/public/profiles/{username}",
                "application_mutability": "READ",
                "has_cross_identity_object_access_success": False,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": True,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "None",
                "observed_facts": [
                    {
                        "fact_id": "FACT-1901",
                        "statement": "GET /api/v1/public/profiles/alex_dev issued without authentication.",
                    },
                    {
                        "fact_id": "FACT-1902",
                        "statement": "Response status is 200 OK containing only public display_name, public bio, and joined_year; private email and phone fields are omitted.",
                    },
                ],
                "parameter_lineage": [
                    {"param_id": "PARAM-1901", "param_name": "username", "location": "path"}
                ],
            },
            expected_security_concept="Intended Public API / Negative Control",
            expected_security_invariant="Public profile projection invariant: Explicitly public profile routes properly filter private PII attributes.",
            expected_evidence_requirements=[
                "Verify route is explicitly designated /public/profiles/",
                "Verify sensitive fields (email, password, phone, billing) are absent",
            ],
            expected_experiment_characteristics="N/A - Endpoint correctly implements public data projection.",
            expected_falsification_characteristics="N/A - Functional public profile.",
            expected_decision=ReasoningDecision.NO_RELEVANT_FUNCTIONALITY,
            relevant_knowledge_types=["NEGATIVE_CONTROL_GUIDE", "FALSE_POSITIVE_GUIDANCE"],
            relevant_chunk_ids=["CHK-DOC-CWE-284-001-03", "CHK-DOC-CWE-639-001-02"],
            difficulty=DifficultyLevel.MEDIUM,
            is_negative_control=True,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Reporting BOLA or PII exposure when only public display attributes are returned",
            ],
            evaluation_notes="Negative control: properly projected public profile must not be classified as BOLA.",
        ),
        M3ReasoningCase(
            reasoning_case_id="RC-20",
            case_name="Deprecated API Endpoint Correctly Returning 410 Gone",
            user_query="Can legacy data be extracted through the deprecated v0 export endpoint?",
            security_domain="False-Positive Resistance",
            target_evidence={
                "asset_id": "ASSET-LEGACY-EXP-20",
                "endpoint_id": "EP-V0-EXPORT",
                "http_method": "GET",
                "route_template": "/api/v0/legacy/export",
                "application_mutability": "READ",
                "has_cross_identity_object_access_success": False,
                "has_privilege_level_delta": False,
                "has_unauthenticated_success": False,
                "status_code_changed_under_different_role": False,
                "has_cross_role_response_shape_delta": False,
                "has_evidence_parse_asymmetry": False,
                "auth_header_delta": "Bearer user_token",
                "observed_facts": [
                    {
                        "fact_id": "FACT-2001",
                        "statement": "Client attempted GET /api/v0/legacy/export with valid user token.",
                    },
                    {
                        "fact_id": "FACT-2002",
                        "statement": "Server responded with HTTP 410 Gone {'error': 'ENDPOINT_DECOMMISSIONED'} and zero data payload.",
                    },
                ],
                "parameter_lineage": [],
            },
            expected_security_concept="Decommissioned Route / Negative Control",
            expected_security_invariant="Decommissioning invariant: Inactive legacy endpoints must fail closed with 410 Gone and zero data return.",
            expected_evidence_requirements=[
                "Observe 410 Gone status code",
                "Confirm zero business data returned",
            ],
            expected_experiment_characteristics="N/A - Endpoint is inactive and safe.",
            expected_falsification_characteristics="N/A - Response confirms decommissioned status.",
            expected_decision=ReasoningDecision.NO_RELEVANT_FUNCTIONALITY,
            relevant_knowledge_types=["NEGATIVE_CONTROL_GUIDE", "FALSE_POSITIVE_GUIDANCE"],
            relevant_chunk_ids=["CHK-DOC-CWE-284-001-03", "CHK-DOC-CWE-862-001-04"],
            difficulty=DifficultyLevel.MEDIUM,
            is_negative_control=True,
            is_evidence_gap=False,
            forbidden_or_unsupported_conclusions=[
                "Reporting vulnerability on decommissioned route returning 410 Gone",
            ],
            evaluation_notes="Negative control: inactive route returning 410 Gone must not be treated as vulnerable.",
        ),
    ]


def load_m3_reasoning_dataset(dataset_path: Optional[Path] = None) -> M3ReasoningDataset:
    """Load or generate the frozen 20-case reasoning evaluation dataset."""
    cases = get_m3_reasoning_cases()
    dataset = M3ReasoningDataset(
        total_cases=len(cases),
        cases=cases,
    )
    if dataset_path:
        p = Path(dataset_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(dataset.model_dump_json(indent=2))
    return dataset
