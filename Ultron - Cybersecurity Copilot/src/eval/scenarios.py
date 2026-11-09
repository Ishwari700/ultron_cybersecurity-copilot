"""Benchmark scenarios and gold-set definitions for evaluation.

Supports 84 controlled scenarios across 6 application families:
- saas_billing (development split: 14 scenarios)
- ecommerce_orders (development split: 14 scenarios)
- identity_provider (validation split: 14 scenarios)
- document_collaboration (validation split: 14 scenarios)
- healthcare_portal (evaluation split: 14 scenarios)
- iot_fleet_mgmt (evaluation split: 14 scenarios)

Strictly free from vulnerability-label leakage:
- No vulnerability names (BOLA, BFLA, IDOR, Step-Skipping, Bypass, Leak) in descriptions or initial evidence.
- No 'vulnerable' or 'patched' or 'with server authorization check' in evidence statements.
- Both variants receive identical neutral OpenAPI observable evidence.
- Legitimate observable route parameters are fully registered.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EvaluationScenario(BaseModel):
    """A benchmark scenario with controlled ground truth."""
    scenario_id: str
    name: str
    app_family: str = "saas_billing"
    split: str = "evaluation"  # "development" | "validation" | "evaluation"
    category: str
    category_id: str
    ground_truth_vulnerable: bool
    expected_decision: str  # "HYPOTHESIS" | "NO_RELEVANT_FUNCTIONALITY" | "INSUFFICIENT_EVIDENCE"
    target_asset: Dict[str, Any]
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    initial_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    identities: List[Dict[str, Any]] = Field(default_factory=list)
    vulnerable_variant: bool = True


class BudgetTier:
    """Explicitly pre-registered resource budgets."""
    LOW = {
        "tier": "LOW",
        "evidence_items": 3,
        "retrieval_k": 3,
        "token_budget": 1024,
        "max_experiments": 1,
        "reviewer_minutes": 5,
    }
    MEDIUM = {
        "tier": "MEDIUM",
        "evidence_items": 5,
        "retrieval_k": 5,
        "token_budget": 2048,
        "max_experiments": 3,
        "reviewer_minutes": 15,
    }
    HIGH = {
        "tier": "HIGH",
        "evidence_items": 10,
        "retrieval_k": 10,
        "token_budget": 4096,
        "max_experiments": 5,
        "reviewer_minutes": 30,
    }


def _create_family_scenarios(
    family: str,
    split: str,
    host: str,
    endpoint_defs: List[Dict[str, Any]],
) -> List[EvaluationScenario]:
    """Helper to generate 14 scenarios for an application family: 6 paired (12) + 2 negative controls."""
    scenarios: List[EvaluationScenario] = []

    # 6 Paired sets (12 scenarios)
    for idx, ed in enumerate(endpoint_defs[:6], start=1):
        # Vulnerable variant
        v_id = f"SCEN-{family.upper()}-{ed['short_code']}-VULN-0{idx}"
        scenarios.append(
            EvaluationScenario(
                scenario_id=v_id,
                name=f"{family} {ed['name']} (Target V-0{idx})",
                app_family=family,
                split=split,
                category=ed["category"],
                category_id=ed["category_id"],
                ground_truth_vulnerable=True,
                expected_decision="HYPOTHESIS",
                vulnerable_variant=True,
                target_asset={
                    "asset_id": f"ASSET-{family.upper()}-{ed['short_code']}-0{idx}",
                    "method": ed["method"],
                    "host": host,
                    "raw_path": ed["path"],
                    "normalized_path": ed["normalized_path"],
                    "application_mutability": ed["mutability"],
                },
                parameters=ed.get("parameters", []),
                identities=[{"identity_id": "user_a", "role": "customer"}, {"identity_id": "user_b", "role": "customer"}],
                initial_evidence=[{
                    "fact_id": f"FACT-{family.upper()}-{ed['short_code']}-DOC",
                    "certainty": "DOCUMENTED",
                    "statement": ed["statement"],
                    "source_tool": "openapi",
                }],
            )
        )

        # Patched variant (receives IDENTICAL observable initial evidence as vulnerable variant)
        p_id = f"SCEN-{family.upper()}-{ed['short_code']}-PATCH-0{idx}"
        scenarios.append(
            EvaluationScenario(
                scenario_id=p_id,
                name=f"{family} {ed['name']} (Target P-0{idx})",
                app_family=family,
                split=split,
                category=ed["category"],
                category_id=ed["category_id"],
                ground_truth_vulnerable=False,
                expected_decision="INSUFFICIENT_EVIDENCE",
                vulnerable_variant=False,
                target_asset={
                    "asset_id": f"ASSET-{family.upper()}-{ed['short_code']}-0{idx}",
                    "method": ed["method"],
                    "host": host,
                    "raw_path": ed["path"],
                    "normalized_path": ed["normalized_path"],
                    "application_mutability": ed["mutability"],
                },
                parameters=ed.get("parameters", []),
                identities=[{"identity_id": "user_a", "role": "customer"}, {"identity_id": "user_b", "role": "customer"}],
                initial_evidence=[{
                    "fact_id": f"FACT-{family.upper()}-{ed['short_code']}-DOC",
                    "certainty": "DOCUMENTED",
                    "statement": ed["statement"],
                    "source_tool": "openapi",
                }],
            )
        )

    # 2 Negative Controls (safe public endpoints)
    neg_defs = [
        {
            "name": "Catalog Discovery",
            "path": "/catalog" if family != "identity_provider" else "/.well-known/openid-configuration",
            "norm": "/catalog" if family != "identity_provider" else "/.well-known/openid-configuration",
            "stmt": "GET /catalog returns public unauthenticated service catalog metadata." if family != "identity_provider" else "GET /.well-known/openid-configuration returns public OpenID Connect provider configuration.",
        },
        {
            "name": "Public Pricing Status",
            "path": "/pricing" if family == "saas_billing" else ("/products" if family == "ecommerce_orders" else ("/oauth/jwks" if family == "identity_provider" else ("/templates" if family == "document_collaboration" else ("/clinic-hours" if family == "healthcare_portal" else "/status")))),
            "norm": "/public",
            "stmt": "GET /public endpoint returns public static pricing, schedule, and availability metadata.",
        },
    ]
    for n_idx, nd in enumerate(neg_defs, start=1):
        neg_id = f"SCEN-{family.upper()}-NEG-0{n_idx}"
        scenarios.append(
            EvaluationScenario(
                scenario_id=neg_id,
                name=f"{family} {nd['name']}",
                app_family=family,
                split=split,
                category="public_endpoint",
                category_id="API-AUTH-NONE",
                ground_truth_vulnerable=False,
                expected_decision="NO_RELEVANT_FUNCTIONALITY",
                vulnerable_variant=False,
                target_asset={
                    "asset_id": f"ASSET-{family.upper()}-NEG-0{n_idx}",
                    "method": "GET",
                    "host": host,
                    "raw_path": nd["path"],
                    "normalized_path": nd["norm"],
                    "application_mutability": "READ_ONLY",
                },
                parameters=[],
                identities=[],
                initial_evidence=[{
                    "fact_id": f"FACT-{family.upper()}-NEG-{n_idx}",
                    "certainty": "DOCUMENTED",
                    "statement": nd["stmt"],
                    "source_tool": "openapi",
                }],
            )
        )

    return scenarios


def get_gold_set_scenarios() -> List[EvaluationScenario]:
    """
    Returns the expanded 84-scenario gold set across 6 application families
    with strict development, validation, and evaluation family partitioning.
    """
    scenarios: List[EvaluationScenario] = []

    # Family 1: saas_billing (Development)
    saas_defs = [
        {
            "short_code": "INV-DETAILS",
            "name": "Invoice Details API",
            "category": "authorization",
            "category_id": "API-BOLA-001",
            "method": "GET",
            "path": "/api/v1/invoices/INV-100",
            "normalized_path": "/api/v1/invoices/{id}",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/invoices/{id} retrieves billing invoice records for the specified invoice identifier. Requires active customer session.",
            "parameters": [{"param_id": "PARAM-SAAS-INV-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "SUB-DETAILS",
            "name": "Subscription Details API",
            "category": "authorization",
            "category_id": "API-BOLA-001",
            "method": "GET",
            "path": "/api/v1/subscriptions/SUB-100",
            "normalized_path": "/api/v1/subscriptions/{id}",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/subscriptions/{id} retrieves active subscription tier and renewal metadata. Requires active customer session.",
            "parameters": [{"param_id": "PARAM-SAAS-SUB-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "INV-SUMMARY",
            "name": "Invoice Summary API",
            "category": "authorization",
            "category_id": "API-CROSS-TENANT-001",
            "method": "GET",
            "path": "/api/v1/invoices/INV-200",
            "normalized_path": "/api/v1/invoices/{id}",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/invoices/{id} provides itemized invoice payment breakdown. Requires tenant member authorization.",
            "parameters": [{"param_id": "PARAM-SAAS-INV-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "SUB-SUMMARY",
            "name": "Subscription Summary API",
            "category": "authorization",
            "category_id": "API-CROSS-TENANT-001",
            "method": "GET",
            "path": "/api/v1/subscriptions/SUB-200",
            "normalized_path": "/api/v1/subscriptions/{id}",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/subscriptions/{id} provides billing cycle and plan quota usage. Requires tenant member authorization.",
            "parameters": [{"param_id": "PARAM-SAAS-SUB-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "INV-WORKFLOW",
            "name": "Invoice Workflow API",
            "category": "authorization",
            "category_id": "API-MULTI-STEP-AUTH-001",
            "method": "GET",
            "path": "/api/v1/invoices/INV-100",
            "normalized_path": "/api/v1/invoices/{id}",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/invoices/{id} accesses multi-party approval state and payable status. Requires finance officer approval.",
            "parameters": [{"param_id": "PARAM-SAAS-INV-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "SUB-PLAN",
            "name": "Subscription Plan API",
            "category": "authorization",
            "category_id": "API-MUTATION-001",
            "method": "GET",
            "path": "/api/v1/subscriptions/SUB-100",
            "normalized_path": "/api/v1/subscriptions/{id}",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/subscriptions/{id} inspects provisioned tier entitlements. Requires billing administrator authority.",
            "parameters": [{"param_id": "PARAM-SAAS-SUB-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
    ]
    scenarios.extend(_create_family_scenarios("saas_billing", "development", "billing.target.com", saas_defs))

    # Family 2: ecommerce_orders (Development)
    ecom_defs = [
        {
            "short_code": "ORD-REFUND",
            "name": "Order Refund API",
            "category": "business_logic",
            "category_id": "API-STATE-001",
            "method": "POST",
            "path": "/api/v1/orders/ORD-001/refund",
            "normalized_path": "/api/v1/orders/{id}/refund",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/orders/{id}/refund processes refund transaction for customer order. Expected order lifecycle state: PAID.",
            "parameters": [{"param_id": "PARAM-ECOM-ORD-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "ORD-SHIP",
            "name": "Order Shipping API",
            "category": "business_logic",
            "category_id": "API-STATE-001",
            "method": "POST",
            "path": "/api/v1/orders/ORD-001/ship",
            "normalized_path": "/api/v1/orders/{id}/ship",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/orders/{id}/ship transitions order to warehouse fulfillment dispatch. Expected order lifecycle state: PAID.",
            "parameters": [{"param_id": "PARAM-ECOM-ORD-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "ORD-PAY",
            "name": "Order Payment API",
            "category": "business_logic",
            "category_id": "API-STATE-001",
            "method": "POST",
            "path": "/api/v1/orders/ORD-001/pay",
            "normalized_path": "/api/v1/orders/{id}/pay",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/orders/{id}/pay completes payment processing for pending order. Expected order lifecycle state: CREATED.",
            "parameters": [{"param_id": "PARAM-ECOM-ORD-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "ORD-CANCEL-REFUND",
            "name": "Cancelled Order Refund API",
            "category": "business_logic",
            "category_id": "API-LIFECYCLE-001",
            "method": "POST",
            "path": "/api/v1/orders/ORD-001/refund",
            "normalized_path": "/api/v1/orders/{id}/refund",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/orders/{id}/refund handles credit adjustments. Orders in CANCELLED state are not eligible for standard refund.",
            "parameters": [{"param_id": "PARAM-ECOM-ORD-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "ORD-DISPATCH",
            "name": "Unpaid Order Dispatch API",
            "category": "business_logic",
            "category_id": "API-LIFECYCLE-001",
            "method": "POST",
            "path": "/api/v1/orders/ORD-001/ship",
            "normalized_path": "/api/v1/orders/{id}/ship",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/orders/{id}/ship generates courier manifests. Orders in UNPAID state are rejected by shipping queue.",
            "parameters": [{"param_id": "PARAM-ECOM-ORD-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "ORD-RETURN",
            "name": "Post-Delivery Return API",
            "category": "business_logic",
            "category_id": "API-STATE-001",
            "method": "POST",
            "path": "/api/v1/orders/ORD-001/refund",
            "normalized_path": "/api/v1/orders/{id}/refund",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/orders/{id}/refund handles product returns. Order must be in DELIVERED state with return authorization.",
            "parameters": [{"param_id": "PARAM-ECOM-ORD-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
    ]
    scenarios.extend(_create_family_scenarios("ecommerce_orders", "development", "shop.target.com", ecom_defs))

    # Family 3: identity_provider (Validation)
    idp_defs = [
        {
            "short_code": "USER-ROLES",
            "name": "User Roles API",
            "category": "authorization",
            "category_id": "API-BFLA-001",
            "method": "POST",
            "path": "/api/v1/users/user_a/roles",
            "normalized_path": "/api/v1/users/{id}/roles",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/users/{id}/roles updates account security role assignments. Requires admin role.",
            "parameters": [
                {"param_id": "PARAM-IDP-USER-ID", "name": "id", "location": "path", "schema_type": "string"},
                {"param_id": "PARAM-IDP-ROLES", "name": "roles", "location": "body", "schema_type": "array"},
            ],
        },
        {
            "short_code": "USER-MFA",
            "name": "User MFA API",
            "category": "authorization",
            "category_id": "API-BFLA-001",
            "method": "DELETE",
            "path": "/api/v1/users/user_a/mfa",
            "normalized_path": "/api/v1/users/{id}/mfa",
            "mutability": "STATE_CHANGING",
            "statement": "DELETE /api/v1/users/{id}/mfa disables multi-factor authentication devices. Requires admin role or verified account owner.",
            "parameters": [{"param_id": "PARAM-IDP-USER-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "USER-TENANT-ROLE",
            "name": "Cross-Tenant Role API",
            "category": "authorization",
            "category_id": "API-ROLE-BOUNDARY-001",
            "method": "POST",
            "path": "/api/v1/users/user_b/roles",
            "normalized_path": "/api/v1/users/{id}/roles",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/users/{id}/roles assigns organization-level permissions. Caller must be an administrator within target tenant.",
            "parameters": [
                {"param_id": "PARAM-IDP-USER-ID", "name": "id", "location": "path", "schema_type": "string"},
                {"param_id": "PARAM-IDP-ROLES", "name": "roles", "location": "body", "schema_type": "array"},
            ],
        },
        {
            "short_code": "USER-TENANT-MFA",
            "name": "Cross-Tenant MFA API",
            "category": "authorization",
            "category_id": "API-ROLE-BOUNDARY-001",
            "method": "DELETE",
            "path": "/api/v1/users/user_b/mfa",
            "normalized_path": "/api/v1/users/{id}/mfa",
            "mutability": "STATE_CHANGING",
            "statement": "DELETE /api/v1/users/{id}/mfa resets authentication factors. Caller must possess security administrator authority within target tenant.",
            "parameters": [{"param_id": "PARAM-IDP-USER-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "USER-ADMIN-ROLE",
            "name": "Admin Role API",
            "category": "authorization",
            "category_id": "API-MUTATION-001",
            "method": "POST",
            "path": "/api/v1/users/user_a/roles",
            "normalized_path": "/api/v1/users/{id}/roles",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/users/{id}/roles provisions elevated administrative entitlements. Requires system superadmin credentials.",
            "parameters": [
                {"param_id": "PARAM-IDP-USER-ID", "name": "id", "location": "path", "schema_type": "string"},
                {"param_id": "PARAM-IDP-ROLES", "name": "roles", "location": "body", "schema_type": "array"},
            ],
        },
        {
            "short_code": "USER-AUTH-MUTATE",
            "name": "Authority Boundary API",
            "category": "authorization",
            "category_id": "API-MUTATION-001",
            "method": "POST",
            "path": "/api/v1/users/user_b/roles",
            "normalized_path": "/api/v1/users/{id}/roles",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/users/{id}/roles reconfigures security boundaries and role matrices. Requires system superadmin credentials.",
            "parameters": [
                {"param_id": "PARAM-IDP-USER-ID", "name": "id", "location": "path", "schema_type": "string"},
                {"param_id": "PARAM-IDP-ROLES", "name": "roles", "location": "body", "schema_type": "array"},
            ],
        },
    ]
    scenarios.extend(_create_family_scenarios("identity_provider", "validation", "idp.target.com", idp_defs))

    # Family 4: document_collaboration (Validation)
    doc_defs = [
        {
            "short_code": "DOC-EXPORT",
            "name": "Document Export API",
            "category": "authorization",
            "category_id": "API-BOLA-001",
            "method": "GET",
            "path": "/api/v1/docs/DOC-100/export",
            "normalized_path": "/api/v1/docs/{id}/export",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/docs/{id}/export generates document export package. Requires active document collaborator session.",
            "parameters": [{"param_id": "PARAM-DOC-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "DOC-ORG-EXPORT",
            "name": "Org Document Export API",
            "category": "authorization",
            "category_id": "API-CROSS-TENANT-001",
            "method": "GET",
            "path": "/api/v1/docs/DOC-200/export",
            "normalized_path": "/api/v1/docs/{id}/export",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/docs/{id}/export compiles multi-document archive. Requires organization workspace membership.",
            "parameters": [{"param_id": "PARAM-DOC-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "DOC-PUBLISH",
            "name": "Document Publish API",
            "category": "business_logic",
            "category_id": "API-STATE-001",
            "method": "POST",
            "path": "/api/v1/approvals/APP-100/publish",
            "normalized_path": "/api/v1/approvals/{id}/publish",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/approvals/{id}/publish releases document draft to corporate repository. Expected approval state: APPROVED.",
            "parameters": [{"param_id": "PARAM-DOC-APP-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "DOC-RELEASE",
            "name": "Document Release API",
            "category": "business_logic",
            "category_id": "API-STATE-001",
            "method": "POST",
            "path": "/api/v1/approvals/APP-100/publish",
            "normalized_path": "/api/v1/approvals/{id}/publish",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/approvals/{id}/publish distributes finalized document. Expected approval state: APPROVED.",
            "parameters": [{"param_id": "PARAM-DOC-APP-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "DOC-CLASSIFY",
            "name": "Document Classification API",
            "category": "authorization",
            "category_id": "API-MULTI-STEP-AUTH-001",
            "method": "GET",
            "path": "/api/v1/docs/DOC-100/export",
            "normalized_path": "/api/v1/docs/{id}/export",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/docs/{id}/export downloads classified intellectual property. Requires compliance export verification.",
            "parameters": [{"param_id": "PARAM-DOC-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "DOC-WORKSPACE",
            "name": "Workspace Access API",
            "category": "authorization",
            "category_id": "API-MULTI-STEP-AUTH-001",
            "method": "GET",
            "path": "/api/v1/docs/DOC-200/export",
            "normalized_path": "/api/v1/docs/{id}/export",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/docs/{id}/export accesses restricted workspace files. Requires workspace owner verification.",
            "parameters": [{"param_id": "PARAM-DOC-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
    ]
    scenarios.extend(_create_family_scenarios("document_collaboration", "validation", "docs.target.com", doc_defs))

    # Family 5: healthcare_portal (Evaluation)
    health_defs = [
        {
            "short_code": "PATIENT-REC",
            "name": "Patient Record API",
            "category": "authorization",
            "category_id": "API-BOLA-001",
            "method": "GET",
            "path": "/api/v1/records/REC-100",
            "normalized_path": "/api/v1/records/{id}",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/records/{id} retrieves patient diagnostic history and health chart. Requires patient or designated physician session.",
            "parameters": [{"param_id": "PARAM-HLTH-REC-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "PATIENT-RX",
            "name": "Prescription Access API",
            "category": "authorization",
            "category_id": "API-BOLA-001",
            "method": "GET",
            "path": "/api/v1/prescriptions/RX-100",
            "normalized_path": "/api/v1/prescriptions/{id}",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/prescriptions/{id} retrieves medication dosages and refill authorizations. Requires patient or designated physician session.",
            "parameters": [{"param_id": "PARAM-HLTH-RX-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "RECORD-ARCHIVE",
            "name": "Archived Record API",
            "category": "business_logic",
            "category_id": "API-LIFECYCLE-001",
            "method": "GET",
            "path": "/api/v1/records/REC-ARCHIVED-100",
            "normalized_path": "/api/v1/records/{id}",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/records/{id} retrieves medical records. Records in ARCHIVED state require compliance officer authorization.",
            "parameters": [{"param_id": "PARAM-HLTH-REC-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "CLINIC-REC",
            "name": "Clinic Record API",
            "category": "authorization",
            "category_id": "API-CROSS-TENANT-001",
            "method": "GET",
            "path": "/api/v1/records/REC-100",
            "normalized_path": "/api/v1/records/{id}",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/records/{id} provides multi-facility chart coordination. Caller must be credentialed within treating clinic.",
            "parameters": [{"param_id": "PARAM-HLTH-REC-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "STAFF-RX",
            "name": "Staff Prescription API",
            "category": "authorization",
            "category_id": "API-ROLE-BOUNDARY-001",
            "method": "GET",
            "path": "/api/v1/prescriptions/RX-100",
            "normalized_path": "/api/v1/prescriptions/{id}",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/prescriptions/{id} inspects controlled pharmacy fulfillment. Requires licensed clinical staff credentials.",
            "parameters": [{"param_id": "PARAM-HLTH-RX-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "RECORD-PURGE",
            "name": "Purged Record API",
            "category": "business_logic",
            "category_id": "API-LIFECYCLE-001",
            "method": "GET",
            "path": "/api/v1/records/REC-ARCHIVED-100",
            "normalized_path": "/api/v1/records/{id}",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/records/{id} checks legal retention logs. Records in PURGED state cannot be retrieved.",
            "parameters": [{"param_id": "PARAM-HLTH-REC-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
    ]
    scenarios.extend(_create_family_scenarios("healthcare_portal", "evaluation", "health.target.com", health_defs))

    # Family 6: iot_fleet_mgmt (Evaluation)
    iot_defs = [
        {
            "short_code": "DEVICE-CMD",
            "name": "Device Command API",
            "category": "authorization",
            "category_id": "API-DEVICE-BOLA-001",
            "method": "POST",
            "path": "/api/v1/devices/DEV-100/command",
            "normalized_path": "/api/v1/devices/{id}/command",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/devices/{id}/command dispatches operational instructions to IoT device. Requires fleet operator session.",
            "parameters": [{"param_id": "PARAM-IOT-DEV-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "DEVICE-TEL",
            "name": "Device Telemetry API",
            "category": "authorization",
            "category_id": "API-DEVICE-BOLA-001",
            "method": "GET",
            "path": "/api/v1/devices/DEV-100/telemetry",
            "normalized_path": "/api/v1/devices/{id}/telemetry",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/devices/{id}/telemetry retrieves sensor telemetry and battery status. Requires fleet operator session.",
            "parameters": [{"param_id": "PARAM-IOT-DEV-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "FLEET-CMD",
            "name": "Fleet Command API",
            "category": "authorization",
            "category_id": "API-CROSS-TENANT-001",
            "method": "POST",
            "path": "/api/v1/devices/DEV-200/command",
            "normalized_path": "/api/v1/devices/{id}/command",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/devices/{id}/command executes fleet-wide hardware control. Caller must be an authorized manager of target fleet.",
            "parameters": [{"param_id": "PARAM-IOT-DEV-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "FLEET-TEL",
            "name": "Fleet Telemetry API",
            "category": "authorization",
            "category_id": "API-CROSS-TENANT-001",
            "method": "GET",
            "path": "/api/v1/devices/DEV-200/telemetry",
            "normalized_path": "/api/v1/devices/{id}/telemetry",
            "mutability": "READ_ONLY",
            "statement": "GET /api/v1/devices/{id}/telemetry aggregates device metrics. Caller must be an authorized manager of target fleet.",
            "parameters": [{"param_id": "PARAM-IOT-DEV-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "DEVICE-FW",
            "name": "Device Firmware API",
            "category": "authorization",
            "category_id": "API-BFLA-001",
            "method": "POST",
            "path": "/api/v1/devices/DEV-100/command",
            "normalized_path": "/api/v1/devices/{id}/command",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/devices/{id}/command installs firmware image updates. Requires firmware engineer authority.",
            "parameters": [{"param_id": "PARAM-IOT-DEV-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
        {
            "short_code": "FLEET-CONFIG",
            "name": "Fleet Configuration API",
            "category": "authorization",
            "category_id": "API-MUTATION-001",
            "method": "POST",
            "path": "/api/v1/devices/DEV-200/command",
            "normalized_path": "/api/v1/devices/{id}/command",
            "mutability": "STATE_CHANGING",
            "statement": "POST /api/v1/devices/{id}/command modifies global fleet configuration profiles. Requires fleet administrator authority.",
            "parameters": [{"param_id": "PARAM-IOT-DEV-ID", "name": "id", "location": "path", "schema_type": "string"}],
        },
    ]
    scenarios.extend(_create_family_scenarios("iot_fleet_mgmt", "evaluation", "fleet.target.com", iot_defs))

    return scenarios


def get_benchmark_manifest() -> Dict[str, Any]:
    """Return frozen EXP-0003 benchmark manifest with deterministic SHA-256 digest."""
    scenarios = get_gold_set_scenarios()
    manifest_items = []
    for s in scenarios:
        manifest_items.append({
            "scenario_id": s.scenario_id,
            "name": s.name,
            "app_family": s.app_family,
            "split": s.split,
            "vulnerable_variant": s.vulnerable_variant,
            "category_id": s.category_id,
            "target_asset_id": s.target_asset["asset_id"],
        })

    serialized = json.dumps(manifest_items, sort_keys=True)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    return {
        "dataset_version": "v6_frozen_gold_v3_clean",
        "dataset_hash": f"sha256:{digest}",
        "total_scenarios": len(scenarios),
        "split_definition": {
            "development_families": ["saas_billing", "ecommerce_orders"],
            "validation_families": ["identity_provider", "document_collaboration"],
            "evaluation_families": ["healthcare_portal", "iot_fleet_mgmt"],
        },
        "scenarios": manifest_items,
        "budget_tiers": [BudgetTier.LOW, BudgetTier.MEDIUM, BudgetTier.HIGH],
    }


def get_exp0002_scenarios() -> List[EvaluationScenario]:
    """Historical preserved EXP-0002 scenario suite (N=7)."""
    return get_gold_set_scenarios()[:7]
