"""Deterministic synthetic application state machine for controlled benchmark evaluation.

Supports 6 distinct application families:
1. saas_billing
2. ecommerce_orders
3. identity_provider
4. document_collaboration
5. healthcare_portal
6. iot_fleet_mgmt
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class SyntheticPrincipal:
    """
    Deterministic identity binding for synthetic evaluation.
    Allows simulator and application to bind callers securely without leaking raw credentials.
    """
    identity_id: str
    is_authenticated: bool = True


class SyntheticApp:
    """
    A deterministic API state machine (NOT an LLM) modeling users, resources,
    roles, and state transitions to simulate target backend logic.
    """

    def __init__(
        self,
        app_id: str,
        vulnerable_variant: bool = True,
        simulate_server_error: bool = False,
    ) -> None:
        self.app_id = app_id
        self.vulnerable_variant = vulnerable_variant
        self.simulate_server_error = simulate_server_error

        # Users and identities
        self.users: Dict[str, Dict[str, Any]] = {
            "user_a": {"id": "user_a", "tenant": "org_a", "role": "customer", "token": "token_a"},
            "user_b": {"id": "user_b", "tenant": "org_b", "role": "customer", "token": "token_b"},
            "admin_user": {"id": "admin_user", "tenant": "system", "role": "admin", "token": "token_admin"},
            "tenant_alice": {"id": "tenant_alice", "tenant": "org_alice", "role": "customer", "token": "token_alice"},
            "tenant_bob": {"id": "tenant_bob", "tenant": "org_bob", "role": "customer", "token": "token_bob"},
        }

        # 1. SaaS Billing state
        self.invoices: Dict[str, Dict[str, Any]] = {
            "INV-100": {"id": "INV-100", "owner": "user_a", "tenant": "org_a", "amount": 250.00, "status": "ISSUED"},
            "INV-200": {"id": "INV-200", "owner": "user_b", "tenant": "org_b", "amount": 99.00, "status": "ISSUED"},
            "INV-9001": {"id": "INV-9001", "owner": "tenant_alice", "tenant": "org_alice", "amount": 500.00, "status": "ISSUED"},
        }
        self.subscriptions: Dict[str, Dict[str, Any]] = {
            "SUB-100": {"id": "SUB-100", "owner": "user_a", "tenant": "org_a", "plan": "enterprise", "status": "ACTIVE"},
            "SUB-200": {"id": "SUB-200", "owner": "user_b", "tenant": "org_b", "plan": "basic", "status": "ACTIVE"},
            "SUB-9001": {"id": "SUB-9001", "owner": "tenant_alice", "tenant": "org_alice", "plan": "enterprise", "status": "ACTIVE"},
        }

        # 2. E-commerce Orders state
        self.orders: Dict[str, Dict[str, Any]] = {
            "ORD-001": {"id": "ORD-001", "owner": "user_a", "state": "CREATED", "amount": 50.0},
            "ORD-002": {"id": "ORD-002", "owner": "user_a", "state": "PAID", "amount": 120.0},
        }

        # 3. Document Collaboration state
        self.documents: Dict[str, Dict[str, Any]] = {
            "DOC-100": {"id": "DOC-100", "owner": "user_a", "tenant": "org_a", "title": "Confidential Q3 Plan", "classified": True},
            "DOC-200": {"id": "DOC-200", "owner": "user_b", "tenant": "org_b", "title": "Team Notes", "classified": False},
        }
        self.approvals: Dict[str, Dict[str, Any]] = {
            "APP-100": {"id": "APP-100", "owner": "user_a", "state": "DRAFT", "approved_by": None},
        }

        # 4. Healthcare Portal state
        self.records: Dict[str, Dict[str, Any]] = {
            "REC-100": {"id": "REC-100", "patient": "user_a", "diagnosis": "Hypertension", "archived": False},
            "REC-ARCHIVED-100": {"id": "REC-ARCHIVED-100", "patient": "user_a", "diagnosis": "Resolved Sprain", "archived": True},
        }
        self.prescriptions: Dict[str, Dict[str, Any]] = {
            "RX-100": {"id": "RX-100", "patient": "user_a", "medication": "Lisinopril 10mg", "refills": 3},
        }

        # 5. IoT Fleet Management state
        self.devices: Dict[str, Dict[str, Any]] = {
            "DEV-100": {"id": "DEV-100", "owner": "user_a", "fleet": "fleet_alpha", "status": "ONLINE", "firmware": "v2.1.0"},
            "DEV-200": {"id": "DEV-200", "owner": "user_b", "fleet": "fleet_beta", "status": "ONLINE", "firmware": "v2.1.0"},
        }

    def handle_request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        authenticated_principal: Optional[SyntheticPrincipal] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        """
        Deterministic request handler implementing authentication, authorization,
        and state-transition logic across all application families.
        """
        if self.simulate_server_error:
            return 500, {"error": "Internal server error occurred"}

        headers = headers or {}
        auth_header = headers.get("Authorization", "")
        caller = None

        # 1. Preferred: Typed internal authenticated principal (zero secret leakage)
        if authenticated_principal is not None:
            if authenticated_principal.is_authenticated and authenticated_principal.identity_id:
                # Authoritative resolution strictly against registered users database.
                # Role and tenant are derived from application state, preventing privilege escalation.
                caller = self.users.get(authenticated_principal.identity_id)
        # 2. Backwards compatibility: Header token fallback
        elif auth_header:
            for u_id, u_data in self.users.items():
                if u_data["token"] in auth_header:
                    caller = u_data
                    break

        # ==========================================
        # PUBLIC / NEGATIVE CONTROL ENDPOINTS (All 200 OK)
        # ==========================================
        if "openid-configuration" in path or "/jwks" in path:
            return 200, {"issuer": "https://idp.target.com", "keys": [{"kty": "RSA", "kid": "key1"}]}
        if "/pricing" in path or "/catalog" in path or "/products" in path or "/templates" in path or "/clinic-hours" in path or "/status" in path:
            return 200, {"public_catalog": [{"item": "standard", "accessible": True}]}

        # Protected routes require valid authentication
        if not caller:
            return 401, {"error": "Authentication required"}

        # ==========================================
        # 1. SAAS BILLING
        # ==========================================
        if "/invoices/" in path and method == "GET":
            inv_id = path.split("/")[-1]
            inv = self.invoices.get(inv_id)
            if not inv:
                return 404, {"error": "Invoice not found"}
            if self.vulnerable_variant:
                return 200, {"invoice": inv}
            return (200, {"invoice": inv}) if inv["owner"] == caller["id"] or caller["role"] == "admin" else (403, {"error": "Access forbidden: caller does not own this invoice"})

        if "/subscriptions/" in path and method == "GET":
            sub_id = path.split("/")[-1]
            sub = self.subscriptions.get(sub_id)
            if not sub:
                return 404, {"error": "Subscription not found"}
            if self.vulnerable_variant:
                return 200, {"subscription": sub}
            return (200, {"subscription": sub}) if sub["owner"] == caller["id"] or caller["role"] == "admin" else (403, {"error": "Tenant isolation violation"})

        # ==========================================
        # 2. E-COMMERCE ORDERS
        # ==========================================
        if "/orders/" in path and "/pay" in path and method == "POST":
            ord_id = path.split("/")[4]
            order = self.orders.get(ord_id)
            if not order:
                return 404, {"error": "Order not found"}
            order["state"] = "PAID"
            return 200, {"order": order, "status": "Payment processed"}

        if "/orders/" in path and "/refund" in path and method == "POST":
            ord_id = path.split("/")[4]
            order = self.orders.get(ord_id)
            if not order:
                return 404, {"error": "Order not found"}
            if self.vulnerable_variant:
                order["state"] = "REFUNDED"
                return 200, {"order": order, "status": "Refund issued without payment"}
            if order["state"] != "PAID":
                return 400, {"error": "Cannot refund an unpaid order"}
            order["state"] = "REFUNDED"
            return 200, {"order": order, "status": "Refund issued"}

        if "/orders/" in path and "/ship" in path and method == "POST":
            ord_id = path.split("/")[4]
            order = self.orders.get(ord_id)
            if not order:
                return 404, {"error": "Order not found"}
            if self.vulnerable_variant:
                order["state"] = "SHIPPED"
                return 200, {"order": order, "status": "Order shipped without payment"}
            if order["state"] != "PAID":
                return 400, {"error": "Order must be PAID before shipping"}
            order["state"] = "SHIPPED"
            return 200, {"order": order, "status": "Order shipped"}

        # ==========================================
        # 3. IDENTITY PROVIDER
        # ==========================================
        if "/users/" in path and "/roles" in path and method == "POST":
            if self.vulnerable_variant:
                return 200, {"status": "Role updated", "assigned_role": "admin"}
            if caller.get("role") != "admin":
                return 403, {"error": "Admin role required"}
            return 200, {"status": "Role updated by admin"}

        if "/users/" in path and "/mfa" in path and method == "DELETE":
            if self.vulnerable_variant:
                return 200, {"status": "MFA disabled"}
            if caller.get("role") != "admin" and caller["id"] != path.split("/")[4]:
                return 403, {"error": "Unauthorized MFA modification"}
            return 200, {"status": "MFA disabled"}

        # ==========================================
        # 4. DOCUMENT COLLABORATION
        # ==========================================
        if "/docs/" in path and "/export" in path and method == "GET":
            doc_id = path.split("/")[4]
            doc = self.documents.get(doc_id)
            if not doc:
                return 404, {"error": "Document not found"}
            if self.vulnerable_variant:
                return 200, {"document": doc}
            return (200, {"document": doc}) if doc["owner"] == caller["id"] or caller["role"] == "admin" else (403, {"error": "Document ownership required"})

        if "/approvals/" in path and "/publish" in path and method == "POST":
            app_id = path.split("/")[4]
            approval = self.approvals.get(app_id)
            if not approval:
                return 404, {"error": "Approval request not found"}
            if self.vulnerable_variant:
                approval["state"] = "PUBLISHED"
                return 200, {"approval": approval, "status": "Published without review"}
            if approval["state"] != "APPROVED":
                return 400, {"error": "Document must be in APPROVED state prior to publication"}
            approval["state"] = "PUBLISHED"
            return 200, {"approval": approval, "status": "Published"}

        # ==========================================
        # 5. HEALTHCARE PORTAL
        # ==========================================
        if "/records/" in path and method == "GET":
            rec_id = path.split("/")[-1]
            rec = self.records.get(rec_id)
            if not rec:
                return 404, {"error": "Medical record not found"}
            if self.vulnerable_variant:
                return 200, {"record": rec}
            if rec.get("archived", False):
                return 400, {"error": "Archived records require compliance officer authorization"}
            return (200, {"record": rec}) if rec["patient"] == caller["id"] or caller["role"] == "admin" else (403, {"error": "Patient privacy violation"})

        if "/prescriptions/" in path and method == "GET":
            rx_id = path.split("/")[-1]
            rx = self.prescriptions.get(rx_id)
            if not rx:
                return 404, {"error": "Prescription not found"}
            if self.vulnerable_variant:
                return 200, {"prescription": rx}
            return (200, {"prescription": rx}) if rx["patient"] == caller["id"] or caller["role"] == "admin" else (403, {"error": "Prescription access denied"})

        # ==========================================
        # 6. IOT FLEET MANAGEMENT
        # ==========================================
        if "/devices/" in path and "/command" in path and method == "POST":
            dev_id = path.split("/")[4]
            dev = self.devices.get(dev_id)
            if not dev:
                return 404, {"error": "Device not found"}
            if self.vulnerable_variant:
                return 200, {"status": "Command dispatched", "device_id": dev_id}
            return (200, {"status": "Command dispatched", "device_id": dev_id}) if dev["owner"] == caller["id"] or caller["role"] == "admin" else (403, {"error": "Fleet command authorization denied"})

        if "/devices/" in path and "/telemetry" in path and method == "GET":
            dev_id = path.split("/")[4]
            dev = self.devices.get(dev_id)
            if not dev:
                return 404, {"error": "Device not found"}
            if self.vulnerable_variant:
                return 200, {"telemetry": {"device_id": dev_id, "battery": 98.4, "temp_c": 34.2}}
            return (200, {"telemetry": {"device_id": dev_id, "battery": 98.4, "temp_c": 34.2}}) if dev["owner"] == caller["id"] or caller["role"] == "admin" else (403, {"error": "Telemetry access denied"})

        return 404, {"error": f"Endpoint not found: {method} {path}"}
