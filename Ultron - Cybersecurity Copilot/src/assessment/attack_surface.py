"""Attack Surface Mapping Engine for M6 Authorized Security Assessments.

Enforces:
1. Multi-dimensional synthesis of discovered assets, services, endpoints,
   auth boundaries, and data flows from passive telemetry.
2. INVARIANT: Interesting != Vulnerable. An endpoint or parameter being
   classified as INTERESTING or HYPOTHESIS_EXISTS does NOT imply vulnerability.
3. Explicit state progression: UNKNOWN -> OBSERVED -> INTERESTING ->
   HYPOTHESIS_EXISTS -> VALIDATION_REQUIRED -> VALIDATED (human verified) / NOT_VULNERABLE.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field
from src.assessment.models import (
    AssetRecord,
    AttackSurfaceState,
    CanonicalObservation,
    ObservationType,
)
from src.assessment.assets import AssetGraph


class AttackSurfaceNode(BaseModel):
    """Component node within the mapped attack surface."""
    node_id: str
    asset_id: str
    canonical_identifier: str
    node_type: str  # ENDPOINT, SERVICE, AUTH_BOUNDARY, ADMIN_INTERFACE, HEADER, COOKIE
    state: AttackSurfaceState = AttackSurfaceState.OBSERVED
    title: str
    properties: Dict[str, Any] = Field(default_factory=dict)
    associated_observations: List[str] = Field(default_factory=list)
    associated_hypotheses: List[str] = Field(default_factory=list)
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AttackSurfaceMap:
    """Aggregated attack surface map for an assessment."""

    def __init__(self, assessment_id: str) -> None:
        self.assessment_id = assessment_id
        self.nodes: Dict[str, AttackSurfaceNode] = {}
        self.technologies: Set[str] = set()
        self.exposed_services: List[Dict[str, Any]] = []
        self.endpoints: List[Dict[str, Any]] = []
        self.auth_mechanisms: List[Dict[str, Any]] = []
        self.admin_interfaces: List[Dict[str, Any]] = []
        self.interesting_headers: List[Dict[str, Any]] = []
        self.cookies: List[Dict[str, Any]] = []

    def process_observations(
        self,
        observations: List[CanonicalObservation],
        asset_graph: Optional[AssetGraph] = None,
    ) -> None:
        """
        Synthesizes canonical observations into structured attack surface nodes.
        Strictly deterministic.
        """
        for obs in observations:
            norm = obs.normalized_data
            target = norm.get("target_identifier", obs.asset_id)

            # 1. Process HTTP requests/responses (Endpoints, Headers, Cookies, Admin interfaces)
            if obs.observation_type in (ObservationType.HTTP_REQUEST, ObservationType.HTTP_RESPONSE):
                url = norm.get("url", "")
                path = norm.get("path", "")
                method = norm.get("method", "GET")
                status = norm.get("status_code", 200)

                if url or path:
                    endpoint_key = f"{method}:{url or path}"
                    node_id = f"ASN-{hashlib.sha256(endpoint_key.encode('utf-8')).hexdigest()[:12].upper()}"

                    is_admin = any(k in (url or path).lower() for k in ("/admin", "/manage", "/internal", "/dashboard", "/actuator"))
                    initial_state = AttackSurfaceState.INTERESTING if is_admin else AttackSurfaceState.OBSERVED

                    if node_id not in self.nodes:
                        self.nodes[node_id] = AttackSurfaceNode(
                            node_id=node_id,
                            asset_id=obs.asset_id,
                            canonical_identifier=url or path,
                            node_type="ENDPOINT",
                            state=initial_state,
                            title=f"HTTP Endpoint [{method}] {path or url}",
                            properties={
                                "method": method,
                                "path": path,
                                "status_code": status,
                                "is_admin_candidate": is_admin,
                            },
                            associated_observations=[obs.observation_id],
                        )
                        self.endpoints.append({"method": method, "endpoint": path or url, "is_admin": is_admin})
                        if is_admin:
                            self.admin_interfaces.append({"endpoint": path or url, "observation_id": obs.observation_id})
                    else:
                        node = self.nodes[node_id]
                        if obs.observation_id not in node.associated_observations:
                            node.associated_observations.append(obs.observation_id)

                # Inspect Headers (Auth, Cookies, CORS, Security headers)
                headers = norm.get("request_headers", {}) or norm.get("headers", {}) or {}
                resp_headers = norm.get("response_headers", {}) or {}
                all_headers = {**headers, **resp_headers}

                for h_name, h_val in all_headers.items():
                    h_lower = h_name.lower()
                    if h_lower in ("authorization", "x-api-key", "bearer"):
                        self.auth_mechanisms.append({
                            "type": "HEADER_TOKEN",
                            "header": h_name,
                            "target": target,
                        })
                    if h_lower == "set-cookie" or h_lower == "cookie":
                        self.cookies.append({
                            "header": h_name,
                            "target": target,
                            "has_httponly": "httponly" in h_val.lower(),
                            "has_secure": "secure" in h_val.lower(),
                        })
                    if h_lower in ("server", "x-powered-by"):
                        self.technologies.add(h_val)

            # 2. Process Security Tool output (nmap ports, httpx tech)
            elif obs.observation_type == ObservationType.TOOL_OUTPUT:
                techs = norm.get("technologies", [])
                for t in techs:
                    self.technologies.add(str(t))
                if norm.get("webserver"):
                    self.technologies.add(str(norm.get("webserver")))

                ports = norm.get("ports", [])
                for p in ports:
                    p_id = f"ASN-PORT-{target}-{p}"
                    self.exposed_services.append({"target": target, "port": p})
                    if p_id not in self.nodes:
                        self.nodes[p_id] = AttackSurfaceNode(
                            node_id=p_id,
                            asset_id=obs.asset_id,
                            canonical_identifier=f"{target}:{p}",
                            node_type="SERVICE",
                            state=AttackSurfaceState.OBSERVED,
                            title=f"Exposed Port {p} on {target}",
                            properties={"port": p},
                            associated_observations=[obs.observation_id],
                        )

    def attach_hypothesis(self, node_id: str, hypothesis_id: str) -> None:
        """Transitions node state to HYPOTHESIS_EXISTS and links hypothesis."""
        if node_id in self.nodes:
            node = self.nodes[node_id]
            node.state = AttackSurfaceState.HYPOTHESIS_EXISTS
            if hypothesis_id not in node.associated_hypotheses:
                node.associated_hypotheses.append(hypothesis_id)
            node.updated_at = datetime.now(timezone.utc).isoformat()

    def export_summary(self) -> Dict[str, Any]:
        """Provides a complete, auditable snapshot of the attack surface."""
        return {
            "assessment_id": self.assessment_id,
            "total_nodes": len(self.nodes),
            "discovered_technologies": sorted(list(self.technologies)),
            "exposed_services_count": len(self.exposed_services),
            "endpoints_count": len(self.endpoints),
            "admin_interfaces_count": len(self.admin_interfaces),
            "auth_mechanisms_count": len(self.auth_mechanisms),
            "state_distribution": {
                state.value: sum(1 for n in self.nodes.values() if n.state == state)
                for state in AttackSurfaceState
            },
            "nodes": [n.model_dump() for n in self.nodes.values()],
        }
