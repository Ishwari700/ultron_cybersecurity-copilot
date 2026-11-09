"""Headless deterministic simulator executing experiment proposals against synthetic apps."""

from typing import Any, Dict, Optional, Tuple
from src.evidence.models import CanonicalEvidence, EpistemicCertainty, EvidenceTrust
from src.eval.synthetic_app import SyntheticApp, SyntheticPrincipal
from src.hypothesis.experiment import ExperimentProposal, MutationClass


class ExperimentExecutionResult:
    """Result of executing an experiment proposal in the simulator."""
    def __init__(
        self,
        observation_type: str, # SUPPORTING | CONTRADICTING | UNRESOLVED
        status_code: int,
        response_data: Dict[str, Any],
        discriminative: bool,
        evidence_item: CanonicalEvidence,
    ) -> None:
        self.observation_type = observation_type
        self.status_code = status_code
        self.response_data = response_data
        self.discriminative = discriminative
        self.evidence_item = evidence_item


class HeadlessSimulator:
    """
    Deterministic state-machine test execution engine.
    Validates and runs experiment proposals against controlled synthetic applications
    to generate new ground-truth OBSERVED evidence automatically.
    """

    def execute_experiment(
        self,
        experiment: ExperimentProposal,
        app: SyntheticApp,
        scope_decision_id: Optional[str] = "SCOPE-SIM-001",
        target_path: Optional[str] = None,
        target_method: Optional[str] = None,
    ) -> ExperimentExecutionResult:
        """Execute experiment proposal against the deterministic synthetic app."""
        discriminative = experiment.is_discriminative()

        # Construct request according to mutation class or custom path/method
        method = target_method or "GET"
        path = target_path or "/api/v1/invoices/INV-100"
        headers: Dict[str, str] = {}
        data: Optional[Dict[str, Any]] = None

        actor_id: Optional[str] = None
        is_authenticated: bool = True

        if target_path and target_method:
            method = target_method
            path = target_path
            actor_id = experiment.actor_identity_id or ("user_b" if experiment.mutation_class == MutationClass.CROSS_IDENTITY_REPLAY else "user_a")
            if experiment.mutation_class == MutationClass.UNAUTHENTICATED_ACCESS:
                is_authenticated = False
                actor_id = None
        elif experiment.mutation_class == MutationClass.CROSS_IDENTITY_REPLAY:
            method = "GET"
            actor_id = experiment.actor_identity_id or "user_b"
            path = "/api/v1/invoices/INV-100"

        elif experiment.mutation_class == MutationClass.STEP_SKIPPING:
            method = "POST"
            actor_id = experiment.actor_identity_id or "user_a"
            path = "/api/v1/orders/ORD-001/refund"

        elif experiment.mutation_class == MutationClass.PRIVILEGE_ELEVATION:
            method = "POST"
            actor_id = experiment.actor_identity_id or "user_a"
            path = "/api/v1/users/user_a/roles"
            data = {"role": "admin"}

        elif experiment.mutation_class == MutationClass.UNAUTHENTICATED_ACCESS:
            method = "GET"
            path = target_path or "/api/v1/invoices/INV-100"
            is_authenticated = False
            actor_id = None
        else:
            actor_id = experiment.actor_identity_id or "user_a"

        # Deterministic identity binding via typed SyntheticPrincipal
        principal = (
            SyntheticPrincipal(identity_id=actor_id, is_authenticated=is_authenticated)
            if is_authenticated and actor_id
            else None
        )

        # Header contains only safe identity marker; raw tokens never leak into evidence or logs
        if principal:
            headers["Authorization"] = f"Bearer [REDACTED_SIM_TOKEN_FOR_{actor_id}]"

        # Execute request on deterministic state machine with typed principal
        status, resp_data = app.handle_request(
            method=method,
            path=path,
            headers=headers,
            data=data,
            authenticated_principal=principal,
        )

        # Discriminative outcome matching
        if status == 200:
            observation_type = "SUPPORTING"
            stmt = f"Experiment executed {method} {path} returned HTTP 200 with data: {resp_data}"
        elif status in (400, 403, 404):
            observation_type = "CONTRADICTING"
            stmt = f"Experiment executed {method} {path} was blocked with HTTP {status}: {resp_data}"
        else:
            observation_type = "UNRESOLVED"
            stmt = f"Experiment executed {method} {path} returned unexpected HTTP {status}"

        # Generate new CanonicalEvidence record
        fact_id = CanonicalEvidence.compute_fact_id("headless_simulator", stmt)
        asset_id = CanonicalEvidence.compute_asset_id(method, "api.target.com", path)

        new_evidence = CanonicalEvidence(
            fact_id=fact_id,
            certainty=EpistemicCertainty.OBSERVED, # Experiment generates OBSERVED ground fact!
            statement=stmt,
            source_tool="headless_simulator",
            trust=EvidenceTrust.UNTRUSTED,
            scope_decision_id=scope_decision_id,
            asset_id=asset_id,
            http_method=method,
            host="api.target.com",
            raw_path=path,
            normalized_path=path,
            response_status=status,
            response_body_summary=str(resp_data),
        )

        return ExperimentExecutionResult(
            observation_type=observation_type,
            status_code=status,
            response_data=resp_data,
            discriminative=discriminative,
            evidence_item=new_evidence,
        )
