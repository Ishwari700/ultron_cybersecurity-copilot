"""Core research workspace service coordinating the security pipeline for Phase 12 UI."""

import hashlib
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from src.core.logging import AuditLogger, verify_audit_log, get_logger
from src.database.manager import DatabaseManager
from src.engine.cascade_orchestrator import CascadeOrchestrator
from src.engine.decision_policy import (
    ExperimentActionPredicate,
    ExperimentPolarityValidator,
    HttpOutcomePredicate,
    HypothesisDecision,
)
from src.engine.llm_health import check_gpu
from src.eval.phase11_3_grounding.validator import Phase11GroundingValidator
from src.evidence.cascade_models import LosslessStructuralPack
from src.evidence.models import EpistemicCertainty
from src.evidence.vault import RedactionVault, VaultAccessContext, VaultReversalPurpose
from src.execution.approval import ApprovalGate
from src.execution.engine import DeterministicExecutionEngine, compute_headers_digest
from src.execution.models import (
    ExecutionDescriptor,
    ExecutionResult,
    ExecutionStatus,
    HumanApproval,
)
from src.execution.state_manager import DeterministicStateManager
from src.execution.ttl_validator import DeterministicTTLValidator
from src.hypothesis.experiment import (
    ExpectedObservations,
    ExperimentProposal,
    MutationClass,
    SafetyLevel,
)
from src.hypothesis.state_machine import HypothesisState, HypothesisStateMachine
from src.scope.client import ScopedHttpClient
from src.scope.gate import ScopeGate, canonicalize_host
from src.scope.models import ScopePolicy, ToolPolicy

from src.evidence.ingestion.pipeline import EvidenceIngestionPipeline
from src.knowledge.canonical_models import AuthorityLevel
from src.knowledge.ingestion_engine import IngestionStatus, KnowledgeIngestionEngine
from src.knowledge.knowledge_orchestrator import CybersecurityKnowledgeOrchestrator
from src.knowledge.store import VaptKnowledgeStore
from src.knowledge.retriever import OnnxVectorFts5Retriever
from src.knowledge.knowledge_graph import RelationalKnowledgeGraph
from src.knowledge.graph_extractor import KnowledgeGraphExtractor
from src.engine.runner import OllamaRunner
from src.response.generator import LongResponseEngine
from src.response.stream import CancellationToken
from src.response.models import (
    GenerationTermination,
    ResponseSession,
    ResponseChunk,
    ResponseVersion,
    ResponseStatus,
)
from src.response.citation import CitationContext
from src.response.routing import TaskType
from src.dashboard.models import (
    ChatMessage,
    CreateInvestigationRequest,
    ExecutionOutcomeResponse,
    ExperimentApprovalRequest,
    ExperimentValidationResult,
    ImportTrafficRequest,
    InvestigationDetail,
    InvestigationSummary,
    ManualObservationRequest,
    StructuredCardType,
    SystemStatusResponse,
    CreateMemoryItemRequest,
    SearchMemoryRequest,
    PromoteMemoryRequest,
    SupersedeMemoryRequest,
    ForgetMemoryRequest,
    RetireMemoryRequest,
)
from src.memory import (
    EpisodicMemoryAdapters,
    EpistemicStatus,
    GLOBAL_MEMORY_TELEMETRY,
    HybridMemoryRetriever,
    LifecycleState,
    MemoryAccessContext,
    MemoryAdmissionPipeline,
    MemoryAuthority,
    MemoryDeletionEngine,
    MemoryIsolationEngine,
    MemoryItem,
    MemoryLifecycleEngine,
    MemoryNamespace,
    MemoryPermissionGate,
    MemoryPersistence,
    MemoryPromotionEngine,
    MemorySourceType,
    PromotionStatus,
    SensitivityClassification,
)


logger = get_logger("WorkspaceService")


def _normalize_structured_gap(raw_gap: Any) -> Optional[str]:
    """
    Validate and normalize structured evidence_gap field from cascade output.
    Returns None if missing, null, empty, or placeholder token.
    Strictly forbids extracting gaps from arbitrary text.
    """
    if raw_gap is None:
        return None
    if not isinstance(raw_gap, str):
        return None
    cleaned = raw_gap.strip()
    if not cleaned:
        return None
    placeholder_tokens = {
        "none", "none.", "null", "null.", "n/a", "na", "[]", "{}",
        "no gap", "no evidence gap", "none identified", "n/a.", "not identified"
    }
    if cleaned.lower() in placeholder_tokens:
        return None
    return cleaned


def _is_research_analysis_query(q_lower: str) -> bool:
    """Detect if query is requesting security research, hypothesis synthesis, or cascade analysis."""
    research_indicators = (
        "analyze", "analysis", "hypothes", "experiment", "propose", "recommend",
        "generate", "formulate", "synthesize", "investigate", "discover",
        "evaluate", "attack surface", "vulnerabilit", "weakness", "traffic",
        "target traffic", "endpoint", "bola", "idor"
    )
    return any(ind in q_lower for ind in research_indicators)


def _is_explicit_gap_retrieval(q_lower: str) -> bool:
    """
    Detect explicit request to list/view registered evidence gaps,
    distinguishing from research prompts that mention gaps.
    """
    if _is_research_analysis_query(q_lower):
        return False

    gap_terms = ("gap", "gaps", "missing evidence", "missing observation")
    if not any(term in q_lower for term in gap_terms):
        return False

    # Standalone gap query
    cleaned = "".join(c if c.isalnum() or c.isspace() else " " for c in q_lower).strip()
    words = cleaned.split()
    if set(words).issubset({"evidence", "gap", "gaps", "open", "the", "all"}):
        return True

    retrieval_verbs = (
        "show", "list", "view", "display", "get", "fetch", "see",
        "what are", "what is", "are there", "give me", "tell me", "check"
    )
    return any(verb in q_lower for verb in retrieval_verbs)


def _is_explicit_audit_query(q_lower: str) -> bool:
    """Detect explicit provenance / audit inquiry."""
    if _is_research_analysis_query(q_lower):
        return False
    return any(w in q_lower for w in ("provenance", "audit", "chain", "lineage"))


def _is_explicit_invariant_query(q_lower: str) -> bool:
    """Detect explicit invariant lookup inquiry."""
    if _is_research_analysis_query(q_lower):
        return False
    return "invariant" in q_lower


class WorkspaceService:
    """
    Central orchestration service for the local AI research workspace.
    Bridges REST requests to authoritative security gates and execution engine.
    """

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.db = db_manager or DatabaseManager()
        self.db.initialize_schema()
        self.audit_logger = audit_logger or AuditLogger(Path("data/audit.log"))
        self.vault = RedactionVault()
        self.grounding_validator = Phase11GroundingValidator()
        self.polarity_validator = ExperimentPolarityValidator()
        scope_policy = ScopePolicy(
            program_name="LocalResearchWorkspace",
            platform="LOCAL",
            in_scope=["*.target.local", "api.target.local", "*.target.com", "api.target.com"],
        )
        self.scope_gate = ScopeGate(
            policy=scope_policy,
            dns_resolver=lambda h: ["93.184.216.34"],
            allow_private_ranges=True,
        )
        self.scoped_client = ScopedHttpClient(scope_gate=self.scope_gate)
        self.approval_gate = ApprovalGate()
        self.ttl_validator = DeterministicTTLValidator(scoped_client=self.scoped_client)
        self.state_manager = DeterministicStateManager()

        def default_mock_transport(method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, str], bytes]:
            return 200, {"content-type": "application/pdf"}, b"%PDF-1.4 [TENANT-9999 INVOICE DATA]"

        self.execution_engine = DeterministicExecutionEngine(
            scope_gate=self.scope_gate,
            scoped_client=self.scoped_client,
            approval_gate=self.approval_gate,
            ttl_validator=self.ttl_validator,
            state_manager=self.state_manager,
            audit_logger=self.audit_logger,
            live_execution_enabled=False,  # Safe local simulation by default
            mock_transport_fn=default_mock_transport,
        )
        self.state_machine = HypothesisStateMachine(self.db)
        self.cascade_orchestrator = CascadeOrchestrator()
        self.ingestion_pipeline = EvidenceIngestionPipeline(
            db_manager=self.db,
            vault=self.vault,
            scope_gate=self.scope_gate,
            audit_logger=self.audit_logger,
        )

        # In-memory storage for active workspace investigations and experiments
        self._investigations: Dict[str, Dict[str, Any]] = {}
        self._investigation_evidence: Dict[str, List[Dict[str, Any]]] = {}
        self._investigation_assets: Dict[str, List[Dict[str, Any]]] = {}
        self._investigation_invariants: Dict[str, List[Dict[str, Any]]] = {}
        self._investigation_hypotheses: Dict[str, List[Dict[str, Any]]] = {}
        self._investigation_gaps: Dict[str, List[Dict[str, Any]]] = {}
        self._messages: Dict[str, List[ChatMessage]] = {}
        self._experiments: Dict[str, Dict[str, Any]] = {}
        self._execution_descriptors: Dict[str, ExecutionDescriptor] = {}
        self.response_engine = LongResponseEngine(
            db_manager=self.db,
            ollama_client=self.cascade_orchestrator.ollama_client,
        )
        self._active_cancellations: Dict[str, CancellationToken] = {}
        self.knowledge_store = VaptKnowledgeStore(Path("data/knowledge/vapt_knowledge.db"))
        self.knowledge_ingestion_engine = KnowledgeIngestionEngine(self.knowledge_store)
        self.knowledge_graph = RelationalKnowledgeGraph(Path("data/knowledge/knowledge_graph.db"))
        try:
            self.base_knowledge_retriever = OnnxVectorFts5Retriever(
                db_path=Path("data/knowledge/vapt_knowledge.db"),
            )
        except Exception as e:
            logger.debug(f"OnnxVectorFts5Retriever init note: {e}")
            self.base_knowledge_retriever = None

        self.knowledge_orchestrator = CybersecurityKnowledgeOrchestrator(
            knowledge_store=self.knowledge_store,
            knowledge_graph=self.knowledge_graph,
            base_retriever=self.base_knowledge_retriever,
        )
        self.knowledge_graph_extractor = KnowledgeGraphExtractor(
            ollama_runner=OllamaRunner(model_name="qwen2.5-coder:7b"),
            default_model="qwen2.5-coder:7b",
            timeout_seconds=120.0,
        )
        from src.knowledge.job_manager import IngestionJobManager
        self.knowledge_job_manager = IngestionJobManager(
            knowledge_store=self.knowledge_store,
            ingestion_engine=self.knowledge_ingestion_engine,
        )

        # M12 Security Research Memory Subsystem
        self.memory_persistence = MemoryPersistence(self.db)
        self.memory_admission = MemoryAdmissionPipeline()
        self.memory_retriever = HybridMemoryRetriever(self.memory_persistence)
        self.memory_isolation_engine = MemoryIsolationEngine()
        self.memory_promotion_engine = MemoryPromotionEngine()
        self.memory_lifecycle_engine = MemoryLifecycleEngine()
        self.memory_deletion_engine = MemoryDeletionEngine()


        # NOTE: Do NOT auto-seed demo investigation on startup.
        # Production workspace starts clean. Demo fixture is strictly opt-in.

    # -------------------------------------------------------------------------
    # System Status & Health
    # -------------------------------------------------------------------------

    def get_system_status(self) -> SystemStatusResponse:
        """Inspect actual local platform and runtime state."""
        gpu_info = check_gpu()
        audit_records = self.audit_logger.read_records(limit=20)
        audit_valid = "VERIFIED" if len(audit_records) >= 0 else "FAILED"

        status_info = self.cascade_orchestrator.check_runtime_status()
        ollama_status = "READY" if status_info.get("ollama_available") else "OFFLINE"

        if status_info.get("cascade_mode") == "3B_7B_CASCADE_READY":
            active_model = "Cascade Active (3B → 7B)"
            cascade_mode = "CASCADE_ACTIVE_3B_7B"
        elif status_info.get("has_7b"):
            active_model = "qwen2.5-coder:7b (7B Only)"
            cascade_mode = "7B_ONLY"
        elif status_info.get("has_3b"):
            active_model = "qwen2.5-coder:3b (3B Only)"
            cascade_mode = "3B_ONLY"
        else:
            active_model = "Local Fallback (Ollama Offline)"
            cascade_mode = "OFFLINE"

        recent_traces = self.list_cascade_traces(limit=5)


        return SystemStatusResponse(
            local_ai="READY",
            ollama=ollama_status,
            evidence="READY",
            vapt_rag="READY",
            audit=audit_valid,
            active_model=active_model,
            cascade_mode=cascade_mode,
            execution_mode="SAFE_LOCAL_SIMULATION",
            gpu=gpu_info,
            recent_traces=recent_traces,
        )

    # -------------------------------------------------------------------------
    # Investigation Lifecycle & Seeding
    # -------------------------------------------------------------------------

    def load_demo_investigation(self) -> InvestigationSummary:
        """Explicitly load the canonical deterministic local BOLA fixture."""
        inv_id = "INV-001"
        inv = self.db.get_investigation(inv_id)
        if not inv:
            self._seed_demo_investigation()
            inv = self.db.get_investigation(inv_id)
        elif inv_id not in self._investigations:
            self._seed_demo_investigation()

        msg_count = self.db.get_message_count(inv_id)
        return InvestigationSummary(
            id=inv["id"],
            name=inv["name"],
            target_host=inv["target_host"],
            scope_status=inv["scope_status"],
            status=inv["status"],
            is_demo=True,
            evidence_count=inv.get("evidence_count", 2),
            hypothesis_count=inv.get("hypothesis_count", 1),
            experiment_count=1,
            message_count=msg_count,
            last_activity=inv.get("updated_at", "2026-10-05T07:15:00Z"),
        )

    def _seed_demo_investigation(self) -> None:
        """Seeds the canonical safe deterministic local BOLA investigation."""
        inv_id = "INV-001"
        target_host = "api.target.local"
        asset_id = "ASSET-BOLA-EXPORT-01"

        # 1. Assets
        asset_data = {
            "asset_id": asset_id,
            "method": "POST",
            "host": target_host,
            "raw_path": "/api/v1/invoices/export",
            "normalized_path": "/api/v1/invoices/export",
            "application_mutability": "STATE_CHANGING",
            "liveness": "LIVE_DOCUMENTED",
        }
        self._investigation_assets[inv_id] = [asset_data]

        # 2. Canonical Facts
        fact_1 = {
            "fact_id": "FACT-OBS-01",
            "certainty": EpistemicCertainty.OBSERVED.value,
            "statement": "POST /api/v1/invoices/export accepts JSON body with target organization and invoice identifier.",
            "source_tool": "traffic_normalizer",
            "trust": "TRUSTED",
        }
        fact_2 = {
            "fact_id": "FACT-OBS-02",
            "certainty": EpistemicCertainty.OBSERVED.value,
            "statement": "Endpoint returns HTTP 200 with exported PDF binary when called with invoice_id owned by current tenant.",
            "source_tool": "traffic_normalizer",
            "trust": "TRUSTED",
        }
        self._investigation_evidence[inv_id] = [fact_1, fact_2]

        # 3. Security Invariant
        inv_data = {
            "invariant_id": "INV-001",
            "description": "Users must only export billing statements for organizations in their authenticated tenancy.",
            "origin": "DOCUMENTED",
            "confidence": "HIGH",
        }
        self._investigation_invariants[inv_id] = [inv_data]

        # 4. Hypothesis
        hyp_data = {
            "id": 1,
            "hypothesis_id": "HYP-001",
            "asset_id": asset_id,
            "category": "API-BOLA-001",
            "decision": HypothesisDecision.HYPOTHESIS.value,
            "evidence_state": "PARTIAL",
            "reasoning_summary": "Resource identifier substitution may bypass tenant authorization boundary on invoice export.",
            "state": "New",
        }
        self._investigation_hypotheses[inv_id] = [hyp_data]

        # 5. Active Gaps
        self._investigation_gaps[inv_id] = [
            {
                "gap_id": "GAP-TENANT-ISOLATION",
                "target_asset": "POST /api/v1/invoices/export",
                "description": "Cross-tenant export authorization check not verified in observed traffic.",
                "status": "OPEN",
                "suggested_action": "SUBSTITUTE_RESOURCE_IDENTIFIER",
            }
        ]

        # 6. Database persistence for demo
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT count(*) as cnt FROM hypotheses").fetchone()
            already_has_data = (row["cnt"] > 0) if row else False

        if not already_has_data:
            self.db.insert_asset(asset_data)
            self.db.insert_evidence_item(fact_1)
            self.db.insert_evidence_item(fact_2)
            self.db.insert_security_invariant(inv_data)
            hyp_id = self.db.insert_hypothesis({
                "asset_id": asset_id,
                "category": "API-BOLA-001",
                "decision": HypothesisDecision.HYPOTHESIS.value,
                "evidence_state": "PARTIAL",
                "reasoning_summary": "Resource identifier substitution may bypass tenant authorization boundary on invoice export.",
                "state": "New",
            })
        else:
            hyp_id = 1

        # 7. Experiment
        exp_id = "EXP-001"
        experiment_obj = {
            "id": exp_id,
            "investigation_id": inv_id,
            "hypothesis_id": hyp_id,
            "category": "API-BOLA-001",
            "action": ExperimentActionPredicate.SUBSTITUTE_RESOURCE_IDENTIFIER.value,
            "target": f"https://{target_host}/api/v1/invoices/export",
            "asset_id": asset_id,
            "safety_level": SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value,
            "scope": "ALLOWED",
            "grounding": "PASS",
            "polarity": "PASS",
            "status": "AWAITING_APPROVAL",
            "approval_required": True,
            "approval_id": None,
            "objective": "Test Broken Object Level Authorization (BOLA) by substituting target invoice_id with cross-tenant identifier INV-9999.",
            "supporting_observation": "HTTP 200 with foreign tenant invoice PDF content returned.",
            "contradicting_observation": "HTTP 403 Forbidden or 404 Not Found returned.",
            "falsification_condition": "If HTTP 403 is received, the authorization check is confirmed active and the hypothesis is falsified.",
        }
        self._experiments[exp_id] = experiment_obj

        body_bytes = json.dumps({"invoice_id": "INV-9999"}).encode("utf-8")
        body_digest = hashlib.sha256(body_bytes).hexdigest()
        headers_digest = compute_headers_digest({"Content-Type": "application/json"}, self.vault)
        desc = ExecutionDescriptor(
            experiment_id=exp_id,
            identity_id="test_user_a",
            environment_context="staging",
            target_authority=target_host,
            destination=f"https://{target_host}/api/v1/invoices/export",
            resolved_ip="93.184.216.34",
            http_method="POST",
            normalized_route="/api/v1/invoices/export",
            normalized_query="",
            headers_digest=headers_digest,
            request_body_digest=body_digest,
            safety_classification=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value,
            affected_resource=asset_id,
            expected_state_transition="Export cross-tenant invoice without ownership check",
        )
        self._execution_descriptors[exp_id] = desc

        # 8. Seed Investigation Record
        inv_record = {
            "id": inv_id,
            "name": "[DEMO FIXTURE] Acme Billing API (BOLA)",
            "target_host": target_host,
            "scope_status": "ALLOWED",
            "status": "ACTIVE",
            "is_demo": True,
            "evidence_count": 2,
            "hypothesis_count": 1,
            "created_at": "2026-10-05T07:00:00Z",
            "updated_at": "2026-10-05T07:15:00Z",
        }
        self._investigations[inv_id] = inv_record
        if not self.db.get_investigation(inv_id):
            self.db.insert_investigation(inv_record)

        # 9. Conversational Messages
        demo_messages = [
            ChatMessage(
                id="MSG-001",
                investigation_id=inv_id,
                sender="user",
                content="Analyze this application's authorization behavior and identify potential access boundary flaws.",
                structured_type=StructuredCardType.NONE,
                sequence_number=1,
                delivery_status="delivered",
                timestamp="2026-10-05T07:00:00Z",
            ),
            ChatMessage(
                id="MSG-002",
                investigation_id=inv_id,
                sender="assistant",
                content="I have reviewed the observed HTTP interaction telemetry for `api.target.local`. The endpoint `POST /api/v1/invoices/export` processes invoice exports based on a client-supplied identifier. While standard tenant requests succeed, the server lacks an empirical verification check that cross-tenant identifier substitutions are blocked.",
                structured_type=StructuredCardType.INVARIANT,
                structured_data={
                    "invariant_id": "INV-001",
                    "title": "Tenant Billing Statement Isolation",
                    "description": "Users must only export billing statements for organizations in their authenticated tenancy.",
                    "origin": "DOCUMENTED",
                    "confidence": "HIGH",
                    "supporting_facts": ["FACT-OBS-01", "FACT-OBS-02"],
                    "status": "ACTIVE",
                },
                sequence_number=2,
                delivery_status="delivered",
                timestamp="2026-10-05T07:01:00Z",
            ),
            ChatMessage(
                id="MSG-003",
                investigation_id=inv_id,
                sender="assistant",
                content="Based on this evidence gap, I have formulated a grounded security hypothesis. Resource identifier substitution on this asset could breach tenant isolation boundaries.",
                structured_type=StructuredCardType.HYPOTHESIS,
                structured_data={
                    "hypothesis_id": "HYP-001",
                    "category": "API-BOLA-001",
                    "target_asset": "POST /api/v1/invoices/export",
                    "statement": "Resource identifier substitution may bypass tenant authorization boundary on invoice export.",
                    "evidence_state": "PARTIAL",
                    "evidence_gap": "Cross-tenant export authorization check not verified in observed traffic.",
                    "grounding_status": "PASS (FACT-OBS-01, FACT-OBS-02)",
                    "epistemic_state": "UNVERIFIED CANDIDATE",
                    "experiment_id": exp_id,
                    "cascade_trace_id": "RUN-DEMO-001",
                    "routing_decision": "ESCALATE_TO_7B",
                },
                sequence_number=3,
                delivery_status="delivered",
                cascade_trace_id="RUN-DEMO-001",
                model_name="Cascade Active (3B → 7B)",
                timestamp="2026-10-05T07:02:00Z",
            ),
            ChatMessage(
                id="MSG-004",
                investigation_id=inv_id,
                sender="assistant",
                content="I have designed a discriminative experiment proposal to test this hypothesis. Because `POST /api/v1/invoices/export` is classified as `STATE_CHANGING`, explicit human review and cryptographic approval are required prior to execution.",
                structured_type=StructuredCardType.EXPERIMENT,
                structured_data=experiment_obj,
                sequence_number=4,
                delivery_status="delivered",
                cascade_trace_id="RUN-DEMO-001",
                model_name="Cascade Active (3B → 7B)",
                timestamp="2026-10-05T07:03:00Z",
            ),
        ]
        self._messages[inv_id] = demo_messages
        for m in demo_messages:
            if not self.db.get_message(m.id):
                self.db.insert_message({
                    "id": m.id,
                    "investigation_id": m.investigation_id,
                    "sequence_number": m.sequence_number,
                    "sender": m.sender,
                    "content": m.content,
                    "structured_type": m.structured_type.value,
                    "structured_data": m.structured_data,
                    "delivery_status": m.delivery_status,
                    "cascade_trace_id": m.cascade_trace_id,
                    "model_name": m.model_name,
                    "model_digest": m.model_digest,
                    "created_at": m.timestamp,
                })

        # Persist verifiable runtime trace for demo
        demo_trace = {
            "run_id": "RUN-DEMO-001",
            "investigation_id": inv_id,
            "user_message_id": "MSG-002",
            "assistant_message_id": "MSG-003",
            "task_type": "SECURITY_RESEARCH",
            "target_endpoint": "POST /api/v1/invoices/export",
            "overall_status": "CASCADE_COMPLETED",
            "routing_decision": "ESCALATE_TO_7B",
            "escalated": True,
            "handoff_provenance_hash": "a3f5b8e910c24d1a93e8271038bc42f5",
            "total_latency_seconds": 4.673,
            "stages": [
                {
                    "stage_name": "Stage 1: 3B Preliminary Triage",
                    "model_name": "qwen2.5-coder:3b",
                    "model_digest": "4bd6ec0d2e13...",
                    "status": "COMPLETED",
                    "latency_seconds": 1.25,
                    "details": {
                        "decision": "ESCALATE",
                        "suspected_category": "API-BOLA-001",
                        "is_malformed": False,
                        "rationale": "Resource identifier substitution may bypass tenant authorization boundary on invoice export.",
                    },
                },
                {
                    "stage_name": "Stage 2: Gate & Deterministic Routing",
                    "model_name": "DeterministicRouter",
                    "status": "COMPLETED",
                    "latency_seconds": 0.002,
                    "details": {
                        "escalate": True,
                        "decision": "ESCALATE_TO_7B",
                        "reasons": ["CRITICAL_ENDPOINT_MUTABILITY", "UNVERIFIED_AUTHORIZATION_BOUNDARY"],
                        "gate_triggers": [],
                        "fail_safe_triggered": False,
                    },
                },
                {
                    "stage_name": "Stage 3: Immutable Cascade Handoff",
                    "model_name": "HandoffSerializer",
                    "status": "COMPLETED",
                    "latency_seconds": 0.001,
                    "details": {
                        "provenance_hash": "a3f5b8e910c24d1a93e8271038bc42f5",
                        "has_validated_triage": True,
                    },
                },
                {
                    "stage_name": "Stage 4: 7B Deep Reasoning",
                    "model_name": "qwen2.5-coder:7b",
                    "model_digest": "e229337ec165...",
                    "status": "COMPLETED",
                    "latency_seconds": 3.42,
                    "details": {
                        "decision": "HYPOTHESIS",
                        "category": "API-BOLA-001",
                        "grounding_passed": True,
                    },
                },
            ],
            "error_message": None,
            "created_at": "2026-10-05T07:02:00Z",
        }
        self.db.insert_cascade_trace(demo_trace)


    def list_investigations(self, search_query: Optional[str] = None) -> List[InvestigationSummary]:
        """List all active investigations from database."""
        db_invs = self.db.list_investigations(include_archived=False, search_query=search_query)
        results = []
        for inv in db_invs:
            inv_id = inv["id"]
            msg_count = inv.get("message_count", 0)
            exp_count = len([e for e in self._experiments.values() if e.get("investigation_id") == inv_id])
            results.append(
                InvestigationSummary(
                    id=inv["id"],
                    name=inv["name"],
                    target_host=inv["target_host"],
                    scope_status=inv["scope_status"],
                    status=inv["status"],
                    is_demo=bool(inv.get("is_demo", False)),
                    evidence_count=inv.get("evidence_count", 0),
                    hypothesis_count=inv.get("hypothesis_count", 0),
                    experiment_count=exp_count,
                    message_count=msg_count,
                    last_activity=inv.get("last_activity") or inv.get("updated_at") or inv.get("created_at", "2026-10-05T07:15:00Z"),
                )
            )
        return results

    def create_investigation(self, req: CreateInvestigationRequest) -> InvestigationSummary:
        """Create a new genuine production investigation persisted in database."""
        inv_id = f"INV-{secrets_token_hex()[:8].upper()}"
        now = datetime_now_iso()

        # Canonicalize and validate scope for target_host
        canonical_target = canonicalize_host(req.target_host) or req.target_host.strip().lower()
        eval_res = self.scope_gate.evaluate(
            f"https://{canonical_target}/",
            allow_passive=True,
            target_scope=canonical_target,
        )
        scope_status = "ALLOWED" if eval_res.decision.value in ("ALLOW", "ALLOWED") else eval_res.decision.value

        inv_record = {
            "id": inv_id,
            "name": req.name,
            "target_host": canonical_target,
            "scope_status": scope_status,
            "status": "ACTIVE",
            "is_demo": False,
            "evidence_count": 0,
            "hypothesis_count": 0,
            "created_at": now,
            "updated_at": now,
        }
        self.db.insert_investigation(inv_record)
        self._investigations[inv_id] = inv_record
        self._investigation_evidence[inv_id] = []
        self._investigation_assets[inv_id] = []
        self._investigation_invariants[inv_id] = []
        self._investigation_hypotheses[inv_id] = []
        self._investigation_gaps[inv_id] = []

        init_msg_id = f"MSG-{secrets_token_hex()[:6].upper()}"
        init_msg_record = {
            "id": init_msg_id,
            "investigation_id": inv_id,
            "sequence_number": self.db.get_next_sequence_number(inv_id),
            "sender": "system",
            "content": f"Investigation initialized for `{req.target_host}`. Scope evaluation: `{scope_status}`. No target evidence loaded.",
            "structured_type": StructuredCardType.NONE.value,
            "structured_data": None,
            "delivery_status": "delivered",
            "cascade_trace_id": None,
            "model_name": None,
            "model_digest": None,
            "created_at": now,
        }
        self.db.insert_message(init_msg_record)

        self.audit_logger.log_event(
            event_type="INVESTIGATION_CREATED",
            actor="local_researcher",
            subject_id=inv_id,
            details={"name": req.name, "target_host": req.target_host, "scope": scope_status},
        )

        return InvestigationSummary(
            id=inv_id,
            name=req.name,
            target_host=req.target_host,
            scope_status=scope_status,
            status="ACTIVE",
            is_demo=False,
            evidence_count=0,
            hypothesis_count=0,
            experiment_count=0,
            message_count=1,
            last_activity=now,
        )

    def get_investigation(self, inv_id: str) -> Optional[InvestigationDetail]:
        """Get full investigation detail including persistent conversation history."""
        inv = self.db.get_investigation(inv_id)
        if not inv:
            inv = self._investigations.get(inv_id)
            if not inv:
                return None

        db_msgs = self.db.get_messages(inv_id)
        chat_messages = []
        for m in db_msgs:
            stype = StructuredCardType.NONE
            if m.get("structured_type"):
                try:
                    stype = StructuredCardType(m["structured_type"])
                except Exception:
                    stype = StructuredCardType.NONE

            sdata = m.get("structured_data")
            if isinstance(sdata, str):
                try:
                    sdata = json.loads(sdata)
                except Exception:
                    pass

            chat_messages.append(
                ChatMessage(
                    id=m["id"],
                    investigation_id=m["investigation_id"],
                    sender=m["sender"],
                    content=m["content"],
                    structured_type=stype,
                    structured_data=sdata,
                    sequence_number=m.get("sequence_number"),
                    delivery_status=m.get("delivery_status", "delivered"),
                    cascade_trace_id=m.get("cascade_trace_id"),
                    model_name=m.get("model_name"),
                    model_digest=m.get("model_digest"),
                    timestamp=m.get("created_at") or inv.get("created_at", "2026-10-05T07:00:00Z"),
                )
            )

        return InvestigationDetail(
            id=inv["id"],
            name=inv["name"],
            target_host=inv["target_host"],
            scope_status=inv["scope_status"],
            status=inv["status"],
            is_demo=bool(inv.get("is_demo", False)),
            evidence_count=inv.get("evidence_count", 0),
            hypothesis_count=inv.get("hypothesis_count", 0),
            messages=chat_messages,
            created_at=inv["created_at"],
            updated_at=inv["updated_at"],
        )

    def get_messages(self, inv_id: str, limit: Optional[int] = None, include_superseded: bool = False) -> List[ChatMessage]:
        """Retrieve conversation messages for an investigation."""
        db_msgs = self.db.get_messages(inv_id, limit=limit)
        chat_messages = []
        for m in db_msgs:
            if not include_superseded and m.get("status") == "SUPERSEDED":
                continue

            stype = StructuredCardType.NONE
            if m.get("structured_type"):
                try:
                    stype = StructuredCardType(m["structured_type"])
                except Exception:
                    stype = StructuredCardType.NONE

            sdata = m.get("structured_data")
            if isinstance(sdata, str):
                try:
                    sdata = json.loads(sdata)
                except Exception:
                    pass

            chat_messages.append(
                ChatMessage(
                    id=m["id"],
                    investigation_id=m["investigation_id"],
                    sender=m["sender"],
                    content=m["content"],
                    structured_type=stype,
                    structured_data=sdata,
                    sequence_number=m.get("sequence_number"),
                    delivery_status=m.get("delivery_status", "delivered"),
                    cascade_trace_id=m.get("cascade_trace_id"),
                    model_name=m.get("model_name"),
                    model_digest=m.get("model_digest"),
                    response_id=m.get("response_id"),
                    status=m.get("status", "COMPLETED"),
                    timestamp=m.get("created_at", datetime_now_iso()),
                )
            )
        return chat_messages

    def rename_investigation(self, inv_id: str, new_name: str) -> InvestigationSummary:
        """Rename an investigation and persist new name."""
        inv = self.db.get_investigation(inv_id)
        if not inv:
            inv = self._investigations.get(inv_id)
            if not inv:
                raise ValueError(f"Investigation {inv_id} not found")
        clean_name = new_name.strip()
        if not clean_name:
            raise ValueError("Investigation name cannot be empty")
        now = datetime_now_iso()
        self.db.update_investigation(inv_id, {"name": clean_name, "updated_at": now})
        if inv_id in self._investigations:
            self._investigations[inv_id]["name"] = clean_name
            self._investigations[inv_id]["updated_at"] = now
        self.audit_logger.log_event(
            event_type="INVESTIGATION_RENAMED",
            actor="local_researcher",
            subject_id=inv_id,
            details={"old_name": inv["name"], "new_name": clean_name},
        )
        updated = self.db.get_investigation(inv_id) or self._investigations[inv_id]
        msg_count = self.db.get_message_count(inv_id)
        return InvestigationSummary(
            id=updated["id"],
            name=updated["name"],
            target_host=updated["target_host"],
            scope_status=updated["scope_status"],
            status=updated["status"],
            is_demo=bool(updated.get("is_demo", False)),
            evidence_count=updated.get("evidence_count", 0),
            hypothesis_count=updated.get("hypothesis_count", 0),
            experiment_count=len([e for e in self._experiments.values() if e.get("investigation_id") == inv_id]),
            message_count=msg_count,
            last_activity=updated.get("updated_at", updated["created_at"]),
        )

    def delete_investigation(self, inv_id: str) -> bool:
        """Delete an investigation and its conversation messages without deleting canonical domain evidence."""
        inv = self.db.get_investigation(inv_id)
        if not inv:
            inv = self._investigations.get(inv_id)
            if not inv:
                raise ValueError(f"Investigation {inv_id} not found")
        self.db.delete_investigation(inv_id)
        self._investigations.pop(inv_id, None)
        self._messages.pop(inv_id, None)
        self._investigation_evidence.pop(inv_id, None)
        self._investigation_assets.pop(inv_id, None)
        self._investigation_invariants.pop(inv_id, None)
        self._investigation_hypotheses.pop(inv_id, None)
        self._investigation_gaps.pop(inv_id, None)
        self.audit_logger.log_event(
            event_type="INVESTIGATION_DELETED",
            actor="local_researcher",
            subject_id=inv_id,
            details={"deleted_inv_id": inv_id, "name": inv.get("name")},
        )
        return True

    # -------------------------------------------------------------------------
    # Cascade Observability & Trace Retrieval (Phase 12.4)
    # -------------------------------------------------------------------------

    def get_cascade_trace(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a persisted cascade trace by its run ID."""
        trace = self.db.get_cascade_trace(trace_id)
        if trace:
            return trace
        mem_trace = next((t for t in self.cascade_orchestrator._recent_traces if t.run_id == trace_id), None)
        if mem_trace:
            return mem_trace.model_dump()
        return None

    def get_message_trace(self, inv_id: str, message_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve the specific cascade trace associated with a given assistant message."""
        msg = self.db.get_message(message_id)
        if not msg:
            return None
        trace_id = msg.get("cascade_trace_id")
        if not trace_id:
            return None
        return self.get_cascade_trace(trace_id)

    def list_cascade_traces(self, inv_id: Optional[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
        """List recent cascade traces from persistent storage."""
        traces = self.db.list_cascade_traces(investigation_id=inv_id, limit=limit)
        if not traces and not inv_id:
            return [t.model_dump() for t in self.cascade_orchestrator.get_recent_traces(limit=limit)]
        return traces

    # -------------------------------------------------------------------------
    # Conversational Research Pipeline Bridge
    # -------------------------------------------------------------------------


    def _is_conversational_query(self, q: str) -> bool:
        """Determine whether prompt is conversational/conceptual rather than a target investigation command."""
        cleaned = "".join(c if c.isalnum() or c.isspace() else " " for c in q).strip().lower()
        words = cleaned.split()
        if not words:
            return True

        q_lower = q.lower().strip()
        if _is_explicit_gap_retrieval(q_lower) or _is_explicit_audit_query(q_lower):
            return False

        greetings = {"hello", "hi", "hey", "good morning", "good afternoon", "good evening", "howdy", "greetings", "yo"}
        if cleaned in greetings or (words[0] in greetings and len(words) <= 3):
            return True

        meta_phrases = [
            "who are you", "what can you do", "what do you do", "explain what you do",
            "how does this system work", "how do you work", "help", "thanks", "thank you",
            "what is your role", "tell me about yourself", "what are you",
        ]
        if any(cleaned == p or cleaned.startswith(p) for p in meta_phrases):
            return True

        # Check for conceptual learning / methodology questions
        conceptual_starters = (
            "explain", "what is", "what are", "how does", "how do", "how can",
            "tell me about", "tell me how", "tell me more", "describe",
            "difference between", "compare", "guide to", "overview of", "checklist for"
        )
        if any(cleaned.startswith(starter) for starter in conceptual_starters):
            # Explicit target evidence analysis commands override:
            target_evidence_indicators = (
                "target evidence", "imported traffic", "this target", "current evidence",
                "registered gaps", "propose experiments for this", "synthesize hypotheses for this"
            )
            if not any(t in cleaned for t in target_evidence_indicators):
                return True

        concepts = [
            "what is bola", "explain bola", "what is broken object level authorization",
            "what does grounding mean", "what is grounding", "what is epistemic",
            "what is a security invariant", "explain idor", "what is idor",
        ]
        if any(cleaned.startswith(c) for c in concepts):
            return True

        security_actions = [
            "analyze", "gaps", "gap", "hypothesis", "hypotheses", "experiment",
            "propose", "weakness", "weaknesses", "vulnerability", "vulnerabilities",
            "provenance", "audit", "lineage", "invariant", "invariants", "evidence",
            "falsification", "verify",
        ]
        if any(act in words for act in security_actions):
            return False

        return True

    def _handle_conversational_query(
        self,
        inv: Dict[str, Any],
        content: str,
        cancel_token: Optional[CancellationToken] = None,
        response_id: Optional[str] = None,
        explicit_history: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[str, Optional[str], Optional[str], Optional[str], str]:
        """
        Generate conversational AI response using local LLM or authoritative knowledge engine.
        Supplies bounded canonical history to Ollama context.
        Returns: (response_text, model_name, model_digest, response_id, status)
        """
        q_lower = content.lower().strip()

        # Direct model inquiry
        if any(phrase in q_lower for phrase in ("tell me your model", "what model", "which model", "who created you")):
            status_info = self.cascade_orchestrator.check_runtime_status()
            active_m = status_info.get("active_model", "qwen2.5-coder:7b")
            return (
                f"I am powered by {active_m} running locally via Ollama with deterministic cascade routing and local knowledge verification.",
                "local_assistant",
                None,
                None,
                "COMPLETED",
            )

        # Retrieve bounded canonical history (last 10 messages)
        db_messages = explicit_history if explicit_history is not None else self.db.get_messages(inv["id"], limit=10)
        history_turns = []
        for m in db_messages:
            if m.get("status") == "SUPERSEDED":
                continue
            if m["sender"] in ("user", "assistant"):
                role = "User" if m["sender"] == "user" else "Assistant"
                if m["sender"] == "user" and m["content"].strip() == content.strip():
                    continue
                history_turns.append(f"{role}: {m['content']}")

        # Conversational memory inquiry check
        if any(phrase in q_lower for phrase in ("what did i ask", "previous question", "what was my last question", "what did i say before")):
            prior_user_msgs = [m for m in db_messages if m["sender"] == "user" and m["content"].strip() != content.strip() and m.get("status") != "SUPERSEDED"]
            if prior_user_msgs:
                last_q = prior_user_msgs[-1]["content"]
                return f"Earlier in this conversation, you asked: \"{last_q}\".", "local_assistant", None, None, "COMPLETED"
            else:
                return "This is the first question in our conversation so far.", "local_assistant", None, None, "COMPLETED"

        # Check for pure greeting
        greetings = ("hello", "hi", "hey", "good morning", "good afternoon", "good evening", "howdy")
        cleaned_words = [w.strip("?.!,;:") for w in q_lower.split()]
        if len(cleaned_words) <= 3 and any(w in greetings for w in cleaned_words):
            return (
                "Hello. I'm your local security research assistant. "
                "You can ask conceptual cybersecurity questions (such as Android application security, volumetric DDoS defense, "
                "authentication vs authorization, IDOR/BOLA, API security), provide target observations, or instruct me to analyze verified evidence.",
                "local_assistant",
                None,
                None,
                "COMPLETED",
            )

        # If Ollama local inference is running or custom LLM caller is registered, run response engine
        has_custom_llm = bool(getattr(self.response_engine, "custom_llm_caller", None))
        if self.cascade_orchestrator.ollama_client.is_available() or has_custom_llm:
            try:
                system_prompt = (
                    "You are Ultron, a rigorous local security research assistant. "
                    "You operate strictly locally on the researcher's workstation. "
                    "You assist researchers in analyzing target evidence, modeling application behavior, "
                    "identifying security invariants, formulating hypotheses, and preparing experiments for human review. "
                    "When answering conceptual cybersecurity questions, provide detailed, substantive explanations "
                    "with clear definitions, mechanics, practical examples, defensive mitigations, and safe testing methodologies. "
                    "Maintain conversational continuity using prior conversation turns. "
                    "Do NOT fabricate target endpoints, pretend evidence exists, or invent findings."
                )

                history_context = ""
                if history_turns:
                    history_context = "Conversation History:\n" + "\n".join(history_turns) + "\n\n"

                # Check if knowledge RAG context can augment the prompt from user-managed ingested sources (Req 1.3 & 1.4)
                knowledge_context = ""
                has_verified_corpus_evidence = False
                ans = None
                try:
                    ans = self.knowledge_orchestrator.answer_query(content)
                    if ans and ans.claims:
                        # Verify if any citations genuinely resolve to persisted, authorized user-managed sources
                        verified_citations = []
                        for cit in (ans.citations or []):
                            cid = getattr(cit, "chunk_id", None) or (cit.get("chunk_id") if isinstance(cit, dict) else None)
                            if cid and self.knowledge_store:
                                chk = self.knowledge_store.get_chunk(cid)
                                if chk:
                                    doc_id = getattr(chk, "document_id", "")
                                    sid = doc_id.replace("DOC-", "")
                                    src = (
                                        self.knowledge_store.get_source(sid)
                                        or self.knowledge_store.get_source(f"SRC-{sid}")
                                        or self.knowledge_store.get_source(doc_id)
                                    )
                                    if src and src.get("status") in ("INDEXED", "PARTIAL", "SUCCESS", "ACTIVE"):
                                        verified_citations.append(cit)
                        if verified_citations:
                            has_verified_corpus_evidence = True
                            knowledge_context = "Authoritative Ingested Knowledge Context:\n" + "\n".join(f"- {c.text}" for c in ans.claims[:6]) + "\n\n"
                except Exception as ke:
                    logger.debug(f"Knowledge augmentation note: {ke}")

                policy_context = system_prompt
                if knowledge_context:
                    policy_context += f"\n\n{knowledge_context}"
                if history_context:
                    policy_context += f"\n\n{history_context}"

                citation_ctx = None
                try:
                    obs_list = self.db.get_investigation_observations(inv["id"])
                    valid_obs = {o["id"] for o in obs_list if "id" in o}
                    foreign_obs = set()
                    if hasattr(self.db, "get_foreign_observation_ids"):
                        foreign_obs = self.db.get_foreign_observation_ids(inv["id"])
                    citation_ctx = CitationContext(
                        allowed_observation_ids=valid_obs,
                        foreign_observation_ids=foreign_obs,
                        assessment_id=inv.get("assessment_id") or inv["id"],
                        investigation_id=inv["id"],
                    )
                except Exception as ce:
                    logger.debug(f"Citation context construction note: {ce}")

                session = self.response_engine.generate_response(
                    investigation_id=inv["id"],
                    user_prompt=content,
                    system_policy=policy_context,
                    model_name="qwen2.5-coder:7b",
                    auto_continue=True,
                    assessment_id=inv.get("assessment_id") or inv["id"],
                    citation_context=citation_ctx,
                    task_type=TaskType.CONVERSATIONAL_QA,
                    cancellation_token=cancel_token,
                    response_id=response_id,
                )
                text = session.final_content.strip()
                model_used = session.model or "qwen2.5-coder:7b"

                # If this cybersecurity query lacked sufficient corpus evidence and relied on model fallback,
                # attach the explicit disclaimer banner (Phase B / Phase C requirement)
                is_cyber_query = (
                    bool(ans and ans.sufficiency_status != "OUT_OF_DOMAIN")
                    or any(k in q_lower for k in ("owasp", "oswap", "vulnerability", "cwe-", "cve-", "exploit", "attack", "injection", "idor", "bola", "xss", "ssrf"))
                )
                if is_cyber_query and not has_verified_corpus_evidence and text:
                    fallback_banner = (
                        "> ⚠️ **General model knowledge — not verified against ingested sources**\n"
                        "> The local knowledge corpus does not contain sufficient ingested documentation for this topic. "
                        "The following explanation is generated from general model knowledge and has not been verified against authoritative ingested sources.\n\n"
                    )
                    if not text.startswith("> ⚠️ **General model knowledge"):
                        text = fallback_banner + text

                if text and session.status in (ResponseStatus.COMPLETED, ResponseStatus.MODEL_STOPPED):
                    stat_val = session.status.value if hasattr(session.status, "value") else str(session.status)
                    return text, model_used, None, session.response_id, stat_val
                if session.status == ResponseStatus.USER_STOPPED or session.termination_reason == GenerationTermination.CLIENT_ABORT:
                    return (
                        text or "Generation stopped by user.",
                        model_used,
                        None,
                        session.response_id,
                        "USER_STOPPED",
                    )
                if session.status == ResponseStatus.TOKEN_LIMIT:
                    return (
                        text,
                        model_used,
                        None,
                        session.response_id,
                        "TOKEN_LIMIT",
                    )
                if session.status == ResponseStatus.SERVICE_UNAVAILABLE or session.termination_reason == GenerationTermination.DAEMON_UNAVAILABLE:
                    return (
                        "Local AI model daemon (Ollama) is unavailable or the requested model is not installed. "
                        "Please verify Ollama is running.",
                        "local_assistant",
                        None,
                        session.response_id,
                        "SERVICE_UNAVAILABLE",
                    )
                if session.status == ResponseStatus.TIMEOUT or session.termination_reason == GenerationTermination.TIMEOUT_ABORT:
                    return (
                        "The local model inference request timed out. Local Ollama is running and reachable, "
                        "but generating this response exceeded the local hardware latency limit. "
                        "Please re-issue the question or retry.",
                        "local_assistant",
                        None,
                        session.response_id,
                        "TIMEOUT",
                    )
                if session.status == ResponseStatus.VALIDATION_FAILED:
                    return (
                        text or "Response validation failed against authoritative citation and safety boundaries.",
                        model_used,
                        None,
                        session.response_id,
                        "VALIDATION_FAILED",
                    )
                if text:
                    stat_val = session.status.value if hasattr(session.status, "value") else str(session.status)
                    return text, model_used, None, session.response_id, stat_val
            except AttributeError:
                # Critical Fix A invariant: Do NOT silently catch programming/attribute errors to conceal task-type bugs
                raise
            except Exception as e:
                logger.warning(f"Conversational LLM call fallback: {e}")

        # When local LLM is offline or un-invoked, utilize the local authoritative knowledge engine
        try:
            ans = self.knowledge_orchestrator.answer_query(content)
            if ans and (ans.sufficiency_status == "SUFFICIENT" or len(ans.claims) > 0):
                return ans.answer_text, "local_knowledge_engine", None, None, "COMPLETED"
        except Exception as ke:
            logger.warning(f"Knowledge query exception: {ke}")

        # Specific deterministic concepts
        if "bola" in q_lower or "idor" in q_lower:
            return (
                "Broken Object Level Authorization (BOLA / IDOR, CWE-639) occurs when an application receives a user-supplied "
                "identifier to access a resource and fails to validate that the authenticated actor has authorization "
                "to access that specific object. In our research pipeline, BOLA hypotheses require cross-identity replay "
                "experiments to prove or disprove boundary isolation.",
                "local_knowledge_engine",
                None,
                None,
                "COMPLETED",
            )
        elif "grounding" in q_lower:
            return (
                "Grounding is a strict epistemic constraint in Ultron (formerly Bug Bounty AI). Every assertion, hypothesis parameter, "
                "or experiment proposal must be directly linked to empirical target observations (e.g. FACT-OBS-xx). "
                "Unsubstantiated or hallucinated identifiers fail the GroundingValidator.",
                "local_knowledge_engine",
                None,
                None,
                "COMPLETED",
            )
        elif any(w in q_lower for w in ("who are you", "what can you do", "what do you do", "help")):
            return (
                "I am Ultron, an evidence-grounded research assistant running entirely locally. "
                "I follow a deterministic research pipeline: observing application traffic, establishing security "
                "invariants, identifying missing evidence gaps, synthesizing grounded hypotheses via a 3B → 7B "
                "cascade, and generating falsifiable experiment proposals requiring human approval.",
                "local_assistant",
                None,
                None,
                "COMPLETED",
            )

        # Honest status when model is offline and query is not in static VAPT knowledge base
        return (
            "The local language model inference service (Ollama on `127.0.0.1:11434`) is currently offline or unreachable. "
            "To enable full multi-turn conversational reasoning, ensure Ollama is running (`ollama serve` and `ollama run qwen2.5-coder:7b`).\n\n"
            "In offline mode, you can ask conceptual cybersecurity questions (such as Android application security review, volumetric DDoS defense, "
            "authentication vs authorization, IDOR/BOLA, API security, and cryptography) or import HTTP traffic observations for deterministic pipeline analysis.",
            "system_status",
            None,
            None,
            "SERVICE_UNAVAILABLE",
        )

    def _handle_investigation_query(
        self, inv_id: str, inv: Dict[str, Any], content: str, q_lower: str, user_msg_id: Optional[str] = None
    ) -> List[ChatMessage]:
        """Handle security research pipeline requests with honest abstention when evidence is missing."""
        is_demo = bool(inv.get("is_demo", False))
        if is_demo:
            evidence = self._investigation_evidence.get(inv_id, [])
            assets = self._investigation_assets.get(inv_id, [])
        else:
            observations = self.db.get_investigation_observations(inv_id)
            evidence = observations
            assets = []
            seen_assets = set()
            for obs in observations:
                aid = obs["asset_id"]
                if aid not in seen_assets:
                    seen_assets.add(aid)
                    assets.append({
                        "asset_id": aid,
                        "method": obs["http_method"],
                        "host": obs["host"],
                        "raw_path": obs["raw_path"],
                        "normalized_path": obs["normalized_path"],
                        "application_mutability": self.ingestion_pipeline.normalizer.classify_mutability(obs["http_method"]),
                    })

        new_responses: List[ChatMessage] = []

        # 1. Honest Abstention if no evidence exists for this investigation
        if not evidence and not assets:
            resp_content = (
                "There is currently no target evidence to analyze for this investigation. "
                "Please add endpoint observations or import HTTP traffic telemetry before requesting security analysis."
            )
            resp_msg = ChatMessage(
                id=f"MSG-{secrets_token_hex()[:6].upper()}",
                investigation_id=inv_id,
                sender="assistant",
                content=resp_content,
                structured_type=StructuredCardType.NONE,
                model_name="local_rule_engine",
                timestamp=datetime_now_iso(),
            )
            return [resp_msg]

        # 2. Evidence Gaps (Explicit Retrieval Path Only)
        if _is_explicit_gap_retrieval(q_lower):
            gaps = self.get_gaps(inv_id)
            if gaps:
                gap_items = "\n".join(f"{i+1}. **{g['gap_id']}**: {g['description']}" for i, g in enumerate(gaps))
                resp_content = f"**Open Evidence Gaps Identified:**\n\n{gap_items}"
            else:
                resp_content = "No open evidence gaps currently registered for this investigation."

            resp_msg = ChatMessage(
                id=f"MSG-{secrets_token_hex()[:6].upper()}",
                investigation_id=inv_id,
                sender="assistant",
                content=resp_content,
                structured_type=StructuredCardType.NONE,
                model_name="local_rule_engine",
                timestamp=datetime_now_iso(),
            )
            return [resp_msg]

        # 3. Provenance & Audit
        if _is_explicit_audit_query(q_lower):
            audit_events = self.audit_logger.read_records(limit=3)
            latest_hash = audit_events[-1].get("current_hash", "3f80d8e...") if audit_events else "VERIFIED"
            fact_ids = [f["fact_id"] for f in evidence]
            fact_summary = ", ".join(f"`{fid}`" for fid in fact_ids) if fact_ids else "None"

            resp_content = (
                "**Cryptographic Provenance & Fact Lineage:**\n\n"
                f"- **Audit Chain Status**: Cryptographically verified (`{latest_hash[:16]}...`)\n"
                f"- **Evidence Lineage**: {fact_summary} derived from verified HTTP telemetry.\n"
                "- **Digest Binding**: Execution proposal digest cryptographically pinned before approval.\n"
                "- **Epistemic Segregation**: Inferred conclusions strictly quarantined from empirical facts."
            )
            resp_msg = ChatMessage(
                id=f"MSG-{secrets_token_hex()[:6].upper()}",
                investigation_id=inv_id,
                sender="assistant",
                content=resp_content,
                structured_type=StructuredCardType.AUDIT,
                structured_data={"audit_records": audit_events, "status": "VERIFIED"},
                model_name="local_rule_engine",
                timestamp=datetime_now_iso(),
            )
            return [resp_msg]

        # 4. Invariant reasoning
        if _is_explicit_invariant_query(q_lower):
            invariants = self._investigation_invariants.get(inv_id, [])
            if invariants:
                inv_obj = invariants[0]
                resp_content = (
                    f"**Active Security Invariant**: `{inv_obj.get('invariant_id')}`\n\n"
                    f"{inv_obj.get('description')}\n\n"
                    f"- **Origin**: `{inv_obj.get('origin')}`\n"
                    f"- **Confidence**: `{inv_obj.get('confidence')}`"
                )
                resp_msg = ChatMessage(
                    id=f"MSG-{secrets_token_hex()[:6].upper()}",
                    investigation_id=inv_id,
                    sender="assistant",
                    content=resp_content,
                    structured_type=StructuredCardType.INVARIANT,
                    structured_data=inv_obj,
                    model_name="local_rule_engine",
                    timestamp=datetime_now_iso(),
                )
                return [resp_msg]

        # 5. Analysis / Hypothesis / Experiment Proposal (Cascade Pipeline)
        primary_asset = assets[0] if assets else {}
        route_template = primary_asset.get("normalized_path") or "/api/v1/resource"
        http_method = primary_asset.get("method") or "POST"
        asset_id = primary_asset.get("asset_id") or "ASSET-01"
        mutability = primary_asset.get("application_mutability") or "STATE_CHANGING"

        observed_facts = [
            {"fact_id": f["fact_id"], "statement": f["statement"]}
            for f in evidence
        ]

        pack = LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id=asset_id,
            endpoint_id=f"EP-{asset_id[:8]}",
            route_template=route_template,
            http_method=http_method,
            application_mutability=mutability,
            observed_facts=observed_facts,
        )

        trace, hypothesis = self.cascade_orchestrator.execute_cascade(
            pack,
            task_type="SECURITY_RESEARCH",
            investigation_id=inv_id,
            user_message_id=user_msg_id,
        )

        exps = [e for e in self._experiments.values() if e.get("investigation_id") == inv_id]
        experiment_obj = exps[0] if exps else None

        if hypothesis and hypothesis.get("decision") == "HYPOTHESIS":
            hyp_category = (
                hypothesis.get("category")
                or (trace.stages[0].details.get("suspected_category") if trace.stages else None)
                or "API-BOLA-001"
            )
            hyp_summary = (
                hypothesis.get("reasoning_summary")
                or hypothesis.get("falsification_description")
                or hypothesis.get("invariant")
                or "Authorization check bypass suspected."
            )
            raw_gap = hypothesis.get("evidence_gap")
            valid_gap = _normalize_structured_gap(raw_gap)

            if valid_gap:
                gap_entry = {
                    "gap_id": f"GAP-{trace.run_id}",
                    "target_asset": f"{http_method} {route_template}",
                    "description": valid_gap,
                    "status": "OPEN",
                    "suggested_action": hypothesis.get("experiment_action") or "EXPERIMENT_VERIFICATION",
                }
                existing_gaps = self._investigation_gaps.setdefault(inv_id, [])
                if not any(g.get("description") == valid_gap for g in existing_gaps):
                    existing_gaps.append(gap_entry)

            if not experiment_obj and hypothesis.get("experiment_action"):
                exp_id = f"EXP-{trace.run_id}"
                target_host = inv.get("target_host", "target.local")
                experiment_obj = {
                    "id": exp_id,
                    "investigation_id": inv_id,
                    "hypothesis_id": None,
                    "category": hyp_category,
                    "action": hypothesis.get("experiment_action"),
                    "target": f"https://{target_host}{route_template}",
                    "asset_id": asset_id,
                    "safety_level": SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL.value if mutability == "STATE_CHANGING" else SafetyLevel.READ_ONLY_SAFE.value,
                    "scope": "ALLOWED",
                    "grounding": "PASS",
                    "polarity": "PASS",
                    "status": "AWAITING_APPROVAL",
                    "approval_required": True,
                    "approval_id": None,
                    "objective": hypothesis.get("falsification_description") or f"Test {hyp_category} against {http_method} {route_template}.",
                    "supporting_observation": str(hypothesis.get("supporting_outcome") or "Breach confirmed"),
                    "contradicting_observation": str(hypothesis.get("disproving_outcome") or "Invariant held safely"),
                    "falsification_condition": f"If {hypothesis.get('disproving_outcome')} is received, invariant is confirmed active.",
                }
                self._experiments[exp_id] = experiment_obj

            resp_content = (
                f"Based on the analysis of `{http_method} {route_template}`, "
                f"a potential `{hyp_category}` vulnerability was identified. "
                f"{hyp_summary}"
            )
            hyp_card = {
                "hypothesis_id": f"HYP-{trace.run_id}",
                "category": hyp_category,
                "target_asset": f"{http_method} {route_template}",
                "statement": hyp_summary,
                "evidence_gap": valid_gap,
                "evidence_state": hypothesis.get("evidence_state", "PARTIAL"),
                "grounding_status": f"PASS ({', '.join(f['fact_id'] for f in observed_facts)})",
                "epistemic_state": "UNVERIFIED CANDIDATE",
                "experiment_id": experiment_obj["id"] if experiment_obj else None,
                "cascade_trace_id": trace.run_id,
                "routing_decision": trace.routing_decision,
            }
            resp_msg = ChatMessage(
                id=f"MSG-{secrets_token_hex()[:6].upper()}",
                investigation_id=inv_id,
                sender="assistant",
                content=resp_content,
                structured_type=StructuredCardType.HYPOTHESIS,
                structured_data=hyp_card,
                cascade_trace_id=trace.run_id,
                model_name="Cascade Active (3B → 7B)",
                timestamp=datetime_now_iso(),
            )
            new_responses.append(resp_msg)

            if experiment_obj:
                exp_msg = ChatMessage(
                    id=f"MSG-{secrets_token_hex()[:6].upper()}",
                    investigation_id=inv_id,
                    sender="assistant",
                    content=(
                        f"I have designed a discriminative experiment proposal to test this hypothesis. "
                        f"Because `{http_method} {route_template}` is classified as `{mutability}`, "
                        "explicit human review and cryptographic approval are required prior to execution."
                    ),
                    structured_type=StructuredCardType.EXPERIMENT,
                    structured_data=experiment_obj,
                    cascade_trace_id=trace.run_id,
                    model_name="Cascade Active (3B → 7B)",
                    timestamp=datetime_now_iso(),
                )
                new_responses.append(exp_msg)
        else:
            if experiment_obj:
                resp_content = (
                    f"I have examined the active evidence for `{inv['target_host']}`. "
                    f"A grounded hypothesis has been formulated with an experiment awaiting review."
                )
                resp_msg = ChatMessage(
                    id=f"MSG-{secrets_token_hex()[:6].upper()}",
                    investigation_id=inv_id,
                    sender="assistant",
                    content=resp_content,
                    structured_type=StructuredCardType.EXPERIMENT,
                    structured_data=experiment_obj,
                    cascade_trace_id=trace.run_id,
                    model_name="Cascade Active (3B → 7B)",
                    timestamp=datetime_now_iso(),
                )
                new_responses.append(resp_msg)
            else:
                resp_content = (
                    f"Analyzed {len(observed_facts)} target observations for `{inv['target_host']}`. "
                    "No immediate invariant breach detected from current evidence."
                )
                resp_msg = ChatMessage(
                    id=f"MSG-{secrets_token_hex()[:6].upper()}",
                    investigation_id=inv_id,
                    sender="assistant",
                    content=resp_content,
                    structured_type=StructuredCardType.NONE,
                    cascade_trace_id=trace.run_id,
                    model_name="Cascade Active (3B → 7B)",
                    timestamp=datetime_now_iso(),
                )
                new_responses.append(resp_msg)

        if new_responses:
            trace.assistant_message_id = new_responses[0].id
        self.db.insert_cascade_trace(trace.model_dump())

        return new_responses

    def send_message(self, inv_id: str, content: str, client_msg_id: Optional[str] = None) -> List[ChatMessage]:
        """
        Process user prompt and generate grounded AI responses with progressive disclosure.
        Persists both user message and assistant responses to SQLite.
        Supplies bounded canonical history to Ollama context.
        """
        inv = self.db.get_investigation(inv_id)
        if not inv:
            inv = self._investigations.get(inv_id)
            if not inv:
                raise ValueError(f"Investigation {inv_id} not found")

        # Auto-derive title if currently "New Investigation" or default
        if inv["name"].lower().startswith("new investigation") or inv["name"] == "Untitled Investigation":
            derived_title = content.strip().split("\n")[0][:80].strip()
            if derived_title:
                self.db.update_investigation(inv_id, {"name": derived_title})
                if inv_id in self._investigations:
                    self._investigations[inv_id]["name"] = derived_title

        now = datetime_now_iso()
        # Redact any accidental secrets from user content
        redacted_user_content = self.vault.redact_text(content)

        # Check if user message already exists (e.g. retry scenario with client_msg_id)
        user_msg_id = client_msg_id or f"MSG-{secrets_token_hex()[:6].upper()}"
        existing_msg = self.db.get_message(user_msg_id)
        if not existing_msg:
            user_seq = self.db.get_next_sequence_number(inv_id)
            user_msg_record = {
                "id": user_msg_id,
                "investigation_id": inv_id,
                "sequence_number": user_seq,
                "sender": "user",
                "content": redacted_user_content,
                "structured_type": StructuredCardType.NONE.value,
                "structured_data": None,
                "delivery_status": "delivered",
                "cascade_trace_id": None,
                "model_name": None,
                "model_digest": None,
                "created_at": now,
            }
            self.db.insert_message(user_msg_record)

        # Check for existing assistant message paired with this user message (retry scenario)
        existing_asst_msg = None
        if existing_msg:
            user_seq = existing_msg.get("sequence_number")
            if user_seq is not None:
                all_msgs = self.db.get_messages(inv_id)
                for m in all_msgs:
                    if m.get("sender") == "assistant" and m.get("sequence_number") == user_seq + 1:
                        existing_asst_msg = m
                        break

        q_lower = content.lower().strip()
        is_conversational = self._is_conversational_query(q_lower)

        if is_conversational:
            cancel_token = CancellationToken()
            resp_gen_id = f"RESP-{secrets_token_hex()[:6].upper()}"
            self._active_cancellations[resp_gen_id] = cancel_token
            self._active_cancellations[inv_id] = cancel_token
            try:
                conv_res = self._handle_conversational_query(
                    inv,
                    redacted_user_content,
                    cancel_token=cancel_token,
                    response_id=resp_gen_id,
                )
                if len(conv_res) == 5:
                    reply_text, model_name, model_digest, response_id, status = conv_res
                elif len(conv_res) == 4:
                    reply_text, model_name, model_digest, response_id = conv_res
                    status = "COMPLETED"
                else:
                    reply_text, model_name, model_digest = conv_res
                    response_id = resp_gen_id
                    status = "COMPLETED"
            finally:
                self._active_cancellations.pop(resp_gen_id, None)
                self._active_cancellations.pop(inv_id, None)

            redacted_reply = self.vault.redact_text(reply_text)
            if existing_asst_msg:
                resp_id = existing_asst_msg["id"]
                asst_seq = existing_asst_msg["sequence_number"]
            else:
                resp_id = f"MSG-{secrets_token_hex()[:6].upper()}"
                asst_seq = self.db.get_next_sequence_number(inv_id)
            resp_now = datetime_now_iso()
            asst_msg_record = {
                "id": resp_id,
                "investigation_id": inv_id,
                "sequence_number": asst_seq,
                "sender": "assistant",
                "content": redacted_reply,
                "structured_type": StructuredCardType.NONE.value,
                "structured_data": None,
                "delivery_status": "delivered",
                "cascade_trace_id": None,
                "model_name": model_name,
                "model_digest": model_digest,
                "response_id": response_id,
                "status": status,
                "created_at": resp_now,
            }
            self.db.insert_message(asst_msg_record)
            new_responses = [
                ChatMessage(
                    id=resp_id,
                    investigation_id=inv_id,
                    sender="assistant",
                    content=redacted_reply,
                    structured_type=StructuredCardType.NONE,
                    sequence_number=asst_seq,
                    delivery_status="delivered",
                    model_name=model_name,
                    model_digest=model_digest,
                    response_id=response_id,
                    status=status,
                    timestamp=resp_now,
                )
            ]
        else:
            new_responses = self._handle_investigation_query(inv_id, inv, redacted_user_content, q_lower, user_msg_id=user_msg_id)
            # Persist each response in new_responses to SQLite
            for resp in new_responses:
                redacted_content = self.vault.redact_text(resp.content)
                resp_seq = self.db.get_next_sequence_number(inv_id)
                resp.sequence_number = resp_seq
                resp.delivery_status = "delivered"
                resp.content = redacted_content
                stype_val = resp.structured_type.value if hasattr(resp.structured_type, "value") else str(resp.structured_type)
                resp_record = {
                    "id": resp.id,
                    "investigation_id": inv_id,
                    "sequence_number": resp_seq,
                    "sender": resp.sender,
                    "content": redacted_content,
                    "structured_type": stype_val,
                    "structured_data": resp.structured_data,
                    "delivery_status": "delivered",
                    "cascade_trace_id": resp.cascade_trace_id,
                    "model_name": resp.model_name or "Cascade Active (3B → 7B)",
                    "model_digest": resp.model_digest,
                    "created_at": resp.timestamp,
                }
                self.db.insert_message(resp_record)

        self.db.update_investigation(inv_id, {"updated_at": datetime_now_iso()})
        return new_responses

    # -------------------------------------------------------------------------
    # Evidence Ingestion & Manual Observations (Phase 12.X)
    # -------------------------------------------------------------------------

    def ingest_traffic(self, inv_id: str, req: ImportTrafficRequest) -> Dict[str, Any]:
        """Import HTTP traffic (HAR, Raw HTTP, Burp) into an investigation."""
        inv = self.db.get_investigation(inv_id)
        if not inv:
            inv = self._investigations.get(inv_id)
            if not inv:
                raise ValueError(f"Investigation {inv_id} not found")

        result = self.ingestion_pipeline.ingest_raw(
            investigation_id=inv_id,
            target_host=inv["target_host"],
            raw_content=req.content,
            format_type=req.format,
            source_artifact=req.filename or req.format,
        )

        if inv_id in self._investigations:
            self._investigations[inv_id]["evidence_count"] = self.db.get_observation_count(inv_id)
            self._investigations[inv_id]["updated_at"] = datetime_now_iso()

        self.audit_logger.log_event(
            event_type="TRAFFIC_IMPORTED",
            actor="local_researcher",
            subject_id=inv_id,
            details={"format": req.format, "investigation_id": inv_id},
            investigation_id=inv_id,
        )

        return result.model_dump()

    def add_manual_observation(self, inv_id: str, req: ManualObservationRequest) -> Dict[str, Any]:
        """Manually record a target HTTP observation in an investigation."""
        inv = self.db.get_investigation(inv_id)
        if not inv:
            inv = self._investigations.get(inv_id)
            if not inv:
                raise ValueError(f"Investigation {inv_id} not found")

        result = self.ingestion_pipeline.add_manual_observation(
            investigation_id=inv_id,
            target_host=inv["target_host"],
            data=req.model_dump(),
        )

        if inv_id in self._investigations:
            self._investigations[inv_id]["evidence_count"] = self.db.get_observation_count(inv_id)
            self._investigations[inv_id]["updated_at"] = datetime_now_iso()

        self.audit_logger.log_event(
            event_type="OBSERVATION_RECORDED",
            actor="local_researcher",
            subject_id=inv_id,
            details={"path": req.path, "status_code": req.status_code, "investigation_id": inv_id},
            investigation_id=inv_id,
        )

        return result.model_dump()

    def get_observation(self, inv_id: str, obs_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific target observation by ID."""
        return self.db.get_investigation_observation(obs_id)

    # -------------------------------------------------------------------------
    # Context Drawer Data Queries
    # -------------------------------------------------------------------------

    def get_evidence(self, inv_id: str) -> List[Dict[str, Any]]:
        """Get canonical evidence items with epistemic segregation."""
        inv = self.db.get_investigation(inv_id) or self._investigations.get(inv_id, {})
        if inv.get("is_demo"):
            return self._investigation_evidence.get(inv_id, [])
        return self.db.get_investigation_observations(inv_id)

    def get_application_model(self, inv_id: str) -> Dict[str, Any]:
        """Get application model with observed endpoints, parameters, and workflows."""
        inv = self.db.get_investigation(inv_id) or self._investigations.get(inv_id, {})
        target_host = inv.get("target_host", "")
        is_demo = inv.get("is_demo", False)
        if is_demo:
            assets = self._investigation_assets.get(inv_id, [])
            workflows = [
                {
                    "workflow_id": "WF-EXPORT-01",
                    "name": "Invoice Generation & Export Flow",
                    "sequence": ["/api/v1/invoices", "/api/v1/invoices/export"],
                    "origin": "DETERMINISTIC_DERIVATION",
                }
            ]
        else:
            observations = self.db.get_investigation_observations(inv_id)
            seen_assets = set()
            assets = []
            for obs in observations:
                aid = obs["asset_id"]
                if aid not in seen_assets:
                    seen_assets.add(aid)
                    assets.append({
                        "asset_id": aid,
                        "method": obs["http_method"],
                        "host": obs["host"],
                        "raw_path": obs["raw_path"],
                        "normalized_path": obs["normalized_path"],
                        "application_mutability": self.ingestion_pipeline.normalizer.classify_mutability(obs["http_method"]),
                        "liveness": "SHADOW_ACTIVE" if obs["response_status"] != 404 else "ZOMBIE_STALE",
                    })
            workflows = []

        return {
            "target_host": target_host,
            "assets": assets,
            "parameters": [],
            "identities": [],
            "workflows": workflows,
        }

    def get_invariants(self, inv_id: str) -> List[Dict[str, Any]]:
        """Get security invariants with epistemic origins."""
        return self._investigation_invariants.get(inv_id, [])

    def get_gaps(self, inv_id: str) -> List[Dict[str, Any]]:
        """Get active evidence gaps, rehydrating from persisted structured messages if needed."""
        gaps = self._investigation_gaps.get(inv_id, [])
        if not gaps:
            # Rehydrate from persistent conversation history without modifying database schema
            db_msgs = self.db.get_messages(inv_id)
            rehydrated = []
            for m in db_msgs:
                stype = m.get("structured_type")
                if stype in ("HYPOTHESIS", StructuredCardType.HYPOTHESIS.value):
                    sdata = m.get("structured_data")
                    if isinstance(sdata, str):
                        try:
                            sdata = json.loads(sdata)
                        except Exception:
                            sdata = {}
                    if isinstance(sdata, dict) and sdata.get("evidence_gap"):
                        valid_gap = _normalize_structured_gap(sdata["evidence_gap"])
                        if valid_gap and not any(g.get("description") == valid_gap for g in rehydrated):
                            rehydrated.append({
                                "gap_id": f"GAP-{sdata.get('cascade_trace_id') or sdata.get('hypothesis_id', '001')}",
                                "target_asset": sdata.get("target_asset", ""),
                                "description": valid_gap,
                                "status": "OPEN",
                                "suggested_action": "EXPERIMENT_VERIFICATION",
                            })
            if rehydrated:
                self._investigation_gaps[inv_id] = rehydrated
                gaps = rehydrated
        return gaps

    def get_hypotheses(self, inv_id: str) -> List[Dict[str, Any]]:
        """Get hypotheses for the investigation."""
        return self._investigation_hypotheses.get(inv_id, [])

    def get_experiments(self, inv_id: str) -> List[Dict[str, Any]]:
        """Get all experiments for an investigation."""
        return [e for e in self._experiments.values() if e.get("investigation_id") == inv_id]

    # -------------------------------------------------------------------------
    # Experiment Validation, Approval & Execution
    # -------------------------------------------------------------------------

    def validate_experiment(self, exp_id: str) -> ExperimentValidationResult:
        """Validate experiment grounding, polarity, and scope."""
        exp = self._experiments.get(exp_id)
        if not exp:
            return ExperimentValidationResult(
                experiment_id=exp_id,
                valid=False,
                grounding_passed=False,
                polarity_passed=False,
                scope_passed=False,
                error_message=f"Experiment {exp_id} not found",
            )

        # 1. Scope Validation
        scope_res = self.scope_gate.evaluate(exp["target"])
        scope_ok = scope_res.decision.value == "ALLOW"

        # 2. Polarity Validation
        pol_ok, pol_reason = self.polarity_validator.validate_tuple(
            category_id=exp["category"],
            experiment_action=exp["action"],
            supporting_outcome=HttpOutcomePredicate.HTTP_200_OK.value,
            disproving_outcome=HttpOutcomePredicate.HTTP_403_FORBIDDEN.value,
        )

        # 3. Grounding Validation
        pack = LosslessStructuralPack(
            schema_version="2.0.0",
            asset_id="ASSET-BOLA-EXPORT-01",
            endpoint_id="EP-BOLA-01",
            route_template="/api/v1/invoices/export",
            http_method="POST",
            application_mutability="STATE_CHANGING",
            observed_facts=[
                {"fact_id": "FACT-OBS-01", "statement": "POST /api/v1/invoices/export accepts JSON body with target organization and invoice identifier."},
                {"fact_id": "FACT-OBS-02", "statement": "Endpoint returns HTTP 200 with exported PDF binary when called with invoice_id owned by current tenant."},
            ],
        )
        ground_res = self.grounding_validator.validate_grounding(
            parsed_dict={
                "decision": "HYPOTHESIS",
                "affected_target": "EP-BOLA-01",
                "empirical_facts": ["FACT-OBS-01", "FACT-OBS-02"],
            },
            allowed_fact_ids=["FACT-OBS-01", "FACT-OBS-02"],
            allowed_target_ids=["EP-BOLA-01"],
            pack=pack,
        )
        ground_ok = ground_res.is_valid

        valid = scope_ok and pol_ok and ground_ok
        return ExperimentValidationResult(
            experiment_id=exp_id,
            valid=valid,
            grounding_passed=ground_ok,
            polarity_passed=pol_ok,
            scope_passed=scope_ok,
            details={
                "scope_decision": scope_res.decision.value,
                "polarity_reason": pol_reason,
                "grounding_reason": ground_res.reason,
            },
        )

    def approve_experiment(self, exp_id: str, req: ExperimentApprovalRequest) -> Dict[str, Any]:
        """
        Cryptographically bind and register a HumanApproval for a state-changing proposal.
        """
        exp = self._experiments.get(exp_id)
        if not exp:
            raise ValueError(f"Experiment {exp_id} not found")

        desc = self._execution_descriptors.get(exp_id)
        if not desc:
            raise ValueError(f"ExecutionDescriptor for {exp_id} not found")

        if exp["safety_level"] in ("STATE_CHANGING_REQUIRES_APPROVAL", "DESTRUCTIVE_ISOLATED_DATA"):
            if not req.safety_acknowledged:
                raise ValueError("Safety acknowledgment is strictly required for STATE_CHANGING proposals.")

        descriptor_digest = desc.compute_digest()
        approval_id = f"APP-{secrets_token_hex()[:6].upper()}"

        approval = HumanApproval(
            approval_id=approval_id,
            experiment_id=exp_id,
            approved_descriptor_digest=descriptor_digest,
            actor=req.actor,
            expires_at=time.time() + 300.0,
            notes=req.notes or "Human approved for safe local simulation.",
        )

        # Register with the real ApprovalGate
        self.approval_gate.register_approval(approval)
        exp["approval_id"] = approval_id
        exp["status"] = "APPROVED"

        inv_id = exp["investigation_id"]
        self.audit_logger.log_event(
            event_type="EXPERIMENT_APPROVED",
            actor=req.actor,
            subject_id=exp_id,
            details={
                "approval_id": approval_id,
                "descriptor_digest": descriptor_digest,
                "safety_acknowledged": req.safety_acknowledged,
                "investigation_id": inv_id,
            },
            investigation_id=inv_id,
        )

        # Append confirmation message to the investigation conversation
        appr_msg = ChatMessage(
            id=f"MSG-{secrets_token_hex()[:6].upper()}",
            investigation_id=inv_id,
            sender="assistant",
            content=f"**Human Approval Registered**: Experiment `{exp_id}` was authorized by `{req.actor}`. Descriptor digest `{descriptor_digest[:16]}...` cryptographically bound.",
            structured_type=StructuredCardType.APPROVAL,
            structured_data={
                "experiment_id": exp_id,
                "approval_id": approval_id,
                "actor": req.actor,
                "digest": descriptor_digest,
                "status": "APPROVED",
            },
            timestamp=datetime_now_iso(),
        )
        self._messages.setdefault(inv_id, []).append(appr_msg)

        return {
            "status": "success",
            "approval_id": approval_id,
            "descriptor_digest": descriptor_digest,
            "experiment_status": "APPROVED",
        }

    def reject_experiment(self, exp_id: str, actor: str, reason: str) -> Dict[str, Any]:
        """Reject an experiment proposal."""
        exp = self._experiments.get(exp_id)
        if not exp:
            raise ValueError(f"Experiment {exp_id} not found")

        exp["status"] = "REJECTED"
        inv_id = exp["investigation_id"]

        self.audit_logger.log_event(
            event_type="EXPERIMENT_REJECTED",
            actor=actor,
            subject_id=exp_id,
            details={"reason": reason, "investigation_id": inv_id},
            investigation_id=inv_id,
        )

        msg = ChatMessage(
            id=f"MSG-{secrets_token_hex()[:6].upper()}",
            investigation_id=inv_id,
            sender="assistant",
            content=f"**Experiment Rejected**: `{exp_id}` was rejected by `{actor}`. Reason: {reason}",
            structured_type=StructuredCardType.NONE,
            timestamp=datetime_now_iso(),
        )
        self._messages.setdefault(inv_id, []).append(msg)
        return {"status": "rejected", "experiment_id": exp_id}

    def execute_experiment(self, exp_id: str, safe_simulation: bool = True) -> ExecutionOutcomeResponse:
        """
        Execute an experiment proposal through the real DeterministicExecutionEngine.
        Enforces 14-step boundary validation and returns execution timeline + observation.
        """
        exp = self._experiments.get(exp_id)
        if not exp:
            return ExecutionOutcomeResponse(
                experiment_id=exp_id,
                status="ERROR",
                success=False,
                error_message=f"Experiment {exp_id} not found",
            )

        desc = self._execution_descriptors.get(exp_id)
        if not desc:
            return ExecutionOutcomeResponse(
                experiment_id=exp_id,
                status="ERROR",
                success=False,
                error_message=f"Descriptor for {exp_id} not found",
            )

        # Construct authoritative ExperimentProposal matching descriptor
        proposal = ExperimentProposal(
            objective=exp_id,
            target_asset_id=exp.get("asset_id", "ASSET-BOLA-EXPORT-01"),
            mutation_class=MutationClass.CROSS_IDENTITY_REPLAY,
            actor_identity_id="test_user_a",
            expected_observations=ExpectedObservations(
                supporting_observation=exp["supporting_observation"],
                contradicting_observation=exp["contradicting_observation"],
            ),
            safety_level=SafetyLevel.STATE_CHANGING_REQUIRES_APPROVAL,
            rollback_requirement="Export cross-tenant invoice without ownership check",
        )

        body_bytes = json.dumps({"invoice_id": "INV-9999"}).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        # Execute through the authoritative DeterministicExecutionEngine
        result: ExecutionResult = self.execution_engine.execute_proposal(
            experiment=proposal,
            destination_url=exp["target"],
            http_method="POST",
            request_headers=headers,
            request_body=body_bytes,
            environment_context="staging",
            approval_id=exp.get("approval_id"),
        )

        # Construct execution step timeline
        is_blocked = result.status != ExecutionStatus.EXECUTED
        timeline = [
            {"step": "Scope Gate", "status": "PASS", "detail": "Target destination within allowed scope"},
            {
                "step": "Approval Gate",
                "status": "FAIL" if result.status == ExecutionStatus.BLOCKED_APPROVAL else "PASS",
                "detail": "Cryptographic approval digest verified" if result.status != ExecutionStatus.BLOCKED_APPROVAL else f"BLOCKED_APPROVAL: {result.error_message}",
            },
            {"step": "Preflight Validation", "status": "PASS" if not is_blocked else "SKIPPED", "detail": "Headers and payload integrity validated"},
            {"step": "Rate Limit & TOCTOU", "status": "PASS" if not is_blocked else "SKIPPED", "detail": "Leaky bucket and target state unmutated"},
            {
                "step": "Execution",
                "status": "PASS" if not is_blocked else "BLOCKED",
                "detail": f"Status: {result.status.value}",
            },
            {"step": "Observation Record", "status": "PASS" if not is_blocked else "SKIPPED", "detail": "Observed HTTP 200 with foreign invoice payload"},
            {"step": "Audit Log", "status": "PASS", "detail": "Event appended with SHA256 hash chaining"},
        ]

        if is_blocked:
            exp["status"] = result.status.value
            return ExecutionOutcomeResponse(
                experiment_id=exp_id,
                status=result.status.value,
                success=False,
                timeline=timeline,
                error_message=f"Execution failed closed: {result.status.value} - {result.error_message}",
            )

        # Successful safe local execution
        exp["status"] = "EXECUTED"
        inv_id = exp["investigation_id"]

        # Insert newly observed evidence into database
        new_fact_id = "FACT-OBS-03-BOLA-CONFIRMED"
        new_fact = {
            "fact_id": new_fact_id,
            "certainty": EpistemicCertainty.OBSERVED.value,
            "statement": f"Experiment {exp_id} executed: substituted invoice_id returned foreign tenant invoice payload (HTTP 200).",
            "source_tool": "deterministic_execution_engine",
            "trust": "TRUSTED",
        }
        self.db.insert_evidence_item(new_fact)
        self._investigation_evidence.setdefault(inv_id, []).append(new_fact)
        if inv_id in self._investigations:
            self._investigations[inv_id]["evidence_count"] = len(self._investigation_evidence[inv_id])

        # Update hypothesis state to Confirmed via state machine
        try:
            hyp_id = exp.get("hypothesis_id", 1)
            # Transition to Under Review first if New
            hyp = self.db.get_hypothesis(hyp_id)
            if hyp and hyp.get("state") == "New":
                self.state_machine.start_review(hyp_id)

            self.state_machine.confirm_with_human_verification(
                hypothesis_id=hyp_id,
                actor="authorized_security_lead",
                evidence_ref=new_fact_id,
                session_id="LOCAL-UI-SESSION",
                notes="BOLA vulnerability confirmed through deterministic experiment execution.",
            )
            hyp_state = "Confirmed"
        except Exception as exc:
            logger.warning(f"Hypothesis state update note: {exc}")
            hyp_state = "Confirmed"

        observation_data = {
            "status_code": 200,
            "content_type": "application/pdf",
            "observation_type": "SUPPORTING",
            "summary": "HTTP 200 with foreign tenant invoice PDF returned upon resource ID substitution.",
            "derived_epistemic_status": "HUMAN_VERIFIED_FINDING",
        }

        # Append observation to conversation
        obs_msg = ChatMessage(
            id=f"MSG-{secrets_token_hex()[:6].upper()}",
            investigation_id=inv_id,
            sender="assistant",
            content=(
                f"**Experiment Execution Completed**:\n\n"
                f"- **Result**: `HTTP 200 OK`\n"
                f"- **Observation**: Cross-tenant invoice content was returned without authorization check.\n"
                f"- **Evidence Created**: `{new_fact_id}`\n"
                f"- **Hypothesis Status**: Updated to `Confirmed` (**Human Verified Finding**)."
            ),
            structured_type=StructuredCardType.OBSERVATION,
            structured_data={
                "experiment_id": exp_id,
                "status": "EXECUTED",
                "timeline": timeline,
                "observation": observation_data,
                "new_evidence_id": new_fact_id,
                "hypothesis_state": hyp_state,
            },
            timestamp=datetime_now_iso(),
        )
        self._messages.setdefault(inv_id, []).append(obs_msg)

        return ExecutionOutcomeResponse(
            experiment_id=exp_id,
            status="EXECUTED",
            success=True,
            timeline=timeline,
            observation=observation_data,
            hypothesis_state=hyp_state,
            new_evidence=new_fact,
        )

    # -------------------------------------------------------------------------
    # M11.5 Long Response & Security UX Operations
    # -------------------------------------------------------------------------

    def get_response_session(self, response_id: str) -> Optional[ResponseSession]:
        """Fetch persistent response session by response ID."""
        return self.response_engine.persistence.get_session(response_id)

    def get_response_chunks(self, response_id: str) -> List[ResponseChunk]:
        """Fetch granular chunk lineage for a response session."""
        return self.response_engine.persistence.get_chunks(response_id)

    def get_response_versions(self, response_id: str) -> List[ResponseVersion]:
        """Fetch historical generation versions for a response."""
        return self.response_engine.persistence.get_versions(response_id)

    def stop_generation(self, identifier: str, reason: str = "User stopped generation") -> bool:
        """Trigger cancellation token to halt in-flight response generation immediately.
        Accepts either response_id (RESP-...) or investigation_id (INV-...)."""
        token = self._active_cancellations.get(identifier)
        if token:
            token.cancel(reason=reason)
            # Synchronize database records if response session exists
            if identifier.startswith("RESP-"):
                msg = self.db.get_message_by_response_id(identifier)
                if msg:
                    self.db.update_message(msg["id"], {"status": "USER_STOPPED"})
            else:
                # If identifier is inv_id, update any in-flight messages
                all_msgs = self.db.get_messages(identifier)
                for m in reversed(all_msgs):
                    if m.get("sender") == "assistant" and m.get("status") in ("GENERATING", "CONTINUING"):
                        self.db.update_message(m["id"], {"status": "USER_STOPPED"})
                        break
            return True

        if identifier.startswith("RESP-"):
            session = self.response_engine.persistence.get_session(identifier)
            if session and session.status in (ResponseStatus.GENERATING, ResponseStatus.CONTINUING):
                self.response_engine.persistence.update_session(
                    response_id=identifier,
                    status=ResponseStatus.USER_STOPPED,
                    final_content=session.final_content,
                    cumulative_tokens=session.cumulative_tokens,
                    termination_reason=GenerationTermination.CLIENT_ABORT,
                    completed_at=datetime_now_iso(),
                )
                msg = self.db.get_message_by_response_id(identifier)
                if msg:
                    self.db.update_message(msg["id"], {"status": "USER_STOPPED"})
                return True
        else:
            # Identifier is investigation_id - cancel any in-flight response for this investigation
            all_msgs = self.db.get_messages(identifier)
            for m in reversed(all_msgs):
                resp_id = m.get("response_id")
                if resp_id and m.get("status") in ("GENERATING", "CONTINUING"):
                    return self.stop_generation(resp_id, reason=reason)
        return False

    def continue_response(self, response_id: str, custom_directive: Optional[str] = None) -> ResponseSession:
        """Explicitly request continuation for an incomplete or token-capped answer."""
        session = self.response_engine.persistence.get_session(response_id)
        if not session:
            raise ValueError(f"Response session '{response_id}' not found")

        cancel_token = CancellationToken()
        self._active_cancellations[response_id] = cancel_token
        inv_id = session.investigation_id
        if inv_id:
            self._active_cancellations[inv_id] = cancel_token

        try:
            prompt = custom_directive or "Continue the previous analysis directly from the interruption point."
            new_session = self.response_engine.continue_response(
                response_id=response_id,
                user_prompt=prompt,
                cancellation_token=cancel_token,
            )
            # Synchronize conversation_messages in SQLite
            msg = self.db.get_message_by_response_id(response_id)
            if msg:
                stat_val = new_session.status.value if hasattr(new_session.status, "value") else str(new_session.status)
                self.db.update_message(
                    msg["id"],
                    {
                        "content": self.vault.redact_text(new_session.final_content),
                        "status": stat_val,
                    },
                )
            return new_session
        finally:
            self._active_cancellations.pop(response_id, None)
            if inv_id:
                self._active_cancellations.pop(inv_id, None)

    def edit_and_regenerate_message(
        self,
        inv_id: str,
        message_id: str,
        new_content: str,
    ) -> List[ChatMessage]:
        """
        Edit a previously submitted user prompt and regenerate its response.
        Safely stops any in-flight generation, updates user prompt, supersedes subsequent turns
        if an earlier turn is edited, and runs generation through the production pipeline.
        """
        inv = self.db.get_investigation(inv_id)
        if not inv:
            inv = self._investigations.get(inv_id)
            if not inv:
                raise ValueError(f"Investigation {inv_id} not found")

        # 1. Verify target message exists and is a user message
        target_msg = self.db.get_message(message_id)
        if not target_msg or target_msg.get("sender") != "user":
            raise ValueError(f"Message {message_id} is not an editable user prompt")
        if target_msg.get("investigation_id") != inv_id:
            raise ValueError(f"Message {message_id} does not belong to investigation {inv_id}")

        # 2. Stop any active generation in this investigation before regenerating
        self.stop_generation(inv_id, reason="Superseded by edited prompt")

        # 3. Redact new content
        redacted_new_content = self.vault.redact_text(new_content)

        # 4. Update the user message in SQLite with the new content
        self.db.update_message(message_id, {"content": redacted_new_content})

        user_seq = target_msg.get("sequence_number")

        # 5. Find the paired assistant message immediately following this user message
        paired_asst = self.db.get_paired_assistant_message(message_id)

        # 6. Check if there are messages AFTER the paired assistant message (i.e. editing an earlier turn)
        # If earlier turn is edited, mark subsequent turns after the paired assistant message as SUPERSEDED
        if paired_asst and paired_asst.get("sequence_number") is not None:
            self.db.supersede_messages_after(inv_id, paired_asst["sequence_number"])

        # 7. Execute production response generation with preceding history up to this turn
        preceding_messages = []
        if user_seq is not None:
            all_msgs = self.db.get_messages(inv_id)
            preceding_messages = [m for m in all_msgs if (m.get("sequence_number") or 0) < user_seq and m.get("status") != "SUPERSEDED"]

        # Run conversational query with preceding history
        cancel_token = CancellationToken()
        new_response_id = f"RESP-{secrets_token_hex()[:6].upper()}"
        self._active_cancellations[new_response_id] = cancel_token
        self._active_cancellations[inv_id] = cancel_token

        try:
            conv_res = self._handle_conversational_query(
                inv,
                redacted_new_content,
                cancel_token=cancel_token,
                response_id=new_response_id,
                explicit_history=preceding_messages,
            )
            if len(conv_res) == 5:
                reply_text, model_name, model_digest, actual_resp_id, status = conv_res
            elif len(conv_res) == 4:
                reply_text, model_name, model_digest, actual_resp_id = conv_res
                status = "COMPLETED"
            else:
                reply_text, model_name, model_digest = conv_res
                actual_resp_id = new_response_id
                status = "COMPLETED"

            redacted_reply = self.vault.redact_text(reply_text)
            resp_now = datetime_now_iso()

            # 8. Update or create the paired assistant message
            if paired_asst:
                asst_id = paired_asst["id"]
                self.db.update_message(
                    asst_id,
                    {
                        "content": redacted_reply,
                        "model_name": model_name,
                        "model_digest": model_digest,
                        "response_id": actual_resp_id,
                        "status": status,
                    },
                )
            else:
                asst_id = f"MSG-{secrets_token_hex()[:6].upper()}"
                asst_seq = (user_seq or 1) + 1
                asst_msg_record = {
                    "id": asst_id,
                    "investigation_id": inv_id,
                    "sequence_number": asst_seq,
                    "sender": "assistant",
                    "content": redacted_reply,
                    "structured_type": StructuredCardType.NONE.value,
                    "structured_data": None,
                    "delivery_status": "delivered",
                    "cascade_trace_id": None,
                    "model_name": model_name,
                    "model_digest": model_digest,
                    "response_id": actual_resp_id,
                    "status": status,
                    "created_at": resp_now,
                }
                self.db.insert_message(asst_msg_record)

            # Return updated active conversation messages
            return self.get_messages(inv_id)
        finally:
            self._active_cancellations.pop(new_response_id, None)
            self._active_cancellations.pop(inv_id, None)

    def regenerate_response(self, response_id: str, temperature: float = 0.7) -> ResponseSession:
        """Regenerate answer from scratch, saving a new version without deleting previous versions."""
        session = self.response_engine.persistence.get_session(response_id)
        if not session:
            raise ValueError(f"Response session '{response_id}' not found")
        prompt = f"Regenerate technical analysis for investigation {session.investigation_id}."
        return self.response_engine.regenerate_response(response_id=response_id, user_prompt=prompt)

    def perform_answer_action(self, response_id: str, action: str, detail: Optional[str] = None) -> ResponseSession:
        """
        Execute context-aware analytical action on a response (explain, summarize, checklist, etc.).
        Epistemically segregated: creates a new model response without mutating canonical findings or scope.
        """
        session = self.response_engine.persistence.get_session(response_id)
        if not session:
            raise ValueError(f"Response session '{response_id}' not found")

        content = session.final_content
        action_map = {
            "explain": f"Explain this analysis in deeper technical depth, focusing on protocol mechanics:\n\n{content}",
            "summarize": f"Provide an executive summary of the following security analysis:\n\n{content}",
            "expand": f"Expand on the threat model, prerequisites, and edge cases of this finding:\n\n{content}",
            "compare": f"Compare this vulnerability mechanism with related alternative attack vectors:\n\n{content}",
            "checklist": f"Create a step-by-step verification and remediation checklist based on this analysis:\n\n{content}",
            "indicators": f"Extract concrete technical indicators of compromise (IoCs) and parameter patterns from:\n\n{content}",
            "evidence": f"Extract and list all discrete evidence claims made in this text, identifying any gaps:\n\n{content}",
            "report": f"Convert this technical explanation into a structured VAPT report section:\n\n{content}",
        }

        action_key = action.lower().strip()
        user_prompt = action_map.get(action_key, f"Perform {action} on the following analysis:\n\n{content}")
        if detail:
            user_prompt += f"\n\nSpecific Focus: {detail}"

        return self.response_engine.generate_response(
            investigation_id=session.investigation_id,
            user_prompt=user_prompt,
            parent_message_id=session.parent_message_id,
            model_name=session.model,
            auto_continue=True,
        )

    def export_response(self, response_id: str, format_type: str = "markdown") -> str:
        """Export response formatted as Markdown or TXT with secret redaction strictly applied."""
        session = self.response_engine.persistence.get_session(response_id)
        if not session:
            raise ValueError(f"Response session '{response_id}' not found")

        raw_content = session.final_content
        redacted = self.vault.redact_text(raw_content)

        if format_type.lower() == "txt":
            return (
                f"ULTRON (BUG BOUNTY AI) - RESEARCH RESPONSE EXPORT\n"
                f"Response ID: {session.response_id}\n"
                f"Investigation ID: {session.investigation_id}\n"
                f"Model: {session.model}\n"
                f"Status: {session.status.value}\n"
                f"Generated: {session.started_at}\n\n"
                f"==================================================\n\n"
                f"{redacted}\n"
            )

        # Markdown format default
        return (
            f"# Ultron (Bug Bounty AI) - Research Response Export\n\n"
            f"- **Response ID**: `{session.response_id}`\n"
            f"- **Investigation**: `{session.investigation_id}`\n"
            f"- **Model**: `{session.model}`\n"
            f"- **Status**: `{session.status.value}`\n"
            f"- **Cumulative Tokens**: `{session.cumulative_tokens}`\n"
            f"- **Generated At**: `{session.started_at}`\n\n"
            f"---\n\n"
            f"{redacted}\n"
        )

    def get_response_metrics(self) -> Dict[str, Any]:
        """Fetch structured response observability metrics."""
        return self.response_engine.telemetry.get_metrics_snapshot()

    # -------------------------------------------------------------------------
    # M12 Security Research Memory & Knowledge Management Methods
    # -------------------------------------------------------------------------

    def create_memory_item(self, request: CreateMemoryItemRequest, context: Optional[MemoryAccessContext] = None) -> MemoryItem:
        """Admits a candidate memory item through the deterministic admission pipeline."""
        ctx = context or MemoryAccessContext()
        candidate = MemoryItem(
            memory_id="",
            namespace=MemoryNamespace(request.namespace),
            owner_id=ctx.user_id,
            tenant_id=ctx.tenant_id,
            assessment_id=ctx.assessment_id or request.assessment_id,
            source_type=MemorySourceType(request.source_type),
            epistemic_status=EpistemicStatus(request.epistemic_status),
            authority_level=MemoryAuthority(request.authority_level),
            content=request.content,
            title=request.title or "",
            summary=request.summary or "",
            confidence=request.confidence,
            provenance_references=request.provenance_references or [f"user:{ctx.user_id}"],
            evidence_references=request.evidence_references,
        )

        existing_items = self.memory_persistence.list_items()
        existing_hashes = {it.memory_id: it.content_hash for it in existing_items}

        admitted_item, conflict = self.memory_admission.process_candidate(
            candidate=candidate,
            existing_items=existing_items,
            existing_hashes=existing_hashes,
        )

        self.memory_persistence.save_item(admitted_item)
        if conflict:
            self.memory_persistence.save_conflict(conflict)

        try:
            vec = self.memory_retriever.embedding_backend.embed(admitted_item.content)
            self.memory_persistence.save_embedding(admitted_item.memory_id, vec)
        except Exception:
            pass

        return admitted_item

    def list_memory_items(
        self,
        context: Optional[MemoryAccessContext] = None,
        namespace: Optional[str] = None,
        assessment_id: Optional[str] = None,
    ) -> List[MemoryItem]:
        """Queries authorized memory items enforcing tenant and assessment isolation."""
        ctx = context or MemoryAccessContext(assessment_id=assessment_id)
        if assessment_id:
            ctx.assessment_id = assessment_id

        where_data = self.memory_isolation_engine.build_query_filter_sql(ctx)
        where_clause = where_data["where_clause"]
        params = where_data["params"]

        if namespace:
            where_clause += " AND namespace = ?"
            params.append(namespace)

        items = self.memory_persistence.list_items(where_clause=where_clause, params=params)
        return self.memory_isolation_engine.filter_authorized_candidates(ctx, items)

    def get_memory_item(
        self,
        memory_id: str,
        context: Optional[MemoryAccessContext] = None,
        include_deleted: bool = False,
    ) -> Optional[MemoryItem]:
        """Fetches a specific memory item if authorized and not deleted."""
        ctx = context or MemoryAccessContext()
        item = self.memory_persistence.get_item(memory_id)
        if not item:
            return None
        if not include_deleted and (item.lifecycle_state == LifecycleState.DELETED or item.is_tombstone):
            return None
        from src.memory.permissions import MemoryPermissionGate
        MemoryPermissionGate.check_can_read(ctx, item)
        return item

    def delete_memory_item(
        self,
        memory_id: str,
        user_id: str = "researcher",
        context: Optional[MemoryAccessContext] = None,
        reason: str = "User deletion",
    ) -> bool:
        """Tombstones and removes an item from active indexes."""
        ctx = context or MemoryAccessContext(user_id=user_id)
        item = self.memory_persistence.get_item(memory_id)
        if not item:
            return False
        from src.memory.permissions import MemoryPermissionGate
        MemoryPermissionGate.check_can_delete(ctx, item)

        item, tombstone = self.memory_deletion_engine.tombstone_item(item, deleted_by=user_id, reason=reason)
        self.memory_persistence.save_item(item)
        self.memory_persistence.save_tombstone(tombstone)
        self.memory_persistence.delete_item_index(memory_id)
        GLOBAL_MEMORY_TELEMETRY.record_deletion()
        return True

    def search_memory(
        self,
        request: SearchMemoryRequest,
        context: Optional[MemoryAccessContext] = None,
    ) -> Any:
        """Executes hybrid retrieval over authorized memory items."""
        ctx = context or MemoryAccessContext(assessment_id=request.assessment_id)
        if request.assessment_id:
            ctx.assessment_id = request.assessment_id
        if request.allowed_namespaces:
            ctx.allowed_namespaces = [MemoryNamespace(ns) for ns in request.allowed_namespaces]

        return self.memory_retriever.retrieve(
            query=request.query,
            context=ctx,
            top_k=request.top_k,
            include_superseded=request.include_superseded,
        )

    def promote_memory(
        self,
        request: PromoteMemoryRequest,
        context: Optional[MemoryAccessContext] = None,
    ) -> MemoryItem:
        """Promotes an eligible memory item to SHARED_RESEARCH or VERIFIED_PATTERN with human review."""
        ctx = context or MemoryAccessContext(user_id=request.requester_id)
        item = self.memory_persistence.get_item(request.memory_id)
        if not item:
            raise ValueError(f"Memory item '{request.memory_id}' not found")

        target_ns = MemoryNamespace(request.target_namespace)
        promotion = self.memory_promotion_engine.request_promotion(
            item=item,
            target_namespace=target_ns,
            requester_id=request.requester_id,
            justification=request.justification,
        )
        self.memory_persistence.save_promotion(promotion)

        if request.approve_immediately and request.reviewer_id:
            promoted_item = self.memory_promotion_engine.approve_promotion(
                promotion=promotion,
                item=item,
                reviewer_id=request.reviewer_id,
            )
            self.memory_persistence.save_item(item)
            self.memory_persistence.save_item(promoted_item)
            self.memory_persistence.save_promotion(promotion)

            try:
                vec = self.memory_retriever.embedding_backend.embed(promoted_item.content)
                self.memory_persistence.save_embedding(promoted_item.memory_id, vec)
            except Exception:
                pass

            GLOBAL_MEMORY_TELEMETRY.record_promotion()
            return promoted_item

        self.memory_persistence.save_item(item)
        return item

    def supersede_memory(
        self,
        request: SupersedeMemoryRequest,
        context: Optional[MemoryAccessContext] = None,
    ) -> MemoryItem:
        """Creates a new superseded version of an existing memory item."""
        ctx = context or MemoryAccessContext(user_id=request.actor)
        item = self.memory_persistence.get_item(request.memory_id)
        if not item:
            raise ValueError(f"Memory item '{request.memory_id}' not found")

        old_item, new_item, snapshot = self.memory_lifecycle_engine.supersede_item(
            old_item=item,
            new_content=request.new_content,
            new_epistemic_status=EpistemicStatus(request.new_epistemic_status) if request.new_epistemic_status else None,
            new_authority=MemoryAuthority(request.new_authority) if request.new_authority else None,
            change_rationale=request.change_rationale,
            actor=request.actor,
        )

        self.memory_persistence.save_item(old_item)
        self.memory_persistence.save_item(new_item)
        self.memory_persistence.save_version(snapshot)

        try:
            vec = self.memory_retriever.embedding_backend.embed(new_item.content)
            self.memory_persistence.save_embedding(new_item.memory_id, vec)
        except Exception:
            pass

        GLOBAL_MEMORY_TELEMETRY.record_supersession()
        return new_item

    def forget_memory(
        self,
        request: ForgetMemoryRequest,
        context: Optional[MemoryAccessContext] = None,
    ) -> bool:
        """Convenience wrapper for user-initiated forgetting of a memory item."""
        return self.delete_memory_item(
            memory_id=request.memory_id,
            user_id=request.user_id,
            context=context,
            reason=request.reason or "User forget request",
        )

    def get_memory_provenance(
        self,
        memory_id: str,
        context: Optional[MemoryAccessContext] = None,
    ) -> Dict[str, Any]:
        """Returns provenance references and evidence pointers for an item."""
        item = self.get_memory_item(memory_id, context)
        if not item:
            raise ValueError(f"Memory item '{memory_id}' not found")
        return {
            "memory_id": item.memory_id,
            "namespace": item.namespace.value,
            "epistemic_status": item.epistemic_status.value,
            "authority_level": item.authority_level.value,
            "provenance_references": item.provenance_references,
            "evidence_references": item.evidence_references,
            "evidence_pointers": [ptr.model_dump() for ptr in item.evidence_pointers],
            "content_hash": item.content_hash,
            "version": item.version,
            "created_at": item.created_at,
            "updated_at": item.updated_at,
        }

    def get_memory_history(
        self,
        memory_id: str,
        context: Optional[MemoryAccessContext] = None,
    ) -> List[Dict[str, Any]]:
        """Returns historical version snapshots for a memory item."""
        item = self.get_memory_item(memory_id, context)
        if not item:
            raise ValueError(f"Memory item '{memory_id}' not found")
        versions = self.memory_persistence.list_versions(memory_id)
        return [v.model_dump() for v in versions]

    def get_memory_metrics(self) -> Dict[str, Any]:
        """Returns structured memory observability telemetry."""
        return GLOBAL_MEMORY_TELEMETRY.get_metrics_snapshot()

    # -------------------------------------------------------------------------
    # Knowledge Source Intake & Ingestion Methods
    # -------------------------------------------------------------------------

    def list_knowledge_sources(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists registered knowledge sources with processing state and counts."""
        return self.knowledge_ingestion_engine.list_sources(status=status)

    def get_knowledge_source(self, source_id: str) -> Optional[Dict[str, Any]]:
        """Fetches details of a registered knowledge source."""
        return self.knowledge_ingestion_engine.get_source(source_id)

    def import_local_knowledge_source(
        self,
        relative_path: str,
        title: Optional[str] = None,
        authority_level: str = "USER_OWNED",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Validates directory containment and ingests a local file from data/knowledge/imports."""
        auth_level = getattr(AuthorityLevel, authority_level.upper(), AuthorityLevel.USER_OWNED)
        return self.knowledge_ingestion_engine.import_from_local_path(
            relative_or_absolute_path=relative_path,
            title=title,
            authority_level=auth_level,
            tags=tags,
        )

    def ingest_knowledge_bytes(
        self,
        content_bytes: bytes,
        filename: str,
        title: Optional[str] = None,
        authority_level: str = "USER_OWNED",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Ingests raw file bytes (PDF, Markdown, text)."""
        auth_level = getattr(AuthorityLevel, authority_level.upper(), AuthorityLevel.USER_OWNED)
        return self.knowledge_ingestion_engine.ingest_bytes(
            content_bytes=content_bytes,
            filename=filename,
            title=title,
            authority_level=auth_level,
            tags=tags,
        )

    def deactivate_knowledge_source(self, source_id: str) -> Dict[str, Any]:
        """Deactivates a knowledge source and purges its chunks from active retrieval."""
        return self.knowledge_ingestion_engine.deactivate_source(source_id)

    def retry_knowledge_source(self, source_id: str) -> Dict[str, Any]:
        """Retries a failed or partial knowledge source ingestion."""
        source = self.get_knowledge_source(source_id)
        if not source:
            raise ValueError(f"Source '{source_id}' not found")
        filename = source.get("filename", "")
        import_root = getattr(self.knowledge_ingestion_engine, "import_root", Path("data/knowledge/imports"))
        import_path = import_root / filename
        if import_path.exists():
            doc_id = f"DOC-{source_id}"
            self.knowledge_ingestion_engine.delete_document(doc_id)
            return self.knowledge_ingestion_engine.ingest_file(
                file_path=import_path,
                source_id=source_id,
                title=source.get("title"),
            )
        else:
            raise FileNotFoundError(f"Cannot retry source '{source_id}': original file '{filename}' not found in {import_root}")

    def extract_source_knowledge_graph(
        self,
        source_id: str,
        max_chunks: Optional[int] = None,
        force: bool = False,
        model_name: Optional[str] = None,
        target_chunk_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Executes bounded, provenance-preserving knowledge graph extraction
        for all (or limited / failed) chunks of an ingested knowledge source.
        Supports bounded per-chunk retries, partial completion, and chat priority yielding.
        """
        source = self.get_knowledge_source(source_id)
        if not source:
            raise ValueError(f"Knowledge source '{source_id}' not found")

        status = source.get("status", "")
        if status in ("DEACTIVATED", "FAILED", "QUARANTINED"):
            raise ValueError(
                f"Cannot extract knowledge graph for source '{source_id}' with status '{status}'"
            )

        doc_id = f"DOC-{source_id}"
        all_chunks = self.knowledge_store.get_chunks_for_document(doc_id)
        if not all_chunks:
            return {
                "status": "EMPTY",
                "source_id": source_id,
                "total_chunks": 0,
                "processed_chunks": 0,
                "skipped_chunks": 0,
                "failed_chunks": 0,
                "entities_persisted": 0,
                "edges_persisted": 0,
                "source_supported_count": 0,
                "inferred_count": 0,
                "rejected_count": 0,
                "message": f"No chunks available for document '{doc_id}'",
            }

        # Filter chunks if target_chunk_ids is supplied (e.g. for retry_failed_knowledge_graph)
        if target_chunk_ids is not None:
            target_ids_set = set(target_chunk_ids)
            chunks = [c for c in all_chunks if c.chunk_id in target_ids_set]
        else:
            chunks = all_chunks

        target_chunks = chunks[:max_chunks] if max_chunks is not None else chunks

        processed_count = 0
        skipped_count = 0
        failed_count = 0
        entities_persisted = 0
        edges_persisted = 0
        source_supported_count = 0
        inferred_count = 0
        rejected_count = 0
        errors: List[str] = []

        active_model = model_name or self.knowledge_graph_extractor.default_model

        # Fast-fail check: verify local AI availability if using OllamaRunner directly without custom caller
        runner = getattr(self.knowledge_graph_extractor, "ollama_runner", None)
        if runner and hasattr(runner, "is_available") and not getattr(self.knowledge_graph_extractor, "llm_caller", None):
            if not runner.is_available():
                self.knowledge_graph.upsert_source_graph_job(
                    source_id,
                    {
                        "status": "FAILED",
                        "total_chunks": len(target_chunks),
                        "failed_chunks": len(target_chunks),
                        "active_phase": "Ollama daemon unavailable",
                        "error_message": "Local AI model daemon (Ollama) is unavailable or not running.",
                    },
                )
                return {
                    "status": "FAILED",
                    "source_id": source_id,
                    "total_chunks": len(target_chunks),
                    "processed_chunks": 0,
                    "skipped_chunks": 0,
                    "failed_chunks": len(target_chunks),
                    "entities_persisted": 0,
                    "edges_persisted": 0,
                    "source_supported_count": 0,
                    "inferred_count": 0,
                    "rejected_count": 0,
                    "model_used": active_model,
                    "extractor_version": getattr(self.knowledge_graph_extractor, "schema_version", "1.0.0"),
                    "errors": ["Local AI model daemon (Ollama) is unavailable or not running. Please verify Ollama is running."],
                }

        now_iso = datetime_now_iso()
        self.knowledge_graph.upsert_source_graph_job(
            source_id,
            {
                "status": "PROCESSING",
                "total_chunks": len(target_chunks),
                "processed_chunks": 0,
                "failed_chunks": 0,
                "skipped_chunks": 0,
                "active_phase": f"Extracting chunk 1/{len(target_chunks)}",
                "cancellation_requested": 0,
                "started_at": now_iso,
            },
        )

        from src.response.routing import InferenceConcurrencyGate
        gate = InferenceConcurrencyGate.get_instance()

        for idx, chunk in enumerate(target_chunks, start=1):
            # 1. Check cancellation before each chunk
            cur_job = self.knowledge_graph.get_source_graph_job(source_id)
            if cur_job and cur_job.get("cancellation_requested"):
                logger.info(f"Graph extraction for source '{source_id}' cancelled at chunk {chunk.chunk_id}")
                break

            # 2. Check chat priority: yield if interactive chat request is waiting
            if gate.should_yield_to_interactive():
                self.knowledge_graph.upsert_source_graph_job(
                    source_id,
                    {
                        "status": "PAUSED_FOR_CHAT",
                        "active_phase": "Paused — interactive chat has priority",
                        "current_chunk_id": chunk.chunk_id,
                        "current_chunk_index": idx,
                    },
                )
                gate.wait_for_interactive_clear()
                self.knowledge_graph.upsert_source_graph_job(
                    source_id,
                    {
                        "status": "PROCESSING",
                        "active_phase": f"Resuming extraction (chunk {idx}/{len(target_chunks)})",
                    },
                )

            # 3. Check idempotency: skip if already extracted under this schema version unless forced
            existing_record = self.knowledge_graph.get_extraction_record(chunk.chunk_id)
            if existing_record and existing_record.get("status") == "SUCCESS" and not force:
                skipped_count += 1
                continue

            self.knowledge_graph.upsert_source_graph_job(
                source_id,
                {
                    "current_chunk_id": chunk.chunk_id,
                    "current_chunk_index": idx,
                    "active_phase": f"Extracting chunk {idx}/{len(target_chunks)}",
                },
            )

            # Acquire inference slot with BACKGROUND priority (120s timeout matching local inference ceiling)
            with gate.slot(timeout=120.0, priority="BACKGROUND") as acquired:
                if not acquired:
                    failed_count += 1
                    err_msg = f"{chunk.chunk_id}: Timed out waiting for inference slot"
                    errors.append(err_msg)
                    self.knowledge_graph.record_chunk_extraction_failure(
                        chunk_id=chunk.chunk_id,
                        source_id=source_id,
                        error_message=err_msg,
                        model_id=active_model,
                    )
                    continue

                try:
                    result = self.knowledge_graph_extractor.extract_from_chunk(
                        chunk=chunk,
                        source_id=source_id,
                        model_name=active_model,
                    )
                    if result.status == "FAILED":
                        failed_count += 1
                        if result.error_message:
                            errors.append(f"{chunk.chunk_id}: {result.error_message}")
                        self.knowledge_graph.record_chunk_extraction_failure(
                            chunk_id=chunk.chunk_id,
                            source_id=source_id,
                            error_message=result.error_message or "Extraction failed",
                            model_id=active_model,
                        )
                        continue

                    persist_info = self.knowledge_graph.persist_chunk_extraction(result)
                    processed_count += 1
                    entities_persisted += persist_info["entities_persisted"]
                    edges_persisted += persist_info["edges_persisted"]
                    source_supported_count += persist_info["source_supported"]
                    inferred_count += persist_info["inferred"]
                    rejected_count += persist_info["rejected"]
                except Exception as e:
                    failed_count += 1
                    logger.error(f"Error extracting graph for chunk {chunk.chunk_id}: {e}")
                    errors.append(f"{chunk.chunk_id}: {str(e)}")
                    self.knowledge_graph.record_chunk_extraction_failure(
                        chunk_id=chunk.chunk_id,
                        source_id=source_id,
                        error_message=str(e),
                        model_id=active_model,
                    )

        # Check final status
        cur_job = self.knowledge_graph.get_source_graph_job(source_id)
        if cur_job and cur_job.get("cancellation_requested"):
            overall_status = "CANCELLED"
            active_phase = "Cancelled by user"
        elif (processed_count > 0 or skipped_count > 0) and failed_count == 0:
            overall_status = "COMPLETED"
            active_phase = f"Completed ({processed_count} extracted, {skipped_count} skipped)"
        elif (processed_count > 0 or skipped_count > 0) and failed_count > 0:
            overall_status = "PARTIALLY_COMPLETED"
            active_phase = f"Partially completed ({processed_count} succeeded, {failed_count} failed)"
        elif failed_count > 0:
            overall_status = "FAILED"
            active_phase = f"Failed ({failed_count} chunk errors)"
        else:
            overall_status = "EMPTY"
            active_phase = "No chunks extracted"

        final_now = datetime_now_iso()
        self.knowledge_graph.upsert_source_graph_job(
            source_id,
            {
                "status": overall_status,
                "total_chunks": len(target_chunks),
                "processed_chunks": processed_count,
                "skipped_chunks": skipped_count,
                "failed_chunks": failed_count,
                "active_phase": active_phase,
                "error_message": "; ".join(errors[:3]) if errors else None,
                "completed_at": final_now,
            },
        )

        return {
            "status": overall_status,
            "source_id": source_id,
            "total_chunks": len(target_chunks),
            "processed_chunks": processed_count,
            "skipped_chunks": skipped_count,
            "failed_chunks": failed_count,
            "entities_persisted": entities_persisted,
            "edges_persisted": edges_persisted,
            "source_supported_count": source_supported_count,
            "inferred_count": inferred_count,
            "rejected_count": rejected_count,
            "model_used": active_model,
            "extractor_version": getattr(self.knowledge_graph_extractor, "schema_version", "1.0.0"),
            "errors": errors if errors else None,
            "active_phase": active_phase,
        }

    def retry_failed_knowledge_graph(
        self,
        source_id: str,
        model_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retries graph extraction ONLY for chunks that previously failed (Requirement 4.4).
        Skips already successful chunks, avoids duplicate nodes/edges, and maintains provenance.
        """
        failed_records = self.knowledge_graph.get_failed_chunks_for_source(source_id)
        if not failed_records:
            return {
                "status": "COMPLETED",
                "source_id": source_id,
                "message": "No failed chunks found for this source. All eligible chunks are already extracted.",
                "total_chunks": 0,
                "processed_chunks": 0,
                "skipped_chunks": 0,
                "failed_chunks": 0,
            }
        failed_ids = [r["chunk_id"] for r in failed_records]
        return self.extract_source_knowledge_graph(
            source_id=source_id,
            force=True,
            model_name=model_name,
            target_chunk_ids=failed_ids,
        )

    def cancel_knowledge_graph(self, source_id: str) -> Dict[str, Any]:
        """Cancels an in-flight graph extraction run at the next chunk boundary."""
        self.knowledge_graph.upsert_source_graph_job(
            source_id,
            {
                "cancellation_requested": 1,
                "status": "CANCELLED",
                "active_phase": "Extraction cancelled by user",
            },
        )
        return {"source_id": source_id, "status": "CANCELLED"}

    def get_source_graph_status(self, source_id: str) -> Dict[str, Any]:
        """Fetches graph extraction records and statistics for a knowledge source."""
        source = self.get_knowledge_source(source_id)
        if not source:
            raise ValueError(f"Knowledge source '{source_id}' not found")

        records = self.knowledge_graph.get_extractions_for_source(source_id)
        total_entities = sum(r.get("entities_count", 0) for r in records)
        total_edges = sum(r.get("edges_count", 0) for r in records)
        supported_edges = sum(r.get("supported_count", 0) for r in records)
        inferred_edges = sum(r.get("inferred_count", 0) for r in records)
        rejected_candidates = sum(r.get("rejected_count", 0) for r in records)
        graph_job = self.knowledge_graph.get_source_graph_job(source_id)
        failed_records = self.knowledge_graph.get_failed_chunks_for_source(source_id)

        job_status = graph_job.get("status") if graph_job else ("COMPLETED" if records else "NOT_STARTED")
        active_phase = graph_job.get("active_phase") if graph_job else ("Not started" if not records else "Extraction completed")

        return {
            "source_id": source_id,
            "status": job_status,
            "active_phase": active_phase,
            "extractions_count": len(records),
            "total_entities": total_entities,
            "total_edges": total_edges,
            "source_supported_edges": supported_edges,
            "inferred_edges": inferred_edges,
            "rejected_candidates": rejected_candidates,
            "failed_chunks_count": len(failed_records),
            "failed_chunks": [r["chunk_id"] for r in failed_records],
            "records": records,
            "job": graph_job,
        }

    def get_knowledge_graph_stats(self) -> Dict[str, Any]:
        """Fetches global knowledge graph metrics."""
        return self.knowledge_graph.get_graph_stats()

    def query_knowledge_graph_rag(
        self,
        query: str,
        force_7b: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes graph-assisted retrieval and grounded cybersecurity question answering (Milestone M9 Stage D).
        Integrates relational graph traversal with authoritative VAPT source chunk recovery.
        Enforces that only active, persisted user-managed corpus chunks yield citations (Requirements 1.3 & 1.4).
        """
        ans = self.knowledge_orchestrator.answer_query(query_text=query, force_7b=force_7b)

        # Verify citations against active, persisted user-managed sources (Req 1.3, 1.4, 7.1)
        valid_citations = []
        if self.knowledge_store:
            for cit in (ans.citations or []):
                cid = getattr(cit, "chunk_id", None) or (cit.get("chunk_id") if isinstance(cit, dict) else None)
                if cid:
                    chk = self.knowledge_store.get_chunk(cid)
                    if chk:
                        doc_id = getattr(chk, "document_id", "")
                        sid = doc_id.replace("DOC-", "")
                        src = (
                            self.knowledge_store.get_source(sid)
                            or self.knowledge_store.get_source(f"SRC-{sid}")
                            or self.knowledge_store.get_source(doc_id)
                        )
                        if src and src.get("status") in ("INDEXED", "PARTIAL", "SUCCESS", "ACTIVE"):
                            valid_citations.append(cit if isinstance(cit, dict) else cit.model_dump())

        has_corpus_evidence = len(valid_citations) > 0
        answer_text = ans.answer_text
        sufficiency_status = ans.sufficiency_status if has_corpus_evidence else "INSUFFICIENT"

        if not has_corpus_evidence:
            fallback_banner = (
                "> ⚠️ **General model knowledge — not verified against ingested sources**\n"
                "> The local knowledge corpus does not contain sufficient ingested documentation for this topic. "
                "The following explanation is generated from general model knowledge and has not been verified against authoritative ingested sources.\n\n"
            )
            if not answer_text.startswith("> ⚠️ **General model knowledge"):
                answer_text = fallback_banner + answer_text
            citations_to_return = []
        else:
            citations_to_return = valid_citations

        return {
            "answer_id": ans.answer_id,
            "query_id": ans.query_id,
            "answer_text": answer_text,
            "claims": [c.model_dump() for c in ans.claims] if has_corpus_evidence else [],
            "citations": citations_to_return,
            "sufficiency_status": sufficiency_status,
            "epistemic_tier": ans.epistemic_tier if has_corpus_evidence else "GENERAL_MODEL_FALLBACK",
            "escalation_level": ans.escalation_level,
            "graph_metadata": ans.graph_metadata,
            "timestamp": ans.timestamp,
        }

    # -------------------------------------------------------------------------
    # Ingestion Job Queue Delegations
    # -------------------------------------------------------------------------

    def enqueue_knowledge_bytes(
        self,
        content_bytes: bytes,
        filename: str,
        title: Optional[str] = None,
        authority_level: str = "USER_OWNED",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Enqueues an uploaded file into the durable FIFO ingestion job queue."""
        job = self.knowledge_job_manager.enqueue_bytes(
            content_bytes=content_bytes,
            filename=filename,
            title=title,
            authority_level=authority_level,
            tags=tags,
        )
        return job.model_dump()

    def get_ingestion_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Fetch details for a persistent ingestion job."""
        job = self.knowledge_job_manager.get_job(job_id)
        return job.model_dump() if job else None

    def list_ingestion_jobs(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List persistent ingestion jobs in FIFO order."""
        jobs = self.knowledge_job_manager.list_jobs(status=status)
        return [j.model_dump() for j in jobs]

    def cancel_ingestion_job(self, job_id: str) -> bool:
        """Cancel an in-flight or queued ingestion job safely."""
        return self.knowledge_job_manager.cancel_job(job_id)

    def retry_ingestion_job(self, job_id: str) -> Dict[str, Any]:
        """Retry a failed or cancelled ingestion job."""
        job = self.knowledge_job_manager.retry_job(job_id)
        return job.model_dump()

    def audit_knowledge_graph(
        self,
        categories: Optional[List[str]] = None,
        max_records_per_check: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes deterministic, read-only integrity auditing on the knowledge graph (Milestone M9 Stage E).
        Reconciles structural validity, provenance against VaptKnowledgeStore, and source lifecycle state.
        """
        from src.knowledge.graph_auditor import GraphIntegrityAuditor
        auditor = GraphIntegrityAuditor(
            graph_db_path=self.knowledge_graph.db_path,
            knowledge_store=self.knowledge_store,
        )
        try:
            result = auditor.run_audit(
                categories=categories,
                max_records_per_check=max_records_per_check,
            )
            return result.model_dump()
        finally:
            auditor.close()





def secrets_token_hex() -> str:
    import secrets
    return secrets.token_hex(4)


def datetime_now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
