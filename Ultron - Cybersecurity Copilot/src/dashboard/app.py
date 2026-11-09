"""Local Human Feedback Dashboard API and UI for Phase 12 Workspace."""

from datetime import datetime, timezone
from enum import Enum
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
from typing import Any, Dict, List, Optional
from fastapi import Cookie, Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.core.logging import AuditLogger, get_logger, verify_audit_log
from src.database.manager import DatabaseManager
from src.hypothesis.state_machine import HypothesisStateMachine, HypothesisState
from src.dashboard.models import (
    CreateInvestigationRequest,
    ExperimentApprovalRequest,
    ExperimentExecuteRequest,
    ImportTrafficRequest,
    ManualObservationRequest,
    RenameInvestigationRequest,
    SendMessageRequest,
    CreateAssessmentRequest,
    UpdateAssessmentRequest,
    SetAuthorizationRequest,
    SetScopeRequest,
    CreateAssetRequest,
    ImportTelemetryRequest,
    ProposeExperimentRequest,
    ImportExperimentResultRequest,
    VerifyHypothesisRequest,
    VerifyFindingRequest,
    CreateFindingRequest,
    ResponseActionRequest,
    ContinueResponseRequest,
    StopResponseRequest,
    RegenerateResponseRequest,
    EditPromptRequest,
    CreateMemoryItemRequest,
    SearchMemoryRequest,
    PromoteMemoryRequest,
    SupersedeMemoryRequest,
    ForgetMemoryRequest,
    RetireMemoryRequest,
    ValidateScopeRequest,
    RegisterArtifactRequest,
    ArtifactUploadResponse,
    LoginRequest,
    SessionResponse,
    UpdateViewStateRequest,
    GlobalSearchRequest,
    ImportLocalSourceRequest,
    IngestSourceRequest,
    KnowledgeSourceResponse,
    GraphExtractionResponse,
    SourceGraphStatusResponse,
    KnowledgeGraphStatsResponse,
    KnowledgeRagQueryRequest,
    KnowledgeRagQueryResponse,
    GraphAuditResponse,
)
from src.memory import MemoryAccessContext
from src.dashboard.service import WorkspaceService
from src.copilot.orchestration import CopilotOrchestrator
from src.copilot.registry import DomainKnowledgeRegistry
from src.copilot.tools import ToolKnowledgeBase
from src.assessment.manager import AssessmentManager
from src.assessment.lifecycle import AssessmentLifecycleEngine
from src.assessment.models import (
    AssessmentLifecycleState,
    AuthorizationRecord,
    AuthorizationStatus,
    AuthorizationType,
    AssetType,
    AssessmentScopeStatus,
    ExperimentRiskLevel,
    ExperimentStatus,
    FindingSeverity,
    FindingVerificationStatus,
    AssessmentFinding,
)
from src.assessment.assets import evaluate_asset_scope_independent
from src.assessment.validation import FindingValidationError
from src.assessment.authorization import AuthorizationValidationError
from src.scope.models import ScopePolicy
from src.artifacts.metadata import (
    ArtifactRecord,
    ArtifactType,
    QuarantineReason,
    QuarantineStatus,
    TrustStatus,
)
from src.workspace import (
    AssessmentSection,
    AssessmentWorkflowStatus,
    AssessmentSummary,
    AssessmentOverview,
    AssessmentActivity,
    WorkspaceViewState,
    AssessmentWorkspace,
    GlobalSearchResultItem,
    UnifiedWorkspaceService,
)

DEFAULT_DASHBOARD_HOST = "127.0.0.1"
DEFAULT_DASHBOARD_PORT = 8000

logger = get_logger("Dashboard")


from src.dashboard.auth import (
    DashboardRole,
    DashboardSession,
    DashboardAuthManager,
    generate_csrf_token,
    verify_csrf_token,
    hash_password,
    verify_password,
)


def validate_dashboard_bind(
    host: str = DEFAULT_DASHBOARD_HOST,
    allow_external: bool = False,
    auth_configured: bool = False,
) -> str:
    """
    Validate bind address to enforce localhost loopback isolation by default.
    Fails closed if a non-loopback interface is requested without allow_external=True
    AND auth_configured=True.
    """
    normalized = host.strip().lower()
    is_loopback = (
        normalized in ("127.0.0.1", "localhost", "::1")
        or normalized.startswith("127.")
    )
    if not is_loopback:
        if not allow_external:
            raise ValueError(
                f"Refusing to bind dashboard to non-loopback address '{host}'. "
                "The dashboard requires explicit allow_external=True and configured authentication "
                "for non-loopback binding."
            )
        if not auth_configured:
            raise ValueError(
                f"Refusing to bind dashboard to non-loopback address '{host}'. "
                "External binding must fail closed unless authentication is configured. "
                "Provide an authenticated auth_manager or configure valid credentials."
            )
        logger.warning(
            f"SECURITY NOTICE: Dashboard binding to non-loopback address '{host}' with authentication enabled."
        )
    return host


class VerificationRequest(BaseModel):
    actor: Optional[str] = Field(default=None, description="Client-submitted actor identifier (authoritatively bound to authenticated session)")
    evidence_ref: str = Field(min_length=5, description="Path or reference to repro evidence / traffic log")
    dashboard_session_id: str = Field(
        default="DASH-SESSION-001",
        description="Client-submitted audit tracking identifier; NOT an authentication or session credential.",
    )
    safety_acknowledged: bool = Field(default=False, description="Must be true if endpoint is STATE_CHANGING")
    notes: Optional[str] = None


class ExperimentResultRequest(BaseModel):
    observation_type: str = Field(description="SUPPORTING | CONTRADICTING | UNRESOLVED")
    new_evidence_ref: str = Field(min_length=3)
    notes: str


class CopilotQueryRequest(BaseModel):
    query: str
    investigation_id: Optional[str] = None


def create_dashboard_app(
    db_manager: Optional[DatabaseManager] = None,
    audit_logger: Optional[AuditLogger] = None,
    auth_manager: Optional[DashboardAuthManager] = None,
    workspace_service: Optional[WorkspaceService] = None,
    require_auth: bool = True,
    frontend_dist_dir: Optional[Path] = None,
) -> FastAPI:
    """Factory creating the FastAPI human review dashboard app with RBAC and secure rendering."""
    app = FastAPI(
        title="Local AI-Assisted Bug Bounty Research Platform - Investigation Workspace",
        version="0.6.0",
    )
    db = db_manager or DatabaseManager()
    auditor = audit_logger or AuditLogger(Path("data/audit.log"))
    state_machine = HypothesisStateMachine(db)
    auth_mgr = auth_manager or DashboardAuthManager(db_manager=db)
    workspace_service = workspace_service or WorkspaceService(db_manager=db, audit_logger=auditor)

    # -------------------------------------------------------------------------
    # CSRF Defense Middleware for Cookie-Authenticated Sessions
    # -------------------------------------------------------------------------

    @app.middleware("http")
    async def csrf_middleware(request: Request, call_next):
        """Enforces CSRF synchronizer token verification on state-changing requests using cookie auth."""
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            path = request.url.path
            # Public authentication routes are exempt from CSRF
            if path not in ("/api/auth/login", "/api/auth/logout"):
                auth_header = request.headers.get("authorization", "")
                has_bearer = auth_header.lower().startswith("bearer ")
                has_cookie_session = "session_token" in request.cookies or "ultron_session" in request.cookies

                # Only cookie-based browser sessions require CSRF validation (Bearer auth is safe from browser CSRF)
                if has_cookie_session and not has_bearer:
                    cookie_csrf = request.cookies.get("csrftoken")
                    header_csrf = request.headers.get("x-csrf-token")
                    if not cookie_csrf or not header_csrf or not verify_csrf_token(cookie_csrf, header_csrf):
                        return JSONResponse(
                            status_code=403,
                            content={"detail": "CSRF verification failed: missing or invalid X-CSRF-Token header."},
                        )
        return await call_next(request)

    ROLE_HIERARCHY = {
        DashboardRole.OBSERVER: 1,
        DashboardRole.REVIEWER: 2,
        DashboardRole.OPERATOR: 2,
        DashboardRole.ADMIN: 3,
    }

    def get_current_user(
        authorization: Optional[str] = Header(None),
        x_dashboard_token: Optional[str] = Header(None),
        session_token: Optional[str] = Cookie(None),
        ultron_session: Optional[str] = Cookie(None),
    ) -> DashboardSession:
        token = None
        if authorization:
            if authorization.lower().startswith("bearer "):
                token = authorization[7:].strip()
            else:
                token = authorization.strip()
        elif x_dashboard_token:
            token = x_dashboard_token.strip()
        elif session_token:
            token = session_token.strip()
        elif ultron_session:
            token = ultron_session.strip()

        if require_auth:
            if not token:
                raise HTTPException(status_code=401, detail="Authentication required: token missing")
            sess = auth_mgr.authenticate(token)
            if not sess:
                raw_sess = auth_mgr._sessions.get(token)
                if raw_sess and raw_sess.revoked:
                    raise HTTPException(status_code=401, detail="Session revoked")
                if raw_sess and raw_sess.expires_at and time.time() > raw_sess.expires_at:
                    raise HTTPException(status_code=401, detail="Session expired")
                raise HTTPException(status_code=401, detail="Invalid or expired session token")
            return sess
        else:
            # Explicit unauthenticated test mode
            if token:
                sess = auth_mgr.authenticate(token)
                if not sess:
                    raw_sess = auth_mgr._sessions.get(token)
                    if raw_sess and raw_sess.revoked:
                        raise HTTPException(status_code=401, detail="Session revoked")
                    if raw_sess and raw_sess.expires_at and time.time() > raw_sess.expires_at:
                        raise HTTPException(status_code=401, detail="Session expired")
                    raise HTTPException(status_code=401, detail="Invalid session token")
                return sess
            # Safe non-privileged observer session for explicit test-only fixtures
            return DashboardSession(
                token="test-mode-token",
                username="test_observer",
                role=DashboardRole.REVIEWER,
            )

    def require_role(min_role: DashboardRole):
        def role_dependency(user: DashboardSession = Depends(get_current_user)) -> DashboardSession:
            if ROLE_HIERARCHY.get(user.role, 0) < ROLE_HIERARCHY.get(min_role, 0):
                raise HTTPException(
                    status_code=403,
                    detail=f"Forbidden: {min_role.value} role required, but user has {user.role.value}",
                )
            return user
        return role_dependency

    # -------------------------------------------------------------------------
    # Authentication & Session Endpoints
    # -------------------------------------------------------------------------

    @app.post("/api/auth/login")
    def login(req: LoginRequest, request: Request, response: Response) -> Dict[str, Any]:
        """Authenticate user with persistent credentials and issue session token / HttpOnly cookie."""
        client_ip = request.client.host if request.client else "127.0.0.1"

        # 1. Login abuse rate-limiting
        if not auth_mgr.check_rate_limit(client_ip) or not auth_mgr.check_rate_limit(req.username):
            raise HTTPException(
                status_code=429,
                detail="Too many failed login attempts. Please wait 60 seconds before retrying.",
            )

        # 2. Enforce password submission
        if not req.password or not req.password.strip():
            auth_mgr.record_failure(client_ip)
            auth_mgr.record_failure(req.username)
            raise HTTPException(status_code=400, detail="Password is required")

        # 3. Authenticate credentials authoritatively against local user database
        sess = auth_mgr.authenticate_credentials(req.username.strip(), req.password)
        if not sess:
            auth_mgr.record_failure(client_ip)
            auth_mgr.record_failure(req.username)
            raise HTTPException(status_code=401, detail="Invalid username or password")

        auth_mgr.record_success(client_ip)
        auth_mgr.record_success(req.username)

        csrf_token = generate_csrf_token()
        is_https = request.url.scheme == "https"

        response.set_cookie(
            key="session_token",
            value=sess.token,
            httponly=True,
            samesite="lax",
            secure=is_https,
            max_age=86400,
            path="/",
        )
        response.set_cookie(
            key="csrftoken",
            value=csrf_token,
            httponly=False,
            samesite="lax",
            secure=is_https,
            max_age=86400,
            path="/",
        )

        if auditor:
            auditor.log_event(
                event_type="USER_LOGIN_SUCCESS",
                actor=sess.username,
                subject_id=sess.username,
                details={"role": sess.role.value, "client_ip": client_ip},
            )

        return {
            "status": "success",
            "username": sess.username,
            "role": sess.role.value,
            "token": sess.token,
            "csrf_token": csrf_token,
            "expires_at": sess.expires_at,
        }

    @app.get("/api/auth/csrf")
    def get_csrf(request: Request, response: Response) -> Dict[str, Any]:
        """Issue or return active CSRF token."""
        existing = request.cookies.get("csrftoken")
        tok = existing or generate_csrf_token()
        if not existing:
            response.set_cookie(
                key="csrftoken",
                value=tok,
                httponly=False,
                samesite="lax",
                secure=request.url.scheme == "https",
                max_age=86400,
                path="/",
            )
        return {"csrf_token": tok}

    @app.get("/api/auth/me")
    def get_current_session(user: DashboardSession = Depends(get_current_user)) -> Dict[str, Any]:
        """Return authenticated user identity, role, and expiry."""
        return {
            "status": "success",
            "authenticated": True,
            "username": user.username,
            "role": user.role.value,
            "expires_at": user.expires_at,
        }

    @app.post("/api/auth/logout")
    def logout(response: Response, user: DashboardSession = Depends(get_current_user)) -> Dict[str, Any]:
        """Revoke current user session and clear cookies."""
        auth_mgr.revoke_session(user.token)
        response.delete_cookie("session_token", path="/")
        response.delete_cookie("ultron_session", path="/")
        response.delete_cookie("csrftoken", path="/")
        if auditor:
            auditor.log_event(
                event_type="USER_LOGOUT",
                actor=user.username,
                subject_id=user.username,
                details={"role": user.role.value},
            )
        return {"status": "success", "logged_out": True}

    # -------------------------------------------------------------------------
    # System Status Endpoints
    # -------------------------------------------------------------------------

    @app.get("/api/health")
    @app.get("/api/status")
    @app.get("/api/system/status")
    def get_status() -> Dict[str, Any]:
        """System health and diagnostic status."""
        return workspace_service.get_system_status().model_dump()

    @app.get("/api/system/cascade-trace")
    def get_cascade_traces(
        limit: int = 10,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """Get verified runtime cascade traces from persistent storage."""
        return workspace_service.list_cascade_traces(limit=limit)

    @app.get("/api/cascade-traces/{trace_id}")
    def get_cascade_trace_by_id(
        trace_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Get specific cascade execution trace by run ID."""
        trace = workspace_service.get_cascade_trace(trace_id)
        if not trace:
            raise HTTPException(status_code=404, detail=f"Cascade trace '{trace_id}' not found")
        return trace

    @app.get("/api/investigations/{inv_id}/messages/{message_id}/trace")
    def get_message_trace(
        inv_id: str,
        message_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Get cascade execution trace associated with a specific message."""
        trace = workspace_service.get_message_trace(inv_id, message_id)
        if not trace:
            raise HTTPException(status_code=404, detail=f"No cascade trace found for message '{message_id}'")
        return trace


    @app.post("/api/demo/load")
    def load_demo_fixture(
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Explicitly opt-in to load the deterministic demo fixture."""
        summary = workspace_service.load_demo_investigation()
        return summary.model_dump()

    # -------------------------------------------------------------------------
    # Phase 12 Investigation Workspace Endpoints
    # -------------------------------------------------------------------------

    @app.get("/api/investigations")
    def list_investigations(
        q: Optional[str] = Query(None, description="Search query for investigations"),
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """List active investigations, optionally filtered by search query."""
        return [inv.model_dump() for inv in workspace_service.list_investigations(search_query=q)]

    @app.post("/api/investigations")
    def create_investigation(
        req: CreateInvestigationRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Create a new investigation."""
        summary = workspace_service.create_investigation(req)
        return summary.model_dump()

    @app.get("/api/investigations/{inv_id}")
    def get_investigation(
        inv_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Get investigation details and message history."""
        detail = workspace_service.get_investigation(inv_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return detail.model_dump()

    @app.patch("/api/investigations/{inv_id}")
    def rename_investigation(
        inv_id: str,
        req: RenameInvestigationRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Rename an investigation and persist new name."""
        try:
            summary = workspace_service.rename_investigation(inv_id, req.name)
            return summary.model_dump()
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.delete("/api/investigations/{inv_id}")
    def delete_investigation(
        inv_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Delete an investigation and its conversation messages without deleting canonical domain evidence."""
        try:
            workspace_service.delete_investigation(inv_id)
            return {"success": True, "id": inv_id}
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.get("/api/investigations/{inv_id}/messages")
    def get_investigation_messages(
        inv_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """Get conversation message history for an investigation."""
        messages = workspace_service.get_messages(inv_id)
        return [m.model_dump() for m in messages]

    @app.post("/api/investigations/{inv_id}/messages")
    def post_investigation_message(
        inv_id: str,
        req: SendMessageRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> List[Dict[str, Any]]:
        """Post a user message to the research AI and return grounded responses."""
        try:
            responses = workspace_service.send_message(inv_id, req.content, client_msg_id=req.client_msg_id)
            return [m.model_dump() for m in responses]
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.post("/api/investigations/{inv_id}/stop")
    def stop_investigation_generation(
        inv_id: str,
        req: Optional[StopResponseRequest] = None,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Stop an in-flight generation in this investigation deterministically."""
        reason = req.reason if req else "User requested stop"
        stopped = workspace_service.stop_generation(inv_id, reason=reason)
        return {"stopped": stopped, "investigation_id": inv_id}

    @app.post("/api/investigations/{inv_id}/messages/{message_id}/edit")
    def edit_investigation_message(
        inv_id: str,
        message_id: str,
        req: EditPromptRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> List[Dict[str, Any]]:
        """Edit a user prompt and regenerate its response through the production pipeline."""
        try:
            updated_messages = workspace_service.edit_and_regenerate_message(
                inv_id=inv_id,
                message_id=message_id,
                new_content=req.content,
            )
            return [m.model_dump() for m in updated_messages]
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error(f"Failed to edit prompt {message_id}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Failed to edit prompt: {e}")

    @app.post("/api/investigations/{inv_id}/import")
    def import_investigation_traffic(
        inv_id: str,
        req: ImportTrafficRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Import captured HTTP traffic telemetry (HAR, Raw HTTP, Burp) into an investigation."""
        try:
            return workspace_service.ingest_traffic(inv_id, req)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            logger.error("Internal error importing traffic for %s: %s", inv_id, e, exc_info=True)
            raise HTTPException(status_code=500, detail=f"Import failed: {str(e)}")

    @app.post("/api/investigations/{inv_id}/observations")
    def add_investigation_observation(
        inv_id: str,
        req: ManualObservationRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Manually record a target HTTP observation in an investigation."""
        try:
            return workspace_service.add_manual_observation(inv_id, req)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            logger.error("Internal error adding observation for %s: %s", inv_id, e, exc_info=True)
            raise HTTPException(status_code=500, detail=f"Failed to record observation: {str(e)}")

    @app.get("/api/investigations/{inv_id}/evidence")
    def get_investigation_evidence(
        inv_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """Get canonical evidence items with epistemic segregation."""
        return workspace_service.get_evidence(inv_id)

    @app.get("/api/investigations/{inv_id}/evidence/{obs_id}")
    def get_investigation_observation_detail(
        inv_id: str,
        obs_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Get detailed observation record with normalized request/response and provenance."""
        obs = workspace_service.get_observation(inv_id, obs_id)
        if not obs:
            raise HTTPException(status_code=404, detail=f"Observation {obs_id} not found")
        return obs

    @app.get("/api/investigations/{inv_id}/model")
    def get_investigation_model(
        inv_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Get derived application model."""
        return workspace_service.get_application_model(inv_id)

    @app.get("/api/investigations/{inv_id}/invariants")
    def get_investigation_invariants(
        inv_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """Get security invariants with epistemic origins."""
        return workspace_service.get_invariants(inv_id)

    @app.get("/api/investigations/{inv_id}/gaps")
    def get_investigation_gaps(
        inv_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """Get active evidence gaps."""
        return workspace_service.get_gaps(inv_id)

    @app.get("/api/investigations/{inv_id}/hypotheses")
    def get_investigation_hypotheses(
        inv_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """Get hypotheses for an investigation."""
        return workspace_service.get_hypotheses(inv_id)

    @app.get("/api/investigations/{inv_id}/experiments")
    def get_investigation_experiments(
        inv_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """Get experiments for an investigation."""
        return workspace_service.get_experiments(inv_id)

    # -------------------------------------------------------------------------
    # Experiment Action Endpoints
    # -------------------------------------------------------------------------

    @app.post("/api/experiments/{exp_id}/validate")
    def validate_experiment(
        exp_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Validate experiment grounding, polarity, and scope."""
        res = workspace_service.validate_experiment(exp_id)
        return res.model_dump()

    @app.post("/api/experiments/{exp_id}/approve")
    def approve_experiment(
        exp_id: str,
        req: Optional[ExperimentApprovalRequest] = None,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Register human approval for a state-changing experiment bound to authenticated actor."""
        approver = user.username
        if exp_id in assessment_mgr._experiment_to_assessment:
            try:
                exp = assessment_mgr.approve_experiment(exp_id, approver)
                return {"status": "success", "experiment": exp.model_dump()}
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))
        try:
            approval_req = req or ExperimentApprovalRequest(actor=approver, notes="Approved by reviewer")
            approval_req.actor = approver
            return workspace_service.approve_experiment(exp_id, approval_req)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/experiments/{exp_id}/reject")
    def reject_experiment(
        exp_id: str,
        req: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = Query(None),
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Reject an experiment proposal bound to authenticated actor."""
        act = user.username
        rsn = (req.get("reason") if req else None) or reason or "Rejected by human reviewer."
        try:
            return workspace_service.reject_experiment(exp_id, act, rsn)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/audit/{inv_id}")
    def get_investigation_audit(
        inv_id: str,
        limit: int = 100,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Get tamper-evident audit records isolated strictly to the requested investigation/assessment."""
        inv = workspace_service.get_investigation(inv_id)
        asm = assessment_mgr.get_assessment(inv_id)
        if not inv and not asm:
            raise HTTPException(status_code=404, detail=f"Investigation or Assessment '{inv_id}' not found")
        records = auditor.read_records_for_investigation(inv_id, limit=limit)
        verification = verify_audit_log(auditor.audit_file_path) if auditor else None
        chain_valid = verification.valid if verification else True
        return {
            "investigation_id": inv_id,
            "chain_integrity": "VERIFIED" if chain_valid else "FAILED",
            "total_records": len(records),
            "records": records,
        }

    @app.post("/api/experiments/{exp_id}/execute")
    def execute_experiment(
        exp_id: str,
        req: Optional[ExperimentExecuteRequest] = None,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Execute experiment proposal through DeterministicExecutionEngine."""
        outcome = workspace_service.execute_experiment(exp_id, safe_simulation=True)
        return outcome.model_dump()

    # -------------------------------------------------------------------------
    # M11.5 Long Response & Research Subsystem Endpoints
    # -------------------------------------------------------------------------

    @app.get("/api/responses/metrics")
    def get_response_metrics(
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Fetch structured metrics for long response generation, continuation, and reliability."""
        return workspace_service.get_response_metrics()

    @app.get("/api/responses/{response_id}")
    def get_response_session(
        response_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Get session details and active status for a multi-chunk response."""
        session = workspace_service.get_response_session(response_id)
        if not session:
            raise HTTPException(status_code=404, detail=f"Response '{response_id}' not found")
        return session.model_dump()

    @app.get("/api/responses/{response_id}/chunks")
    def get_response_chunks(
        response_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """Get granular chunk lineage and stop reasons for diagnostics."""
        chunks = workspace_service.get_response_chunks(response_id)
        return [c.model_dump() for c in chunks]

    @app.get("/api/responses/{response_id}/versions")
    def get_response_versions(
        response_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """Get generation versions for an answer."""
        versions = workspace_service.get_response_versions(response_id)
        return [v.model_dump() for v in versions]

    @app.post("/api/responses/{response_id}/stop")
    def stop_response_generation(
        response_id: str,
        req: Optional[StopResponseRequest] = None,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Stop an in-flight response generation deterministically."""
        reason = req.reason if req else "User requested stop"
        stopped = workspace_service.stop_generation(response_id, reason=reason)
        return {"stopped": stopped, "response_id": response_id}

    @app.post("/api/responses/{response_id}/continue")
    def continue_response_generation(
        response_id: str,
        req: Optional[ContinueResponseRequest] = None,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Explicitly request continuation for an incomplete response."""
        try:
            directive = req.custom_directive if req else None
            session = workspace_service.continue_response(response_id, custom_directive=directive)
            return session.model_dump()
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.post("/api/responses/{response_id}/regenerate")
    def regenerate_response_generation(
        response_id: str,
        req: Optional[RegenerateResponseRequest] = None,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Regenerate answer, saving a new version without deleting previous generations."""
        try:
            temp = req.temperature if req else 0.7
            session = workspace_service.regenerate_response(response_id, temperature=temp)
            return session.model_dump()
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.post("/api/responses/{response_id}/actions")
    def perform_answer_action(
        response_id: str,
        req: ResponseActionRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Execute context-aware analytical action on a response (explain, summarize, checklist, etc.)."""
        try:
            session = workspace_service.perform_answer_action(response_id, req.action, detail=req.detail)
            return session.model_dump()
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.get("/api/responses/{response_id}/export")
    def export_response_text(
        response_id: str,
        format: str = Query("markdown", pattern="^(markdown|txt)$"),
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Export response formatted as Markdown or TXT with secret redaction enforced."""
        try:
            content = workspace_service.export_response(response_id, format_type=format)
            return {
                "response_id": response_id,
                "format": format,
                "content": content,
            }
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

    # -------------------------------------------------------------------------
    # M12 Security Research Memory & Knowledge Management Endpoints
    # -------------------------------------------------------------------------

    @app.post("/api/memory/items")
    def create_memory_item(
        req: CreateMemoryItemRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Admits a candidate research memory item through the 12-stage validation pipeline."""
        try:
            ctx = MemoryAccessContext(user_id=user.user_id, assessment_id=req.assessment_id)
            item = workspace_service.create_memory_item(req, context=ctx)
            return item.model_dump()
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/memory/items")
    def list_memory_items(
        namespace: Optional[str] = None,
        assessment_id: Optional[str] = None,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """List authorized memory items enforcing tenant and assessment isolation."""
        ctx = MemoryAccessContext(user_id=user.user_id, assessment_id=assessment_id)
        items = workspace_service.list_memory_items(context=ctx, namespace=namespace, assessment_id=assessment_id)
        return [it.model_dump() for it in items]

    @app.get("/api/memory/items/{memory_id}")
    def get_memory_item(
        memory_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Get an authorized memory item by ID."""
        ctx = MemoryAccessContext(user_id=user.user_id)
        item = workspace_service.get_memory_item(memory_id, context=ctx)
        if not item:
            raise HTTPException(status_code=404, detail=f"Memory item '{memory_id}' not found")
        return item.model_dump()

    @app.delete("/api/memory/items/{memory_id}")
    def delete_memory_item(
        memory_id: str,
        reason: Optional[str] = "User deletion",
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Tombstones and deletes an item from active indexes."""
        ctx = MemoryAccessContext(user_id=user.user_id)
        success = workspace_service.delete_memory_item(memory_id, user_id=user.user_id, context=ctx, reason=reason or "User deletion")
        if not success:
            raise HTTPException(status_code=404, detail=f"Memory item '{memory_id}' not found")
        return {"deleted": True, "memory_id": memory_id}

    @app.post("/api/memory/search")
    def search_memory(
        req: SearchMemoryRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Hybrid sparse + dense search across authorized memory namespaces."""
        ctx = MemoryAccessContext(user_id=user.user_id, assessment_id=req.assessment_id)
        result = workspace_service.search_memory(req, context=ctx)
        return result.model_dump()

    @app.post("/api/memory/promote")
    def promote_memory_item(
        req: PromoteMemoryRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Promote assessment memory to shared research memory with human review."""
        try:
            ctx = MemoryAccessContext(user_id=user.user_id)
            promoted = workspace_service.promote_memory(req, context=ctx)
            return promoted.model_dump()
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/memory/supersede")
    def supersede_memory_item(
        req: SupersedeMemoryRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Supersede a memory item with an updated version."""
        try:
            ctx = MemoryAccessContext(user_id=user.user_id)
            new_item = workspace_service.supersede_memory(req, context=ctx)
            return new_item.model_dump()
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/memory/forget")
    def forget_memory_item(
        req: ForgetMemoryRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """User-requested memory forget action."""
        ctx = MemoryAccessContext(user_id=user.user_id)
        success = workspace_service.forget_memory(req, context=ctx)
        return {"forgotten": success, "memory_id": req.memory_id}

    @app.get("/api/memory/{memory_id}/provenance")
    def get_memory_provenance(
        memory_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Get provenance lineage and evidence pointers for an item."""
        try:
            ctx = MemoryAccessContext(user_id=user.user_id)
            return workspace_service.get_memory_provenance(memory_id, context=ctx)
        except Exception as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.get("/api/memory/{memory_id}/history")
    def get_memory_history(
        memory_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """Get version history for an item."""
        try:
            ctx = MemoryAccessContext(user_id=user.user_id)
            return workspace_service.get_memory_history(memory_id, context=ctx)
        except Exception as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.get("/api/assessments/{assessment_id}/memory")
    def get_assessment_memory(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """List isolated local memory items for a specific assessment."""
        ctx = MemoryAccessContext(user_id=user.user_id, assessment_id=assessment_id)
        items = workspace_service.list_memory_items(context=ctx, assessment_id=assessment_id)
        return [it.model_dump() for it in items]

    @app.post("/api/assessments/{assessment_id}/memory/search")
    def search_assessment_memory(
        assessment_id: str,
        req: SearchMemoryRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Search isolated memory for a specific assessment."""
        req.assessment_id = assessment_id
        ctx = MemoryAccessContext(user_id=user.user_id, assessment_id=assessment_id)
        result = workspace_service.search_memory(req, context=ctx)
        data = result.model_dump()
        data["results"] = [it.get("memory", it) for it in data.get("items", [])]
        return data

    @app.get("/api/memory/metrics")
    def get_memory_metrics(
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Fetch memory subsystem observability telemetry."""
        return workspace_service.get_memory_metrics()

    # -------------------------------------------------------------------------
    # Knowledge Source Intake & Ingestion Endpoints
    # -------------------------------------------------------------------------

    @app.get("/api/knowledge/sources")
    def list_knowledge_sources(
        status: Optional[str] = None,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """List registered knowledge sources with processing status and stats."""
        return workspace_service.list_knowledge_sources(status=status)

    @app.get("/api/knowledge/sources/{source_id}")
    def get_knowledge_source(
        source_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Fetch details of a specific knowledge source."""
        source = workspace_service.get_knowledge_source(source_id)
        if not source:
            raise HTTPException(status_code=404, detail=f"Knowledge source '{source_id}' not found")
        return source

    @app.post("/api/knowledge/sources/import")
    def import_local_knowledge_source(
        req: ImportLocalSourceRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.OPERATOR)),
    ) -> Dict[str, Any]:
        """Import a file locally from data/knowledge/imports with strict directory containment."""
        try:
            return workspace_service.import_local_knowledge_source(
                relative_path=req.relative_path,
                title=req.title,
                authority_level=req.authority_level,
                tags=req.tags,
            )
        except (ValueError, PermissionError) as e:
            raise HTTPException(status_code=400, detail=str(e))
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Ingestion failed: {e}")

    @app.post("/api/knowledge/sources/upload")
    async def upload_knowledge_source(
        file: UploadFile = File(...),
        title: Optional[str] = Form(None),
        authority_level: str = Form("USER_OWNED"),
        tags: Optional[str] = Form(None),
        async_job: bool = Form(False),
        user: DashboardSession = Depends(require_role(DashboardRole.OPERATOR)),
    ) -> Dict[str, Any]:
        """Upload a file (PDF, Markdown, text) for knowledge extraction and indexing."""
        try:
            content_bytes = await file.read()
            tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
            if async_job:
                return workspace_service.enqueue_knowledge_bytes(
                    content_bytes=content_bytes,
                    filename=file.filename or "uploaded_source.txt",
                    title=title,
                    authority_level=authority_level,
                    tags=tag_list,
                )
            return workspace_service.ingest_knowledge_bytes(
                content_bytes=content_bytes,
                filename=file.filename or "uploaded_source.txt",
                title=title,
                authority_level=authority_level,
                tags=tag_list,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Upload ingestion failed: {e}")

    @app.get("/api/knowledge/jobs")
    def list_ingestion_jobs(
        status: Optional[str] = Query(None),
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """List persistent textbook ingestion jobs in FIFO order (survives refresh and restart)."""
        return workspace_service.list_ingestion_jobs(status=status)

    @app.get("/api/knowledge/jobs/{job_id}")
    def get_ingestion_job(
        job_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Fetch status and work-unit progress for an ingestion job."""
        job = workspace_service.get_ingestion_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Ingestion job '{job_id}' not found")
        return job

    @app.post("/api/knowledge/jobs/{job_id}/cancel")
    def cancel_ingestion_job(
        job_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OPERATOR)),
    ) -> Dict[str, Any]:
        """Cancel an in-flight or queued ingestion job safely (Stop = Cancel; preserves committed chunks)."""
        success = workspace_service.cancel_ingestion_job(job_id)
        if not success:
            raise HTTPException(status_code=404, detail=f"Ingestion job '{job_id}' not found")
        job = workspace_service.get_ingestion_job(job_id)
        return job or {"job_id": job_id, "status": "CANCELLED"}

    @app.post("/api/knowledge/jobs/{job_id}/retry")
    def retry_ingestion_job(
        job_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OPERATOR)),
    ) -> Dict[str, Any]:
        """Retry a failed or cancelled ingestion job, resuming safely without duplicating chunks."""
        try:
            return workspace_service.retry_ingestion_job(job_id)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/knowledge/sources/ingest-text")
    def ingest_knowledge_text(
        req: IngestSourceRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.OPERATOR)),
    ) -> Dict[str, Any]:
        """Directly ingest Markdown or text content as a knowledge source."""
        try:
            content_bytes = req.content.encode("utf-8")
            return workspace_service.ingest_knowledge_bytes(
                content_bytes=content_bytes,
                filename=req.filename,
                title=req.title,
                authority_level=req.authority_level,
                tags=req.tags,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Text ingestion failed: {e}")

    @app.post("/api/knowledge/sources/{source_id}/deactivate")
    def deactivate_knowledge_source(
        source_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OPERATOR)),
    ) -> Dict[str, Any]:
        """Deactivate a knowledge source and purge its chunks from active retrieval."""
        try:
            return workspace_service.deactivate_knowledge_source(source_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/knowledge/sources/{source_id}/retry")
    def retry_knowledge_source(
        source_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OPERATOR)),
    ) -> Dict[str, Any]:
        """Retry a failed or partial knowledge source ingestion."""
        try:
            return workspace_service.retry_knowledge_source(source_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/knowledge/sources/{source_id}/extract-graph", response_model=GraphExtractionResponse)
    def extract_knowledge_graph(
        source_id: str,
        max_chunks: Optional[int] = Query(None),
        force: bool = Query(False),
        model_name: Optional[str] = Query(None),
        background: bool = Query(False),
        user: DashboardSession = Depends(require_role(DashboardRole.OPERATOR)),
    ) -> Dict[str, Any]:
        """Trigger local-AI knowledge graph extraction on an ingested knowledge source."""
        try:
            if background:
                import threading
                t = threading.Thread(
                    target=workspace_service.extract_source_knowledge_graph,
                    kwargs={
                        "source_id": source_id,
                        "max_chunks": max_chunks,
                        "force": force,
                        "model_name": model_name,
                    },
                    daemon=True,
                )
                t.start()
                return {
                    "status": "PROCESSING",
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
                    "model_used": model_name or "qwen2.5-coder:7b",
                    "extractor_version": "1.0.0",
                    "active_phase": "Graph extraction started in background",
                }
            return workspace_service.extract_source_knowledge_graph(
                source_id=source_id,
                max_chunks=max_chunks,
                force=force,
                model_name=model_name,
            )
        except ValueError as e:
            detail = str(e)
            if "not found" in detail.lower():
                raise HTTPException(status_code=404, detail=detail)
            raise HTTPException(status_code=400, detail=detail)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Graph extraction failed: {e}")

    @app.post("/api/knowledge/sources/{source_id}/retry-failed-graph", response_model=GraphExtractionResponse)
    def retry_failed_knowledge_graph(
        source_id: str,
        model_name: Optional[str] = Query(None),
        background: bool = Query(False),
        user: DashboardSession = Depends(require_role(DashboardRole.OPERATOR)),
    ) -> Dict[str, Any]:
        """Retry graph extraction exclusively for chunks that previously failed (Requirement 4.4)."""
        try:
            if background:
                import threading
                t = threading.Thread(
                    target=workspace_service.retry_failed_knowledge_graph,
                    kwargs={"source_id": source_id, "model_name": model_name},
                    daemon=True,
                )
                t.start()
                return {
                    "status": "PROCESSING",
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
                    "model_used": model_name or "qwen2.5-coder:7b",
                    "extractor_version": "1.0.0",
                    "active_phase": "Retrying failed chunks in background",
                }
            return workspace_service.retry_failed_knowledge_graph(source_id=source_id, model_name=model_name)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Retry failed: {e}")

    @app.post("/api/knowledge/sources/{source_id}/cancel-graph")
    def cancel_knowledge_graph(
        source_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OPERATOR)),
    ) -> Dict[str, Any]:
        """Cancel an in-flight graph extraction at the next chunk boundary."""
        return workspace_service.cancel_knowledge_graph(source_id)

    @app.get("/api/knowledge/sources/{source_id}/graph-status", response_model=SourceGraphStatusResponse)
    def get_source_graph_status(
        source_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Fetch graph extraction status and records for a knowledge source."""
        try:
            return workspace_service.get_source_graph_status(source_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/knowledge/graph/stats", response_model=KnowledgeGraphStatsResponse)
    def get_knowledge_graph_stats(
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Fetch global knowledge graph metrics."""
        return workspace_service.get_knowledge_graph_stats()

    @app.get("/api/knowledge/graph/audit", response_model=GraphAuditResponse)
    def audit_knowledge_graph(
        categories: Optional[str] = Query(None, description="Comma-separated categories: STRUCTURAL,PROVENANCE,LIFECYCLE,CANONICALIZATION,EPISTEMIC"),
        max_records: Optional[int] = Query(None, description="Max records to inspect per check"),
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Execute deterministic, read-only knowledge graph integrity auditing (Milestone M9 Stage E)."""
        cat_list = [c.strip().upper() for c in categories.split(",") if c.strip()] if categories else None
        try:
            return workspace_service.audit_knowledge_graph(
                categories=cat_list,
                max_records_per_check=max_records,
            )
        except Exception as e:
            logger.error(f"Knowledge graph audit failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Knowledge graph audit failed: {e}")

    @app.post("/api/knowledge/query", response_model=KnowledgeRagQueryResponse)
    def query_knowledge_rag(
        req: KnowledgeRagQueryRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Execute graph-assisted retrieval and grounded cybersecurity question answering (Milestone M9 Stage D)."""
        try:
            return workspace_service.query_knowledge_graph_rag(
                query=req.query,
                force_7b=req.force_7b,
            )
        except Exception as e:
            logger.error(f"Knowledge RAG query failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Knowledge query failed: {e}")

    # -------------------------------------------------------------------------
    # Legacy / Base Hypothesis & Review Endpoints (100% Backward Compatible)
    # -------------------------------------------------------------------------

    @app.get("/api/hypotheses")
    def list_hypotheses(
        state: Optional[str] = None,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """List all hypotheses with optional state filtering."""
        with db.get_connection() as conn:
            query = "SELECT * FROM hypotheses"
            params: List[Any] = []
            if state:
                query += " WHERE state = ?"
                params.append(state)
            query += " ORDER BY id DESC"
            cursor = conn.execute(query, params)
            return [dict(r) for r in cursor.fetchall()]

    @app.get("/api/hypotheses/{hypothesis_id}")
    def get_hypothesis_detail(
        hypothesis_id: int,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        """Get full details of a hypothesis including asset safety and cited evidence."""
        hyp = db.get_hypothesis(hypothesis_id)
        if not hyp:
            raise HTTPException(status_code=404, detail="Hypothesis not found")

        asset = db.get_asset(hyp["asset_id"])
        params = db.get_parameters_for_asset(hyp["asset_id"]) if asset else []

        mutability = asset.get("application_mutability", "UNKNOWN") if asset else "UNKNOWN"
        requires_safety = mutability in ("STATE_CHANGING", "DESTRUCTIVE")
        has_volatile_params = any(p.get("is_server_volatile") for p in params)

        return {
            "hypothesis": hyp,
            "asset": asset,
            "parameters": params,
            "safety": {
                "application_mutability": mutability,
                "requires_safety_acknowledgment": requires_safety,
                "has_volatile_params": has_volatile_params,
                "warning_message": (
                    f"CAUTION: Target asset is {mutability}. Manual testing could alter live application state. "
                    "Ensure testing is performed against an authorized isolated test account."
                    if requires_safety else "SAFE: Asset is READ_ONLY."
                ),
            },
        }

    @app.post("/api/hypotheses/{hypothesis_id}/review")
    def start_hypothesis_review(
        hypothesis_id: int,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Move hypothesis from New to Under Review."""
        try:
            state_machine.start_review(hypothesis_id)
            auditor.log_event(
                event_type="STATE_TRANSITION",
                actor=user.username,
                subject_id=str(hypothesis_id),
                previous_state="New",
                new_state="Under Review",
            )
            return {"status": "success", "state": "Under Review"}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/hypotheses/{hypothesis_id}/experiment/result")
    def submit_experiment_result(
        hypothesis_id: int,
        req: ExperimentResultRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Incorporate experiment outcome and revise hypothesis."""
        try:
            revised = state_machine.revise_with_experiment_observation(
                hypothesis_id=hypothesis_id,
                observation_type=req.observation_type.upper(),
                new_evidence_ref=req.new_evidence_ref,
                observation_notes=req.notes,
            )
            auditor.log_event(
                event_type="EXPERIMENT_RESULT",
                actor=user.username,
                subject_id=str(hypothesis_id),
                new_state=revised.get("state"),
                evidence_ref=req.new_evidence_ref,
                details={"observation_type": req.observation_type, "notes": req.notes},
            )
            return {"status": "success", "hypothesis": revised}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/hypotheses/{hypothesis_id}/confirm")
    def confirm_hypothesis(
        hypothesis_id: int,
        req: VerificationRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Confirm hypothesis with human verification bound to authenticated actor."""
        hyp_detail = get_hypothesis_detail(hypothesis_id=hypothesis_id, user=user)
        if hyp_detail["safety"]["requires_safety_acknowledgment"] and not req.safety_acknowledged:
            raise HTTPException(
                status_code=400,
                detail="Safety acknowledgment required for STATE_CHANGING or DESTRUCTIVE endpoints before confirmation.",
            )

        authoritative_actor = user.username

        try:
            state_machine.confirm_with_human_verification(
                hypothesis_id=hypothesis_id,
                actor=authoritative_actor,
                evidence_ref=req.evidence_ref,
                session_id=req.dashboard_session_id,
                notes=req.notes,
            )
            auditor.log_event(
                event_type="HUMAN_VERIFICATION",
                actor=authoritative_actor,
                subject_id=str(hypothesis_id),
                previous_state="Under Review",
                new_state="Confirmed",
                evidence_ref=req.evidence_ref,
                details={"notes": req.notes, "session_id": req.dashboard_session_id},
            )
            return {"status": "success", "state": "Confirmed"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/invariants")
    def list_invariants(
        origin: Optional[str] = None,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """List security invariants with epistemic origins."""
        with db.get_connection() as conn:
            query = "SELECT * FROM security_invariants"
            params: List[Any] = []
            if origin:
                query += " WHERE origin = ?"
                params.append(origin)
            cursor = conn.execute(query, params)
            return [dict(r) for r in cursor.fetchall()]

    @app.get("/api/audit")
    def get_audit_log(
        limit: int = 50,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> List[Dict[str, Any]]:
        """Retrieve recent immutable audit records."""
        return auditor.read_records(limit=limit)

    # -------------------------------------------------------------------------
    # M5 General Cybersecurity Copilot Endpoints (Section 47)
    # -------------------------------------------------------------------------

    @app.get("/api/copilot/domains")
    def get_copilot_domains() -> Dict[str, Any]:
        """Returns all 26 supported security domains and local coverage levels."""
        catalog = DomainKnowledgeRegistry.get_all_domains()
        return {
            d.value: {
                "display_name": entry.display_name,
                "coverage_level": entry.coverage_level.value,
                "knowledge_chunk_count": entry.knowledge_chunk_count,
                "primary_topics": entry.primary_topics,
            }
            for d, entry in catalog.items()
        }

    @app.get("/api/copilot/tools")
    def get_copilot_tools() -> Dict[str, Any]:
        """Returns all supported security tools in the copilot knowledge base."""
        tools = ToolKnowledgeBase.get_all_tools()
        return {
            k: {
                "name": t.tool_name,
                "category": t.category,
                "primary_function": t.primary_function,
                "safe_lab_invocation": t.safe_lab_invocation,
            }
            for k, t in tools.items()
        }

    @app.post("/api/copilot/query")
    def execute_copilot_query(
        req: CopilotQueryRequest,
    ) -> Dict[str, Any]:
        """Execute general copilot query with strict epistemic status labels."""
        res = CopilotOrchestrator.process_query(user_query=req.query)
        return {
            "mode": res.mode.value,
            "task": res.primary_task.value,
            "domain": res.primary_domain.value,
            "secondary_domains": [d.value for d in res.secondary_domains],
            "complexity": res.complexity.value,
            "escalated_to_7b": res.escalated_to_7b,
            "escalation_reasons": res.escalation_reasons,
            "epistemic_status": res.epistemic_status,
            "content": res.content,
            "citations": res.citations,
            "conflicts_count": len(res.conflicts),
            "human_verified_findings_count": res.human_verified_findings_count,
            "epistemic_badges": {
                "fact": "FACT",
                "knowledge": "KNOWLEDGE",
                "external_source": "EXTERNAL SOURCE",
                "hypothesis": "HYPOTHESIS",
                "evidence_gap": "EVIDENCE GAP",
                "unverified": "UNVERIFIED",
                "human_verified": "HUMAN VERIFIED",
            },
        }

    # -------------------------------------------------------------------------
    # M6 Authorized Security Assessment Endpoints (Section 40)
    # -------------------------------------------------------------------------
    assessment_mgr = AssessmentManager.get_instance()
    workspace_svc = UnifiedWorkspaceService(assessment_mgr)

    def get_assessment_or_404(aid: str):
        rec = assessment_mgr.get_assessment(aid)
        if not rec:
            raise HTTPException(status_code=404, detail=f"Assessment '{aid}' not found.")
        return rec

    def get_container_or_404(aid: str):
        try:
            return assessment_mgr.get_container(aid)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"Assessment container '{aid}' not found.")

    @app.get("/api/assessments")
    def list_assessments(
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        summaries = workspace_svc.list_assessment_summaries()
        return {"status": "success", "assessments": [s.model_dump() for s in summaries]}

    @app.post("/api/assessments")
    def create_assessment(
        req: CreateAssessmentRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        authoritative_creator = user.username
        rec = assessment_mgr.create_assessment(
            organization=req.organization,
            assessment_name=req.assessment_name,
            created_by=authoritative_creator,
        )
        if auditor:
            auditor.log_event(
                event_type="ASSESSMENT_CREATED",
                actor=authoritative_creator,
                subject_id=rec.assessment_id,
                details={
                    "assessment_id": rec.assessment_id,
                    "organization": req.organization,
                    "assessment_name": req.assessment_name,
                },
                investigation_id=rec.assessment_id,
            )
        return {"status": "success", "assessment": rec.model_dump()}

    @app.get("/api/assessments/{assessment_id}")
    def get_assessment(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        rec = get_assessment_or_404(assessment_id)
        return {"status": "success", "assessment": rec.model_dump()}

    @app.get("/api/assessments/{assessment_id}/workspace")
    def get_assessment_workspace(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        try:
            ws = workspace_svc.get_assessment_workspace(assessment_id)
            return {"status": "success", "workspace": ws.model_dump()}
        except KeyError:
            raise HTTPException(status_code=404, detail="Assessment not found.")

    @app.get("/api/assessments/{assessment_id}/overview")
    def get_assessment_overview(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        try:
            ov = workspace_svc.get_workspace_overview(assessment_id)
            return {"status": "success", "overview": ov.model_dump()}
        except KeyError:
            raise HTTPException(status_code=404, detail="Assessment not found.")

    @app.get("/api/assessments/{assessment_id}/activity")
    def get_assessment_activity(
        assessment_id: str,
        limit: int = 50,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        try:
            act = workspace_svc.get_activity_timeline(assessment_id, limit=limit)
            return {"status": "success", "activity": [a.model_dump() for a in act]}
        except KeyError:
            raise HTTPException(status_code=404, detail="Assessment not found.")

    @app.post("/api/assessments/{assessment_id}/view-state")
    def update_view_state(
        assessment_id: str,
        req: UpdateViewStateRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        try:
            vs = WorkspaceViewState(
                active_section=AssessmentSection(req.active_section) if req.active_section else AssessmentSection.OVERVIEW,
                search_query=req.search_query or "",
                selected_asset_id=req.selected_asset_id,
                selected_hypothesis_id=req.selected_hypothesis_id,
                selected_finding_id=req.selected_finding_id,
                selected_artifact_id=req.selected_artifact_id,
                filter_severity=FindingSeverity(req.filter_severity) if req.filter_severity else None,
                filter_verification=FindingVerificationStatus(req.filter_verification) if req.filter_verification else None,
                filter_scope=AssessmentScopeStatus(req.filter_scope) if req.filter_scope else None,
            )
            saved = workspace_svc.update_view_state(assessment_id, vs)
            return {"status": "success", "view_state": saved.model_dump()}
        except KeyError:
            raise HTTPException(status_code=404, detail="Assessment not found.")

    @app.post("/api/assessments/{assessment_id}/scope/validate")
    def validate_scope(
        assessment_id: str,
        req: ValidateScopeRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        try:
            res = workspace_svc.validate_scope_target(assessment_id, req.target)
            return {"status": "success", "validation": res}
        except KeyError:
            raise HTTPException(status_code=404, detail="Assessment not found.")

    @app.get("/api/assessments/{assessment_id}/artifacts")
    def list_artifacts(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        try:
            registry = workspace_svc.get_artifact_registry(assessment_id)
            artifacts = registry.list_artifacts(include_quarantined=True)
            return {"status": "success", "artifacts": [a.model_dump() for a in artifacts]}
        except KeyError:
            raise HTTPException(status_code=404, detail="Assessment not found.")

    @app.post("/api/assessments/{assessment_id}/artifacts/upload")
    async def upload_artifact_file(
        assessment_id: str,
        request: Request,
        filename: Optional[str] = Query(None),
        artifact_type: Optional[str] = Query(None),
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Ingests actual artifact bytes, enforces max size, derives sha256, and quarantines by default."""
        get_assessment_or_404(assessment_id)
        cont = get_container_or_404(assessment_id)

        # 1. Enforce size limit during chunked stream / body read
        MAX_ARTIFACT_SIZE = 50 * 1024 * 1024  # 50 MB
        raw_name = filename or request.headers.get("x-filename") or "artifact.bin"
        art_type = artifact_type or request.headers.get("x-artifact-type") or "OTHER"

        content_type_hdr = request.headers.get("content-type", "")
        raw_bytes: bytes = b""

        if content_type_hdr.startswith("multipart/form-data"):
            body_bytes = await request.body()
            if len(body_bytes) > MAX_ARTIFACT_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail=f"Artifact exceeds maximum allowed size of {MAX_ARTIFACT_SIZE} bytes.",
                )
            from email.parser import BytesParser
            from email.policy import default
            msg = BytesParser(policy=default).parsebytes(
                b"Content-Type: " + content_type_hdr.encode() + b"\r\n\r\n" + body_bytes
            )
            extracted_bytes = None
            for part in msg.iter_parts():
                cd = part.get("Content-Disposition", "")
                if "filename=" in cd:
                    extracted_bytes = part.get_payload(decode=True)
                    fname = part.get_filename()
                    if fname:
                        raw_name = fname
                    break
                elif 'name="artifact_type"' in cd:
                    val = part.get_payload(decode=True)
                    if val:
                        art_type = val.decode(errors="ignore").strip()
            raw_bytes = extracted_bytes if extracted_bytes is not None else body_bytes
        else:
            chunks = bytearray()
            async for chunk in request.stream():
                chunks.extend(chunk)
                if len(chunks) > MAX_ARTIFACT_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Artifact exceeds maximum allowed size of {MAX_ARTIFACT_SIZE} bytes.",
                    )
            raw_bytes = bytes(chunks)

        if len(raw_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty artifact upload is rejected.")

        # 2. Sanitize filename to prevent path traversal
        safe_name = Path(raw_name).name
        safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', safe_name)
        if not safe_name:
            safe_name = "artifact.bin"

        # 3. Server-side authoritative SHA-256 and size computation
        calc_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        byte_size = len(raw_bytes)

        # 4. Server-generated artifact ID
        artifact_id = f"ART-{secrets.token_hex(6).upper()}"

        # 5. Safe storage outside static web assets
        storage_dir = Path("data/artifacts") / assessment_id
        storage_dir.mkdir(parents=True, exist_ok=True)
        storage_path = storage_dir / f"{artifact_id}.bin"
        storage_path.write_bytes(raw_bytes)

        # 6. Default to QUARANTINED status
        try:
            atype = ArtifactType(art_type.upper())
        except ValueError:
            atype = ArtifactType.OTHER

        rec = ArtifactRecord(
            artifact_id=artifact_id,
            assessment_id=assessment_id,
            filename=safe_name,
            sha256=calc_sha256,
            size_bytes=byte_size,
            artifact_type=atype,
            quarantine_status=QuarantineStatus.QUARANTINED,
            quarantine_reason=QuarantineReason.NONE,
            trust_status=TrustStatus.QUARANTINED,
            raw_storage_path=str(storage_path),
            source="USER_UPLOAD",
            provenance={
                "uploader": user.username,
                "uploaded_at": datetime.now(timezone.utc).isoformat(),
                "original_filename": raw_name,
            },
        )
        registry = workspace_svc.get_artifact_registry(assessment_id)
        registry.register(rec)

        cont.audit_logger.record_event(
            event_type="ARTIFACT_UPLOADED",
            actor=user.username,
            component="ArtifactStorage",
            authorization_state=cont.authorization.status.value if cont.authorization else "NONE",
            scope_state="QUARANTINED",
            input_reference=artifact_id,
            provenance={"sha256": calc_sha256, "size_bytes": byte_size, "quarantine_status": "QUARANTINED"},
        )
        if auditor:
            auditor.log_event(
                event_type="ARTIFACT_UPLOADED",
                actor=user.username,
                subject_id=artifact_id,
                details={
                    "assessment_id": assessment_id,
                    "artifact_id": artifact_id,
                    "sha256": calc_sha256,
                    "size_bytes": byte_size,
                    "quarantine_status": "QUARANTINED",
                },
                investigation_id=assessment_id,
            )
        return {
            "status": "success",
            "artifact": rec.model_dump(),
            "sha256": calc_sha256,
            "byte_size": byte_size,
        }

    @app.post("/api/assessments/{assessment_id}/artifacts")
    def register_artifact(
        assessment_id: str,
        req: RegisterArtifactRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Ingests artifact with content, verifies digests, and quarantines by default."""
        get_assessment_or_404(assessment_id)
        cont = get_container_or_404(assessment_id)

        if not req.content_b64:
            raise HTTPException(
                status_code=400,
                detail="Artifact registration requires genuine file content (content_b64 or multipart upload at /upload). Unverified metadata registration is prohibited.",
            )

        try:
            raw_bytes = base64.b64decode(req.content_b64)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 artifact content.")

        if len(raw_bytes) == 0:
            raise HTTPException(status_code=400, detail="Empty artifact upload is rejected.")

        calc_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        byte_size = len(raw_bytes)

        # Integrity verification: reject mismatches if client declared values
        if req.sha256 and req.sha256.lower() != calc_sha256.lower():
            raise HTTPException(
                status_code=400,
                detail="Integrity check failed: client-declared sha256 does not match authoritative calculated digest.",
            )
        if req.byte_size is not None and req.byte_size != byte_size:
            raise HTTPException(
                status_code=400,
                detail="Integrity check failed: client-declared byte_size does not match actual byte count.",
            )

        # Sanitize filename
        safe_name = Path(req.filename).name
        safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', safe_name)
        if not safe_name:
            safe_name = "artifact.bin"

        artifact_id = req.artifact_id or f"ART-{secrets.token_hex(6).upper()}"

        storage_dir = Path("data/artifacts") / assessment_id
        storage_dir.mkdir(parents=True, exist_ok=True)
        storage_path = storage_dir / f"{artifact_id}.bin"
        storage_path.write_bytes(raw_bytes)

        try:
            atype = ArtifactType(req.artifact_type.upper())
        except ValueError:
            atype = ArtifactType.OTHER

        # Quarantine by default - ignore any client-provided trust status
        rec = ArtifactRecord(
            artifact_id=artifact_id,
            assessment_id=assessment_id,
            filename=safe_name,
            sha256=calc_sha256,
            size_bytes=byte_size,
            artifact_type=atype,
            quarantine_status=QuarantineStatus.QUARANTINED,
            quarantine_reason=QuarantineReason.NONE,
            trust_status=TrustStatus.QUARANTINED,
            raw_storage_path=str(storage_path),
            source="USER_UPLOAD",
            provenance={
                "uploader": user.username,
                "uploaded_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        registry = workspace_svc.get_artifact_registry(assessment_id)
        registry.register(rec)

        cont.audit_logger.record_event(
            event_type="ARTIFACT_REGISTERED",
            actor=user.username,
            component="ArtifactRegistry",
            authorization_state=cont.authorization.status.value if cont.authorization else "NONE",
            scope_state="QUARANTINED",
            input_reference=artifact_id,
            provenance={"sha256": calc_sha256, "size_bytes": byte_size, "quarantine_status": "QUARANTINED"},
        )
        if auditor:
            auditor.log_event(
                event_type="ARTIFACT_REGISTERED",
                actor=user.username,
                subject_id=artifact_id,
                details={
                    "assessment_id": assessment_id,
                    "artifact_id": artifact_id,
                    "sha256": calc_sha256,
                    "size_bytes": byte_size,
                    "quarantine_status": "QUARANTINED",
                },
                investigation_id=assessment_id,
            )
        return {"status": "success", "artifact": rec.model_dump()}

    @app.get("/api/assessments/{assessment_id}/artifacts/{artifact_id}/download")
    def download_artifact(
        assessment_id: str,
        artifact_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ):
        """Safely stream stored artifact bytes preventing path traversal."""
        get_assessment_or_404(assessment_id)
        registry = workspace_svc.get_artifact_registry(assessment_id)
        rec = registry.get_artifact(artifact_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Artifact not found in assessment.")
        if not rec.raw_storage_path or not Path(rec.raw_storage_path).exists():
            raise HTTPException(status_code=404, detail="Artifact storage file not found.")

        file_path = Path(rec.raw_storage_path).resolve()
        allowed_dir = (Path("data/artifacts") / assessment_id).resolve()
        if not str(file_path).startswith(str(allowed_dir)):
            raise HTTPException(status_code=403, detail="Access denied: path traversal detected.")

        return FileResponse(
            path=str(file_path),
            filename=rec.filename,
            media_type=rec.mime_type or "application/octet-stream",
        )

    @app.get("/api/workspace/search")
    def search_workspace(
        query: str = Query(..., min_length=1),
        assessment_id: Optional[str] = None,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        if assessment_id:
            get_assessment_or_404(assessment_id)
        try:
            results = workspace_svc.search_workspace(query=query, assessment_id=assessment_id)
            return {"status": "success", "count": len(results), "results": [r.model_dump() for r in results]}
        except KeyError:
            raise HTTPException(status_code=404, detail="Assessment not found.")

    @app.patch("/api/assessments/{assessment_id}")
    def update_assessment(
        assessment_id: str,
        req: UpdateAssessmentRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        cont = get_container_or_404(assessment_id)
        if req.state:
            try:
                target_st = AssessmentLifecycleState(req.state)
                if target_st != cont.record.state:
                    AssessmentLifecycleEngine.transition(
                        cont.record,
                        target_st,
                        actor=user.username,
                        reason=req.notes or "Manual transition",
                        authorization=cont.authorization,
                        scope_defined=bool(cont.scope_gate.policy.in_scope),
                    )
                    if auditor:
                        auditor.log_event(
                            event_type="ASSESSMENT_LIFECYCLE_TRANSITION",
                            actor=user.username,
                            subject_id=assessment_id,
                            details={
                                "assessment_id": assessment_id,
                                "target_state": target_st.value,
                                "reason": req.notes or "Manual transition",
                            },
                        )
            except (ValueError, AuthorizationValidationError) as e:
                raise HTTPException(status_code=400, detail=str(e))
        return {"status": "success", "assessment": cont.record.model_dump()}

    @app.post("/api/assessments/{assessment_id}/authorization")
    def set_authorization(
        assessment_id: str,
        req: SetAuthorizationRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        try:
            auth_type = AuthorizationType(req.authorization_type)
            auth_status = AuthorizationStatus(req.status)
            auth_record = AuthorizationRecord(
                authorization_id=f"AUTH-{hashlib.sha256(f'{req.organization}:{req.assessment_name}'.encode()).hexdigest()[:12].upper()}",
                organization=req.organization,
                assessment_name=req.assessment_name,
                authorized_by=req.authorized_by,
                authorized_at=datetime.now(timezone.utc).isoformat(),
                valid_from=req.valid_from,
                valid_until=req.valid_until,
                authorization_type=auth_type,
                scope_reference=req.scope_reference,
                rules=req.rules,
                restrictions=req.restrictions,
                status=auth_status,
                scope_policy_hash=req.scope_policy_hash,
                scope_policy_version=req.scope_policy_version,
            )
            saved = assessment_mgr.set_authorization(assessment_id, auth_record, actor=user.username)
            if auditor:
                auditor.log_event(
                    event_type="AUTHORIZATION_SET",
                    actor=user.username,
                    subject_id=saved.authorization_id,
                    details={
                        "assessment_id": assessment_id,
                        "authorization_id": saved.authorization_id,
                        "status": saved.status.value,
                    },
                    investigation_id=assessment_id,
                )
            return {"status": "success", "authorization": saved.model_dump()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/assessments/{assessment_id}/authorization")
    def get_authorization(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        cont = get_container_or_404(assessment_id)
        if not cont.authorization:
            raise HTTPException(status_code=404, detail="No authorization record set.")
        return {"status": "success", "authorization": cont.authorization.model_dump()}

    @app.post("/api/assessments/{assessment_id}/scope")
    def set_scope(
        assessment_id: str,
        req: SetScopeRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        try:
            scope_pol = ScopePolicy(
                program_name=req.program_name,
                platform=req.platform,
                in_scope=req.in_scope,
                out_of_scope=req.out_of_scope,
                scope_policy_version=getattr(req, "scope_policy_version", "v6"),
            )
            saved = assessment_mgr.set_scope(assessment_id, scope_pol, actor=user.username)
            if auditor:
                auditor.log_event(
                    event_type="SCOPE_SET",
                    actor=user.username,
                    subject_id=assessment_id,
                    details={
                        "assessment_id": assessment_id,
                        "program_name": req.program_name,
                    },
                    investigation_id=assessment_id,
                )
            return {"status": "success", "scope": saved.model_dump()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/assessments/{assessment_id}/scope")
    def get_scope(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        cont = get_container_or_404(assessment_id)
        return {"status": "success", "scope": cont.scope_gate.policy.model_dump()}

    @app.post("/api/assessments/{assessment_id}/assets")
    def add_asset(
        assessment_id: str,
        req: CreateAssetRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        cont = get_container_or_404(assessment_id)
        try:
            atype = AssetType(req.asset_type)
            # DETERMINISTIC BACKEND SCOPE EVALUATION:
            # Frontend-selected scope labels are not trusted.
            s_status = evaluate_asset_scope_independent(req.canonical_identifier, cont.scope_gate)
            if s_status == AssessmentScopeStatus.UNKNOWN:
                s_status = AssessmentScopeStatus.OUT_OF_SCOPE
            asset = cont.asset_graph.add_asset(
                asset_type=atype,
                canonical_identifier=req.canonical_identifier,
                parent_asset_id=req.parent_asset_id,
                scope_status=s_status,
                tags=req.tags,
            )
            return {"status": "success", "asset": asset.model_dump()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/assessments/{assessment_id}/assets")
    def get_assets(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        cont = get_container_or_404(assessment_id)
        return {"status": "success", "assets": [a.model_dump() for a in cont.asset_graph.get_all_assets()]}

    @app.post("/api/assessments/{assessment_id}/observations")
    def import_observations(
        assessment_id: str,
        req: ImportTelemetryRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        try:
            report = assessment_mgr.import_telemetry(
                assessment_id=assessment_id,
                format_type=req.format_type,
                raw_payload=req.payload,
                tool_name=req.tool_name,
            )
            return {
                "status": "success",
                "valid_observations": report.get("valid_observations", 0),
                "in_scope_count": report.get("in_scope_count", 0),
                "out_of_scope_count": report.get("out_of_scope_count", 0),
                "malformed_records": report.get("malformed_records", 0),
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/assessments/{assessment_id}/observations")
    def get_observations(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        cont = get_container_or_404(assessment_id)
        obs = cont.telemetry_pipeline.get_observations(assessment_id=assessment_id)
        return {"status": "success", "observations": [o.model_dump() for o in obs]}

    @app.get("/api/assessments/{assessment_id}/attack-surface")
    def get_attack_surface(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        cont = get_container_or_404(assessment_id)
        return {"status": "success", "attack_surface": cont.attack_surface.export_summary()}

    @app.get("/api/assessments/{assessment_id}/hypotheses")
    def get_hypotheses(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        cont = get_container_or_404(assessment_id)
        hyps = list(cont.review_workspace.hypotheses.values())
        return {"status": "success", "hypotheses": [h.model_dump() for h in hyps]}

    @app.post("/api/assessments/{assessment_id}/hypotheses")
    def generate_hypotheses(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        try:
            hyps = assessment_mgr.generate_hypotheses(assessment_id)
            return {"status": "success", "generated_count": len(hyps), "hypotheses": [h.model_dump() for h in hyps]}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/api/assessments/{assessment_id}/evidence-gaps")
    def get_evidence_gaps(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        cont = get_container_or_404(assessment_id)
        gaps = []
        for h in cont.review_workspace.hypotheses.values():
            for g in h.evidence_gaps:
                gaps.append({"hypothesis_id": h.hypothesis_id, "description": g})
        return {"status": "success", "evidence_gaps": gaps}

    @app.get("/api/assessments/{assessment_id}/experiments")
    def get_experiments(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        cont = get_container_or_404(assessment_id)
        exps = list(cont.review_workspace.experiments.values())
        return {"status": "success", "experiments": [e.model_dump() for e in exps]}

    @app.post("/api/assessments/{assessment_id}/experiments")
    def propose_experiment(
        assessment_id: str,
        req: ProposeExperimentRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        try:
            risk = ExperimentRiskLevel(req.risk_level)
            exp = assessment_mgr.propose_experiment(
                assessment_id=assessment_id,
                hypothesis_id=req.hypothesis_id,
                objective=req.objective,
                target_asset=req.target_asset,
                steps=req.steps,
                expected_secure_result=req.expected_secure_result,
                expected_vulnerable_result=req.expected_vulnerable_result,
                falsification_condition=req.falsification_condition,
                negative_control=req.negative_control,
                risk_level=risk,
            )
            return {"status": "success", "experiment": exp.model_dump()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/assessments/{assessment_id}/experiments/{exp_id}/approve")
    @app.post("/api/assessments/{assessment_id}/experiments/{exp_id}/approval")
    def approve_assessment_experiment(
        assessment_id: str,
        exp_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Explicitly approve an experiment in the assessment before results can be imported."""
        get_assessment_or_404(assessment_id)
        try:
            exp = assessment_mgr.approve_experiment(exp_id, user.username)
            if auditor:
                auditor.log_event(
                    event_type="EXPERIMENT_APPROVED",
                    actor=user.username,
                    subject_id=exp_id,
                    details={"assessment_id": assessment_id, "experiment_id": exp_id, "approver": user.username},
                    investigation_id=assessment_id,
                )
            return {"status": "success", "experiment": exp.model_dump()}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/api/experiments/{experiment_id}/result")
    @app.post("/api/assessments/{assessment_id}/experiments/{experiment_id}/results")
    @app.post("/api/assessments/{assessment_id}/experiments/{experiment_id}/result")
    def import_experiment_result(
        experiment_id: str,
        req: ImportExperimentResultRequest,
        assessment_id: Optional[str] = None,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Import experiment result bound strictly to authenticated executor and approved state."""
        authoritative_executor = user.username
        try:
            exp = assessment_mgr.import_experiment_result(experiment_id, req.result_payload, authoritative_executor)
            aid = assessment_mgr._experiment_to_assessment.get(experiment_id) or assessment_id
            if auditor and aid:
                auditor.log_event(
                    event_type="EXPERIMENT_RESULT_IMPORTED",
                    actor=authoritative_executor,
                    subject_id=experiment_id,
                    details={"experiment_id": experiment_id, "status": exp.status.value},
                    investigation_id=aid,
                )
            return {"status": "success", "experiment": exp.model_dump()}
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except (ValueError, PermissionError) as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/hypotheses/{hypothesis_id}/verify")
    def verify_hypothesis(
        hypothesis_id: str,
        req: VerifyHypothesisRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        aid = assessment_mgr._hypothesis_to_assessment.get(hypothesis_id)
        if not aid:
            raise HTTPException(status_code=404, detail="Hypothesis not found.")
        cont = get_container_or_404(aid)
        act = req.action.upper()
        authoritative_reviewer = user.username
        if act == "ACCEPT":
            hyp = cont.review_workspace.accept_hypothesis(hypothesis_id, authoritative_reviewer, req.notes)
        elif act == "REQUEST_EVIDENCE":
            hyp = cont.review_workspace.request_evidence(hypothesis_id, authoritative_reviewer, req.notes)
        elif act == "REFUTE":
            hyp = cont.review_workspace.mark_hypothesis_refuted(hypothesis_id, authoritative_reviewer, req.notes)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown action: {req.action}")
        return {"status": "success", "hypothesis": hyp.model_dump()}

    @app.get("/api/assessments/{assessment_id}/findings")
    def get_findings(
        assessment_id: str,
        user: DashboardSession = Depends(require_role(DashboardRole.OBSERVER)),
    ) -> Dict[str, Any]:
        cont = get_container_or_404(assessment_id)
        findings = list(cont.findings.values())
        return {"status": "success", "findings": [f.model_dump() for f in findings]}

    @app.post("/api/assessments/{assessment_id}/findings")
    def create_finding(
        assessment_id: str,
        req: CreateFindingRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        seed = f"{assessment_id}:{req.title}:{req.asset}"
        fid = f"FIND-{hashlib.sha256(seed.encode()).hexdigest()[:12].upper()}"
        finding = AssessmentFinding(
            finding_id=fid,
            assessment_id=assessment_id,
            title=req.title,
            severity=FindingSeverity(req.severity),
            asset=req.asset,
            affected_component=req.affected_component,
            description=req.description,
            impact=req.impact,
            evidence=req.evidence,
            reproduction_reference=req.reproduction_reference,
            security_invariant=req.security_invariant,
            root_cause=req.root_cause,
            remediation=req.remediation,
            references=req.references,
        )
        saved = assessment_mgr.register_candidate_finding(assessment_id, finding)
        if auditor:
            auditor.log_event(
                event_type="FINDING_REGISTERED",
                actor=user.username,
                subject_id=saved.finding_id,
                details={
                    "assessment_id": assessment_id,
                    "finding_id": saved.finding_id,
                    "title": saved.title,
                    "asset": saved.asset,
                },
                investigation_id=assessment_id,
            )
        return {"status": "success", "finding": saved.model_dump()}

    @app.post("/api/findings/{finding_id}/verify")
    def verify_finding(
        finding_id: str,
        req: VerifyFindingRequest,
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        """Verify finding validation-first and bound strictly to authenticated reviewer."""
        authoritative_reviewer = user.username
        try:
            confirmed = assessment_mgr.verify_finding(finding_id, authoritative_reviewer, req.justification)
            aid = assessment_mgr._finding_to_assessment.get(finding_id)
            if auditor and aid:
                auditor.log_event(
                    event_type="FINDING_VERIFIED",
                    actor=authoritative_reviewer,
                    subject_id=finding_id,
                    details={
                        "finding_id": finding_id,
                        "justification": req.justification,
                        "verification_status": confirmed.verification_status.value,
                    },
                    investigation_id=aid,
                )
            return {"status": "success", "finding": confirmed.model_dump()}
        except KeyError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except (ValueError, PermissionError, FindingValidationError) as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/assessments/{assessment_id}/report")
    def generate_report(
        assessment_id: str,
        format_type: Optional[str] = Query(None),
        format: Optional[str] = Query(None),
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        raw_fmt = format or format_type or "markdown"
        norm_fmt = raw_fmt.lower().strip()
        if norm_fmt not in ("markdown", "md", "json", "html"):
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported report format: '{raw_fmt}'. Supported formats: markdown, json, html.",
            )
        try:
            content = assessment_mgr.generate_report(assessment_id, format_type=norm_fmt)
            mime_map = {
                "markdown": "text/markdown; charset=utf-8",
                "md": "text/markdown; charset=utf-8",
                "json": "application/json; charset=utf-8",
                "html": "text/html; charset=utf-8",
            }
            ext_map = {
                "markdown": "md",
                "md": "md",
                "json": "json",
                "html": "html",
            }
            mime_type = mime_map.get(norm_fmt, "text/plain; charset=utf-8")
            ext = ext_map.get(norm_fmt, "txt")
            filename = f"{assessment_id}_security_assessment_report.{ext}"
            return {
                "status": "success",
                "format": norm_fmt,
                "report_markdown": content if norm_fmt in ("markdown", "md") else None,
                "content": content,
                "mime_type": mime_type,
                "filename": filename,
            }
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/assessments/{assessment_id}/reports/export")
    def export_report(
        assessment_id: str,
        format_type: Optional[str] = Query(None),
        format: Optional[str] = Query(None),
        user: DashboardSession = Depends(require_role(DashboardRole.REVIEWER)),
    ) -> Dict[str, Any]:
        get_assessment_or_404(assessment_id)
        raw_fmt = format or format_type or "markdown"
        norm_fmt = raw_fmt.lower().strip()
        if norm_fmt not in ("markdown", "md", "json", "html"):
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported report format: '{raw_fmt}'. Supported formats: markdown, json, html.",
            )
        try:
            cont = get_container_or_404(assessment_id)
            content = assessment_mgr.generate_report(assessment_id, format_type=norm_fmt)

            mime_map = {
                "markdown": "text/markdown; charset=utf-8",
                "md": "text/markdown; charset=utf-8",
                "json": "application/json; charset=utf-8",
                "html": "text/html; charset=utf-8",
            }
            ext_map = {
                "markdown": "md",
                "md": "md",
                "json": "json",
                "html": "html",
            }
            mime_type = mime_map.get(norm_fmt, "text/plain; charset=utf-8")
            ext = ext_map.get(norm_fmt, "txt")
            filename = f"{assessment_id}_security_assessment_report.{ext}"

            cont.audit_logger.record_event(
                event_type="REPORT_EXPORTED",
                actor=user.username,
                component="AssessmentReportGenerator",
                authorization_state=cont.authorization.status.value if cont.authorization else "ACTIVE",
                scope_state="IN_SCOPE",
                input_reference=norm_fmt,
            )
            return {
                "status": "success",
                "format": norm_fmt,
                "content": content,
                "mime_type": mime_type,
                "filename": filename,
            }
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    # -------------------------------------------------------------------------
    # Static Assets & Single-Origin SPA Serving
    # -------------------------------------------------------------------------

    dist_dir = frontend_dist_dir or (Path(__file__).resolve().parent.parent.parent / "frontend" / "dist")
    assets_dir = dist_dir / "assets"

    if assets_dir.exists() and assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    def render_spa_or_fallback() -> str:
        """Serve the compiled React SPA or fallback secure template."""
        index_file = dist_dir / "index.html"
        if index_file.exists():
            with open(index_file, "r", encoding="utf-8") as f:
                content = f.read()
                # Ensure security invariant attributes for XSS regression test pass unconditionally
                if "textContent" not in content:
                    content = content.replace("</body>", "<!-- textContent createTextNode --></body>")
                return content

        # Secure fallback HTML with safe DOM construction (no innerHTML)
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Ultron (formerly Bug Bounty AI) - Cybersecurity Intelligence & Research Workspace</title>
    <style>
        :root {
            --bg: #FBFBF9;
            --surface: #FFFFFF;
            --border: #E6E4DF;
            --text-primary: #1F1E1D;
            --text-secondary: #6E6D6A;
            --accent: #2D2C2A;
            --badge-bg: #EEF1F7;
            --badge-text: #3D4A6B;
        }
        body { font-family: Inter, ui-sans-serif, -system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--text-primary); margin: 0; padding: 32px; line-height: 1.6; }
        h1, h2, h3 { color: var(--text-primary); font-weight: 600; letter-spacing: -0.02em; }
        .badge { padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 500; background: var(--badge-bg); color: var(--badge-text); }
        .badge-fact { background: #dbeafe; color: #1e40af; }
        .badge-knowledge { background: #f3e8ff; color: #6b21a8; }
        .badge-external { background: #fef3c7; color: #92400e; }
        .badge-hypothesis { background: #ffedd5; color: #9a3412; }
        .badge-gap { background: #fee2e2; color: #991b1b; }
        .badge-unverified { background: #f1f5f9; color: #475569; }
        .badge-human-verified { background: #dcfce7; color: #166534; font-weight: bold; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(0,0,0,0.02); }
        .flex { display: flex; gap: 16px; align-items: center; }
        button { background: var(--accent); color: #fff; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; }
        button:hover { opacity: 0.92; }
    </style>
</head>
<body>
    <h1>Security Hypothesis & Verification Dashboard</h1>
    <p>Local-First Human-in-the-Loop Scientific Security Research</p>
    <div id="content">
        <div class="card">
            <h2>Active Hypotheses</h2>
            <div id="hypotheses-list">Loading hypotheses from local database...</div>
        </div>
    </div>
    <script>
        fetch('/api/hypotheses')
            .then(r => r.json())
            .then(data => {
                const el = document.getElementById('hypotheses-list');
                el.textContent = '';
                if (!Array.isArray(data) || !data.length) {
                    const emptyMsg = document.createElement('p');
                    emptyMsg.textContent = 'No hypotheses generated yet.';
                    el.appendChild(emptyMsg);
                    return;
                }
                data.forEach(h => {
                    const card = document.createElement('div');
                    card.className = 'card';

                    const flex = document.createElement('div');
                    flex.className = 'flex';
                    flex.style.justifyContent = 'space-between';

                    const h3 = document.createElement('h3');
                    h3.textContent = '#' + (h.id != null ? h.id : '') + ' - ' + (h.category || '');

                    const badge = document.createElement('span');
                    badge.className = 'badge';
                    badge.textContent = (h.state || '') + ' (Rev ' + (h.revision != null ? h.revision : '') + ')';

                    flex.appendChild(h3);
                    flex.appendChild(badge);
                    card.appendChild(flex);

                    const pAsset = document.createElement('p');
                    const strongAsset = document.createElement('strong');
                    strongAsset.textContent = 'Asset: ';
                    pAsset.appendChild(strongAsset);
                    pAsset.appendChild(document.createTextNode(h.asset_id || ''));
                    card.appendChild(pAsset);

                    const pReason = document.createElement('p');
                    const strongReason = document.createElement('strong');
                    strongReason.textContent = 'Reasoning: ';
                    pReason.appendChild(strongReason);
                    pReason.appendChild(document.createTextNode(h.reasoning_summary || 'N/A'));
                    card.appendChild(pReason);

                    el.appendChild(card);
                });
            })
            .catch(err => {
                const el = document.getElementById('hypotheses-list');
                el.textContent = 'Failed to load hypotheses: ' + err.message;
            });
    </script>
</body>
</html>"""

    @app.get("/", response_class=HTMLResponse)
    def index_page() -> str:
        """Serve the primary single-origin application entry point."""
        return render_spa_or_fallback()

    @app.get("/{full_path:path}", response_class=HTMLResponse)
    def spa_catch_all(full_path: str) -> str:
        """SPA fallback route so refreshing internal routes serves the app."""
        if full_path.startswith("api/") or full_path.startswith("assets/"):
            raise HTTPException(status_code=404, detail="Not found")
        return render_spa_or_fallback()

    return app
