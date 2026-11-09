"""Review Dashboard API Implementation for M8 (Phase 21).

Provides:
- GET endpoints for assessments, assets, artifacts, hypotheses, evidence, reviews, findings, audit
- POST endpoints for human review actions (request-evidence, contest, reject, approve-validation, verify)
- Strict deterministic authorization validation on every mutation
- Zero unvalidated database mutations
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from src.artifacts.ingestion import ArtifactIngestionPipeline
from src.assessment.manager import AssessmentManager
from src.assessment.models import FindingVerificationStatus
from src.review.review_actions import (
    ApproveForValidationRequest,
    ContestRequest,
    RejectRequest,
    RequestEvidenceRequest,
    SubmitVerificationRequest,
)
from src.review.review_models import ReviewStatus
from src.review.review_service import ReviewService


router = APIRouter(prefix="", tags=["Review Dashboard"])


class DashboardApiHandler:
    """Encapsulates backend service bindings for review dashboard operations."""

    def __init__(
        self,
        assessment_manager: Optional[AssessmentManager] = None,
        review_service: Optional[ReviewService] = None,
    ):
        self.manager = assessment_manager or AssessmentManager()
        self.review_service = review_service or ReviewService(self.manager)
        self.artifact_pipelines: Dict[str, ArtifactIngestionPipeline] = {}

    def get_pipeline(self, assessment_id: str) -> ArtifactIngestionPipeline:
        if assessment_id not in self.artifact_pipelines:
            self.artifact_pipelines[assessment_id] = ArtifactIngestionPipeline(assessment_id)
        return self.artifact_pipelines[assessment_id]

    # --- GET Endpoints ---

    def get_assessment(self, assessment_id: str) -> Dict[str, Any]:
        try:
            cont = self.manager.get_container(assessment_id)
            return cont.record.model_dump()
        except KeyError:
            raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    def get_assets(self, assessment_id: str) -> List[Dict[str, Any]]:
        try:
            cont = self.manager.get_container(assessment_id)
            return [a.model_dump() for a in cont.asset_graph.get_all_assets()]
        except KeyError:
            raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    def get_artifacts(self, assessment_id: str) -> List[Dict[str, Any]]:
        pipeline = self.get_pipeline(assessment_id)
        return [a.model_dump() for a in pipeline.registry.list_artifacts()]

    def get_hypotheses(self, assessment_id: str) -> List[Dict[str, Any]]:
        try:
            cont = self.manager.get_container(assessment_id)
            return [h.model_dump() for h in cont.review_workspace.hypotheses.values()]
        except KeyError:
            raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    def get_evidence(self, assessment_id: str) -> List[Dict[str, Any]]:
        try:
            cont = self.manager.get_container(assessment_id)
            return [o.model_dump() for o in cont.telemetry_pipeline.get_observations()]
        except KeyError:
            raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    def get_reviews(self, assessment_id: str, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        status_enum = ReviewStatus(status_filter) if status_filter else None
        cases = self.review_service.list_cases(assessment_id, status=status_enum)
        return [c.model_dump() for c in cases]

    def get_findings(self, assessment_id: str) -> List[Dict[str, Any]]:
        try:
            cont = self.manager.get_container(assessment_id)
            return [f.model_dump() for f in cont.findings.values()]
        except KeyError:
            raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    def get_audit(self, assessment_id: str) -> List[Dict[str, Any]]:
        try:
            cont = self.manager.get_container(assessment_id)
            if hasattr(cont.audit_logger, "get_events"):
                return [e.model_dump() for e in cont.audit_logger.get_events()]
            return []
        except KeyError:
            raise HTTPException(status_code=404, detail=f"Assessment '{assessment_id}' not found.")

    # --- POST Mutation Endpoints ---

    def request_evidence(
        self,
        assessment_id: str,
        review_id: str,
        req: RequestEvidenceRequest,
    ) -> Dict[str, Any]:
        try:
            updated = self.review_service.request_evidence(assessment_id, review_id, req)
            return {"status": "SUCCESS", "case": updated.model_dump()}
        except (KeyError, ValueError) as e:
            raise HTTPException(status_code=400, detail=str(e))

    def contest(
        self,
        assessment_id: str,
        review_id: str,
        req: ContestRequest,
    ) -> Dict[str, Any]:
        try:
            updated = self.review_service.contest(assessment_id, review_id, req)
            return {"status": "SUCCESS", "case": updated.model_dump()}
        except (KeyError, ValueError) as e:
            raise HTTPException(status_code=400, detail=str(e))

    def reject(
        self,
        assessment_id: str,
        review_id: str,
        req: RejectRequest,
    ) -> Dict[str, Any]:
        try:
            updated = self.review_service.reject(assessment_id, review_id, req)
            return {"status": "SUCCESS", "case": updated.model_dump()}
        except (KeyError, ValueError) as e:
            raise HTTPException(status_code=400, detail=str(e))

    def approve_validation(
        self,
        assessment_id: str,
        review_id: str,
        req: ApproveForValidationRequest,
    ) -> Dict[str, Any]:
        try:
            updated = self.review_service.approve_for_validation(assessment_id, review_id, req)
            return {"status": "SUCCESS", "case": updated.model_dump()}
        except (KeyError, ValueError) as e:
            raise HTTPException(status_code=400, detail=str(e))

    def verify_finding(
        self,
        assessment_id: str,
        review_id: str,
        req: SubmitVerificationRequest,
    ) -> Dict[str, Any]:
        is_confirmed, finding, errors = self.review_service.submit_human_verification(
            assessment_id, review_id, req
        )
        if not is_confirmed:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": "Deterministic finding validation failed.", "reasons": errors},
            )
        return {
            "status": "CONFIRMED",
            "finding": finding.model_dump() if finding else None,
            "epistemic_status": "HUMAN_VERIFIED_FINDING",
        }
