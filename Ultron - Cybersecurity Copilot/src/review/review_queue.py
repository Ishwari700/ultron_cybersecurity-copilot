"""Review Queue Management for Human Security Reviewers.

Provides:
- In-memory and assessment-isolated indexing of review cases
- Status filtering (PENDING, IN_REVIEW, NEEDS_EVIDENCE, CONTESTED, etc.)
- Priority sorting based on severity and evidence grounding
"""

from typing import Dict, List, Optional
from src.review.review_models import ReviewCase, ReviewStatus


class ReviewQueue:
    """Assessment-scoped review case queue."""

    def __init__(self, assessment_id: str):
        self.assessment_id = assessment_id
        self._cases: Dict[str, ReviewCase] = {}

    def add_case(self, case: ReviewCase) -> None:
        """Adds or updates a review case in the queue with assessment boundary check."""
        if case.assessment_id != self.assessment_id:
            raise ValueError(
                f"Assessment mismatch: cannot add case for {case.assessment_id} to queue {self.assessment_id}"
            )
        self._cases[case.review_id] = case

    def get_case(self, review_id: str) -> Optional[ReviewCase]:
        """Retrieves a review case by ID."""
        return self._cases.get(review_id)

    def list_cases(
        self,
        status: Optional[ReviewStatus] = None,
        severity: Optional[str] = None,
    ) -> List[ReviewCase]:
        """Lists cases filtered by status and severity, sorted by severity priority."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        cases = list(self._cases.values())

        if status:
            cases = [c for c in cases if c.status == status]
        if severity:
            cases = [c for c in cases if c.severity.upper() == severity.upper()]

        return sorted(
            cases,
            key=lambda c: severity_order.get(c.severity.upper(), 5),
        )

    def count_by_status(self) -> Dict[str, int]:
        """Returns distribution of review statuses."""
        counts = {s.value: 0 for s in ReviewStatus}
        for c in self._cases.values():
            counts[c.status.value] = counts.get(c.status.value, 0) + 1
        return counts
