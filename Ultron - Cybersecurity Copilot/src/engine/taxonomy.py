"""Taxonomy loader and deterministic Applicability Filter pre-screening candidate categories."""

from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field
from src.graph.models import WorkflowNode


class TaxonomyCategory(BaseModel):
    id: str
    category: str
    name: str
    applicability: Dict[str, List[str]] = Field(default_factory=dict)
    required_evidence: List[str] = Field(default_factory=list)
    validation_evidence: List[str] = Field(default_factory=list)
    retrieval_queries: List[str] = Field(default_factory=list)
    allowed_outputs: List[str] = Field(default_factory=list)


class ApplicabilityFilter:
    """
    Deterministic pre-check that evaluates taxonomy applicability predicates against
    the Evidence Graph. If predicates are unmet, skips retrieval and model inference.
    """

    def __init__(self, taxonomy_file: Optional[Path] = None) -> None:
        target = taxonomy_file or Path("taxonomy/categories.yaml")
        self.categories: Dict[str, TaxonomyCategory] = {}
        if target.exists():
            with open(target, "r", encoding="utf-8") as f:
                raw_list = yaml.safe_load(f) or []
                for item in raw_list:
                    cat = TaxonomyCategory(**item)
                    self.categories[cat.id] = cat

    def is_applicable(
        self,
        category_id: str,
        asset: Dict[str, Any],
        parameters: List[Dict[str, Any]],
        workflows: Optional[List[WorkflowNode]] = None,
    ) -> bool:
        """
        Evaluate structural predicates for this category against the asset.
        Returns True if structurally plausible; False if impossible.
        """
        cat = self.categories.get(category_id)
        if not cat:
            return False

        predicates = cat.applicability.get("all", [])
        for pred in predicates:
            if pred == "object_identifier_present":
                # Must have at least one identifier-like parameter in path or query
                has_id = any(
                    p["location"] in ("path", "query") and
                    ("id" in p["param_name"].lower() or p.get("param_type") in ("uuid", "identifier"))
                    for p in parameters
                )
                if not has_id:
                    return False

            elif pred == "role_restricted_endpoint":
                # Must have role requirement or admin in path
                has_role = bool(asset.get("role")) or "admin" in asset.get("raw_path", "").lower()
                if not has_role:
                    return False

            elif pred == "workflow_transition_present":
                # Must be part of a multi-step workflow sequence
                wf_list = workflows or []
                in_wf = any(asset["asset_id"] in wf.asset_sequence for wf in wf_list)
                if not in_wf:
                    return False

            elif pred == "read_endpoint":
                if asset.get("method", "").upper() not in ("GET", "HEAD"):
                    return False

        return True
