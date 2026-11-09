"""Version Awareness and Scope Evaluation Engine (M4).

Evaluates target software versions against external vulnerability ranges.

Rules:
1. Target version UNKNOWN -> EVIDENCE_GAP (cannot confirm or hypothesize specific version bug)
2. Target version OUTSIDE affected range -> NOT_APPLICABLE
3. Target version OVERLAPS affected range -> APPLICABILITY_HYPOTHESIS
   (NEVER creates a vulnerability finding directly!)
"""

import re
from typing import Optional, Tuple
from packaging.version import InvalidVersion, Version

from src.research.models import VersionApplicability, VersionScope


class VersionEvaluator:
    """Deterministic parser and evaluator for version ranges and compatibility."""

    @staticmethod
    def _parse_semver(v_str: str) -> Optional[Version]:
        """Safely parses semver or clean version string."""
        if not v_str:
            return None
        cleaned = re.sub(r"^[vV]", "", v_str.strip())
        # Strip trailing commit hashes or build info if simple version format
        cleaned = re.split(r"[-+]", cleaned)[0]
        try:
            return Version(cleaned)
        except InvalidVersion:
            # Fallback regex for numeric dots
            m = re.match(r"^(\d+(\.\d+)*)", cleaned)
            if m:
                try:
                    return Version(m.group(1))
                except InvalidVersion:
                    return None
            return None

    @classmethod
    def evaluate_applicability(
        cls,
        target_version: Optional[str],
        scope: VersionScope,
    ) -> VersionApplicability:
        """
        Determines applicability of an external version constraint to target evidence.
        
        Enforces Section 11:
        - If target version unknown -> UNKNOWN_TARGET_VERSION (Produces EVIDENCE_GAP)
        - If target version outside -> NOT_AFFECTED / NOT_APPLICABLE
        - If target version inside -> AFFECTED (Produces APPLICABILITY_HYPOTHESIS)
        """
        if not target_version or target_version.strip() == "" or target_version.lower() in ("unknown", "null", "none"):
            return VersionApplicability.UNKNOWN_TARGET_VERSION

        parsed_target = cls._parse_semver(target_version)
        if not parsed_target:
            return VersionApplicability.UNKNOWN_TARGET_VERSION

        # 1. Check fixed_versions if specified (e.g. ">= 2.3.5" or "2.3.5+")
        if scope.fixed_versions:
            m_fixed = re.search(r"(\d+(\.\d+)*)", scope.fixed_versions)
            if m_fixed:
                parsed_fixed = cls._parse_semver(m_fixed.group(1))
                if parsed_fixed and parsed_target >= parsed_fixed:
                    return VersionApplicability.NOT_AFFECTED

        # 2. Check affected_versions if specified (e.g. "2.1.0 - 2.3.4" or "< 2.3.5" or "2.1.0 to 2.3.4")
        if scope.affected_versions:
            # Check range pattern: X.Y.Z - A.B.C or X.Y.Z to A.B.C
            range_match = re.search(r"(\d+(\.\d+)*)\s*(?:-|to)\s*(\d+(\.\d+)*)", scope.affected_versions)
            if range_match:
                v_min = cls._parse_semver(range_match.group(1))
                v_max = cls._parse_semver(range_match.group(3))
                if v_min and v_max:
                    if v_min <= parsed_target <= v_max:
                        return VersionApplicability.AFFECTED
                    else:
                        return VersionApplicability.NOT_AFFECTED

            # Check upper bound: < X.Y.Z or <= X.Y.Z
            upper_match = re.search(r"<(=?)\s*(\d+(\.\d+)*)", scope.affected_versions)
            if upper_match:
                is_inclusive = upper_match.group(1) == "="
                v_bound = cls._parse_semver(upper_match.group(2))
                if v_bound:
                    if is_inclusive and parsed_target <= v_bound:
                        return VersionApplicability.AFFECTED
                    elif not is_inclusive and parsed_target < v_bound:
                        return VersionApplicability.AFFECTED
                    else:
                        return VersionApplicability.NOT_AFFECTED

            # Check single version exact match
            single_match = re.search(r"(\d+(\.\d+)*)", scope.affected_versions)
            if single_match:
                v_exact = cls._parse_semver(single_match.group(1))
                if v_exact:
                    if parsed_target == v_exact:
                        return VersionApplicability.AFFECTED
                    else:
                        return VersionApplicability.NOT_AFFECTED

        # 3. Check single scope.version exact match
        if scope.version:
            single_v = cls._parse_semver(scope.version)
            if single_v:
                return VersionApplicability.AFFECTED if parsed_target == single_v else VersionApplicability.NOT_AFFECTED

        return VersionApplicability.NOT_APPLICABLE
