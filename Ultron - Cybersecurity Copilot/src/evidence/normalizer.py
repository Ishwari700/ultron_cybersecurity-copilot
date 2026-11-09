"""Path normalizer retaining raw and templated paths with confidence scoring."""

import re
from typing import Tuple


class PathNormalizer:
    """
    Normalizes variable path segments (integers, UUIDs, hex tokens) into canonical
    path templates while retaining the raw path and assigning normalization confidence.
    """

    UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
    HEX_REGEX = re.compile(r"^[0-9a-f]{16,64}$", re.I)
    INT_REGEX = re.compile(r"^\d+$")

    @classmethod
    def normalize_path(cls, raw_path: str) -> Tuple[str, float]:
        """
        Normalize a raw path into a templated path.
        Returns (normalized_path, confidence).
        """
        if not raw_path:
            return "/", 1.0

        # Split off query string if present
        clean_path = raw_path.split("?")[0].strip()
        segments = clean_path.strip("/").split("/")

        normalized_segments = []
        replaced_count = 0

        for seg in segments:
            if not seg:
                continue
            if cls.UUID_REGEX.match(seg):
                normalized_segments.append("{uuid}")
                replaced_count += 1
            elif cls.INT_REGEX.match(seg):
                normalized_segments.append("{id}")
                replaced_count += 1
            elif cls.HEX_REGEX.match(seg):
                normalized_segments.append("{hash}")
                replaced_count += 1
            else:
                normalized_segments.append(seg)

        normalized_path = "/" + "/".join(normalized_segments)
        # High confidence for standard patterns
        confidence = 1.0 if replaced_count == 0 else 0.95
        return normalized_path, confidence

    @classmethod
    def classify_mutability(cls, method: str) -> str:
        """Classify HTTP semantics into application mutability."""
        m = method.upper().strip()
        if m in ("GET", "HEAD", "OPTIONS"):
            return "READ_ONLY"
        elif m in ("POST", "PUT", "PATCH"):
            return "STATE_CHANGING"
        elif m == "DELETE":
            return "DESTRUCTIVE"
        return "UNKNOWN"
