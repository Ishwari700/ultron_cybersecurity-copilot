"""Deduplication and Near-Duplicate Detection Engine for Memory Subsystem."""

import re
from typing import Dict, List, Optional, Set, Tuple
from src.memory.models import MemoryItem


def tokenize_text(text: str) -> Set[str]:
    """Extracts lowercased alphanumeric tokens from string."""
    tokens = re.findall(r"\b[a-z0-9_]{3,}\b", text.lower())
    return set(tokens)


def jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Computes Jaccard similarity coefficient between token sets."""
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return float(intersection) / float(union) if union > 0 else 0.0


class MemoryDeduplicator:
    """
    Detects exact content-hash duplicates and near-duplicate memory items.
    """

    def __init__(self, near_duplicate_threshold: float = 0.85) -> None:
        self.near_duplicate_threshold = near_duplicate_threshold

    def check_exact_duplicate(
        self,
        candidate_hash: str,
        existing_hashes: Dict[str, str],  # memory_id -> content_hash
    ) -> Optional[str]:
        """
        Returns existing memory_id if exact content_hash matches, else None.
        """
        for mem_id, h in existing_hashes.items():
            if h == candidate_hash:
                return mem_id
        return None

    def check_near_duplicate(
        self,
        candidate_content: str,
        existing_items: List[MemoryItem],
    ) -> Tuple[bool, Optional[str], float]:
        """
        Compares candidate tokens against existing memory items.
        Returns (is_near_dup, existing_memory_id, similarity_score).
        """
        candidate_tokens = tokenize_text(candidate_content)
        if not candidate_tokens:
            return False, None, 0.0

        best_score = 0.0
        best_match_id = None

        for item in existing_items:
            existing_tokens = tokenize_text(item.content)
            score = jaccard_similarity(candidate_tokens, existing_tokens)
            if score > best_score:
                best_score = score
                best_match_id = item.memory_id

        if best_score >= self.near_duplicate_threshold:
            return True, best_match_id, best_score

        return False, None, best_score
