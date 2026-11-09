"""Call Graph and Inter-procedural Reachability Analyzer for M7 Binary Analysis.

Traces call graph edges from public exports/entry points to dangerous sinks.
"""

from collections import deque
from typing import Dict, List, Set, Tuple
from src.binary.artifacts import CallRelationship


class CallGraphAnalyzer:
    """Builds and queries directed call graphs for binary vulnerability reachability."""

    def __init__(self, relationships: List[CallRelationship]) -> None:
        self.relationships = relationships
        self._adj: Dict[str, List[str]] = {}
        for rel in relationships:
            self._adj.setdefault(rel.caller, []).append(rel.callee)

    def is_reachable(self, entry_point: str, target_sink: str) -> Tuple[bool, List[str]]:
        """
        Executes BFS to determine if target_sink can be reached from entry_point.
        Returns (is_reachable: bool, call_path: List[str]).
        """
        if entry_point == target_sink:
            return True, [entry_point]

        queue = deque([(entry_point, [entry_point])])
        visited: Set[str] = {entry_point}

        while queue:
            curr, path = queue.popleft()
            for neighbor in self._adj.get(curr, []):
                if neighbor == target_sink:
                    return True, path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return False, []
