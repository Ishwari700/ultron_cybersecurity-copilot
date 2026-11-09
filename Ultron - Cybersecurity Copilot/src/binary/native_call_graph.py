"""Native Binary Call Graph and Reachability Analyzer for M10.

Constructs directed graph:
FUNCTION -> CALL -> FUNCTION
and
IMPORT -> CALLER -> FUNCTION

Enforces:
- Direct and indirect call edges.
- Unresolved functions and indirect jumps marked as UNRESOLVED_FUNCTION (INV-M10-06).
- Never invents call relationships or entry points.
- Inter-procedural reachability queries to dangerous sinks.
"""

from collections import deque
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from src.binary.artifacts import CallRelationship


class NativeCallGraph:
    """Inter-procedural directed call graph for native compiled binaries."""

    def __init__(self, edges: Optional[List[CallRelationship]] = None) -> None:
        self.edges: List[CallRelationship] = edges or []
        self._adj: Dict[str, List[CallRelationship]] = {}
        for edge in self.edges:
            self._adj.setdefault(edge.caller, []).append(edge)

    def add_call(
        self,
        caller: str,
        callee: str,
        call_site_address: Optional[str] = None,
        is_direct: bool = True,
        is_unresolved: bool = False,
    ) -> None:
        """Adds a verified call edge."""
        rel = CallRelationship(
            caller=caller,
            callee=callee,
            call_site_address=call_site_address,
            is_direct=is_direct,
            is_unresolved=is_unresolved,
        )
        self.edges.append(rel)
        self._adj.setdefault(caller, []).append(rel)

    def add_unresolved_call(self, caller: str, raw_target_hint: Optional[str] = None) -> None:
        """Records an unresolved call or computed jump without hallucination (INV-M10-06)."""
        callee = raw_target_hint or "UNRESOLVED_FUNCTION"
        self.add_call(caller, callee, is_direct=False, is_unresolved=True)

    def is_reachable(
        self,
        entry_point: str,
        target_sink: str,
    ) -> Tuple[bool, List[str], List[str]]:
        """
        Executes BFS reachability analysis from entry_point to target_sink.
        Returns: (is_reachable: bool, path: List[str], unresolved_hops: List[str])
        """
        if entry_point == target_sink:
            return True, [entry_point], []

        queue = deque([(entry_point, [entry_point], [])])
        visited: Set[str] = {entry_point}

        while queue:
            curr, path, unres = queue.popleft()
            for edge in self._adj.get(curr, []):
                new_unres = list(unres)
                if edge.is_unresolved:
                    new_unres.append(f"{edge.caller} -> {edge.callee}")

                if edge.callee == target_sink or target_sink in edge.callee:
                    return True, path + [edge.callee], new_unres

                if edge.callee not in visited:
                    visited.add(edge.callee)
                    queue.append((edge.callee, path + [edge.callee], new_unres))

        return False, [], []

    def get_callees(self, caller: str) -> List[CallRelationship]:
        return self._adj.get(caller, [])
