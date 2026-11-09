"""Android Call Graph and Inter-Procedural Reachability Analyzer for M10.

Constructs directed graph:
CLASS -> METHOD -> CALL -> CALLEE

Enforces:
- Direct, static, virtual, and interface call edges.
- Unresolved reflective calls are explicitly marked as UNRESOLVED_EDGE (INV-M10-06).
- Never invents call relationships.
- Reachability queries from component entry points to sinks.
"""

from collections import deque
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from src.binary.artifacts import CallRelationship


class AndroidCallEdge(BaseModel):
    caller: str
    callee: str
    call_type: str = "DIRECT"  # DIRECT, STATIC, VIRTUAL, INTERFACE, REFLECTIVE
    is_unresolved: bool = False
    source_layer: str = "DEX"  # DEX, SMALI


class AndroidCallGraph:
    """Inter-procedural directed call graph for Dalvik / Smali bytecode."""

    def __init__(self, edges: Optional[List[AndroidCallEdge]] = None):
        self.edges: List[AndroidCallEdge] = edges or []
        self._adj: Dict[str, List[AndroidCallEdge]] = {}
        for edge in self.edges:
            self._adj.setdefault(edge.caller, []).append(edge)

    def add_edge(
        self,
        caller: str,
        callee: str,
        call_type: str = "DIRECT",
        is_unresolved: bool = False,
        source_layer: str = "DEX",
    ) -> None:
        """Adds a verified call edge."""
        edge = AndroidCallEdge(
            caller=caller,
            callee=callee,
            call_type=call_type,
            is_unresolved=is_unresolved,
            source_layer=source_layer,
        )
        self.edges.append(edge)
        self._adj.setdefault(caller, []).append(edge)

    def add_unresolved_reflection(self, caller: str, raw_target_hint: Optional[str] = None) -> None:
        """Records an unresolved reflective edge without fabricating targets (INV-M10-06)."""
        callee = raw_target_hint or "UNRESOLVED_REFLECTION_TARGET"
        self.add_edge(caller, callee, call_type="REFLECTIVE", is_unresolved=True)

    def find_reachability(
        self,
        entry_point: str,
        target_sink: str,
    ) -> Tuple[bool, List[str], List[str]]:
        """
        Traces path from entry point to target sink.
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
                    new_unres.append(f"{edge.caller} -> {edge.callee} (REFLECTIVE/UNRESOLVED)")

                if edge.callee == target_sink or target_sink in edge.callee:
                    return True, path + [edge.callee], new_unres

                if edge.callee not in visited and not edge.is_unresolved:
                    visited.add(edge.callee)
                    queue.append((edge.callee, path + [edge.callee], new_unres))

        return False, [], []

    def get_callees(self, caller: str) -> List[AndroidCallEdge]:
        return self._adj.get(caller, [])
