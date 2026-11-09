"""Scope gate and authorization subsystem."""

from src.scope.models import ScopeDecision, ScopeDecisionObject, ScopePolicy, ToolPolicy
from src.scope.gate import ScopeGate, ScopeValidationError
from src.scope.client import ScopedHttpClient, ScopeViolationError

__all__ = [
    "ScopeDecision",
    "ScopeDecisionObject",
    "ScopePolicy",
    "ToolPolicy",
    "ScopeGate",
    "ScopeValidationError",
    "ScopedHttpClient",
    "ScopeViolationError",
]
