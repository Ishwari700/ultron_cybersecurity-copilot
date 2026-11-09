"""Typed domain exceptions for M12 Security Research Memory Subsystem."""


class MemoryError(Exception):
    """Base exception for all memory subsystem operations."""
    pass


class MemoryAccessDeniedError(MemoryError):
    """Raised when memory access violates namespace, user, or tenant authorization."""
    pass


class AssessmentIsolationViolationError(MemoryAccessDeniedError):
    """Raised when an assessment attempts to access private memory of another assessment."""
    pass


class MemoryAdmissionRejectedError(MemoryError):
    """Raised when a candidate memory item fails admission validation."""
    pass


class SecretPersistenceForbiddenError(MemoryAdmissionRejectedError):
    """Raised when candidate memory contains credentials, API keys, or unredacted secrets."""
    pass


class MemoryPoisoningAttemptError(MemoryAdmissionRejectedError):
    """Raised when candidate memory contains adversarial instruction injection."""
    pass


class EpistemicViolationError(MemoryError):
    """Raised when an invalid epistemic transition is attempted (e.g. hypothesis -> fact)."""
    pass


class InvalidMemoryPromotionError(MemoryError):
    """Raised when memory promotion violates policy or lacks required human authorization."""
    pass


class MemoryConflictError(MemoryError):
    """Raised when unresolvable memory conflicts occur."""
    pass


class MemoryPointerError(MemoryError):
    """Raised when an evidence pointer is invalid or refers to non-existent evidence."""
    pass
