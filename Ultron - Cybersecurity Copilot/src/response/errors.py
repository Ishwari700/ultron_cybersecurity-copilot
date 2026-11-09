"""Custom exception types for M11.5 Long Response Subsystem."""


class ResponseEngineError(Exception):
    """Base exception for all long response engine errors."""
    pass


class ContinuationLimitError(ResponseEngineError):
    """Raised when maximum continuation chunks or cumulative tokens are exceeded."""
    pass


class ContextExhaustionError(ResponseEngineError):
    """Raised when context window is exhausted and cannot be repacked."""
    pass


class OverlapError(ResponseEngineError):
    """Raised when duplicate overlap detection or resolution fails."""
    pass


class PersistenceError(ResponseEngineError):
    """Raised when saving or loading response sessions/chunks fails."""
    pass


class StreamingInterruptedError(ResponseEngineError):
    """Raised when a stream connection is abruptly severed."""
    pass


class UserCancelledError(ResponseEngineError):
    """Raised when response generation is terminated by user command."""
    pass
