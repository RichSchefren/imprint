"""Typed failures. Public commands fail closed and never hide degraded state."""


class ImprintError(Exception):
    """Base public error."""


class ValidationError(ImprintError):
    """Input or transition violates the frozen contract."""


class SafetyError(ImprintError):
    """A path, writer, privacy, or deletion safety rule failed."""


class ConflictError(ImprintError):
    """An ID, hash, writer, or version conflict was detected."""

