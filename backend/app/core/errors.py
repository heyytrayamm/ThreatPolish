"""Application error types.

Errors carry a stable machine-readable code so that API clients, tests and
audit records do not depend on human wording.
"""

from __future__ import annotations

from typing import Any


class ThreatPolishError(Exception):
    """Base class for expected, mapped application errors."""

    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(ThreatPolishError):
    status_code = 500
    code = "configuration_error"


class ValidationFailure(ThreatPolishError):
    status_code = 422
    code = "validation_failed"


class PayloadTooLarge(ThreatPolishError):
    status_code = 413
    code = "payload_too_large"


class AuthenticationFailure(ThreatPolishError):
    status_code = 401
    code = "authentication_failed"


class AuthorizationFailure(ThreatPolishError):
    status_code = 403
    code = "forbidden"


class NotFound(ThreatPolishError):
    status_code = 404
    code = "not_found"


class Conflict(ThreatPolishError):
    status_code = 409
    code = "conflict"


class RateLimited(ThreatPolishError):
    status_code = 429
    code = "rate_limited"


class UpstreamFailure(ThreatPolishError):
    status_code = 502
    code = "upstream_failure"


class PolicyDenied(ThreatPolishError):
    status_code = 403
    code = "policy_denied"


class StorageFailure(ThreatPolishError):
    status_code = 500
    code = "storage_failure"
