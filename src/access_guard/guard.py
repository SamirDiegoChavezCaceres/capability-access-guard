"""Call-site helpers: raise on denial, and parse untrusted input fail-closed."""

from __future__ import annotations

from typing import Any, Mapping, Optional

from .contracts import AccessDenied, PolicyDecision, RequestContext, ResourceRef, new_context
from .policy import PolicyEngine

_ENGINE = PolicyEngine()


def require_capability(context: RequestContext, capability: str) -> PolicyDecision:
    """Return the allow decision, or raise :class:`AccessDenied`."""
    decision = _ENGINE.evaluate(context, capability)
    if not decision.allowed:
        raise AccessDenied(decision)
    return decision


def require_resource(
    context: RequestContext, capability: str, resource: ResourceRef
) -> PolicyDecision:
    decision = _ENGINE.evaluate(context, capability, resource)
    if not decision.allowed:
        raise AccessDenied(decision)
    return decision


def context_from_mapping(data: Any) -> RequestContext:
    """Build a context from untrusted input (e.g. a request header/claim set).

    Fail closed: anything missing or of the wrong type raises AccessDenied
    rather than producing a permissive context.
    """
    if not isinstance(data, Mapping):
        raise AccessDenied(PolicyDecision(False, "missing_context", "context payload is not a mapping"))
    actor = data.get("actor")
    if not isinstance(actor, str) or not actor:
        raise AccessDenied(PolicyDecision(False, "missing_context", "actor is required"))
    try:
        return new_context(
            actor=actor,
            is_internal=bool(data.get("is_internal", False)),
            group_ids=list(data.get("group_ids", []) or []),
            capabilities=list(data.get("capabilities", []) or []),
        )
    except TypeError as exc:
        raise AccessDenied(
            PolicyDecision(False, "missing_context", f"malformed context: {exc}")
        ) from exc
