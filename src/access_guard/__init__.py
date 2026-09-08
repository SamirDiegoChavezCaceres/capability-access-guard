"""A fail-closed, capability-based access guard with tenant isolation."""

from .contracts import (
    AccessDenied,
    PolicyDecision,
    RequestContext,
    ResourceRef,
    new_context,
)
from .guard import context_from_mapping, require_capability, require_resource
from .policy import PolicyEngine

__all__ = [
    "RequestContext",
    "new_context",
    "ResourceRef",
    "PolicyDecision",
    "AccessDenied",
    "PolicyEngine",
    "require_capability",
    "require_resource",
    "context_from_mapping",
]
