"""Shared types for the access guard.

The design rule is *fail closed*: anything the engine is unsure about - a
missing context, an unknown capability, a resource in another tenant - is a
denial, never a silent pass. Every denial carries a machine-readable
``reason_code`` so callers can log and branch without string-matching messages.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Iterable, Optional


@dataclass(frozen=True)
class RequestContext:
    """Who is asking, which tenants they belong to, and what they were granted."""

    actor: str
    is_internal: bool = False
    group_ids: FrozenSet[str] = frozenset()
    capabilities: FrozenSet[str] = frozenset()


def new_context(
    actor: str,
    *,
    is_internal: bool = False,
    group_ids: Iterable[str] = (),
    capabilities: Iterable[str] = (),
) -> RequestContext:
    """Build a context, normalizing the collections to frozensets."""
    return RequestContext(
        actor=actor,
        is_internal=is_internal,
        group_ids=frozenset(group_ids),
        capabilities=frozenset(capabilities),
    )


@dataclass(frozen=True)
class ResourceRef:
    """A thing being acted on, tagged with the tenant that owns it."""

    kind: str
    owner_group: str
    resource_id: str


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason_code: str
    detail: Optional[str] = None


class AccessDenied(PermissionError):
    """Raised by the guard helpers when a decision is a denial."""

    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        super().__init__(f"{decision.reason_code}: {decision.detail or 'access denied'}")
