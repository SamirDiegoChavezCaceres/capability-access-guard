"""The policy engine. Pure, deterministic, and deny-by-default.

Capabilities are dotted namespaces, e.g. ``knowledge.read.marketing``. A grant
may be exact, or a prefix wildcard ending in ``*`` (``knowledge.read.*`` grants
``knowledge.read.marketing`` but not ``knowledge.write.marketing``; ``*`` alone
grants everything). Nothing is allowed unless a grant matches.
"""

from __future__ import annotations

from typing import Optional

from .contracts import PolicyDecision, RequestContext, ResourceRef

_ALLOW = PolicyDecision(allowed=True, reason_code="ok")


def _granted(capabilities, needed: str) -> bool:
    for grant in capabilities:
        if grant == needed or grant == "*":
            return True
        if grant.endswith(".*") and (
            needed == grant[:-2] or needed.startswith(grant[:-1])
        ):
            return True
    return False


class PolicyEngine:
    def evaluate(
        self,
        context: RequestContext,
        capability: str,
        resource: Optional[ResourceRef] = None,
    ) -> PolicyDecision:
        # Fail closed on anything malformed.
        if not isinstance(context, RequestContext):
            return PolicyDecision(False, "missing_context", "no valid request context")
        if not isinstance(capability, str) or not capability.strip():
            return PolicyDecision(False, "invalid_capability", "capability must be a non-empty string")

        if not _granted(context.capabilities, capability):
            return PolicyDecision(False, "capability_not_granted", capability)

        # Tenant isolation: a non-internal actor may only touch resources owned
        # by a group they belong to. Internal actors skip the tenant check but
        # still needed the capability above.
        if resource is not None and not context.is_internal:
            if resource.owner_group not in context.group_ids:
                return PolicyDecision(
                    False, "cross_tenant_resource",
                    f"{resource.kind}:{resource.resource_id} belongs to another tenant",
                )

        return _ALLOW
