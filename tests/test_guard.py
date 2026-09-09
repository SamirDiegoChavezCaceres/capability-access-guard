import pytest

from access_guard import (
    AccessDenied,
    PolicyEngine,
    ResourceRef,
    context_from_mapping,
    new_context,
    require_capability,
    require_resource,
)

engine = PolicyEngine()


def test_exact_grant_allows():
    ctx = new_context("u", capabilities=["knowledge.read.marketing"])
    assert require_capability(ctx, "knowledge.read.marketing").allowed


def test_missing_grant_denies_with_reason():
    ctx = new_context("u", capabilities=["knowledge.read.marketing"])
    with pytest.raises(AccessDenied) as exc:
        require_capability(ctx, "knowledge.write.marketing")
    assert exc.value.decision.reason_code == "capability_not_granted"


def test_prefix_wildcard_grants_subtree_only():
    ctx = new_context("u", capabilities=["knowledge.read.*"])
    assert engine.evaluate(ctx, "knowledge.read.marketing").allowed
    assert engine.evaluate(ctx, "knowledge.read").allowed
    assert not engine.evaluate(ctx, "knowledge.write.marketing").allowed


def test_root_wildcard_grants_everything():
    ctx = new_context("admin", capabilities=["*"])
    assert engine.evaluate(ctx, "anything.at.all").allowed


def test_empty_context_fails_closed():
    assert not engine.evaluate(None, "x").allowed  # type: ignore[arg-type]
    assert engine.evaluate(None, "x").reason_code == "missing_context"  # type: ignore[arg-type]


def test_cross_tenant_resource_denied():
    ctx = new_context("u", group_ids=["team-a"], capabilities=["campaign.read"])
    other = ResourceRef("campaign", owner_group="team-b", resource_id="42")
    with pytest.raises(AccessDenied) as exc:
        require_resource(ctx, "campaign.read", other)
    assert exc.value.decision.reason_code == "cross_tenant_resource"


def test_own_tenant_resource_allowed():
    ctx = new_context("u", group_ids=["team-a"], capabilities=["campaign.read"])
    mine = ResourceRef("campaign", owner_group="team-a", resource_id="42")
    assert require_resource(ctx, "campaign.read", mine).allowed


def test_internal_actor_crosses_tenants_but_still_needs_capability():
    internal = new_context("ops", is_internal=True, capabilities=["campaign.read"])
    anywhere = ResourceRef("campaign", owner_group="team-z", resource_id="1")
    assert require_resource(internal, "campaign.read", anywhere).allowed
    # ...but a capability it was not granted is still denied.
    with pytest.raises(AccessDenied):
        require_resource(internal, "campaign.delete", anywhere)


def test_context_from_mapping_is_fail_closed():
    with pytest.raises(AccessDenied):
        context_from_mapping("not-a-mapping")
    with pytest.raises(AccessDenied):
        context_from_mapping({"is_internal": True})  # no actor
    ctx = context_from_mapping({"actor": "u", "capabilities": ["x.y"], "group_ids": ["g"]})
    assert ctx.actor == "u" and "x.y" in ctx.capabilities
