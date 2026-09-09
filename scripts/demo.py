"""Show the guard allowing and denying, with reason codes.

    python scripts/demo.py
"""

from __future__ import annotations

from access_guard import AccessDenied, ResourceRef, new_context, require_capability, require_resource


def main() -> None:
    user = new_context("u-1", group_ids=["team-a"], capabilities=["knowledge.read.*", "campaign.read"])

    print("read marketing  ->", require_capability(user, "knowledge.read.marketing").reason_code)

    for cap in ("knowledge.write.marketing", "campaign.delete"):
        try:
            require_capability(user, cap)
        except AccessDenied as exc:
            print(f"{cap:<28}-> denied ({exc.decision.reason_code})")

    mine = ResourceRef("campaign", owner_group="team-a", resource_id="42")
    other = ResourceRef("campaign", owner_group="team-b", resource_id="99")
    print("own campaign    ->", require_resource(user, "campaign.read", mine).reason_code)
    try:
        require_resource(user, "campaign.read", other)
    except AccessDenied as exc:
        print("other tenant    -> denied (" + exc.decision.reason_code + ")")


if __name__ == "__main__":
    main()
