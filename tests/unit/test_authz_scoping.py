"""Authorization-scoping tests for campaign-scoped API data.

These lock in that one tenant cannot read or write another tenant's campaign
data through the OOB and payload endpoints (IDOR regression guards).
"""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from src.api.v1.campaigns import _check_campaign_membership, user_campaign_ids
from src.core.database import Campaign, CampaignMember, MemberRole, OOBInteraction, PayloadRecord


async def _make_campaign(db, owner: str) -> Campaign:
    campaign = Campaign(name="c", scope={"allowed_domains": ["example.com"]}, created_by=owner)
    db.add(campaign)
    await db.commit()
    await db.refresh(campaign)
    return campaign


def _req(user_id: str):
    return SimpleNamespace(state=SimpleNamespace(user_id=user_id))


@pytest.mark.asyncio
async def test_user_campaign_ids_scopes_by_creator_and_member(db_session):
    campaign = await _make_campaign(db_session, "userA")
    db_session.add(CampaignMember(campaign_id=campaign.id, user_id="userB", role=MemberRole.OBSERVER))
    await db_session.commit()

    assert campaign.id in await user_campaign_ids("userA", db_session)  # creator
    assert campaign.id in await user_campaign_ids("userB", db_session)  # member
    assert campaign.id not in await user_campaign_ids("userC", db_session)  # outsider


@pytest.mark.asyncio
async def test_check_membership_denies_outsider(db_session):
    campaign = await _make_campaign(db_session, "userA")
    await _check_campaign_membership(campaign.id, "userA", db_session)  # creator passes
    with pytest.raises(HTTPException) as exc:
        await _check_campaign_membership(campaign.id, "userC", db_session)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_oob_interactions_hidden_from_outsider(db_session):
    from src.api.v1.oob import list_interactions

    campaign = await _make_campaign(db_session, "userA")
    db_session.add(OOBInteraction(campaign_id=campaign.id, listener_id="L1", interaction_type="http"))
    await db_session.commit()

    # Outsider, unfiltered: must not see another tenant's interactions.
    out = await list_interactions(
        request=_req("userC"), campaign_id=None, listener_id=None, interaction_type=None, db=db_session
    )
    assert out == []

    # Outsider asking for the campaign explicitly: 403.
    with pytest.raises(HTTPException) as exc:
        await list_interactions(
            request=_req("userC"), campaign_id=campaign.id, listener_id=None, interaction_type=None, db=db_session
        )
    assert exc.value.status_code == 403

    # Owner sees it.
    owned = await list_interactions(
        request=_req("userA"), campaign_id=campaign.id, listener_id=None, interaction_type=None, db=db_session
    )
    assert len(owned) == 1


@pytest.mark.asyncio
async def test_payload_effectiveness_hidden_from_outsider(db_session):
    from src.api.v1.payloads import get_effectiveness

    campaign = await _make_campaign(db_session, "userA")
    db_session.add(PayloadRecord(name="p", category="xss", original_payload="<script>", campaign_id=campaign.id))
    await db_session.commit()

    out = await get_effectiveness(request=_req("userC"), campaign_id=None, category=None, db=db_session)
    assert out == []

    with pytest.raises(HTTPException) as exc:
        await get_effectiveness(request=_req("userC"), campaign_id=campaign.id, category=None, db=db_session)
    assert exc.value.status_code == 403
