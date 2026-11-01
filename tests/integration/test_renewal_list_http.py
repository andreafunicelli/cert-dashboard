"""``/renewals`` over HTTP (spec §8.5): the renewal list, filterable by state, with the next action.

The world is built once for the module — one renewal per state — so a page total is an exact number and the
state filters can be proven against rows that really exist and must stay out.
"""

import re
import secrets
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.models import PrivateKey, Renewal
from app.models.enums import PrivateKeyType, RenewalState
from app.services.renewals import RenewalFilters, list_renewals

_WORLD: SimpleNamespace | None = None
NEXT_ACTIONS = {
    RenewalState.DRAFT: "Generate the CSR",
    RenewalState.CSR_GENERATED: "Record the CA order",
    RenewalState.SUBMITTED: "Upload the issued certificate",
    RenewalState.ISSUED: "Deploy the certificate",
    RenewalState.DEPLOYED: "Finish the renewal",
}
AWAITING = (RenewalState.DRAFT, RenewalState.CSR_GENERATED, RenewalState.SUBMITTED)


def _key(db) -> int:
    key = PrivateKey(
        key_type=PrivateKeyType.ECDSA,
        key_size=256,
        curve="P-256",
        ciphertext=b"x",
        nonce=b"n" * 12,
        aad="fixture",
        master_key_version=1,
        public_key_sha256=secrets.token_hex(32),
        public_key_pem="fixture",
        origin="generated",
    )
    db.add(key)
    db.flush()
    return key.id


def _build(factory, now) -> SimpleNamespace:
    with factory.begin() as db:
        renewals = {}
        for state, age in (
            (RenewalState.DRAFT, 10),
            (RenewalState.CSR_GENERATED, 5),
            (RenewalState.SUBMITTED, 3),
            (RenewalState.ISSUED, 1),
            (RenewalState.DONE, 0),
            (RenewalState.CANCELLED, 0),
        ):
            name = f"{state.value}-{secrets.token_hex(3)}.example.test"
            row = Renewal(
                common_name=name,
                sans=[name],
                state=state,
                state_changed_at=now - timedelta(days=age),
                key_id=None if state in (RenewalState.DRAFT, RenewalState.CANCELLED) else _key(db),
            )
            db.add(row)
            db.flush()
            renewals[state.value] = SimpleNamespace(id=str(row.id), common_name=name, age=age)
    return SimpleNamespace(total=len(renewals), **renewals)


@pytest.fixture
def renewal_list_world(web_factory, now):
    global _WORLD
    if _WORLD is None:
        _WORLD = _build(web_factory, now)
    return _WORLD


def _ids(html: str) -> list[str]:
    return re.findall(r'data-renewal-id="([0-9a-f-]+)"', html)


def _row(html: str, renewal_id: str) -> str:
    start = html.index(f'data-renewal-id="{renewal_id}"')
    return html[html.rindex("<tr", 0, start) : html.index("</tr>", start)]


def test_renewal_list_requires_a_session(client):
    response = client.get("/renewals", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_renewal_list_shows_name_state_age_and_next_action(signed_in, renewal_list_world):
    page = signed_in.get("/renewals")
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert f'data-total="{renewal_list_world.total}"' in page.text
    assert len(_ids(page.text)) == renewal_list_world.total

    draft = _row(page.text, renewal_list_world.draft.id)
    assert renewal_list_world.draft.common_name in draft
    assert 'data-state="draft"' in draft and 'data-age-days="10">10</span>' in draft  # state and age in days
    assert "Generate the CSR" in draft
    assert f"/renewals/{renewal_list_world.draft.id}?step=csr" in draft

    submitted = _row(page.text, renewal_list_world.submitted.id)
    assert "Upload the issued certificate" in submitted
    assert f"/renewals/{renewal_list_world.submitted.id}?step=upload" in submitted

    done = _row(page.text, renewal_list_world.done.id)
    assert "data-next-action" not in done  # nothing left to do on a finished renewal


def test_state_filter_keeps_the_non_matching_rows_out(signed_in, renewal_list_world):
    submitted = signed_in.get("/renewals?state=submitted")
    assert submitted.status_code == 200
    assert _ids(submitted.text) == [renewal_list_world.submitted.id]

    cancelled = signed_in.get("/renewals?state=cancelled")
    assert _ids(cancelled.text) == [renewal_list_world.cancelled.id]


def test_awaiting_certificate_filter_is_the_overview_queue(signed_in, renewal_list_world):
    awaiting = signed_in.get("/renewals?state=awaiting_certificate")
    assert awaiting.status_code == 200
    assert set(_ids(awaiting.text)) == {getattr(renewal_list_world, state.value).id for state in AWAITING}
    issued = renewal_list_world.issued.id
    assert issued not in _ids(awaiting.text)  # already issued: waiting for a deploy, not for the CA


def test_renewal_list_is_paginated_like_every_other_list(signed_in, renewal_list_world):
    first = signed_in.get("/renewals?state=awaiting_certificate&page_size=1")
    assert first.status_code == 200
    assert f'data-total="{len(AWAITING)}"' in first.text
    assert len(_ids(first.text)) == 1
    second = signed_in.get("/renewals?state=awaiting_certificate&page_size=1&page=2")
    third = signed_in.get("/renewals?state=awaiting_certificate&page_size=1&page=3")
    assert [len(_ids(page.text)) for page in (second, third)] == [1, 1]
    assert len({_ids(first.text)[0], _ids(second.text)[0], _ids(third.text)[0]}) == 3


@pytest.mark.parametrize("query", ["state=bogus", "page=0", "page_size=0", "page_size=101"])
def test_renewal_list_rejects_invalid_query_values(signed_in, query):
    assert signed_in.get(f"/renewals?{query}").status_code == 422


def test_list_renewals_reports_the_next_action_of_every_state(db, now):
    """Service level: the action and the step page the list links to, for every state (oldest first)."""
    ids = {}
    for index, state in enumerate(RenewalState):
        name = f"{state.value}-{secrets.token_hex(3)}.example.test"
        row = Renewal(
            common_name=name,
            sans=[name],
            state=state,
            state_changed_at=now - timedelta(days=len(RenewalState) - index),
            key_id=None if state in (RenewalState.DRAFT, RenewalState.CANCELLED) else _key(db),
        )
        db.add(row)
        db.flush()
        ids[state] = str(row.id)

    page = list_renewals(db, RenewalFilters(), now=now)
    assert page.total == len(RenewalState)
    by_id = {row.id: row for row in page.items}
    for state in RenewalState:
        row = by_id[ids[state]]
        if state in NEXT_ACTIONS:
            assert row.next_action == NEXT_ACTIONS[state]
            assert row.next_action_url == f"/renewals/{row.id}?step={row.next_action_step}"
        else:
            assert (row.next_action, row.next_action_url) == (None, None)
    assert {row.state for row in page.items} == {state.value for state in RenewalState}
    draft = by_id[ids[RenewalState.DRAFT]]
    assert draft.age_days == len(RenewalState)  # oldest state change first, age in days
