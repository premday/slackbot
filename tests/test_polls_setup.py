from dataclasses import replace
from datetime import date, timedelta

import pytest

from helpers import (
    ADMIN_EMAIL,
    ADMIN_EMAILS,
    COMPANIES,
    NOT_ADMIN_EMAIL,
    SECOND_ADMIN_EMAIL,
    TEMPLATE_METRICS,
    enroll_and_attribute,
    make_world,
    owner,
)
from premday_bot import immap
from premday_bot.polls import (
    CREATED,
    MAX_ADMIN_KEYS,
    MAX_TITLE_LENGTH,
    PollError,
    PollService,
    PollStore,
    is_admin,
    poll_document,
    unfence,
)


def test_admin_is_decided_by_email_case_insensitively() -> None:
    assert is_admin("A.Rougemont@Criteo.com", ADMIN_EMAILS)
    assert is_admin(SECOND_ADMIN_EMAIL, ADMIN_EMAILS)
    assert not is_admin(NOT_ADMIN_EMAIL, ADMIN_EMAILS)
    assert not is_admin(None, ADMIN_EMAILS)
    assert not is_admin("a.rougemont@criteo.com", frozenset())


def members_of(service: PollService, company_id: str) -> tuple[str, ...]:
    companies = {c.company_id: c for c in service.companies(email=ADMIN_EMAIL)}
    return companies[company_id].members


def test_enrolling_needs_a_valid_key_and_unique_keys(tmp_path) -> None:
    world = make_world(tmp_path)
    key = immap.public_key(immap.generate_private_key())
    assert world.service.enroll(user_id="U_NEW", public_key=key) == immap.fingerprint(key)
    with pytest.raises(PollError, match="already enrolled"):
        world.service.enroll(user_id="U_OTHER", public_key=key)
    with pytest.raises(PollError, match="Invalid public key"):
        world.service.enroll(user_id="U_NEW", public_key="zz")
    # Enrolling again replaces your key (rotation); the company follows its key holder.
    new_key = immap.public_key(immap.generate_private_key())
    world.service.enroll(user_id=owner("acme"), public_key=new_key)
    company = next(c for c in world.service.companies(email=ADMIN_EMAIL) if c.company_id == "acme")
    assert company.public_key == new_key and company.members == (owner("acme"),)


def test_admins_manage_the_list_of_companies(tmp_path) -> None:
    world = make_world(tmp_path)
    service = world.service
    service.add_company(email=ADMIN_EMAIL, company_id="newco")
    with pytest.raises(PollError, match="already exists"):
        service.add_company(email=ADMIN_EMAIL, company_id="newco")
    for bad_id in ("A", "x", "has space", "UPPER", "a" * 33):
        with pytest.raises(PollError, match="company id"):
            service.add_company(email=ADMIN_EMAIL, company_id=bad_id)
    listed = {c.company_id: c for c in service.companies(email=SECOND_ADMIN_EMAIL)}
    assert set(listed) == {*COMPANIES, "newco"}
    assert listed["newco"].members == () and listed["newco"].public_key is None
    service.remove_company(email=ADMIN_EMAIL, company_id="newco")
    assert "newco" not in {c.company_id for c in service.companies(email=ADMIN_EMAIL)}
    with pytest.raises(PollError, match="does not exist"):
        service.remove_company(email=ADMIN_EMAIL, company_id="newco")


def test_admins_add_enrolled_users_to_a_company_and_the_first_holds_the_key(tmp_path) -> None:
    world = make_world(tmp_path)
    service = world.service
    first_key = immap.public_key(immap.generate_private_key())
    second_key = immap.public_key(immap.generate_private_key())
    service.add_company(email=ADMIN_EMAIL, company_id="newco")
    with pytest.raises(PollError, match="has not enrolled"):
        service.attribute_company(email=ADMIN_EMAIL, company_id="newco", user_id="U_ONE")
    service.enroll(user_id="U_ONE", public_key=first_key)
    service.enroll(user_id="U_TWO", public_key=second_key)
    assert service.unattributed_users(email=ADMIN_EMAIL) == ["U_ONE", "U_TWO"]
    service.attribute_company(email=ADMIN_EMAIL, company_id="newco", user_id="U_ONE")
    company = service.attribute_company(email=ADMIN_EMAIL, company_id="newco", user_id="U_TWO")
    assert company.members == ("U_ONE", "U_TWO") and company.public_key == first_key
    assert service.attribute_company(email=ADMIN_EMAIL, company_id="newco", user_id="U_ONE") == (
        company
    )
    assert service.unattributed_users(email=ADMIN_EMAIL) == []
    assert service.members_of("newco") == ["U_ONE", "U_TWO"]
    assert service.company_of("U_TWO") == "newco" and service.company_of("U_STRANGER") is None
    with pytest.raises(PollError, match="does not exist"):
        service.attribute_company(email=ADMIN_EMAIL, company_id="ghost", user_id="U_ONE")
    # A user belongs to one company.
    with pytest.raises(PollError, match="already belongs to `newco`"):
        service.attribute_company(email=ADMIN_EMAIL, company_id="acme", user_id="U_TWO")
    assert service.unattribute_user(email=ADMIN_EMAIL, user_id="U_ONE") == "newco"
    company = next(c for c in service.companies(email=ADMIN_EMAIL) if c.company_id == "newco")
    assert company.members == ("U_TWO",) and company.public_key == second_key  # key holder moves
    with pytest.raises(PollError, match="does not belong"):
        service.unattribute_user(email=ADMIN_EMAIL, user_id="U_ONE")
    service.attribute_company(email=ADMIN_EMAIL, company_id="acme", user_id="U_ONE")
    assert members_of(service, "acme") == (owner("acme"), "U_ONE")


def test_company_management_is_for_admins_only(tmp_path) -> None:
    world = make_world(tmp_path)
    service = world.service
    for email in (NOT_ADMIN_EMAIL, None):
        for call in (
            lambda e=email: service.add_company(email=e, company_id="newco"),
            lambda e=email: service.remove_company(email=e, company_id="acme"),
            lambda e=email: service.attribute_company(email=e, company_id="acme", user_id="U1"),
            lambda e=email: service.unattribute_user(email=e, user_id=owner("acme")),
            lambda e=email: service.companies(email=e),
            lambda e=email: service.unattributed_users(email=e),
        ):
            with pytest.raises(PollError, match="Only admins"):
                call()
    assert len(service.companies(email=ADMIN_EMAIL)) == len(COMPANIES)


def test_a_companys_key_cannot_change_while_it_is_in_an_open_poll(tmp_path) -> None:
    world = make_world(tmp_path)
    service = world.service
    poll = world.new_poll()
    service.enroll(user_id="U_NEW", public_key=immap.public_key(immap.generate_private_key()))
    for call in (
        lambda: service.remove_company(email=ADMIN_EMAIL, company_id="acme"),
        lambda: service.unattribute_user(email=ADMIN_EMAIL, user_id=owner("acme")),  # key holder
    ):
        with pytest.raises(PollError, match=f"open poll `{poll.id}`"):
            call()
    # Adding a colleague, and removing a non-holder, leave the key alone, so they stay possible.
    service.attribute_company(email=ADMIN_EMAIL, company_id="acme", user_id="U_NEW")
    assert service.unattribute_user(email=ADMIN_EMAIL, user_id="U_NEW") == "acme"
    # A company that is not in that poll is free to change.
    service.add_company(email=ADMIN_EMAIL, company_id="other")
    service.remove_company(email=ADMIN_EMAIL, company_id="other")


def test_a_company_without_a_member_cannot_join_a_poll(tmp_path) -> None:
    world = make_world(tmp_path)
    world.service.add_company(email=ADMIN_EMAIL, company_id="empty")
    with pytest.raises(PollError, match="no member"):
        world.new_poll(participants=[*COMPANIES, "empty"])
    assert "empty" not in world.service.pollable_company_ids()


def test_only_admins_can_register_admin_keys_and_the_number_is_capped(tmp_path) -> None:
    world = make_world(tmp_path)
    key = immap.public_key(immap.generate_private_key())
    with pytest.raises(PollError, match="Only admins"):
        world.service.register_admin_key(email=NOT_ADMIN_EMAIL, public_key=key)
    with pytest.raises(PollError, match="Only admins"):
        world.service.register_admin_key(email=None, public_key=key)
    assert world.service.register_admin_key(email=ADMIN_EMAIL, public_key=key) == (
        immap.fingerprint(key)
    )
    many = frozenset(f"admin{i}@example.com" for i in range(MAX_ADMIN_KEYS + 1))
    service = PollService(PollStore(tmp_path / "many.sqlite3"), timezone="UTC", admin_emails=many)
    for email in sorted(many)[:MAX_ADMIN_KEYS]:
        service.register_admin_key(
            email=email, public_key=immap.public_key(immap.generate_private_key())
        )
    with pytest.raises(PollError, match="At most"):
        service.register_admin_key(
            email=sorted(many)[-1], public_key=immap.public_key(immap.generate_private_key())
        )


def test_create_poll_snapshots_keys_and_starts_in_created(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    assert poll.status == CREATED
    assert poll.participant_ids == sorted(COMPANIES)
    assert [email for email, _ in poll.admins] == sorted([ADMIN_EMAIL, SECOND_ADMIN_EMAIL])
    assert poll.deadline.tzinfo is not None and poll.deadline == poll.original_deadline
    # Rotating a company key later does not change an existing poll.
    world.service.enroll(
        user_id=owner("acme"), public_key=immap.public_key(immap.generate_private_key())
    )
    assert world.service.get(poll.id).participants == poll.participants


def test_poll_document_never_contains_private_material(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    document = poll_document(poll)
    assert document["bot_public_key"] == poll.bot_public_key
    assert poll.bot_private_key not in str(document)
    assert set(document["metrics"]) == set(TEMPLATE_METRICS)
    assert [p["company_id"] for p in document["participants"]] == sorted(COMPANIES)


def test_create_poll_validation(tmp_path) -> None:
    world = make_world(tmp_path)
    service = world.service
    day = (world.clock.now + timedelta(days=3)).date()
    base = {"channel_id": "C1", "creator_user_id": "U1", "title": "t", "deadline_day": day}
    with pytest.raises(PollError, match="at least 3"):
        service.create_poll(**base, participants=["acme", "bolt"])
    with pytest.raises(PollError, match="at least 3"):
        service.create_poll(**base, participants=["acme", "acme", "bolt"])
    with pytest.raises(PollError, match="does not exist"):
        service.create_poll(**base, participants=["acme", "bolt", "ghost"])
    with pytest.raises(PollError, match="title"):
        service.create_poll(**{**base, "title": "  "}, participants=list(COMPANIES))
    yesterday = (world.clock.now - timedelta(days=1)).date()
    with pytest.raises(PollError, match="future"):
        service.create_poll(**{**base, "deadline_day": yesterday}, participants=list(COMPANIES))


def test_create_poll_needs_an_admin_key(tmp_path) -> None:
    store = PollStore(tmp_path / "noadmin.sqlite3")
    service = PollService(store, timezone="UTC", admin_emails=ADMIN_EMAILS)
    for company_id in COMPANIES:
        enroll_and_attribute(service, company_id, immap.public_key(immap.generate_private_key()))

    with pytest.raises(PollError, match="admin"):
        service.create_poll(
            channel_id="C1",
            creator_user_id="U1",
            title="t",
            deadline_day=date(2999, 1, 1),
            participants=list(COMPANIES),
        )


def test_pollable_companies_are_listed_sorted(tmp_path) -> None:
    world = make_world(tmp_path)
    assert world.service.pollable_company_ids() == sorted(COMPANIES)


def test_polls_cannot_start_before_enough_companies_and_an_admin_key_exist(tmp_path) -> None:
    store = PollStore(tmp_path / "early.sqlite3")
    service = PollService(store, timezone="UTC", admin_emails=ADMIN_EMAILS)
    with pytest.raises(PollError, match="At least 3 companies need a member"):
        service.pollable_company_ids()
    for company_id in COMPANIES:
        enroll_and_attribute(service, company_id, immap.public_key(immap.generate_private_key()))
    with pytest.raises(PollError, match="No admin has registered a key"):
        service.pollable_company_ids()
    service.register_admin_key(
        email=ADMIN_EMAIL, public_key=immap.public_key(immap.generate_private_key())
    )
    assert service.pollable_company_ids() == sorted(COMPANIES)


def test_two_users_cannot_share_a_public_key(tmp_path) -> None:
    world = make_world(tmp_path)
    shared = immap.public_key(world.company_keys["acme"])
    with pytest.raises(PollError, match="already enrolled by another"):
        world.service.enroll(user_id="U_TWIN", public_key=shared)
    # Enrolling your own key again is fine.
    world.service.enroll(user_id=owner("acme"), public_key=shared)


def test_pasted_keys_may_carry_backticks_but_not_hex_prefixes(tmp_path) -> None:
    world = make_world(tmp_path)
    key = immap.public_key(immap.generate_private_key())
    world.service.enroll(user_id="U_NEW", public_key=f"`{key}`")
    world.service.add_company(email=ADMIN_EMAIL, company_id="newco")
    company = world.service.attribute_company(
        email=ADMIN_EMAIL, company_id="newco", user_id="U_NEW"
    )
    assert company.public_key == key
    for bad in ("0x" + key, key[:10] + "_" + key[10:], "", "   "):
        with pytest.raises(PollError, match="Invalid public key"):
            world.service.enroll(user_id="U_O", public_key=bad)


def test_titles_are_limited_in_length(tmp_path) -> None:
    world = make_world(tmp_path)
    with pytest.raises(PollError, match="too long"):
        world.new_poll(title="x" * (MAX_TITLE_LENGTH + 1))
    assert world.new_poll(title="x" * MAX_TITLE_LENGTH).title == "x" * MAX_TITLE_LENGTH


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("abc", "abc"),
        ("  abc\n", "abc"),
        ("`abc`", "abc"),
        ("```abc```", "abc"),
        ("```\nabc\n```", "abc"),
        ('```json\n{"a": 1}\n```', '{"a": 1}'),
    ],
)
def test_unfence_strips_slack_code_markup(raw: str, expected: str) -> None:
    assert unfence(raw) == expected


def test_poll_snapshots_its_template(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    template = immap.POLL_TEMPLATES[immap.DEFAULT_TEMPLATE]
    assert (poll.template, poll.schema_version) == (template.id, template.version)
    assert poll.metrics == template.metrics
    assert poll_document(poll)["template"] == template.id
    # A later edit of the template must not change a poll that already exists.
    edited = {**template.metrics, "extra_metric": "units"}
    immap.POLL_TEMPLATES[template.id] = replace(template, version=2, metrics=edited)
    try:
        stored = world.service.get(poll.id)
        assert stored.metrics == template.metrics and stored.schema_version == 1
        assert "extra_metric" not in poll_document(stored)["metrics"]
    finally:
        immap.POLL_TEMPLATES[template.id] = template


def test_create_poll_rejects_an_unknown_template(tmp_path) -> None:
    world = make_world(tmp_path)
    with pytest.raises(PollError, match="template"):
        world.service.create_poll(
            channel_id="C1",
            creator_user_id=owner("acme"),
            title="Infra",
            deadline_day=date(2026, 12, 1),
            participants=list(COMPANIES),
            template="nope",
        )


def test_poll_json_does_not_publish_admin_emails(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    document = poll_document(poll)
    assert ADMIN_EMAIL not in str(document) and SECOND_ADMIN_EMAIL not in str(document)
    ids = [admin["admin_id"] for admin in document["admins"]]
    assert len(set(ids)) == 2 and all(len(i) == 8 for i in ids)
