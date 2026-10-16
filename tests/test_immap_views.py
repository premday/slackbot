from datetime import date, timedelta

from helpers import ADMIN_EMAIL, COMPANIES, make_world
from premday_bot import immap
from premday_bot.immap_views import (
    EXTEND_ACTION_ID,
    HELP_TEXT,
    START_ACTION_ID,
    SUBMIT_ACTION_ID,
    VALIDATE_ACTION_ID,
    answered_text,
    attribute_modal,
    chunk_lines,
    companies_text,
    done_list_text,
    extend_modal,
    poll_card,
    poll_json_message,
    poll_modal,
    report_text,
    submit_modal,
    unattribute_modal,
    validate_modal,
)
from premday_bot.polls import ACTION_DONE, ACTION_EXTEND, poll_document


def actions(blocks) -> list[str]:
    return [e["action_id"] for b in blocks if b["type"] == "actions" for e in b["elements"]]


def validated(world, poll):
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    result = world.admin_totals(poll, ADMIN_EMAIL, nonce)
    return world.service.mark_done(
        poll.id, email=ADMIN_EMAIL, nonce=nonce, totals=result["totals"], proof=result["proof"]
    )


def card(world, poll):
    return poll_card(
        poll,
        submitted=world.service.submitted(poll),
        missing=world.service.missing(poll),
    )


def test_buttons_follow_the_status(tmp_path) -> None:
    world = make_world(tmp_path)
    created = world.new_poll(days=1)
    assert actions(card(world, created)[1]) == [START_ACTION_ID, EXTEND_ACTION_ID]
    collecting = world.collecting_poll()
    assert actions(card(world, collecting)[1]) == [SUBMIT_ACTION_ID, EXTEND_ACTION_ID]
    complete = world.complete_poll()
    assert actions(card(world, complete)[1]) == [VALIDATE_ACTION_ID]
    stale = world.collecting_poll(days=1)
    world.clock.advance(timedelta(days=3))
    world.service.expire_overdue()
    incomplete = world.service.get(stale.id)
    assert actions(card(world, incomplete)[1]) == [EXTEND_ACTION_ID]
    done = validated(world, complete)
    assert actions(card(world, done)[1]) == []


def test_card_shows_progress_extension_badge_and_small_pool_warning(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    world.submit(poll, "acme")
    text, _ = card(world, poll)
    assert "Submitted 1/3: acme" in text and "Missing: bolt, corp" in text
    assert "fewer than 10" in text and "Extended" not in text
    email = ADMIN_EMAIL
    nonce = world.service.begin_admin_action(poll.id, email=email, action=ACTION_EXTEND)
    day = (world.clock.now + timedelta(days=30)).date()
    extended = world.service.extend(
        poll.id,
        email=email,
        new_day=day,
        nonce=nonce,
        proof=world.extend_proof(poll, email, day, nonce),
    )
    text, _ = card(world, extended)
    assert "Extended \u00d71" in text and "original:" in text


def test_card_escapes_the_title_and_hides_results(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll(title="<!channel> & friends")
    text, _ = card(world, poll)
    assert "&lt;!channel&gt; &amp; friends" in text and "<!channel>" not in text


def test_complete_card_says_results_are_hidden(tmp_path) -> None:
    world = make_world(tmp_path)
    text, _ = card(world, world.complete_poll())
    assert "hidden until an admin validates" in text
    assert "Missing" not in text


def test_poll_json_message_has_fingerprints_and_no_private_key(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    message = poll_json_message(poll)
    assert poll.bot_private_key not in message
    for _, key in poll.participants:
        assert immap.fingerprint(key) in message
    assert f'"poll_id": "{poll.id}"' in message


def test_chunk_lines_keeps_lines_whole_and_under_the_limit() -> None:
    lines = ["a" * 40, "b" * 40, "c" * 40, "d" * 10]
    chunks = chunk_lines(lines, limit=85)
    assert chunks == ["a" * 40 + "\n" + "b" * 40, "c" * 40 + "\n" + "d" * 10]
    assert chunk_lines([]) == []
    assert chunk_lines(["x" * 200], limit=50) == ["x" * 200]  # never splits a line


def test_modals_carry_what_the_handlers_need() -> None:
    modal = poll_modal(
        channel_id="C1", company_ids=["acme", "bolt"], default_deadline=date(2026, 12, 1)
    )
    assert [b["block_id"] for b in modal["blocks"]] == [
        "title",
        "template",
        "deadline",
        "participants",
    ]
    template = modal["blocks"][1]["element"]
    assert [o["value"] for o in template["options"]] == list(immap.POLL_TEMPLATES)
    assert template["initial_option"] == template["options"][0]
    assert [o["value"] for o in modal["blocks"][3]["element"]["options"]] == ["acme", "bolt"]
    many = poll_modal(
        channel_id="C1",
        company_ids=[f"co-{i:03d}" for i in range(150)],
        default_deadline=date(2026, 12, 1),
    )
    assert len(many["blocks"][3]["element"]["options"]) == 100
    assert "pid" in submit_modal(poll_id="pid", title="t")["private_metadata"]
    extend = extend_modal(poll_id="pid", nonce="n0nce", current_deadline=date(2026, 12, 1))
    assert "n0nce" in extend["private_metadata"] and "n0nce" in str(extend["blocks"][0])
    validate = validate_modal(poll_id="pid", nonce="n0nce")
    assert "n0nce" in validate["private_metadata"] and "aggregate" in str(validate["blocks"][0])


def test_report_text_lists_totals_and_done_list(tmp_path) -> None:
    world = make_world(tmp_path)
    complete = world.complete_poll()
    done = validated(world, complete)
    text = report_text(done)
    assert f"host_count: {world.expected_totals()['host_count']:,} hosts" in text
    assert "validated by a.rougemont@criteo.com" in text
    assert done.id in done_list_text([done])
    assert "No validated polls" in done_list_text([])
    assert poll_document(done)["poll_id"] == done.id
    assert set(COMPANIES) <= set(text.replace(",", " ").split())


def test_card_and_report_follow_the_polls_template(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    text, _ = poll_card(poll, submitted=[], missing=list(COMPANIES))
    assert "Template: Infrastructure footprint v1 (23 metrics)" in text
    done = validated(world, world.complete_poll())
    lines = report_text(done).split("```")[1].strip().splitlines()
    assert [line.split(":")[0] for line in lines] == list(done.metrics)  # template order


def test_companies_text_lists_members_key_holder_and_users_without_a_company(tmp_path) -> None:
    world = make_world(tmp_path)
    world.service.add_company(email=ADMIN_EMAIL, company_id="empty")
    world.service.enroll(user_id="U_COLLEAGUE", public_key=immap.public_key(7654321))
    world.service.attribute_company(email=ADMIN_EMAIL, company_id="acme", user_id="U_COLLEAGUE")
    world.service.enroll(user_id="U_WAITING", public_key=immap.public_key(1234567))
    text = companies_text(
        world.service.companies(email=ADMIN_EMAIL),
        world.service.unattributed_users(email=ADMIN_EMAIL),
    )
    assert "*Companies (4)*" in text
    key = immap.public_key(world.company_keys["acme"])
    assert f"`acme`: <@U_ACME> (key holder, key `{immap.fingerprint(key)}`), <@U_COLLEAGUE>" in text
    assert "`empty`: _no member_" in text
    assert "*Enrolled, without a company:* <@U_WAITING>" in text
    assert "none yet" in companies_text([], [])


def test_answered_text_mentions_the_colleagues_and_names_the_submitter() -> None:
    text = answered_text("acme", "U_ONE", ["U_TWO", "U_THREE"])
    assert text.startswith("<@U_TWO> <@U_THREE> <@U_ONE> submitted the values of *acme*")
    assert "replaces it" in text
    assert "&lt;" in answered_text("a<b", "U_ONE", ["U_TWO"])


def test_attribute_modal_and_help_cover_company_management() -> None:
    modal = attribute_modal(["acme", "bolt"])
    assert [b["block_id"] for b in modal["blocks"]] == ["company", "user"]
    assert [o["value"] for o in modal["blocks"][0]["element"]["options"]] == ["acme", "bolt"]
    assert modal["blocks"][1]["element"]["type"] == "users_select"
    assert unattribute_modal()["blocks"][0]["element"]["type"] == "users_select"
    for command in ("register <public_key>", "companies", "company add", "company remove",
                    "company attribute", "company unattribute"):
        assert f"/immap {command}" in HELP_TEXT
