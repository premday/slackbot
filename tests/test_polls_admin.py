from datetime import timedelta
from typing import Any

import pytest

from helpers import (
    ADMIN_EMAIL,
    COMPANIES,
    NOT_ADMIN_EMAIL,
    SECOND_ADMIN_EMAIL,
    TEMPLATE_METRICS,
    make_world,
    owner,
)
from premday_bot import immap
from premday_bot.polls import (
    ACTION_DONE,
    ACTION_EXTEND,
    COLLECTING,
    COMPLETE,
    CREATED,
    DONE,
    INCOMPLETE,
    NONCE_TTL,
    PollError,
    poll_document,
)


def extend(world, poll, email, days, *, nonce=None, proof=None):
    new_day = (world.clock.now + timedelta(days=days)).date()
    nonce = nonce or world.service.begin_admin_action(poll.id, email=email, action=ACTION_EXTEND)
    proof = proof or world.extend_proof(poll, email, new_day, nonce)
    return world.service.extend(poll.id, email=email, new_day=new_day, nonce=nonce, proof=proof)


def validate(world, poll, email=ADMIN_EMAIL):
    nonce = world.service.begin_admin_action(poll.id, email=email, action=ACTION_DONE)
    result = world.admin_totals(poll, email, nonce)
    return world.service.mark_done(
        poll.id, email=email, nonce=nonce, totals=result["totals"], proof=result["proof"]
    )


# -- the full happy path, by either admin ----------------------------------------------------


@pytest.mark.parametrize("email", [ADMIN_EMAIL, SECOND_ADMIN_EMAIL])
def test_any_admin_can_validate_and_totals_become_readable(tmp_path, email) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    done = validate(world, poll, email)
    assert done.status == DONE and done.validated_by == email
    assert world.service.report(poll.id).totals == world.expected_totals()
    assert [p.id for p in world.service.done_polls("C1")] == [poll.id]
    assert world.service.done_polls("C_OTHER") == []


# -- visibility gate --------------------------------------------------------------------------


@pytest.mark.parametrize("stage", [CREATED, COLLECTING, COMPLETE, INCOMPLETE])
def test_report_refuses_every_status_but_done(tmp_path, stage) -> None:
    world = make_world(tmp_path)
    if stage == COMPLETE:
        poll = world.complete_poll()
    else:
        poll = world.new_poll(days=1) if stage in (CREATED, INCOMPLETE) else world.collecting_poll()
        if stage == INCOMPLETE:
            world.service.start(poll.id, user_id=owner("acme"), email=None)
            world.clock.advance(timedelta(days=3))
            world.service.expire_overdue()
    assert world.service.get(poll.id).status == stage
    with pytest.raises(PollError, match="not been validated"):
        world.service.report(poll.id)
    assert world.service.done_polls("C1") == []


def test_report_of_unknown_poll(tmp_path) -> None:
    with pytest.raises(PollError, match="could not find"):
        make_world(tmp_path).service.report("nope")


# -- authorization ----------------------------------------------------------------------------


@pytest.mark.parametrize("email", [NOT_ADMIN_EMAIL, None])
def test_non_admins_cannot_use_admin_actions(tmp_path, email) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    for action in (ACTION_EXTEND, ACTION_DONE):
        with pytest.raises(PollError, match="Only admins"):
            world.service.begin_admin_action(poll.id, email=email, action=action)
    with pytest.raises(PollError, match="Only admins"):
        world.service.submission_lines(poll.id, email=email)
    with pytest.raises(PollError, match="Only admins"):
        world.service.mark_done(poll.id, email=email, nonce="x", totals={}, proof="x")
    with pytest.raises(PollError, match="Only admins"):
        world.service.extend(
            poll.id, email=email, new_day=world.clock.now.date(), nonce="x", proof="x"
        )


def test_slack_email_alone_is_not_enough_for_done(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    result = world.admin_totals(poll, ADMIN_EMAIL, nonce)
    with pytest.raises(PollError, match="proof is invalid"):
        world.service.mark_done(
            poll.id, email=ADMIN_EMAIL, nonce=nonce, totals=result["totals"], proof="0" * 64
        )
    assert world.service.get(poll.id).status == COMPLETE


def test_a_proof_made_with_another_admins_key_is_refused(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    forged = world.admin_totals(poll, SECOND_ADMIN_EMAIL, nonce)  # second admin's proof
    with pytest.raises(PollError, match="proof is invalid"):
        world.service.mark_done(
            poll.id, email=ADMIN_EMAIL, nonce=nonce, totals=forged["totals"], proof=forged["proof"]
        )


def test_done_proof_covers_the_totals(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    result = world.admin_totals(poll, ADMIN_EMAIL, nonce)
    tampered = {**result["totals"], "host_count": result["totals"]["host_count"] + 1}
    with pytest.raises(PollError, match="proof is invalid"):
        world.service.mark_done(
            poll.id, email=ADMIN_EMAIL, nonce=nonce, totals=tampered, proof=result["proof"]
        )


def test_totals_must_match_the_metrics(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    bad_totals: list[dict[str, Any]] = [
        {},
        {"host_count": 1},
        {**dict.fromkeys(TEMPLATE_METRICS, 1), "x": 1},
        dict.fromkeys(TEMPLATE_METRICS, -1),
        dict.fromkeys(TEMPLATE_METRICS, "1"),
    ]
    for totals in bad_totals:
        nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
        with pytest.raises(PollError, match="do not match"):
            world.service.mark_done(
                poll.id, email=ADMIN_EMAIL, nonce=nonce, totals=totals, proof="x"
            )


def test_an_admin_key_registered_after_creation_cannot_act_on_older_polls(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    late = "late.admin@example.com"
    world.service._admin_emails = world.service._admin_emails | {late}
    late_key = immap.generate_private_key()
    world.service.register_admin_key(email=late, public_key=immap.public_key(late_key))
    nonce = world.service.begin_admin_action(poll.id, email=late, action=ACTION_EXTEND)
    day = (world.clock.now + timedelta(days=30)).date()
    proof = immap.make_proof(late_key, poll_document(poll), ACTION_EXTEND, day.isoformat(), nonce)
    with pytest.raises(PollError, match="not registered when this poll was created"):
        world.service.extend(poll.id, email=late, new_day=day, nonce=nonce, proof=proof)


# -- nonces -------------------------------------------------------------------------------------


def test_nonces_are_single_use_expiring_and_bound(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    updated = extend(world, poll, ADMIN_EMAIL, 14)
    # Reusing the spent nonce fails.
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    new_day = (world.clock.now + timedelta(days=20)).date()
    proof = world.extend_proof(updated, ADMIN_EMAIL, new_day, nonce)
    world.service.extend(poll.id, email=ADMIN_EMAIL, new_day=new_day, nonce=nonce, proof=proof)
    with pytest.raises(PollError, match="expired or was already used"):
        world.service.extend(poll.id, email=ADMIN_EMAIL, new_day=new_day, nonce=nonce, proof=proof)
    # A nonce issued to one admin cannot be used by the other.
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    day = (world.clock.now + timedelta(days=40)).date()
    with pytest.raises(PollError, match="expired or was already used"):
        world.service.extend(
            poll.id,
            email=SECOND_ADMIN_EMAIL,
            new_day=day,
            nonce=nonce,
            proof=world.extend_proof(updated, SECOND_ADMIN_EMAIL, day, nonce),
        )
    # An expired nonce fails.
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    world.clock.advance(NONCE_TTL + timedelta(seconds=1))
    with pytest.raises(PollError, match="expired or was already used"):
        world.service.extend(
            poll.id,
            email=ADMIN_EMAIL,
            new_day=day,
            nonce=nonce,
            proof=world.extend_proof(updated, ADMIN_EMAIL, day, nonce),
        )
    # A nonce is bound to its poll and action: an extend nonce cannot validate another poll.
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    other = world.complete_poll()
    with pytest.raises(PollError, match="expired or was already used"):
        world.service.mark_done(
            other.id, email=ADMIN_EMAIL, nonce=nonce, totals=world.expected_totals(), proof="x"
        )


def test_begin_admin_action_checks_status_and_action(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    with pytest.raises(PollError, match="complete poll"):
        world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    with pytest.raises(PollError, match="Unknown"):
        world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action="delete")
    complete = world.complete_poll()
    with pytest.raises(PollError, match="cannot be extended"):
        world.service.begin_admin_action(complete.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)


def test_submissions_are_released_only_for_a_complete_poll(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    world.submit(poll, "acme")
    with pytest.raises(PollError, match="complete poll"):
        world.service.submission_lines(poll.id, email=ADMIN_EMAIL)
    complete = world.complete_poll()
    assert len(world.service.submission_lines(complete.id, email=ADMIN_EMAIL)) == len(COMPANIES)


def test_a_done_poll_cannot_be_validated_or_extended_again(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = validate(world, world.complete_poll())
    with pytest.raises(PollError):
        world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    with pytest.raises(PollError, match="cannot be extended"):
        world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)


# -- extending ----------------------------------------------------------------------------------


def test_extend_from_created_and_collecting_keeps_the_state_and_badges_it(tmp_path) -> None:
    world = make_world(tmp_path)
    created = world.new_poll(days=2)
    extended = extend(world, created, ADMIN_EMAIL, 9)
    assert extended.status == CREATED and extended.extension_count == 1
    assert extended.deadline > extended.original_deadline == created.deadline
    collecting = world.collecting_poll()
    extended = extend(world, collecting, SECOND_ADMIN_EMAIL, 30)
    assert extended.status == COLLECTING and extended.extension_count == 1
    extended = extend(world, extended, ADMIN_EMAIL, 40)
    assert extended.extension_count == 2


def test_extend_from_incomplete_resumes_collecting_and_keeps_submissions(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll(days=1)
    world.submit(poll, "acme")
    world.submit(poll, "bolt")
    world.clock.advance(timedelta(days=3))
    [(expired, missing)] = world.service.expire_overdue()
    assert expired.status == INCOMPLETE and missing == ["corp"]
    with pytest.raises(PollError, match="incomplete"):
        world.submit(poll, "corp")
    resumed = extend(world, expired, ADMIN_EMAIL, 5)
    assert resumed.status == COLLECTING and resumed.extension_count == 1
    assert resumed.last_reminded_at == world.clock.now
    assert world.service.submitted(resumed) == ["acme", "bolt"]
    final = world.submit(resumed, "corp")
    assert final.status == COMPLETE


def test_extend_rejects_earlier_or_past_deadlines(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll(days=10)
    for days in (10, 3, -1):
        with pytest.raises(PollError, match="later than the current"):
            extend(world, poll, ADMIN_EMAIL, days)
    assert world.service.get(poll.id).extension_count == 0


def test_extend_after_deadline_needs_a_future_date(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll(days=1)
    world.clock.advance(timedelta(days=5))
    world.service.expire_overdue()
    with pytest.raises(PollError, match="later than the current"):
        extend(world, world.service.get(poll.id), ADMIN_EMAIL, -1)
    resumed = extend(world, world.service.get(poll.id), ADMIN_EMAIL, 0)  # later today is fine
    assert resumed.status == COLLECTING


def test_extend_needs_a_valid_proof(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    day = (world.clock.now + timedelta(days=30)).date()
    with pytest.raises(PollError, match="proof is invalid"):
        world.service.extend(poll.id, email=ADMIN_EMAIL, new_day=day, nonce=nonce, proof="0" * 64)
    other_day = day + timedelta(days=1)  # proof is bound to the date it was made for
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    with pytest.raises(PollError, match="proof is invalid"):
        world.service.extend(
            poll.id, email=ADMIN_EMAIL, new_day=other_day, nonce=nonce,
            proof=world.extend_proof(poll, ADMIN_EMAIL, day, nonce),
        )
    assert world.service.get(poll.id).extension_count == 0


# -- deadline and reminders ---------------------------------------------------------------------


def test_expiry_only_touches_overdue_collecting_polls(tmp_path) -> None:
    world = make_world(tmp_path)
    overdue = world.collecting_poll(days=1)
    fresh = world.collecting_poll(days=10)
    created = world.new_poll(days=1)
    world.clock.advance(timedelta(days=3))
    expired = world.service.expire_overdue()
    assert [(p.id, m) for p, m in expired] == [(overdue.id, sorted(COMPANIES))]
    assert world.service.get(fresh.id).status == COLLECTING
    assert world.service.get(created.id).status == CREATED
    assert world.service.expire_overdue() == []


def test_reminders_follow_the_period_and_only_name_missing_companies(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll(days=10)
    period = timedelta(hours=24)
    assert world.service.due_reminders(period) == []
    world.clock.advance(timedelta(hours=23))
    assert world.service.due_reminders(period) == []
    world.submit(poll, "acme")
    world.clock.advance(timedelta(hours=1))
    [(reminded, missing)] = world.service.due_reminders(period)
    assert reminded.id == poll.id and missing == ["bolt", "corp"]
    assert world.service.due_reminders(period) == []  # not again until a period has passed
    world.clock.advance(timedelta(hours=24))
    assert len(world.service.due_reminders(period)) == 1
    world.clock.advance(timedelta(hours=6))
    assert world.service.due_reminders(timedelta(hours=6)) != []  # period is configurable


def test_no_reminders_outside_collecting_or_after_the_deadline(tmp_path) -> None:
    world = make_world(tmp_path)
    world.new_poll(days=10)  # created
    complete = world.complete_poll()  # complete
    overdue = world.collecting_poll(days=1)
    world.clock.advance(timedelta(days=2))
    assert world.service.due_reminders(timedelta(hours=1)) == []
    assert world.service.get(complete.id).status == COMPLETE
    assert world.service.get(overdue.id).status == COLLECTING  # sweeper has not run yet


def test_a_proof_and_totals_pasted_with_code_fences_are_accepted(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    result = world.admin_totals(poll, ADMIN_EMAIL, nonce)
    done = world.service.mark_done(
        poll.id,
        email=ADMIN_EMAIL,
        nonce=nonce,
        totals=result["totals"],
        proof=f"```{result['proof']}```",
    )
    assert done.status == DONE


def test_totals_beyond_what_the_companies_could_have_submitted_are_refused(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    result = world.admin_totals(poll, ADMIN_EMAIL, nonce)
    absurd = {**result["totals"], "rack_count": len(COMPANIES) * immap.MAX_VALUE}
    proof = immap.make_proof(
        world.admin_keys[ADMIN_EMAIL],
        poll_document(poll),
        ACTION_DONE,
        immap.totals_digest(absurd),
        nonce,
    )
    with pytest.raises(PollError, match="out of range"):
        world.service.mark_done(
            poll.id, email=ADMIN_EMAIL, nonce=nonce, totals=absurd, proof=proof
        )
    assert world.service.get(poll.id).status == COMPLETE
