import base64
import json
from datetime import timedelta

import pytest

from helpers import ADMIN_EMAIL, COMPANIES, NOT_ADMIN_EMAIL, TEMPLATE_METRICS, make_world, owner
from premday_bot import immap
from premday_bot.polls import COLLECTING, COMPLETE, CREATED, PollError


def test_start_rules(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    with pytest.raises(PollError, match="creator or an admin"):
        world.service.start(poll.id, user_id="U_RANDOM", email=NOT_ADMIN_EMAIL)
    started = world.service.start(poll.id, user_id="U_RANDOM", email=ADMIN_EMAIL)
    assert started.status == COLLECTING and started.started_at == world.clock.now
    with pytest.raises(PollError, match="already collecting"):
        world.service.start(poll.id, user_id=owner("acme"), email=None)


def test_start_is_refused_after_the_deadline(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll(days=1)
    world.clock.advance(timedelta(days=3))
    with pytest.raises(PollError, match="extend"):
        world.service.start(poll.id, user_id=owner("acme"), email=None)
    assert world.service.get(poll.id).status == CREATED


def test_submissions_are_refused_before_start(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    with pytest.raises(PollError, match="created"):
        world.submit(poll, "acme")


def test_submit_tracks_progress_and_completes_on_the_last_company(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    poll = world.submit(poll, "acme")
    assert poll.status == COLLECTING
    assert world.service.missing(poll) == ["bolt", "corp"]
    assert world.service.submitted(poll) == ["acme"]
    world.submit(poll, "bolt")
    final = world.submit(poll, "corp")
    assert final.status == COMPLETE
    assert world.service.get(poll.id).totals is None  # never computed by the bot


def test_resubmitting_replaces_the_previous_line(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    world.submit(poll, "acme")
    world.submit(poll, "acme")
    assert world.service.submitted(poll) == ["acme"]
    assert len(world.store.submission_lines(poll.id)) == 1


def test_submit_validation(tmp_path) -> None:
    world = make_world(tmp_path, companies=(*COMPANIES, "dyna"))
    poll = world.collecting_poll(participants=list(COMPANIES))
    good = world.line(poll, "acme")
    with pytest.raises(PollError, match="not a member of"):
        world.service.submit(poll.id, user_id=owner("bolt"), line=good)
    with pytest.raises(PollError, match="not part of this poll"):
        world.service.submit(poll.id, user_id=owner("dyna"), line=good.replace(".acme.", ".dyna."))
    with pytest.raises(PollError, match="different poll"):
        world.service.submit(poll.id, user_id=owner("acme"), line=good.replace(poll.id, "other"))
    with pytest.raises(PollError, match="not an immap2"):
        world.service.submit(poll.id, user_id=owner("acme"), line="hello")
    # Wrong number of values: seal a short payload to the right admin keys.
    from premday_bot.polls import poll_document

    document = poll_document(poll)
    short = immap.seal(b"\x00" * 8, document["admins"])
    encoded = base64.urlsafe_b64encode(json.dumps(short).encode()).decode().rstrip("=")
    with pytest.raises(PollError, match="number of values"):
        world.service.submit(
            poll.id, user_id=owner("acme"), line=f"immap2.{poll.id}.acme.{encoded}"
        )
    # Sealed to a different admin: the bot can tell without reading it.
    stranger = {"public_key": immap.public_key(1234567)}
    foreign = immap.seal(b"\x00" * 8 * len(TEMPLATE_METRICS), [stranger])
    encoded = base64.urlsafe_b64encode(json.dumps(foreign).encode()).decode().rstrip("=")
    with pytest.raises(PollError, match="admin keys"):
        world.service.submit(
            poll.id, user_id=owner("acme"), line=f"immap2.{poll.id}.acme.{encoded}"
        )
    assert world.service.submitted(poll) == []


def test_submit_after_the_deadline_is_refused_even_before_the_sweeper_runs(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll(days=1)
    line = world.line(poll, "acme")
    world.clock.advance(timedelta(days=3))
    with pytest.raises(PollError, match="deadline"):
        world.service.submit(poll.id, user_id=owner("acme"), line=line)


def test_the_bot_stores_only_ciphertext(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    world.submit(poll, "acme")
    stored = world.store.submission_lines(poll.id)["acme"]
    _, _, envelope = immap.parse_line(stored)
    from helpers import values_for

    plain = b"".join(v.to_bytes(8, "big") for _, v in sorted(values_for("acme").items()))
    assert bytes.fromhex(envelope["ct"]) != plain


@pytest.mark.parametrize("wrap", ["`{}`", "```{}```", "```\n{}\n```", "  {}\n"])
def test_a_submission_pasted_from_a_slack_code_block_is_accepted(tmp_path, wrap) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    line = world.line(poll, "acme")
    world.service.submit(poll.id, user_id=owner("acme"), line=wrap.format(line))
    assert world.store.submission_lines(poll.id)["acme"] == line  # stored clean
