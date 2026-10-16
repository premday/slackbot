import asyncio
import json
from datetime import timedelta
from typing import Any, cast

from slack_bolt.async_app import AsyncApp
from slack_sdk.web.async_client import AsyncWebClient

from helpers import ADMIN_EMAIL, COMPANIES, make_world, owner
from premday_bot import immap
from premday_bot.config import Settings
from premday_bot.immap_slack import (
    email_of,
    extend_error_block,
    parse_command,
    poll_error_block,
    refresh_card,
    register_immap,
    sweep_once,
)
from premday_bot.immap_views import (
    ATTRIBUTE_CALLBACK_ID,
    SUBMIT_CALLBACK_ID,
    UNATTRIBUTE_CALLBACK_ID,
)
from premday_bot.polls import ACTION_EXTEND, COLLECTING, INCOMPLETE


class FakeClient:
    def __init__(self) -> None:
        self.updates: list[dict] = []
        self.messages: list[dict] = []
        self.profile_email: str | None = ADMIN_EMAIL
        self.fail_profile = False

    async def chat_update(self, **kwargs) -> None:
        self.updates.append(kwargs)

    async def chat_postMessage(self, **kwargs) -> dict:
        self.messages.append(kwargs)
        return {"ts": "1.1"}

    async def users_info(self, user: str) -> dict:
        if self.fail_profile:
            raise RuntimeError("slack down")
        return {"user": {"profile": {"email": self.profile_email}}}


def web(client: FakeClient) -> AsyncWebClient:
    return cast(AsyncWebClient, client)


def with_card(world, poll):
    return world.service.set_message_ts(poll.id, "9.9")


def run(coroutine):
    return asyncio.run(coroutine)


def test_parse_command() -> None:
    assert parse_command("") == ("", [])
    assert parse_command("  Register acme abc ") == ("register", ["acme", "abc"])
    assert parse_command("poll") == ("poll", [])


def test_error_messages_are_routed_to_the_right_input() -> None:
    assert poll_error_block("Add a title.") == "title"
    assert poll_error_block("Choose one of the poll templates.") == "template"
    assert poll_error_block("The deadline must be in the future.") == "deadline"
    assert poll_error_block("A poll needs at least 3 companies.") == "participants"
    assert extend_error_block("The new deadline must be later than the current one.") == "date"
    assert extend_error_block("The admin key proof is invalid.") == "proof"


def test_email_of_reads_the_profile_and_survives_failures() -> None:
    client = FakeClient()
    assert run(email_of(web(client), "U1")) == ADMIN_EMAIL
    client.profile_email = None
    assert run(email_of(web(client), "U1")) is None
    client.fail_profile = True
    assert run(email_of(web(client), "U1")) is None


def test_refresh_card_updates_the_poll_message(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = with_card(world, world.collecting_poll())
    client = FakeClient()
    run(refresh_card(web(client), world.service, poll.id))
    assert client.updates[0]["ts"] == "9.9" and client.updates[0]["channel"] == "C1"
    world2 = make_world(tmp_path / "other")
    run(refresh_card(web(client), world2.service, world2.new_poll().id))  # no card yet: no call
    assert len(client.updates) == 1


def test_sweep_expires_overdue_polls_and_announces_who_is_missing(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = with_card(world, world.collecting_poll(days=1))
    world.submit(poll, "acme")
    world.clock.advance(timedelta(days=3))
    client = FakeClient()
    run(sweep_once(web(client), world.service, timedelta(hours=24)))
    assert world.service.get(poll.id).status == INCOMPLETE
    assert "bolt, corp" in client.messages[0]["text"] and client.messages[0]["thread_ts"] == "9.9"
    assert len(client.updates) == 1
    run(sweep_once(web(client), world.service, timedelta(hours=24)))
    assert len(client.messages) == 1  # nothing more to do


def test_sweep_pings_the_owners_of_missing_companies_once_per_period(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = with_card(world, world.collecting_poll(days=10))
    world.submit(poll, "acme")
    client = FakeClient()
    period = timedelta(hours=24)
    run(sweep_once(web(client), world.service, period))
    assert client.messages == []
    world.clock.advance(timedelta(hours=25))
    run(sweep_once(web(client), world.service, period))
    [message] = client.messages
    assert f"<@{owner('bolt')}>" in message["text"] and f"<@{owner('corp')}>" in message["text"]
    assert f"<@{owner('acme')}>" not in message["text"]
    run(sweep_once(web(client), world.service, period))
    assert len(client.messages) == 1


def test_an_extended_poll_is_reminded_again(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = with_card(world, world.collecting_poll(days=1))
    world.clock.advance(timedelta(days=3))
    client = FakeClient()
    run(sweep_once(web(client), world.service, timedelta(hours=24)))
    day = (world.clock.now + timedelta(days=5)).date()
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    world.service.extend(
        poll.id, email=ADMIN_EMAIL, new_day=day, nonce=nonce,
        proof=world.extend_proof(world.service.get(poll.id), ADMIN_EMAIL, day, nonce),
    )
    assert world.service.get(poll.id).status == COLLECTING
    world.clock.advance(timedelta(hours=25))
    client.messages.clear()
    run(sweep_once(web(client), world.service, timedelta(hours=24)))
    assert "Reminder" in client.messages[0]["text"]


def test_handlers_register_on_a_bolt_app(tmp_path) -> None:
    world = make_world(tmp_path)
    app = AsyncApp(token="xoxb-test")
    settings = Settings(
        slack_bot_token="xoxb-test", slack_app_token="xapp-test", slack_team_id=None,
        timezone="Europe/Paris", default_hour=18, default_duration_minutes=90,
        db_path=tmp_path / "x.sqlite3", smtp_host=None, smtp_port=587, smtp_username=None,
        smtp_password=None, smtp_use_tls=True, smtp_use_ssl=False, email_from=None,
    )
    register_immap(app, world.service, settings)
    # one command, six views and four buttons
    assert len(app._async_listeners) == 11


class CapturingApp:
    """Collects the handlers `register_immap` declares so tests can call them directly."""

    def __init__(self) -> None:
        self.handlers: dict[str, object] = {}

    def command(self, name):
        return self._remember(name)

    def view(self, callback_id):
        return self._remember(callback_id)

    def action(self, action_id):
        return self._remember(action_id)

    def _remember(self, key):
        def decorator(function):
            self.handlers[key] = function
            return function

        return decorator


class Reply:
    def __init__(self) -> None:
        self.texts: list[str] = []
        self.acks: list[dict] = []

    async def respond(self, text: str, response_type: str) -> None:
        self.texts.append(text)

    async def ack(self, **kwargs) -> None:
        self.acks.append(kwargs)


def command_driver(tmp_path):
    world = make_world(tmp_path)
    app = CapturingApp()
    settings = Settings(
        slack_bot_token="xoxb-test", slack_app_token="xapp-test", slack_team_id=None,
        timezone="Europe/Paris", default_hour=18, default_duration_minutes=90,
        db_path=tmp_path / "x.sqlite3", smtp_host=None, smtp_port=587, smtp_username=None,
        smtp_password=None, smtp_use_tls=True, smtp_use_ssl=False, email_from=None,
    )
    register_immap(cast(AsyncApp, app), world.service, settings)
    client = FakeClient()
    opened: list[dict] = []

    async def views_open(**kwargs) -> None:
        opened.append(kwargs)

    client.views_open = views_open  # type: ignore[attr-defined]

    def say(user_id: str, text: str, email: str | None = ADMIN_EMAIL) -> Reply:
        client.profile_email = email
        reply = Reply()
        body = {"user_id": user_id, "channel_id": "C1", "trigger_id": "T1"}
        handler = cast(Any, app.handlers["/immap"])
        run(handler(reply.ack, body, {"text": text}, reply.respond, web(client)))
        return reply

    return world, app, client, opened, say


def test_users_enroll_and_admins_manage_companies_through_the_command(tmp_path) -> None:
    _, _, _, opened, say = command_driver(tmp_path)
    key = immap.public_key(immap.generate_private_key())
    assert "Enrolled" in say("U_NEW", f"register {key}", email=None).texts[0]
    assert "Only admins" in say("U_NEW", "companies", email="x@example.com").texts[0]
    assert "<@U_NEW>" in say("U_ADMIN", "companies").texts[0]  # listed as not attributed
    assert "Added `newco`" in say("U_ADMIN", "company add newco").texts[0]
    assert "already exists" in say("U_ADMIN", "company add newco").texts[0]
    assert "Only admins" in say("U_NEW", "company add other", email="x@example.com").texts[0]
    say("U_ADMIN", "company attribute")
    modal = opened[0]["view"]
    assert [o["value"] for o in modal["blocks"][0]["element"]["options"]][-1] == "newco"
    assert "Removed `newco`" in say("U_ADMIN", "company remove newco").texts[0]
    say("U_ADMIN", "company unattribute")
    assert opened[1]["view"]["callback_id"] == UNATTRIBUTE_CALLBACK_ID
    assert "Only admins" in say("U_NEW", "company unattribute", email="x@example.com").texts[0]
    assert "Only admins" in say("U_ADMIN", "company attribute", email=None).texts[0]
    assert "IMMAP polls" in say("U_NEW", "register acme abc").texts[0]  # the old 2-arg form


def test_the_attribute_modal_attributes_and_reports_errors(tmp_path) -> None:
    world, app, client, _, _ = command_driver(tmp_path)
    world.service.add_company(email=ADMIN_EMAIL, company_id="newco")
    world.service.enroll(user_id="U_NEW", public_key=immap.public_key(1234567))
    handler = cast(Any, app.handlers[ATTRIBUTE_CALLBACK_ID])

    def submit(company: str, user: str, email: str | None = ADMIN_EMAIL) -> Reply:
        client.profile_email = email
        view = {"state": {"values": {
            "company": {"value": {"selected_option": {"value": company}}},
            "user": {"value": {"selected_user": user}},
        }}}
        reply = Reply()
        run(handler(reply.ack, {"user": {"id": "U_ADMIN"}}, view, web(client)))
        return reply

    assert "not enrolled" in submit("newco", "U_STRANGER").acks[0]["errors"]["user"]
    refused = submit("newco", "U_NEW", email="x@example.com")
    assert "Only admins" in refused.acks[0]["errors"]["user"]
    done = submit("newco", "U_NEW").acks[0]
    assert done["response_action"] == "update" and "<@U_NEW>" in str(done["view"])
    assert world.service.members_of("newco") == ["U_NEW"]


def test_removing_a_member_through_the_modal(tmp_path) -> None:
    _, app, client, _, _ = command_driver(tmp_path)
    handler = cast(Any, app.handlers[UNATTRIBUTE_CALLBACK_ID])

    def submit(user: str, email: str | None = ADMIN_EMAIL) -> Reply:
        client.profile_email = email
        view = {"state": {"values": {"user": {"value": {"selected_user": user}}}}}
        reply = Reply()
        run(handler(reply.ack, {"user": {"id": "U_ADMIN"}}, view, web(client)))
        return reply

    assert "does not belong" in submit("U_STRANGER").acks[0]["errors"]["user"]
    assert "Only admins" in submit(owner("bolt"), email="x@example.com").acks[0]["errors"]["user"]
    done = submit(owner("bolt")).acks[0]
    assert done["response_action"] == "update" and "bolt" in str(done["view"])


def test_colleagues_learn_when_a_member_of_their_company_submits(tmp_path) -> None:
    world, app, client, _, _ = command_driver(tmp_path)
    world.service.enroll(user_id="U_ACME_2", public_key=immap.public_key(1111111))
    world.service.enroll(user_id="U_ACME_3", public_key=immap.public_key(2222222))
    for user in ("U_ACME_2", "U_ACME_3"):
        world.service.attribute_company(email=ADMIN_EMAIL, company_id="acme", user_id=user)
    poll = with_card(world, world.collecting_poll())
    handler = cast(Any, app.handlers[SUBMIT_CALLBACK_ID])

    def submit(user: str, company_id: str) -> Reply:
        view = {
            "private_metadata": json.dumps({"poll_id": poll.id}),
            "state": {"values": {"line": {"value": {"value": world.line(poll, company_id)}}}},
        }
        reply = Reply()
        run(handler(reply.ack, {"user": {"id": user}}, view, web(client)))
        return reply

    # A colleague (not the key holder) submits for acme: the other two members are told.
    assert submit("U_ACME_2", "acme").acks == [{}]
    notices = [m for m in client.messages if m.get("thread_ts") == "9.9"]
    assert len(notices) == 1
    assert "<@U_ACME> <@U_ACME_3> <@U_ACME_2> submitted the values of *acme*" in notices[0]["text"]
    assert notices[0]["channel"] == poll.channel_id
    # A company with a single member has nobody to tell.
    client.messages.clear()
    submit(owner("bolt"), "bolt")
    assert [m for m in client.messages if "submitted the values" in m["text"]] == []
    # Someone outside the company cannot answer for it.
    refused = submit(owner("corp"), "acme")
    assert "not a member of `acme`" in refused.acks[0]["errors"]["line"]


def test_reminders_mention_every_member_of_a_missing_company(tmp_path) -> None:
    world = make_world(tmp_path)
    world.service.enroll(user_id="U_ACME_2", public_key=immap.public_key(1111111))
    world.service.attribute_company(email=ADMIN_EMAIL, company_id="acme", user_id="U_ACME_2")
    poll = with_card(world, world.collecting_poll())
    client = FakeClient()
    world.clock.advance(timedelta(hours=25))
    run(sweep_once(web(client), world.service, timedelta(hours=24)))
    reminder = next(m["text"] for m in client.messages if "Reminder" in m["text"])
    assert "<@U_ACME> <@U_ACME_2>" in reminder and poll.id


def test_attribute_modal_needs_a_company_first(tmp_path) -> None:
    world, _, _, opened, say = command_driver(tmp_path)
    for company_id in COMPANIES:
        world.service.remove_company(email=ADMIN_EMAIL, company_id=company_id)
    reply = say("U_ADMIN", "company attribute")
    assert "company add" in reply.texts[0] and opened == []
