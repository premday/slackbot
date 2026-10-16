from __future__ import annotations

import asyncio
import json
import logging
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from slack_bolt.async_app import AsyncApp
from slack_sdk.web.async_client import AsyncWebClient

from premday_bot.config import Settings
from premday_bot.immap_views import (
    ATTRIBUTE_CALLBACK_ID,
    DONE_CALLBACK_ID,
    EXTEND_ACTION_ID,
    EXTEND_CALLBACK_ID,
    HELP_TEXT,
    POLL_CALLBACK_ID,
    START_ACTION_ID,
    SUBMIT_ACTION_ID,
    SUBMIT_CALLBACK_ID,
    UNATTRIBUTE_CALLBACK_ID,
    VALIDATE_ACTION_ID,
    answered_text,
    attribute_modal,
    chunk_lines,
    companies_text,
    done_list_text,
    extend_modal,
    notice_modal,
    poll_card,
    poll_json_message,
    poll_modal,
    report_text,
    submit_modal,
    unattribute_modal,
    validate_modal,
)
from premday_bot.polls import (
    ACTION_DONE,
    ACTION_EXTEND,
    COMPLETE,
    PollError,
    PollService,
    unfence,
)

LOGGER = logging.getLogger(__name__)
SWEEP_INTERVAL_SECONDS = 60


def parse_command(text: str) -> tuple[str, list[str]]:
    """Split ``/immap`` text into a lowercase subcommand and its arguments."""
    parts = (text or "").split()
    return (parts[0].lower(), parts[1:]) if parts else ("", [])


def poll_error_block(message: str) -> str:
    """Pick the poll-modal input an error message belongs to."""
    lowered = message.lower()
    if "title" in lowered:
        return "title"
    if "template" in lowered:
        return "template"
    if "deadline" in lowered:
        return "deadline"
    return "participants"


def extend_error_block(message: str) -> str:
    return "date" if "deadline" in message.lower() else "proof"


async def email_of(client: AsyncWebClient, user_id: str) -> str | None:
    try:
        response = await client.users_info(user=user_id)
    except Exception:
        LOGGER.warning("Could not read the Slack profile of %s", user_id)
        return None
    email = response.get("user", {}).get("profile", {}).get("email")
    return email if isinstance(email, str) else None


async def refresh_card(client: AsyncWebClient, polls: PollService, poll_id: str) -> None:
    poll = polls.get(poll_id)
    if not poll.message_ts:
        return
    text, blocks = poll_card(
        poll, submitted=polls.submitted(poll), missing=polls.missing(poll)
    )
    await client.chat_update(channel=poll.channel_id, ts=poll.message_ts, text=text, blocks=blocks)


async def post_in_thread(
    client: AsyncWebClient, polls: PollService, poll_id: str, text: str
) -> None:
    poll = polls.get(poll_id)
    if poll.message_ts:
        await client.chat_postMessage(
            channel=poll.channel_id, thread_ts=poll.message_ts, text=text
        )


async def sweep_once(
    client: AsyncWebClient, polls: PollService, reminder_period: timedelta
) -> None:
    """Move overdue polls to incomplete and send due reminders."""
    for poll, missing in polls.expire_overdue():
        await refresh_card(client, polls, poll.id)
        await post_in_thread(
            client,
            polls,
            poll.id,
            f"The deadline passed and these companies have not submitted: {', '.join(missing)}. "
            "An admin can extend the deadline.",
        )
    for poll, missing in polls.due_reminders(reminder_period):
        users = [user for company in missing for user in polls.members_of(company)]
        mentions = " ".join(f"<@{user}>" for user in users)
        await post_in_thread(
            client,
            polls,
            poll.id,
            f"Reminder: {mentions} please submit for *{', '.join(missing)}* "
            f"before {poll.deadline.date().isoformat()}.",
        )


async def run_sweeper(
    client: AsyncWebClient, polls: PollService, reminder_period: timedelta
) -> None:
    while True:
        try:
            await sweep_once(client, polls, reminder_period)
        except Exception:
            LOGGER.exception("IMMAP sweep failed")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)


def register_immap(app: AsyncApp, polls: PollService, settings: Settings) -> None:
    async def tell(client: AsyncWebClient, body: dict, text: str) -> None:
        await client.chat_postEphemeral(
            channel=body["channel"]["id"], user=body["user"]["id"], text=text
        )

    @app.command("/immap")
    async def handle_command(ack, body, command, respond, client: AsyncWebClient) -> None:
        await ack()
        user_id = body["user_id"]
        subcommand, args = parse_command(command.get("text", ""))
        try:
            if subcommand == "register" and len(args) == 1:
                fingerprint = polls.enroll(user_id=user_id, public_key=args[0])
                text = (
                    f"Enrolled. Key fingerprint: `{fingerprint}`. An admin will attribute "
                    "your company to you."
                )
            elif subcommand == "companies" and not args:
                email = await email_of(client, user_id)
                text = companies_text(
                    polls.companies(email=email), polls.unattributed_users(email=email)
                )
            elif subcommand == "company" and args and args[0].lower() == "attribute":
                email = await email_of(client, user_id)
                await client.views_open(
                    trigger_id=body["trigger_id"],
                    view=attribute_modal([c.company_id for c in polls.companies(email=email)]),
                )
                return
            elif subcommand == "company" and args and args[0].lower() == "unattribute":
                polls.companies(email=await email_of(client, user_id))  # admins only
                await client.views_open(trigger_id=body["trigger_id"], view=unattribute_modal())
                return
            elif subcommand == "company" and len(args) == 2:
                email = await email_of(client, user_id)
                action, company_id = args[0].lower(), args[1]
                if action == "add":
                    polls.add_company(email=email, company_id=company_id)
                    text = f"Added `{company_id}`. Add members with `/immap company attribute`."
                elif action == "remove":
                    polls.remove_company(email=email, company_id=company_id)
                    text = f"Removed `{company_id}`."
                else:
                    text = HELP_TEXT
            elif subcommand == "admin-register" and len(args) == 1:
                fingerprint = polls.register_admin_key(
                    email=await email_of(client, user_id), public_key=args[0]
                )
                text = f"Admin key registered. Fingerprint: `{fingerprint}`"
            elif subcommand == "poll":
                today = datetime.now(ZoneInfo(settings.timezone)).date()
                await client.views_open(
                    trigger_id=body["trigger_id"],
                    view=poll_modal(
                        channel_id=body["channel_id"],
                        company_ids=polls.pollable_company_ids(),
                        default_deadline=today + timedelta(days=7),
                    ),
                )
                return
            elif subcommand == "report" and len(args) <= 1:
                if args:
                    text = report_text(polls.report(args[0]))
                else:
                    text = done_list_text(polls.done_polls(body["channel_id"]))
            else:
                text = HELP_TEXT
        except PollError as error:
            text = str(error)
        await respond(text=text, response_type="ephemeral")

    @app.view(ATTRIBUTE_CALLBACK_ID)
    async def handle_attribute(ack, body, view, client: AsyncWebClient) -> None:
        values = view["state"]["values"]
        company_id = values["company"]["value"]["selected_option"]["value"]
        user_id = values["user"]["value"]["selected_user"]
        try:
            polls.attribute_company(
                email=await email_of(client, body["user"]["id"]),
                company_id=company_id,
                user_id=user_id,
            )
        except PollError as error:
            await ack(response_action="errors", errors={"user": str(error)})
            return
        await ack(
            response_action="update",
            view=notice_modal("Attributed", f"<@{user_id}> now answers for `{company_id}`."),
        )

    @app.view(UNATTRIBUTE_CALLBACK_ID)
    async def handle_unattribute(ack, body, view, client: AsyncWebClient) -> None:
        user_id = view["state"]["values"]["user"]["value"]["selected_user"]
        try:
            company_id = polls.unattribute_user(
                email=await email_of(client, body["user"]["id"]), user_id=user_id
            )
        except PollError as error:
            await ack(response_action="errors", errors={"user": str(error)})
            return
        await ack(
            response_action="update",
            view=notice_modal("Removed", f"<@{user_id}> no longer belongs to `{company_id}`."),
        )

    @app.view(POLL_CALLBACK_ID)
    async def handle_poll_submission(ack, body, view, client: AsyncWebClient) -> None:
        values = view["state"]["values"]
        metadata = json.loads(view["private_metadata"])
        try:
            poll = polls.create_poll(
                channel_id=metadata["channel_id"],
                creator_user_id=body["user"]["id"],
                title=values["title"]["value"]["value"] or "",
                template=values["template"]["value"]["selected_option"]["value"],
                deadline_day=date.fromisoformat(values["deadline"]["value"]["selected_date"]),
                participants=[
                    option["value"]
                    for option in values["participants"]["value"]["selected_options"]
                ],
            )
        except PollError as error:
            await ack(
                response_action="errors", errors={poll_error_block(str(error)): str(error)}
            )
            return
        await ack()
        text, blocks = poll_card(
            poll, submitted=polls.submitted(poll), missing=polls.missing(poll)
        )
        posted = await client.chat_postMessage(
            channel=poll.channel_id, text=text, blocks=blocks
        )
        polls.set_message_ts(poll.id, str(posted["ts"]))
        await post_in_thread(client, polls, poll.id, poll_json_message(poll))

    @app.action(START_ACTION_ID)
    async def handle_start(ack, body, action, client: AsyncWebClient) -> None:
        await ack()
        try:
            polls.start(
                action["value"],
                user_id=body["user"]["id"],
                email=await email_of(client, body["user"]["id"]),
            )
        except PollError as error:
            await tell(client, body, str(error))
            return
        await refresh_card(client, polls, action["value"])
        await post_in_thread(
            client, polls, action["value"], "Collecting has started. Use the Submit button."
        )

    @app.action(SUBMIT_ACTION_ID)
    async def handle_submit_open(ack, body, action, client: AsyncWebClient) -> None:
        await ack()
        poll = polls.get(action["value"])
        await client.views_open(
            trigger_id=body["trigger_id"], view=submit_modal(poll_id=poll.id, title=poll.title)
        )

    @app.view(SUBMIT_CALLBACK_ID)
    async def handle_submit_view(ack, body, view, client: AsyncWebClient) -> None:
        poll_id = json.loads(view["private_metadata"])["poll_id"]
        line = view["state"]["values"]["line"]["value"]["value"] or ""
        try:
            poll = polls.submit(poll_id, user_id=body["user"]["id"], line=line)
        except PollError as error:
            await ack(response_action="errors", errors={"line": str(error)})
            return
        await ack()
        await refresh_card(client, polls, poll_id)
        submitter = body["user"]["id"]
        company_id = polls.company_of(submitter)
        colleagues = [u for u in polls.members_of(company_id or "") if u != submitter]
        if company_id and colleagues:
            await post_in_thread(
                client, polls, poll_id, answered_text(company_id, submitter, colleagues)
            )
        if poll.status == COMPLETE:
            await post_in_thread(
                client,
                polls,
                poll_id,
                "Every company has submitted. An admin must validate before results are shown.",
            )

    @app.action(EXTEND_ACTION_ID)
    async def handle_extend_open(ack, body, action, client: AsyncWebClient) -> None:
        await ack()
        poll_id = action["value"]
        try:
            nonce = polls.begin_admin_action(
                poll_id,
                email=await email_of(client, body["user"]["id"]),
                action=ACTION_EXTEND,
            )
        except PollError as error:
            await tell(client, body, str(error))
            return
        await client.views_open(
            trigger_id=body["trigger_id"],
            view=extend_modal(
                poll_id=poll_id, nonce=nonce, current_deadline=polls.get(poll_id).deadline.date()
            ),
        )

    @app.view(EXTEND_CALLBACK_ID)
    async def handle_extend_view(ack, body, view, client: AsyncWebClient) -> None:
        metadata = json.loads(view["private_metadata"])
        values = view["state"]["values"]
        selected = values["date"]["value"]["selected_date"]
        if not selected:
            await ack(response_action="errors", errors={"date": "Pick the new deadline."})
            return
        try:
            poll = polls.extend(
                metadata["poll_id"],
                email=await email_of(client, body["user"]["id"]),
                new_day=date.fromisoformat(selected),
                nonce=metadata["nonce"],
                proof=values["proof"]["value"]["value"] or "",
            )
        except PollError as error:
            await ack(response_action="errors", errors={extend_error_block(str(error)): str(error)})
            return
        await ack()
        await refresh_card(client, polls, poll.id)
        await post_in_thread(
            client,
            polls,
            poll.id,
            f"Deadline extended to {poll.deadline.date().isoformat()} "
            f"(extension {poll.extension_count}).",
        )

    @app.action(VALIDATE_ACTION_ID)
    async def handle_validate_open(ack, body, action, client: AsyncWebClient) -> None:
        await ack()
        poll_id = action["value"]
        email = await email_of(client, body["user"]["id"])
        try:
            nonce = polls.begin_admin_action(poll_id, email=email, action=ACTION_DONE)
            lines = polls.submission_lines(poll_id, email=email)
        except PollError as error:
            await tell(client, body, str(error))
            return
        # Open the modal first: the trigger id expires within seconds.
        await client.views_open(
            trigger_id=body["trigger_id"], view=validate_modal(poll_id=poll_id, nonce=nonce)
        )
        for chunk in chunk_lines(lines):
            await tell(client, body, f"```{chunk}```")

    @app.view(DONE_CALLBACK_ID)
    async def handle_done_view(ack, body, view, client: AsyncWebClient) -> None:
        metadata = json.loads(view["private_metadata"])
        raw = unfence(view["state"]["values"]["result"]["value"]["value"] or "")
        try:
            result = json.loads(raw)
            totals, proof = result["totals"], result["proof"]
        except (ValueError, KeyError, TypeError):
            await ack(
                response_action="errors",
                errors={"result": "Paste the full JSON printed by `immap.py aggregate`."},
            )
            return
        try:
            poll = polls.mark_done(
                metadata["poll_id"],
                email=await email_of(client, body["user"]["id"]),
                nonce=metadata["nonce"],
                totals=totals,
                proof=str(proof),
            )
        except PollError as error:
            await ack(response_action="errors", errors={"result": str(error)})
            return
        await ack()
        await refresh_card(client, polls, poll.id)
        await post_in_thread(
            client,
            polls,
            poll.id,
            f"Validated by <@{body['user']['id']}>. Use `/immap report {poll.id}` for the totals.",
        )
