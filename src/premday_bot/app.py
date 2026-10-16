from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from email.utils import parseaddr
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler
from slack_bolt.async_app import AsyncApp
from slack_sdk.web.async_client import AsyncWebClient

from premday_bot.config import Settings
from premday_bot.dates import combine_local_date_time, default_meeting_start
from premday_bot.mailer import InvitationMailer
from premday_bot.models import Meeting
from premday_bot.organizer import MeetingOrganizer, new_meeting_id
from premday_bot.rsvp_mail import RSVPTransferServer, parse_calendar_replies
from premday_bot.slack_services import SlackCanvasClient, SlackDirectory, SlackPublisher
from premday_bot.slack_views import (
    RECEIVE_INVITATION_ACTION_ID,
    SCHEDULE_CALLBACK_ID,
    SHOW_RSVPS_ACTION_ID,
    schedule_modal,
)
from premday_bot.storage import MeetingStore

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class Runtime:
    settings: Settings
    store: MeetingStore
    canvas_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


def build_app(settings: Settings | None = None) -> AsyncApp:
    resolved_settings = settings or Settings.from_env()
    runtime = Runtime(
        settings=resolved_settings,
        store=MeetingStore(resolved_settings.db_path),
    )
    app = AsyncApp(token=runtime.settings.slack_bot_token)

    @app.command("/meeting")
    async def handle_schedule_command(ack, body, client: AsyncWebClient, logger) -> None:
        await ack()
        channel_id = body["channel_id"]
        timezone_name = runtime.settings.timezone
        try:
            response = await client.users_info(user=body["user_id"])
            user_timezone = response.get("user", {}).get("tz")
            if isinstance(user_timezone, str):
                ZoneInfo(user_timezone)
                timezone_name = user_timezone
        except Exception:
            logger.warning("Could not read creator timezone; using configured timezone")
        default_start = default_meeting_start(
            timezone_name,
            runtime.settings.default_hour,
        )
        await client.views_open(
            trigger_id=body["trigger_id"],
            view=schedule_modal(
                channel_id=channel_id,
                default_start=default_start,
                default_duration_minutes=runtime.settings.default_duration_minutes,
                timezone_name=timezone_name,
            ),
        )
        logger.info("Opened Premday schedule modal for channel %s", channel_id)

    @app.view(SCHEDULE_CALLBACK_ID)
    async def handle_schedule_submission(ack, body, view, client: AsyncWebClient, logger) -> None:
        errors = _validate_schedule_view(view)
        if errors:
            await ack(response_action="errors", errors=errors)
            return

        await ack()
        metadata = json.loads(view["private_metadata"])
        organizer = _organizer(runtime, client)
        meeting = _meeting_from_view(
            view=view,
            channel_id=metadata["channel_id"],
            creator_user_id=body["user"]["id"],
            settings=runtime.settings,
            timezone_name=metadata.get("timezone", runtime.settings.timezone),
        )
        publisher = SlackPublisher(client)
        try:
            result = await organizer.schedule(meeting)
        except Exception:
            logger.exception("Failed to schedule Premday meeting")
            await publisher.post_ephemeral(
                channel_id=meeting.channel_id,
                user_id=meeting.creator_user_id,
                text="I could not schedule the meeting. Check the bot logs for details.",
            )
            return

        if result.email_summary.failed:
            await publisher.post_ephemeral(
                channel_id=meeting.channel_id,
                user_id=meeting.creator_user_id,
                text=(
                    f"Meeting scheduled, but {len(result.email_summary.failed)} invitation(s) "
                    "failed to send. Check the bot logs for details."
                ),
            )
            logger.warning("Failed invitations: %s", result.email_summary.failed)

    @app.action(RECEIVE_INVITATION_ACTION_ID)
    async def handle_receive_invitation(ack, body, action, client: AsyncWebClient, logger) -> None:
        await ack()
        channel_id = body["channel"]["id"]
        user_id = body["user"]["id"]
        meeting_id = action["value"]
        organizer = _organizer(runtime, client)
        publisher = SlackPublisher(client)
        try:
            await organizer.send_invitation_to_user(meeting_id=meeting_id, user_id=user_id)
        except Exception as error:
            logger.exception("Could not send one-off invitation")
            await publisher.post_ephemeral(
                channel_id=channel_id,
                user_id=user_id,
                text=f"I could not send the invitation: {error}",
            )
            return
        await publisher.post_ephemeral(
            channel_id=channel_id,
            user_id=user_id,
            text="Invitation sent to your Slack email address.",
        )

    @app.action(SHOW_RSVPS_ACTION_ID)
    async def handle_show_rsvps(ack, body, action, client: AsyncWebClient, logger) -> None:
        await ack()
        channel_id = body["channel"]["id"]
        clicker_user_id = body["user"]["id"]
        meeting_id = action["value"]
        meeting = runtime.store.get(meeting_id)
        publisher = SlackPublisher(client)
        if meeting is None:
            await publisher.post_ephemeral(
                channel_id=channel_id,
                user_id=clicker_user_id,
                text="I could not find that meeting.",
            )
            return

        rsvps = runtime.store.rsvps_for_meeting(meeting_id)
        try:
            text, blocks = await _rsvp_view_blocks(
                meeting=meeting,
                rsvps=rsvps,
                client=client,
            )
            await publisher.post_ephemeral(
                channel_id=channel_id,
                user_id=clicker_user_id,
                text=text,
                blocks=blocks,
            )
        except Exception:
            logger.exception("Could not display meeting RSVP list")
            await publisher.post_ephemeral(
                channel_id=channel_id,
                user_id=clicker_user_id,
                text="I could not load the RSVP list. Check the bot logs for details.",
            )

    return app


def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    settings = Settings.from_env()
    if settings.rsvp_smtp_enabled:
        _, organizer_email = parseaddr(settings.email_from or "")
        if organizer_email.lower() != (settings.rsvp_email_address or "").lower():
            raise RuntimeError(
                "PREMDAY_EMAIL_FROM must use RSVP_EMAIL_ADDRESS so calendar replies reach the bot"
            )
    app = build_app(settings)
    runtime = Runtime(settings=settings, store=MeetingStore(settings.db_path))

    async def start_socket_mode() -> None:
        handler = AsyncSocketModeHandler(app, settings.slack_app_token)
        rsvp_server: RSVPTransferServer | None = None
        if settings.rsvp_smtp_enabled:
            async def handle_rsvp_message(raw_message: bytes) -> None:
                for reply in parse_calendar_replies(raw_message):
                    organizer = _organizer(runtime, app.client)
                    try:
                        meeting = await organizer.record_rsvp(
                            meeting_id=reply.meeting_id,
                            attendee_email=reply.attendee_email,
                            response=reply.response,
                        )
                    except KeyError:
                        LOGGER.warning("Ignoring RSVP for unrecognized meeting or attendee")
                    else:
                        LOGGER.info("Recorded %s RSVP for meeting %s", reply.response, meeting.id)

            rsvp_server = RSVPTransferServer(
                host="0.0.0.0",
                port=settings.rsvp_smtp_port,
                recipient=settings.rsvp_email_address or "",
                on_message=handle_rsvp_message,
            )
            await rsvp_server.start()
        try:
            await handler.start_async()
        finally:
            if rsvp_server:
                await rsvp_server.close()

    asyncio.run(start_socket_mode())


def _organizer(runtime: Runtime, client: AsyncWebClient) -> MeetingOrganizer:
    return MeetingOrganizer(
        store=runtime.store,
        directory=SlackDirectory(client),
        canvas_client=SlackCanvasClient(client, team_id=runtime.settings.slack_team_id),
        canvas_lock=runtime.canvas_lock,
        publisher=SlackPublisher(client),
        mailer=InvitationMailer(runtime.settings),
    )


async def _rsvp_view_blocks(
    *,
    meeting: Meeting,
    rsvps: dict[str, list[str]],
    client: AsyncWebClient,
) -> tuple[str, list[dict]]:
    categories = (
        ("accepted", "Going"),
        ("declined", "Absent"),
        ("tentative", "Maybe"),
    )
    title = f"*RSVPs for {_escape_mrkdwn(meeting.title)}*"
    lines = [title]
    blocks: list[dict] = [{"type": "section", "text": {"type": "mrkdwn", "text": title}}]
    total = sum(len(rsvps.get(response, [])) for response, _ in categories)
    if total == 0:
        empty_text = "No replies yet. Responses to the calendar invitation will show here."
        lines.append(empty_text)
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": empty_text}})

    directory = SlackDirectory(client)
    for response, label in categories:
        emails = rsvps.get(response, [])
        names: list[str] = []
        for email in emails:
            name, profile_user_id = await directory.profile_for_email(email)
            names.append(f"<@{profile_user_id}>" if profile_user_id else _escape_mrkdwn(name))
        if not names:
            names = ["_No one yet_"]
        columns: list[list[str]] = [[], []]
        for index, name in enumerate(names):
            columns[index % 2].append(f"• {name}")
        lines.extend(["", f"{label} ({len(emails)})", *columns[0], *columns[1]])
        blocks.append(
            {
                "type": "container",
                "title": {"type": "plain_text", "text": f"{label} · {len(emails)}"},
                "is_collapsible": True,
                "default_collapsed": True,
                "child_blocks": [
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": "\n".join(column) or "_ _"}
                            for column in columns
                        ],
                    }
                ],
            }
        )
    return "\n".join(lines), blocks


def _meeting_from_view(
    *,
    view: dict,
    channel_id: str,
    creator_user_id: str,
    settings: Settings,
    timezone_name: str | None = None,
) -> Meeting:
    values = view["state"]["values"]
    starts_at = combine_local_date_time(
        values["date"]["value"]["selected_date"],
        values["time"]["value"]["selected_time"],
        timezone_name or settings.timezone,
    )
    return Meeting(
        id=new_meeting_id(),
        channel_id=channel_id,
        creator_user_id=creator_user_id,
        title=values["title"]["value"]["value"].strip(),
        starts_at=starts_at,
        duration_minutes=int(values["duration"]["value"]["value"]),
        proton_meet_url=values["proton_url"]["value"]["value"].strip(),
        timezone=timezone_name or settings.timezone,
    )


def _validate_schedule_view(view: dict) -> dict[str, str]:
    values = view["state"]["values"]
    errors: dict[str, str] = {}
    title = values["title"]["value"].get("value", "").strip()
    proton_url = values["proton_url"]["value"].get("value", "").strip()
    duration = values["duration"]["value"].get("value", "").strip()

    if not title:
        errors["title"] = "Add a title."
    if not _is_https_url(proton_url):
        errors["proton_url"] = "Add a valid HTTPS Proton Meet link."
    if not duration.isdigit() or int(duration) <= 0:
        errors["duration"] = "Add a positive duration."
    return errors


def _is_https_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def _escape_mrkdwn(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
