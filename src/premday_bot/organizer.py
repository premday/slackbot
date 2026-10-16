from __future__ import annotations

import asyncio
from dataclasses import dataclass
from uuid import uuid4

from premday_bot.mailer import InvitationMailer, SendSummary
from premday_bot.models import Meeting
from premday_bot.slack_services import SlackCanvasClient, SlackDirectory, SlackPublisher
from premday_bot.storage import MeetingStore


@dataclass(frozen=True)
class ScheduleResult:
    meeting: Meeting
    email_summary: SendSummary


class MeetingOrganizer:
    def __init__(
        self,
        *,
        store: MeetingStore,
        directory: SlackDirectory,
        canvas_client: SlackCanvasClient,
        canvas_lock: asyncio.Lock,
        publisher: SlackPublisher,
        mailer: InvitationMailer,
    ) -> None:
        self._store = store
        self._directory = directory
        self._canvas_client = canvas_client
        self._canvas_lock = canvas_lock
        self._publisher = publisher
        self._mailer = mailer

    async def schedule(self, meeting: Meeting) -> ScheduleResult:
        async with self._canvas_lock:
            previous = self._store.latest_with_canvas(
                meeting.channel_id, meeting.starts_at.year
            )
            if previous and previous.canvas_id:
                canvas = await self._canvas_client.append_for_meeting(
                    meeting, canvas_id=previous.canvas_id, canvas_url=previous.canvas_url
                )
            else:
                canvas = await self._canvas_client.create_for_meeting(meeting)
            meeting = meeting.with_canvas(canvas.canvas_id, canvas.canvas_url)
            self._store.save(meeting)

        recipients = await self._directory.channel_member_emails(meeting.channel_id)
        email_summary = await asyncio.to_thread(self._mailer.send_many, recipients, meeting)
        self._store.add_invited_attendees(meeting.id, email_summary.sent_recipients)
        meeting = meeting.with_invitation_count(email_summary.sent)
        self._store.save(meeting)

        message_ts = await self._publisher.post_meeting(
            meeting,
            invitation_count=email_summary.sent,
            rsvp_counts=self._store.rsvp_counts(meeting.id),
        )
        meeting = self._store.set_message_ts(meeting.id, message_ts)
        return ScheduleResult(meeting=meeting, email_summary=email_summary)

    async def record_rsvp(self, *, meeting_id: str, attendee_email: str, response: str) -> Meeting:
        if not self._store.set_rsvp(meeting_id, attendee_email, response):
            raise KeyError(meeting_id)
        meeting = self._store.get(meeting_id)
        if meeting is None:
            raise KeyError(meeting_id)
        if meeting.message_ts:
            await self._publisher.update_rsvp(
                meeting,
                rsvp_counts=self._store.rsvp_counts(meeting_id),
            )
        return meeting

    async def send_invitation_to_user(self, *, meeting_id: str, user_id: str) -> None:
        meeting = self._store.get(meeting_id)
        if meeting is None:
            raise KeyError(meeting_id)
        email = await self._directory.user_email(user_id)
        if not email:
            raise RuntimeError("No email address is available for this Slack user")
        await asyncio.to_thread(self._mailer.send_one, email, meeting)
        self._store.add_invited_attendees(meeting_id, [email])


def new_meeting_id() -> str:
    return str(uuid4())
