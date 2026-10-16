from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from slack_sdk.web.async_client import AsyncWebClient

from premday_bot.models import Meeting
from premday_bot.templates import canvas_markdown


@dataclass(frozen=True)
class CanvasReference:
    canvas_id: str | None
    canvas_url: str | None


class SlackDirectory:
    def __init__(self, client: AsyncWebClient) -> None:
        self._client = client

    async def channel_member_emails(self, channel_id: str) -> list[str]:
        emails: list[str] = []
        for user_id in await self._channel_member_ids(channel_id):
            email = await self.user_email(user_id)
            if email:
                emails.append(email)
        return emails

    async def user_email(self, user_id: str) -> str | None:
        response = await self._client.users_info(user=user_id)
        user = response.get("user", {})
        if user.get("deleted") or user.get("is_bot"):
            return None
        profile = user.get("profile", {})
        email = profile.get("email")
        return email if isinstance(email, str) and email else None

    async def profile_for_email(self, email: str) -> tuple[str, str | None]:
        try:
            response = await self._client.users_lookupByEmail(email=email)
        except Exception:
            return email, None
        user = response.get("user", {})
        profile = user.get("profile", {})
        user_id = user.get("id")
        profile_id = user_id if isinstance(user_id, str) else None
        for name in (profile.get("display_name"), profile.get("real_name"), user.get("name")):
            if isinstance(name, str) and name.strip():
                return name.strip(), profile_id
        return email, profile_id

    async def _channel_member_ids(self, channel_id: str) -> list[str]:
        user_ids: list[str] = []
        cursor: str | None = None
        while True:
            response = await self._client.conversations_members(
                channel=channel_id,
                cursor=cursor,
                limit=200,
            )
            user_ids.extend(response.get("members", []))
            cursor = response.get("response_metadata", {}).get("next_cursor")
            if not cursor:
                return user_ids


class SlackCanvasClient:
    def __init__(self, client: AsyncWebClient, *, team_id: str | None) -> None:
        self._client = client
        self._team_id = team_id

    async def create_for_meeting(self, meeting: Meeting) -> CanvasReference:
        response = await self._client.api_call(
            "canvases.create",
            json={
                "title": f"Premday meetings {meeting.starts_at.year}",
                "document_content": {
                    "type": "markdown",
                    "markdown": canvas_markdown(meeting),
                },
                "channel_id": meeting.channel_id,
            },
        )
        data = response.data
        if not isinstance(data, dict):
            raise RuntimeError("Slack Canvas API returned an unexpected response")
        canvas_id, canvas_url = _extract_canvas_reference(cast("dict[str, Any]", data))
        if not canvas_id:
            raise RuntimeError("Slack Canvas API did not return a canvas ID")
        await self._grant_channel_access(canvas_id, meeting.channel_id)
        if not canvas_url and self._team_id:
            canvas_url = f"https://app.slack.com/docs/{self._team_id}/{canvas_id}"
        return CanvasReference(canvas_id=canvas_id, canvas_url=canvas_url)

    async def append_for_meeting(
        self, meeting: Meeting, *, canvas_id: str, canvas_url: str | None
    ) -> CanvasReference:
        await self._client.api_call(
            "canvases.edit",
            json={
                "canvas_id": canvas_id,
                "changes": [
                    {
                        "operation": "insert_at_end",
                        "document_content": {
                            "type": "markdown",
                            "markdown": "\n\n---\n\n" + canvas_markdown(meeting),
                        },
                    }
                ],
            },
        )
        if not canvas_url and self._team_id:
            canvas_url = f"https://app.slack.com/docs/{self._team_id}/{canvas_id}"
        return CanvasReference(canvas_id=canvas_id, canvas_url=canvas_url)

    async def _grant_channel_access(self, canvas_id: str, channel_id: str) -> None:
        await self._client.api_call(
            "canvases.access.set",
            json={
                "canvas_id": canvas_id,
                "access_level": "write",
                "channel_ids": [channel_id],
            },
        )


class SlackPublisher:
    def __init__(self, client: AsyncWebClient) -> None:
        self._client = client

    async def post_meeting(
        self,
        meeting: Meeting,
        *,
        invitation_count: int,
        rsvp_counts: dict[str, int],
    ) -> str:
        from premday_bot.slack_views import meeting_message

        text, blocks = meeting_message(
            meeting, invitation_count=invitation_count, rsvp_counts=rsvp_counts
        )
        response = await self._client.chat_postMessage(
            channel=meeting.channel_id,
            text=text,
            blocks=blocks,
            unfurl_links=False,
            unfurl_media=False,
        )
        ts = response.get("ts")
        if not isinstance(ts, str):
            raise RuntimeError("Slack did not return a message timestamp")
        return ts

    async def update_rsvp(self, meeting: Meeting, *, rsvp_counts: dict[str, int]) -> None:
        if not meeting.message_ts:
            return
        from premday_bot.slack_views import meeting_message

        text, blocks = meeting_message(
            meeting,
            invitation_count=meeting.invitation_count,
            rsvp_counts=rsvp_counts,
        )
        await self._client.chat_update(
            channel=meeting.channel_id,
            ts=meeting.message_ts,
            text=text,
            blocks=blocks,
        )

    async def post_ephemeral(
        self,
        *,
        channel_id: str,
        user_id: str,
        text: str,
        blocks: list[dict[str, Any]] | None = None,
    ) -> None:
        await self._client.chat_postEphemeral(
            channel=channel_id,
            user=user_id,
            text=text,
            blocks=blocks,
        )

def _extract_canvas_reference(data: dict[str, Any]) -> tuple[str | None, str | None]:
    canvas = data.get("canvas")
    if isinstance(canvas, dict):
        canvas_id = _string_or_none(canvas.get("id")) or _string_or_none(canvas.get("canvas_id"))
        canvas_url = _string_or_none(canvas.get("url")) or _string_or_none(canvas.get("permalink"))
        return canvas_id, canvas_url

    return (
        _string_or_none(data.get("canvas_id")),
        _string_or_none(data.get("canvas_url")) or _string_or_none(data.get("url")),
    )


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) and value else None
