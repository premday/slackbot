from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from premday_bot.models import Meeting
from premday_bot.templates import format_meeting_time

SCHEDULE_CALLBACK_ID = "schedule_premday_meeting"
RECEIVE_INVITATION_ACTION_ID = "receive_invitation"
SHOW_RSVPS_ACTION_ID = "show_rsvps"


def schedule_modal(
    *,
    channel_id: str,
    default_start: datetime,
    default_duration_minutes: int,
    timezone_name: str,
) -> dict[str, object]:
    return {
        "type": "modal",
        "callback_id": SCHEDULE_CALLBACK_ID,
        "title": {"type": "plain_text", "text": "Premday meeting"},
        "submit": {"type": "plain_text", "text": "Schedule"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "private_metadata": json.dumps({"channel_id": channel_id, "timezone": timezone_name}),
        "blocks": [
            {
                "type": "input",
                "block_id": "title",
                "label": {"type": "plain_text", "text": "Title"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "value",
                    "initial_value": "Premday usergroup meeting",
                },
            },
            {
                "type": "input",
                "block_id": "date",
                "label": {"type": "plain_text", "text": "Date (your local date)"},
                "element": {
                    "type": "datepicker",
                    "action_id": "value",
                    "initial_date": default_start.date().isoformat(),
                },
            },
            {
                "type": "input",
                "block_id": "time",
                "label": {
                    "type": "plain_text",
                    "text": f"Time (your local time, {timezone_name})",
                },
                "element": {
                    "type": "timepicker",
                    "action_id": "value",
                    "initial_time": default_start.strftime("%H:%M"),
                },
            },
            {
                "type": "input",
                "block_id": "duration",
                "label": {"type": "plain_text", "text": "Duration in minutes"},
                "element": {
                    "type": "number_input",
                    "action_id": "value",
                    "is_decimal_allowed": False,
                    "initial_value": str(default_duration_minutes),
                    "min_value": "15",
                    "max_value": "480",
                },
            },
            {
                "type": "input",
                "block_id": "proton_url",
                "label": {"type": "plain_text", "text": "Proton Meet link"},
                "element": {
                    "type": "plain_text_input",
                    "action_id": "value",
                    "placeholder": {
                        "type": "plain_text",
                        "text": "https://meet.proton.me/...",
                    },
                },
            },
        ],
    }


def meeting_message(
    meeting: Meeting,
    *,
    invitation_count: int,
    rsvp_counts: dict[str, int] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    canvas_fields: list[dict[str, str]] = []
    if meeting.canvas_url:
        canvas_fields.append(
            {"type": "mrkdwn", "text": f"*Canvas:*\n<{meeting.canvas_url}|Open notes>"}
        )
    elif meeting.canvas_id:
        canvas_fields.append({"type": "mrkdwn", "text": f"*Canvas:*\n`{meeting.canvas_id}`"})

    fields = [
        {"type": "mrkdwn", "text": f"*When:*\n{format_meeting_time(meeting)}"},
        {"type": "mrkdwn", "text": f"*Duration:*\n{meeting.duration_minutes} minutes"},
        {"type": "mrkdwn", "text": f"*Meet:*\n<{meeting.proton_meet_url}|Join Proton Meet>"},
        *canvas_fields,
    ]

    text = f"{meeting.title} is scheduled for {format_meeting_time(meeting)}."
    elements: list[dict[str, object]] = [
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "Join Proton Meet"},
            "url": meeting.proton_meet_url,
            "action_id": "open_proton_meet",
        },
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "View RSVPs"},
            "action_id": SHOW_RSVPS_ACTION_ID,
            "value": meeting.id,
        },
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "Resend invitation"},
            "action_id": RECEIVE_INVITATION_ACTION_ID,
            "value": meeting.id,
            "style": "primary",
        },
    ]
    if meeting.canvas_url:
        elements.insert(
            1,
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Open Canvas"},
                "url": meeting.canvas_url,
                "action_id": "open_canvas",
            },
        )

    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": meeting.title}},
        {"type": "section", "fields": fields},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        f"Invitations sent to {invitation_count} channel member(s).  "
                        f"RSVP: Going {((rsvp_counts or {}).get('accepted', 0))} · "
                        f"Maybe {((rsvp_counts or {}).get('tentative', 0))} · "
                        f"Can't go {((rsvp_counts or {}).get('declined', 0))}"
                    ),
                }
            ],
        },
        {
            "type": "actions",
            "elements": elements,
        },
    ]
    return text, blocks
