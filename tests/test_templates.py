from datetime import datetime
from zoneinfo import ZoneInfo

from premday_bot.models import Meeting
from premday_bot.templates import build_invitation_email, calendar_invite, canvas_markdown


def _meeting() -> Meeting:
    return Meeting(
        id="meeting-1",
        channel_id="C123",
        creator_user_id="U123",
        title="Premday usergroup meeting",
        starts_at=datetime(2026, 7, 26, 18, 0, tzinfo=ZoneInfo("Europe/Paris")),
        duration_minutes=90,
        proton_meet_url="https://meet.proton.me/foo",
        canvas_id="F123",
        canvas_url="https://app.slack.com/docs/T123/F123",
    )


def test_canvas_template_contains_meeting_links() -> None:
    rendered = canvas_markdown(_meeting())

    assert "Premday usergroup meeting" in rendered
    assert "https://meet.proton.me/foo" in rendered


def test_calendar_invite_is_request_with_proton_link() -> None:
    rendered = calendar_invite(
        _meeting(),
        recipient="user@example.com",
        organizer="bot@example.com",
    )

    assert "METHOD:REQUEST" in rendered
    assert "ATTENDEE;ROLE=REQ-PARTICIPANT" in rendered
    assert "https://meet.proton.me/foo" in rendered


def test_email_has_calendar_alternative() -> None:
    message = build_invitation_email(
        _meeting(),
        sender="bot@example.com",
        recipient="user@example.com",
    )

    assert message["To"] == "user@example.com"
    assert any(part.get_content_type() == "text/calendar" for part in message.walk())
