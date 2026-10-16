from datetime import datetime
from zoneinfo import ZoneInfo

from premday_bot.models import Meeting
from premday_bot.storage import MeetingStore


def test_meeting_store_round_trip(tmp_path) -> None:
    store = MeetingStore(tmp_path / "meetings.sqlite3")
    meeting = Meeting(
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

    store.save(meeting)
    store.set_message_ts(meeting.id, "123.456")

    stored = store.get(meeting.id)
    assert stored is not None
    assert stored.title == meeting.title
    assert stored.starts_at == meeting.starts_at
    assert stored.message_ts == "123.456"
