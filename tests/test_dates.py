from datetime import datetime
from zoneinfo import ZoneInfo

from premday_bot.dates import add_months, default_meeting_start


def test_add_months_clamps_to_last_valid_day() -> None:
    value = datetime(2026, 1, 31, 9, 30, tzinfo=ZoneInfo("Europe/Paris"))

    assert add_months(value, 1) == datetime(2026, 2, 28, 9, 30, tzinfo=ZoneInfo("Europe/Paris"))


def test_default_meeting_start_uses_next_month_at_configured_hour() -> None:
    now = datetime(2026, 6, 26, 14, 12, tzinfo=ZoneInfo("Europe/Paris"))

    result = default_meeting_start("Europe/Paris", 18, now=now)

    assert result == datetime(2026, 7, 26, 18, 0, tzinfo=ZoneInfo("Europe/Paris"))
