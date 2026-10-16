from __future__ import annotations

import calendar
from datetime import datetime, time
from zoneinfo import ZoneInfo


def add_months(value: datetime, months: int) -> datetime:
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def default_meeting_start(
    timezone_name: str,
    hour: int,
    now: datetime | None = None,
) -> datetime:
    paris_timezone = ZoneInfo("Europe/Paris")
    local_timezone = ZoneInfo(timezone_name)
    paris_now = now.astimezone(paris_timezone) if now else datetime.now(paris_timezone)
    paris_target = add_months(paris_now, 1).replace(
        hour=hour, minute=0, second=0, microsecond=0
    )
    return paris_target.astimezone(local_timezone)


def combine_local_date_time(date_value: str, time_value: str, timezone_name: str) -> datetime:
    year, month, day = (int(part) for part in date_value.split("-"))
    hour, minute = (int(part) for part in time_value.split(":"))
    return datetime.combine(
        date=datetime(year, month, day).date(),
        time=time(hour, minute),
        tzinfo=ZoneInfo(timezone_name),
    )
