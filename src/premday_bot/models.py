from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta


@dataclass(frozen=True)
class Meeting:
    id: str
    channel_id: str
    creator_user_id: str
    title: str
    starts_at: datetime
    duration_minutes: int
    proton_meet_url: str
    timezone: str | None = None
    canvas_id: str | None = None
    canvas_url: str | None = None
    message_ts: str | None = None
    invitation_count: int = 0

    @property
    def ends_at(self) -> datetime:
        return self.starts_at + timedelta(minutes=self.duration_minutes)

    def with_canvas(self, canvas_id: str | None, canvas_url: str | None) -> Meeting:
        return replace(self, canvas_id=canvas_id, canvas_url=canvas_url)

    def with_message_ts(self, message_ts: str) -> Meeting:
        return replace(self, message_ts=message_ts)

    def with_invitation_count(self, invitation_count: int) -> Meeting:
        return replace(self, invitation_count=invitation_count)
