from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from premday_bot.models import Meeting


class MeetingStore:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._db_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _init_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS meetings (
                    id TEXT PRIMARY KEY,
                    channel_id TEXT NOT NULL,
                    creator_user_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    starts_at TEXT NOT NULL,
                    timezone TEXT,
                    duration_minutes INTEGER NOT NULL,
                    proton_meet_url TEXT NOT NULL,
                    canvas_id TEXT,
                    canvas_url TEXT,
                    message_ts TEXT,
                    invitation_count INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            columns = {row["name"] for row in connection.execute("PRAGMA table_info(meetings)")}
            if "timezone" not in columns:
                connection.execute("ALTER TABLE meetings ADD COLUMN timezone TEXT")
            if "invitation_count" not in columns:
                connection.execute(
                    "ALTER TABLE meetings ADD COLUMN invitation_count INTEGER NOT NULL DEFAULT 0"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS meeting_rsvps (
                    meeting_id TEXT NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
                    attendee_email TEXT NOT NULL,
                    response TEXT NOT NULL CHECK(response IN ('accepted', 'tentative', 'declined')),
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (meeting_id, attendee_email)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS meeting_attendees (
                    meeting_id TEXT NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
                    attendee_email TEXT NOT NULL,
                    PRIMARY KEY (meeting_id, attendee_email)
                )
                """
            )

    def save(self, meeting: Meeting) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO meetings (
                    id, channel_id, creator_user_id, title, starts_at, timezone, duration_minutes,
                    proton_meet_url, canvas_id, canvas_url, message_ts, invitation_count
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    channel_id = excluded.channel_id,
                    creator_user_id = excluded.creator_user_id,
                    title = excluded.title,
                    starts_at = excluded.starts_at,
                    timezone = excluded.timezone,
                    duration_minutes = excluded.duration_minutes,
                    proton_meet_url = excluded.proton_meet_url,
                    canvas_id = excluded.canvas_id,
                    canvas_url = excluded.canvas_url,
                    message_ts = excluded.message_ts,
                    invitation_count = excluded.invitation_count
                """,
                _meeting_to_row(meeting),
            )

    def get(self, meeting_id: str) -> Meeting | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM meetings WHERE id = ?",
                (meeting_id,),
            ).fetchone()
        return _row_to_meeting(row) if row else None

    def latest_with_canvas(self, channel_id: str, year: int) -> Meeting | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM meetings
                WHERE channel_id = ? AND canvas_id IS NOT NULL
                    AND substr(starts_at, 1, 4) = ?
                ORDER BY rowid DESC
                LIMIT 1
                """,
                (channel_id, f"{year:04d}"),
            ).fetchone()
        return _row_to_meeting(row) if row else None

    def set_message_ts(self, meeting_id: str, message_ts: str) -> Meeting:
        with self._connect() as connection:
            connection.execute(
                "UPDATE meetings SET message_ts = ? WHERE id = ?",
                (message_ts, meeting_id),
            )
        meeting = self.get(meeting_id)
        if meeting is None:
            raise KeyError(meeting_id)
        return meeting

    def set_rsvp(self, meeting_id: str, attendee_email: str, response: str) -> bool:
        with self._connect() as connection:
            invited = connection.execute(
                "SELECT 1 FROM meeting_attendees WHERE meeting_id = ? AND attendee_email = ?",
                (meeting_id, attendee_email.strip().lower()),
            ).fetchone()
            if not invited:
                return False
            connection.execute(
                """
                INSERT INTO meeting_rsvps (meeting_id, attendee_email, response)
                VALUES (?, ?, ?)
                ON CONFLICT(meeting_id, attendee_email) DO UPDATE SET
                    response = excluded.response, updated_at = CURRENT_TIMESTAMP
                """,
                (meeting_id, attendee_email.strip().lower(), response),
            )
        return True

    def add_invited_attendees(self, meeting_id: str, attendee_emails: Iterable[str]) -> None:
        with self._connect() as connection:
            connection.executemany(
                "INSERT OR IGNORE INTO meeting_attendees "
                "(meeting_id, attendee_email) VALUES (?, ?)",
                [(meeting_id, email.strip().lower()) for email in attendee_emails if email.strip()],
            )

    def rsvp_counts(self, meeting_id: str) -> dict[str, int]:
        counts = {"accepted": 0, "tentative": 0, "declined": 0}
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT response, COUNT(*) AS count FROM meeting_rsvps "
                "WHERE meeting_id = ? GROUP BY response",
                (meeting_id,),
            )
            counts.update({row["response"]: row["count"] for row in rows})
        return counts

    def rsvps_for_meeting(self, meeting_id: str) -> dict[str, list[str]]:
        rsvps = {"accepted": [], "tentative": [], "declined": []}
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT response, attendee_email FROM meeting_rsvps "
                "WHERE meeting_id = ? ORDER BY attendee_email",
                (meeting_id,),
            )
            for row in rows:
                rsvps[row["response"]].append(row["attendee_email"])
        return rsvps


def _meeting_to_row(meeting: Meeting) -> tuple[object, ...]:
    return (
        meeting.id,
        meeting.channel_id,
        meeting.creator_user_id,
        meeting.title,
        meeting.starts_at.isoformat(),
        meeting.timezone,
        meeting.duration_minutes,
        meeting.proton_meet_url,
        meeting.canvas_id,
        meeting.canvas_url,
        meeting.message_ts,
        meeting.invitation_count,
    )


def _row_to_meeting(row: sqlite3.Row) -> Meeting:
    return Meeting(
        id=row["id"],
        channel_id=row["channel_id"],
        creator_user_id=row["creator_user_id"],
        title=row["title"],
        starts_at=datetime_from_iso(row["starts_at"]),
        timezone=row["timezone"],
        duration_minutes=row["duration_minutes"],
        proton_meet_url=row["proton_meet_url"],
        canvas_id=row["canvas_id"],
        canvas_url=row["canvas_url"],
        message_ts=row["message_ts"],
        invitation_count=row["invitation_count"],
    )


def datetime_from_iso(value: str):
    from datetime import datetime

    return datetime.fromisoformat(value)
