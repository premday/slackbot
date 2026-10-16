from __future__ import annotations

import json
import re
import secrets
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from premday_bot import immap

CREATED = "created"
COLLECTING = "collecting"
COMPLETE = "complete"
INCOMPLETE = "incomplete"
DONE = "done"

MIN_PARTICIPANTS = 3
RECOMMENDED_PARTICIPANTS = 10
MAX_ADMIN_KEYS = 5
MAX_TITLE_LENGTH = 150
NONCE_TTL = timedelta(minutes=15)
EXTENDABLE = (CREATED, COLLECTING, INCOMPLETE)
ACTION_EXTEND = "extend"
ACTION_DONE = "done"

_COMPANY_ID = re.compile(r"^[a-z0-9-]{2,32}$")


class PollError(Exception):
    """A rule violation whose message is safe to show to the user."""


@dataclass(frozen=True)
class Company:
    company_id: str
    members: tuple[str, ...]  # Slack users attributed to the company, oldest first
    public_key: str | None  # enrolled key of the first member (key holder); None without members


@dataclass(frozen=True)
class Poll:
    id: str
    channel_id: str
    creator_user_id: str
    title: str
    template: str
    schema_version: int  # version of the template the poll was created from
    metrics: dict[str, str]  # snapshot of the template's metrics (metric id -> unit)
    status: str
    deadline: datetime
    original_deadline: datetime
    extension_count: int
    participants: tuple[tuple[str, str], ...]  # (company_id, public_key), sorted by company id
    admins: tuple[tuple[str, str], ...]  # (admin email, public_key), snapshot at creation
    bot_public_key: str
    bot_private_key: str
    message_ts: str | None = None
    started_at: datetime | None = None
    last_reminded_at: datetime | None = None
    totals: dict[str, int] | None = None
    validated_by: str | None = None
    validated_at: datetime | None = None

    @property
    def participant_ids(self) -> list[str]:
        return [company_id for company_id, _ in self.participants]


def unfence(text: str) -> str:
    """Strip whitespace and the code-fence or backtick markup people copy along from Slack."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned[3:]
        first, _, rest = cleaned.partition("\n")
        cleaned = rest if first.strip().isalpha() else cleaned
        cleaned = cleaned.removesuffix("```")
    return cleaned.strip().strip("`").strip()


def is_admin(email: str | None, admin_emails: frozenset[str]) -> bool:
    return email is not None and email.strip().lower() in admin_emails


def poll_document(poll: Poll) -> dict:
    """The ``poll.json`` participants feed to ``immap.py``; never includes private material."""
    return {
        "poll_id": poll.id,
        "template": poll.template,
        "schema_version": poll.schema_version,
        "metrics": dict(poll.metrics),
        "participants": [
            {"company_id": company_id, "public_key": key} for company_id, key in poll.participants
        ],
        "admins": [{"admin_id": email, "public_key": key} for email, key in poll.admins],
        "bot_public_key": poll.bot_public_key,
        "deadline": poll.deadline.isoformat(),
    }


class PollStore:
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
                CREATE TABLE IF NOT EXISTS enrollments (
                    user_id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL UNIQUE
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS companies (
                    company_id TEXT PRIMARY KEY
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS company_members (
                    user_id TEXT PRIMARY KEY,
                    company_id TEXT NOT NULL REFERENCES companies (company_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS admin_keys (
                    admin_email TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS immap_polls (
                    id TEXT PRIMARY KEY,
                    channel_id TEXT NOT NULL,
                    creator_user_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    template TEXT NOT NULL,
                    schema_version INTEGER NOT NULL,
                    metrics TEXT NOT NULL,
                    status TEXT NOT NULL,
                    deadline TEXT NOT NULL,
                    original_deadline TEXT NOT NULL,
                    extension_count INTEGER NOT NULL DEFAULT 0,
                    participants TEXT NOT NULL,
                    admins TEXT NOT NULL,
                    bot_public_key TEXT NOT NULL,
                    bot_private_key TEXT NOT NULL,
                    message_ts TEXT,
                    started_at TEXT,
                    last_reminded_at TEXT,
                    totals TEXT,
                    validated_by TEXT,
                    validated_at TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS immap_submissions (
                    poll_id TEXT NOT NULL REFERENCES immap_polls(id) ON DELETE CASCADE,
                    company_id TEXT NOT NULL,
                    line TEXT NOT NULL,
                    submitted_at TEXT NOT NULL,
                    PRIMARY KEY (poll_id, company_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS immap_pending_actions (
                    nonce TEXT PRIMARY KEY,
                    poll_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    admin_email TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """
            )

    def upsert_enrollment(self, user_id: str, public_key: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO enrollments (user_id, public_key) VALUES (?, ?)
                ON CONFLICT(user_id) DO UPDATE SET public_key = excluded.public_key
                """,
                (user_id, public_key),
            )

    def enrollments(self) -> dict[str, str]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM enrollments ORDER BY user_id").fetchall()
        return {row["user_id"]: row["public_key"] for row in rows}

    def add_company(self, company_id: str) -> None:
        with self._connect() as connection:
            connection.execute("INSERT INTO companies (company_id) VALUES (?)", (company_id,))

    def delete_company(self, company_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM company_members WHERE company_id = ?", (company_id,))
            connection.execute("DELETE FROM companies WHERE company_id = ?", (company_id,))

    def add_member(self, company_id: str, user_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO company_members (user_id, company_id) VALUES (?, ?)",
                (user_id, company_id),
            )

    def remove_member(self, user_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM company_members WHERE user_id = ?", (user_id,))

    def get_company(self, company_id: str) -> Company | None:
        return next((c for c in self.list_companies() if c.company_id == company_id), None)

    def list_companies(self) -> list[Company]:
        with self._connect() as connection:
            companies = connection.execute(
                "SELECT company_id FROM companies ORDER BY company_id"
            ).fetchall()
            members = connection.execute(
                "SELECT company_id, user_id FROM company_members ORDER BY rowid"
            ).fetchall()
            keys = {
                row["user_id"]: row["public_key"]
                for row in connection.execute("SELECT * FROM enrollments").fetchall()
            }
        by_company: dict[str, list[str]] = {}
        for row in members:
            by_company.setdefault(row["company_id"], []).append(row["user_id"])
        result = []
        for row in companies:
            users = by_company.get(row["company_id"], [])
            result.append(
                Company(row["company_id"], tuple(users), keys.get(users[0]) if users else None)
            )
        return result

    def upsert_admin_key(self, admin_email: str, public_key: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO admin_keys (admin_email, public_key) VALUES (?, ?)
                ON CONFLICT(admin_email) DO UPDATE SET public_key = excluded.public_key
                """,
                (admin_email, public_key),
            )

    def admin_keys(self) -> dict[str, str]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM admin_keys ORDER BY admin_email").fetchall()
        return {row["admin_email"]: row["public_key"] for row in rows}

    def save_poll(self, poll: Poll) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO immap_polls (
                    id, channel_id, creator_user_id, title, template, schema_version, metrics,
                    status, deadline, original_deadline, extension_count, participants, admins,
                    bot_public_key, bot_private_key, message_ts, started_at, last_reminded_at,
                    totals, validated_by, validated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    poll.id,
                    poll.channel_id,
                    poll.creator_user_id,
                    poll.title,
                    poll.template,
                    poll.schema_version,
                    json.dumps(poll.metrics),
                    poll.status,
                    poll.deadline.isoformat(),
                    poll.original_deadline.isoformat(),
                    poll.extension_count,
                    json.dumps(poll.participants),
                    json.dumps(poll.admins),
                    poll.bot_public_key,
                    poll.bot_private_key,
                    poll.message_ts,
                    _iso(poll.started_at),
                    _iso(poll.last_reminded_at),
                    json.dumps(poll.totals) if poll.totals is not None else None,
                    poll.validated_by,
                    _iso(poll.validated_at),
                ),
            )

    def get_poll(self, poll_id: str) -> Poll | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM immap_polls WHERE id = ?", (poll_id,)
            ).fetchone()
        return _row_to_poll(row) if row else None

    def list_polls(self, *, status: str | None = None, channel_id: str | None = None) -> list[Poll]:
        query = "SELECT * FROM immap_polls WHERE 1 = 1"
        arguments: list[str] = []
        if status is not None:
            query += " AND status = ?"
            arguments.append(status)
        if channel_id is not None:
            query += " AND channel_id = ?"
            arguments.append(channel_id)
        with self._connect() as connection:
            rows = connection.execute(query + " ORDER BY rowid", arguments).fetchall()
        return [_row_to_poll(row) for row in rows]

    def put_submission(self, poll_id: str, company_id: str, line: str, at: datetime) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO immap_submissions VALUES (?, ?, ?, ?)",
                (poll_id, company_id, line, at.isoformat()),
            )

    def submission_lines(self, poll_id: str) -> dict[str, str]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT company_id, line FROM immap_submissions WHERE poll_id = ? "
                "ORDER BY company_id",
                (poll_id,),
            ).fetchall()
        return {row["company_id"]: row["line"] for row in rows}

    def add_pending(
        self, nonce: str, poll_id: str, action: str, admin_email: str, expires_at: datetime
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO immap_pending_actions VALUES (?, ?, ?, ?, ?)",
                (nonce, poll_id, action, admin_email, expires_at.isoformat()),
            )

    def pop_pending(self, nonce: str) -> sqlite3.Row | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM immap_pending_actions WHERE nonce = ?", (nonce,)
            ).fetchone()
            connection.execute("DELETE FROM immap_pending_actions WHERE nonce = ?", (nonce,))
        return row


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _parse(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _row_to_poll(row: sqlite3.Row) -> Poll:
    return Poll(
        id=row["id"],
        channel_id=row["channel_id"],
        creator_user_id=row["creator_user_id"],
        title=row["title"],
        template=row["template"],
        schema_version=row["schema_version"],
        metrics=json.loads(row["metrics"]),
        status=row["status"],
        deadline=datetime.fromisoformat(row["deadline"]),
        original_deadline=datetime.fromisoformat(row["original_deadline"]),
        extension_count=row["extension_count"],
        participants=tuple((c, k) for c, k in json.loads(row["participants"])),
        admins=tuple((e, k) for e, k in json.loads(row["admins"])),
        bot_public_key=row["bot_public_key"],
        bot_private_key=row["bot_private_key"],
        message_ts=row["message_ts"],
        started_at=_parse(row["started_at"]),
        last_reminded_at=_parse(row["last_reminded_at"]),
        totals=json.loads(row["totals"]) if row["totals"] else None,
        validated_by=row["validated_by"],
        validated_at=_parse(row["validated_at"]),
    )


def _utcnow() -> datetime:
    return datetime.now(UTC)


class PollService:
    """Poll rules. Slack handlers call this; it knows nothing about Slack."""

    def __init__(
        self,
        store: PollStore,
        *,
        timezone: str,
        admin_emails: frozenset[str] = frozenset(),
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._store = store
        self._tz = ZoneInfo(timezone)
        self._admin_emails = admin_emails
        self._clock = clock

    # -- identity ---------------------------------------------------------------------------

    def is_admin(self, email: str | None) -> bool:
        return is_admin(email, self._admin_emails)

    def _require_admin(self, email: str | None) -> str:
        if not email or not self.is_admin(email):
            raise PollError("Only admins can do this.")
        return email.strip().lower()

    def enroll(self, *, user_id: str, public_key: str) -> str:
        """A Slack user enrolls with their key; an admin then attributes a company to them."""
        key = _normalized_key(public_key)
        for other_user, other_key in self._store.enrollments().items():
            if other_key == key and other_user != user_id:
                raise PollError("This public key is already enrolled by another Slack user.")
        self._store.upsert_enrollment(user_id, key)
        return immap.fingerprint(key)

    def add_company(self, *, email: str | None, company_id: str) -> None:
        self._require_admin(email)
        if not _COMPANY_ID.match(company_id):
            raise PollError("A company id uses 2-32 lowercase letters, digits or dashes.")
        if self._store.get_company(company_id):
            raise PollError(f"`{company_id}` already exists.")
        self._store.add_company(company_id)

    def remove_company(self, *, email: str | None, company_id: str) -> None:
        self._require_admin(email)
        self._existing_company(company_id)
        self._require_no_open_poll(company_id)
        self._store.delete_company(company_id)

    def attribute_company(self, *, email: str | None, company_id: str, user_id: str) -> Company:
        """Add an enrolled Slack user to a company. The first member is the key holder."""
        self._require_admin(email)
        company = self._existing_company(company_id)
        if user_id not in self._store.enrollments():
            raise PollError(
                f"<@{user_id}> has not enrolled yet (`/immap register <public_key>`)."
            )
        for other in self._store.list_companies():
            if user_id in other.members:
                if other.company_id == company_id:
                    return company
                raise PollError(
                    f"<@{user_id}> already belongs to `{other.company_id}`; remove them first."
                )
        self._store.add_member(company_id, user_id)
        return self._existing_company(company_id)

    def unattribute_user(self, *, email: str | None, user_id: str) -> str:
        """Remove a user from their company; returns the company id."""
        self._require_admin(email)
        company = next(
            (c for c in self._store.list_companies() if user_id in c.members), None
        )
        if company is None:
            raise PollError(f"<@{user_id}> does not belong to a company.")
        if company.members[0] == user_id:
            self._require_no_open_poll(company.company_id)  # the company key would change
        self._store.remove_member(user_id)
        return company.company_id

    def companies(self, *, email: str | None) -> list[Company]:
        self._require_admin(email)
        return self._store.list_companies()

    def unattributed_users(self, *, email: str | None) -> list[str]:
        """Enrolled Slack users no company is attributed to yet."""
        self._require_admin(email)
        members = {user for c in self._store.list_companies() for user in c.members}
        return [user for user in self._store.enrollments() if user not in members]

    def pollable_company_ids(self) -> list[str]:
        """Companies a poll can include; fails early when a poll could not be created."""
        companies = [c.company_id for c in self._store.list_companies() if c.public_key]
        if len(companies) < MIN_PARTICIPANTS:
            raise PollError(
                f"At least {MIN_PARTICIPANTS} companies need a member "
                "(`/immap companies`, `/immap company attribute`)."
            )
        if not any(email in self._admin_emails for email in self._store.admin_keys()):
            raise PollError("No admin has registered a key yet (`/immap admin-register`).")
        return companies

    def _existing_company(self, company_id: str) -> Company:
        company = self._store.get_company(company_id)
        if company is None:
            raise PollError(f"`{company_id}` does not exist.")
        return company

    def _require_no_open_poll(self, company_id: str) -> None:
        """A company's key is snapshotted in its polls, so it cannot change until they are done."""
        for poll in self._store.list_polls():
            if poll.status != DONE and company_id in poll.participant_ids:
                raise PollError(
                    f"`{company_id}` is part of the open poll `{poll.id}`; wait until it is done."
                )

    def register_admin_key(self, *, email: str | None, public_key: str) -> str:
        admin = self._require_admin(email)
        key = _normalized_key(public_key)
        keys = self._store.admin_keys()
        if admin not in keys and len(keys) >= MAX_ADMIN_KEYS:
            raise PollError(f"At most {MAX_ADMIN_KEYS} admin keys can be registered.")
        self._store.upsert_admin_key(admin, key)
        return immap.fingerprint(key)

    def company_of(self, user_id: str) -> str | None:
        return next(
            (c.company_id for c in self._store.list_companies() if user_id in c.members), None
        )

    def members_of(self, company_id: str) -> list[str]:
        company = self._store.get_company(company_id)
        return list(company.members) if company else []

    # -- creating and starting ----------------------------------------------------------------

    def create_poll(
        self,
        *,
        channel_id: str,
        creator_user_id: str,
        title: str,
        deadline_day: date,
        participants: list[str],
        template: str = immap.DEFAULT_TEMPLATE,
    ) -> Poll:
        poll_template = immap.POLL_TEMPLATES.get(template)
        if poll_template is None:
            raise PollError("Choose one of the poll templates.")
        title = title.strip()
        if not title:
            raise PollError("Add a title.")
        if len(title) > MAX_TITLE_LENGTH:
            raise PollError(f"The title is too long (at most {MAX_TITLE_LENGTH} characters).")
        unique = sorted(set(participants))
        if len(unique) < MIN_PARTICIPANTS:
            raise PollError(f"A poll needs at least {MIN_PARTICIPANTS} companies.")
        pairs: list[tuple[str, str]] = []
        for company_id in unique:
            company = self._store.get_company(company_id)
            if company is None:
                raise PollError(f"`{company_id}` does not exist.")
            if company.public_key is None:
                raise PollError(f"`{company_id}` has no member yet.")
            pairs.append((company.company_id, company.public_key))
        admins = tuple(
            (email, key)
            for email, key in self._store.admin_keys().items()
            if email in self._admin_emails
        )
        if not admins:
            raise PollError("No admin has registered a key yet (`/immap admin-register`).")
        deadline = self._end_of_day(deadline_day)
        if deadline <= self._clock():
            raise PollError("The deadline must be in the future.")
        bot_private = immap.generate_private_key()
        poll = Poll(
            id=secrets.token_hex(6),
            channel_id=channel_id,
            creator_user_id=creator_user_id,
            title=title,
            template=poll_template.id,
            schema_version=poll_template.version,
            metrics=dict(poll_template.metrics),
            status=CREATED,
            deadline=deadline,
            original_deadline=deadline,
            extension_count=0,
            participants=tuple(pairs),
            admins=admins,
            bot_public_key=immap.public_key(bot_private),
            bot_private_key=format(bot_private, "x"),
        )
        self._store.save_poll(poll)
        return poll

    def get(self, poll_id: str) -> Poll:
        return self._get(poll_id)

    def set_message_ts(self, poll_id: str, message_ts: str) -> Poll:
        return self._save(replace(self._get(poll_id), message_ts=message_ts))

    # -- internals ------------------------------------------------------------------------------

    def _get(self, poll_id: str) -> Poll:
        poll = self._store.get_poll(poll_id)
        if poll is None:
            raise PollError("I could not find that poll.")
        return poll

    def _save(self, poll: Poll) -> Poll:
        self._store.save_poll(poll)
        return poll

    def _end_of_day(self, day: date) -> datetime:
        return datetime.combine(day, time(23, 59, 59), tzinfo=self._tz)


def _normalized_key(public_key: str) -> str:
    try:
        return format(immap.parse_public_key(unfence(public_key)), "x")
    except ValueError as error:
        raise PollError(f"Invalid public key: {error}.") from error
