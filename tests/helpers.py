from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from premday_bot import immap
from premday_bot.polls import Poll, PollService, PollStore, poll_document

ADMIN_EMAIL = "a.rougemont@criteo.com"  # Aurélien Rougemont (Criteo)
SECOND_ADMIN_EMAIL = "second.admin@example.com"
NOT_ADMIN_EMAIL = "someone@example.com"
ADMIN_EMAILS = frozenset({ADMIN_EMAIL, SECOND_ADMIN_EMAIL})
COMPANIES = ("acme", "bolt", "corp")
TEMPLATE_METRICS = immap.POLL_TEMPLATES[immap.DEFAULT_TEMPLATE].metrics
START = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self, now: datetime = START) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def owner(company_id: str) -> str:
    return f"U_{company_id.upper()}"


def values_for(company_id: str) -> dict[str, int]:
    base = sum(company_id.encode())
    return {name: base + index for index, name in enumerate(sorted(TEMPLATE_METRICS))}


@dataclass
class World:
    service: PollService
    store: PollStore
    clock: Clock
    company_keys: dict[str, int]
    admin_keys: dict[str, int]
    polls: list[Poll] = field(default_factory=list)

    def new_poll(
        self, participants: list[str] | None = None, days: int = 7, title: str = "Infra 2026"
    ) -> Poll:
        poll = self.service.create_poll(
            channel_id="C1",
            creator_user_id=owner("acme"),
            title=title,
            deadline_day=(self.clock.now + timedelta(days=days)).date(),
            participants=participants or list(COMPANIES),
        )
        self.polls.append(poll)
        return poll

    def collecting_poll(self, participants: list[str] | None = None, days: int = 7) -> Poll:
        poll = self.new_poll(participants, days)
        return self.service.start(poll.id, user_id=owner("acme"), email=None)

    def line(self, poll: Poll, company_id: str) -> str:
        return immap.submit(
            poll_document(poll), self.company_keys[company_id], values_for(company_id)
        )

    def submit(self, poll: Poll, company_id: str) -> Poll:
        line = self.line(poll, company_id)
        return self.service.submit(poll.id, user_id=owner(company_id), line=line)

    def complete_poll(self) -> Poll:
        poll = self.collecting_poll()
        for company_id in COMPANIES:
            poll = self.submit(poll, company_id)
        return poll

    def admin_totals(self, poll: Poll, email: str, nonce: str) -> dict:
        """What an admin gets by running ``immap.py aggregate`` on the released lines."""
        lines = self.service.submission_lines(poll.id, email=email)
        return immap.aggregate_sealed(
            poll_document(poll), lines, self.admin_keys[email], nonce
        )

    def expected_totals(self) -> dict[str, int]:
        return {
            name: sum(values_for(c)[name] for c in COMPANIES) for name in TEMPLATE_METRICS
        }

    def extend_proof(self, poll: Poll, email: str, day: date, nonce: str) -> str:
        return immap.make_proof(
            self.admin_keys[email], poll_document(poll), "extend", day.isoformat(), nonce
        )


def enroll_and_attribute(service: PollService, company_id: str, public_key: str) -> None:
    """A user enrolls, an admin adds the company and attributes it to that user."""
    service.enroll(user_id=owner(company_id), public_key=public_key)
    service.add_company(email=ADMIN_EMAIL, company_id=company_id)
    service.attribute_company(email=ADMIN_EMAIL, company_id=company_id, user_id=owner(company_id))


def make_world(tmp_path: Path, companies: tuple[str, ...] = COMPANIES) -> World:
    store = PollStore(tmp_path / "polls.sqlite3")
    clock = Clock()
    service = PollService(
        store, timezone="Europe/Paris", admin_emails=ADMIN_EMAILS, clock=clock
    )
    company_keys = {c: immap.generate_private_key() for c in companies}
    for company_id, key in company_keys.items():
        enroll_and_attribute(service, company_id, immap.public_key(key))
    admin_keys = {e: immap.generate_private_key() for e in (ADMIN_EMAIL, SECOND_ADMIN_EMAIL)}
    for email, key in admin_keys.items():
        service.register_admin_key(email=email, public_key=immap.public_key(key))
    return World(service, store, clock, company_keys, admin_keys)
