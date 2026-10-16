from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar
from zoneinfo import ZoneInfo

from premday_bot.config import Settings
from premday_bot.mailer import InvitationMailer
from premday_bot.models import Meeting


class FakeSMTP:
    instances: ClassVar[list["FakeSMTP"]] = []

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.starttls_calls = 0
        self.login_calls = 0
        self.sent_to: list[str] = []
        FakeSMTP.instances.append(self)

    def __enter__(self) -> "FakeSMTP":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def starttls(self) -> None:
        self.starttls_calls += 1

    def login(self, username: str, password: str) -> None:
        assert username == "bot@example.com"
        assert password == "secret"
        self.login_calls += 1

    def send_message(self, message) -> None:
        self.sent_to.append(message["To"])


def test_send_many_reuses_one_authenticated_smtp_session(monkeypatch) -> None:
    FakeSMTP.instances = []
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    mailer = InvitationMailer(_settings())

    summary = mailer.send_many(
        ["a@example.com", "b@example.com", "a@example.com", "c@example.com"],
        _meeting(),
    )

    assert summary.sent == 3
    assert summary.failed == {}
    assert len(FakeSMTP.instances) == 1
    smtp = FakeSMTP.instances[0]
    assert smtp.starttls_calls == 1
    assert smtp.login_calls == 1
    assert smtp.sent_to == ["a@example.com", "b@example.com", "c@example.com"]


def _settings() -> Settings:
    return Settings(
        slack_bot_token="xoxb-test",
        slack_app_token="xapp-test",
        slack_team_id=None,
        timezone="Europe/Paris",
        default_hour=18,
        default_duration_minutes=90,
        db_path=Path(":memory:"),
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_username="bot@example.com",
        smtp_password="secret",
        smtp_use_tls=True,
        smtp_use_ssl=False,
        email_from="Premday <bot@example.com>",
    )


def _meeting() -> Meeting:
    return Meeting(
        id="meeting-1",
        channel_id="C123",
        creator_user_id="U123",
        title="Premday usergroup meeting",
        starts_at=datetime(2026, 7, 26, 18, 0, tzinfo=ZoneInfo("Europe/Paris")),
        duration_minutes=90,
        proton_meet_url="https://meet.proton.me/foo",
    )
