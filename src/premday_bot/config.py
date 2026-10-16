from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    return int(raw)


def _email_set_env(name: str) -> frozenset[str]:
    raw = os.getenv(name, "")
    return frozenset(item.strip().lower() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    slack_bot_token: str
    slack_app_token: str
    slack_team_id: str | None
    timezone: str
    default_hour: int
    default_duration_minutes: int
    db_path: Path
    smtp_host: str | None
    smtp_port: int
    smtp_username: str | None
    smtp_password: str | None
    smtp_use_tls: bool
    smtp_use_ssl: bool
    email_from: str | None
    rsvp_email_address: str | None = None
    rsvp_smtp_port: int = 8025
    immap_reminder_hours: int = 24
    immap_admin_emails: frozenset[str] = frozenset()

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv()
        reminder_hours = _int_env("IMMAP_REMINDER_HOURS", 24)
        if reminder_hours < 1:
            raise RuntimeError("IMMAP_REMINDER_HOURS must be at least 1")
        return cls(
            slack_bot_token=_required_env("SLACK_BOT_TOKEN"),
            slack_app_token=_required_env("SLACK_APP_TOKEN"),
            slack_team_id=os.getenv("SLACK_TEAM_ID"),
            timezone=os.getenv("PREMDAY_TIMEZONE", "Europe/Paris"),
            default_hour=_int_env("PREMDAY_DEFAULT_HOUR", 18),
            default_duration_minutes=_int_env("PREMDAY_DEFAULT_DURATION_MINUTES", 90),
            db_path=Path(os.getenv("PREMDAY_DB_PATH", "premday.sqlite3")),
            smtp_host=os.getenv("SMTP_HOST"),
            smtp_port=_int_env("SMTP_PORT", 587),
            smtp_username=os.getenv("SMTP_USERNAME"),
            smtp_password=os.getenv("SMTP_PASSWORD"),
            smtp_use_tls=_bool_env("SMTP_USE_TLS", True),
            smtp_use_ssl=_bool_env("SMTP_USE_SSL", False),
            email_from=os.getenv("PREMDAY_EMAIL_FROM"),
            rsvp_email_address=os.getenv("RSVP_EMAIL_ADDRESS"),
            rsvp_smtp_port=_int_env("RSVP_SMTP_PORT", 8025),
            immap_reminder_hours=reminder_hours,
            immap_admin_emails=_email_set_env("IMMAP_ADMIN_EMAILS"),
        )

    @property
    def rsvp_smtp_enabled(self) -> bool:
        return bool(self.rsvp_email_address)


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value
