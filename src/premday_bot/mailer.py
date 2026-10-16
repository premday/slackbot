from __future__ import annotations

import smtplib
from collections.abc import Generator, Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from email.message import EmailMessage

from premday_bot.config import Settings
from premday_bot.models import Meeting
from premday_bot.templates import build_invitation_email


@dataclass(frozen=True)
class SendSummary:
    sent: int
    failed: dict[str, str]
    sent_recipients: tuple[str, ...] = ()


class InvitationMailer:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def send_many(self, recipients: Iterable[str], meeting: Meeting) -> SendSummary:
        unique_recipients = sorted(set(recipients))
        if not unique_recipients:
            return SendSummary(sent=0, failed={})

        sent = 0
        sent_recipients: list[str] = []
        failed: dict[str, str] = {}
        try:
            with self._smtp_session() as smtp:
                for recipient in unique_recipients:
                    try:
                        message = self._build_message(meeting, recipient)
                        smtp.send_message(message)
                    except Exception as error:
                        failed[recipient] = str(error)
                    else:
                        sent += 1
                        sent_recipients.append(recipient)
        except Exception as error:
            failed = {recipient: str(error) for recipient in unique_recipients}
        return SendSummary(sent=sent, failed=failed, sent_recipients=tuple(sent_recipients))

    def send_one(self, recipient: str, meeting: Meeting) -> None:
        with self._smtp_session() as smtp:
            smtp.send_message(self._build_message(meeting, recipient))

    def _build_message(self, meeting: Meeting, recipient: str) -> EmailMessage:
        if not self._settings.smtp_host or not self._settings.email_from:
            raise RuntimeError("SMTP_HOST and PREMDAY_EMAIL_FROM must be configured")
        return build_invitation_email(
            meeting,
            sender=self._settings.email_from,
            recipient=recipient,
        )

    @contextmanager
    def _smtp_session(self) -> Generator[smtplib.SMTP | smtplib.SMTP_SSL]:
        if not self._settings.smtp_host or not self._settings.email_from:
            raise RuntimeError("SMTP_HOST and PREMDAY_EMAIL_FROM must be configured")

        if self._settings.smtp_use_ssl:
            with smtplib.SMTP_SSL(self._settings.smtp_host, self._settings.smtp_port) as smtp:
                self._login(smtp)
                yield smtp
            return

        with smtplib.SMTP(self._settings.smtp_host, self._settings.smtp_port) as smtp:
            if self._settings.smtp_use_tls:
                smtp.starttls()
            self._login(smtp)
            yield smtp

    def _login(self, smtp: smtplib.SMTP | smtplib.SMTP_SSL) -> None:
        if self._settings.smtp_username:
            smtp.login(self._settings.smtp_username, self._settings.smtp_password or "")
