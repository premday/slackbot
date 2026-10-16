from __future__ import annotations

from datetime import UTC, datetime
from html import escape
from zoneinfo import ZoneInfo
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid

from premday_bot.models import Meeting


def format_meeting_time(meeting: Meeting) -> str:
    starts_at = (
        meeting.starts_at.astimezone(ZoneInfo(meeting.timezone))
        if meeting.timezone
        else meeting.starts_at
    )
    return starts_at.strftime("%A %Y-%m-%d at %H:%M %Z")


def canvas_markdown(meeting: Meeting) -> str:
    return f"""# {meeting.starts_at:%Y-%m-%d} — {meeting.title}

## Meeting details

- Date: {format_meeting_time(meeting)}
- Proton Meet: {meeting.proton_meet_url}

## Agenda

- Introductions
- Topics and demos
- Open discussion
- Next steps

## Notes

Add notes here during the meeting.

## Actions

- [ ] Share recap
- [ ] Confirm next meeting owner
"""


def invitation_subject(meeting: Meeting) -> str:
    return f"Invitation: {meeting.title} - {meeting.starts_at:%Y-%m-%d}"


def invitation_body(meeting: Meeting) -> str:
    canvas_line = f"\nCanvas: {meeting.canvas_url}\n" if meeting.canvas_url else ""
    return f"""You are invited to the next Premday meeting.

Title: {meeting.title}
When: {format_meeting_time(meeting)}
Duration: {meeting.duration_minutes} minutes
Proton Meet: {meeting.proton_meet_url}
{canvas_line}
See you there.
"""


def invitation_html(meeting: Meeting) -> str:
    title = escape(meeting.title)
    meeting_url = escape(meeting.proton_meet_url, quote=True)
    when = escape(format_meeting_time(meeting))
    canvas_link = (
        f'<p style="margin:20px 0 0"><a href="{escape(meeting.canvas_url, quote=True)}" '
        'style="color:#5365d8;text-decoration:none">Open the meeting notes →</a></p>'
        if meeting.canvas_url
        else ""
    )
    return f"""<!doctype html>
<html lang="en"><body style="margin:0;background:#f3f5f9;color:#202536;font-family:Arial,Helvetica,sans-serif">
  <div style="max-width:560px;margin:0 auto;padding:32px 16px">
    <div style="padding:28px;background:#fff;border:1px solid #e5e8f0;border-radius:16px">
      <p style="margin:0 0 12px;color:#65708a;font-size:12px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase">PREMDAY · MEETING INVITATION</p>
      <h1 style="margin:0 0 24px;font-size:26px;line-height:1.25">{title}</h1>
      <div style="padding:16px;background:#f6f7fb;border-radius:10px">
        <p style="margin:0 0 10px"><strong>When</strong><br>{when}</p>
        <p style="margin:0"><strong>Duration</strong><br>{meeting.duration_minutes} minutes</p>
      </div>
      <p style="margin:24px 0"><a href="{meeting_url}" style="display:inline-block;padding:13px 20px;background:#5365d8;color:#fff;text-decoration:none;border-radius:8px;font-weight:700">Join on Proton Meet</a></p>
      {canvas_link}
      <p style="margin:24px 0 0;color:#65708a;font-size:14px">See you there.</p>
    </div>
  </div>
</body></html>
"""


def calendar_invite(meeting: Meeting, recipient: str, organizer: str) -> str:
    timestamp = _ics_datetime(datetime.now(UTC))
    starts_at = _ics_datetime(meeting.starts_at.astimezone(UTC))
    ends_at = _ics_datetime(meeting.ends_at.astimezone(UTC))
    description = _escape_ics_text(
        f"Proton Meet: {meeting.proton_meet_url}"
        + (f"\\nCanvas: {meeting.canvas_url}" if meeting.canvas_url else "")
    )
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Premday//Premday Bot//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:REQUEST",
        "BEGIN:VEVENT",
        f"UID:{meeting.id}@premday",
        f"DTSTAMP:{timestamp}",
        f"DTSTART:{starts_at}",
        f"DTEND:{ends_at}",
        f"SUMMARY:{_escape_ics_text(meeting.title)}",
        f"DESCRIPTION:{description}",
        f"LOCATION:{_escape_ics_text(meeting.proton_meet_url)}",
        f"ORGANIZER;CN=Premday:mailto:{_email_address(organizer)}",
        f"ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:{recipient}",
        "END:VEVENT",
        "END:VCALENDAR",
    ]
    return "\r\n".join(lines) + "\r\n"


def build_invitation_email(meeting: Meeting, sender: str, recipient: str) -> EmailMessage:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = invitation_subject(meeting)
    message["Date"] = format_datetime(datetime.now(UTC))
    message["Message-ID"] = make_msgid(domain="premday")
    message.set_content(invitation_body(meeting))
    message.add_alternative(invitation_html(meeting), subtype="html")
    message.add_alternative(
        calendar_invite(meeting, recipient=recipient, organizer=sender),
        subtype="calendar",
        params={"method": "REQUEST", "name": "invite.ics"},
    )
    return message


def _ics_datetime(value: datetime) -> str:
    return value.strftime("%Y%m%dT%H%M%SZ")


def _escape_ics_text(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace(",", "\\,")
        .replace(";", "\\;")
    )


def _email_address(header_value: str) -> str:
    if "<" in header_value and ">" in header_value:
        return header_value.split("<", maxsplit=1)[1].split(">", maxsplit=1)[0]
    return header_value
