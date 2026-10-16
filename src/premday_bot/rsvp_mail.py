from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses

LOGGER = logging.getLogger(__name__)
MAX_MESSAGE_SIZE = 10 * 1024 * 1024


@dataclass(frozen=True)
class CalendarReply:
    meeting_id: str
    attendee_email: str
    response: str


def parse_calendar_replies(raw_message: bytes) -> list[CalendarReply]:
    message = BytesParser(policy=policy.default).parsebytes(raw_message)
    sender_addresses = {
        address.lower()
        for _, address in getaddresses(message.get_all("From", []))
        if address
    }
    replies: list[CalendarReply] = []
    for part in message.walk():
        if part.get_content_type() != "text/calendar":
            continue
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            calendar = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        else:
            content = part.get_content()
            calendar = content if isinstance(content, str) else str(content)
        replies.extend(
            reply
            for reply in _parse_icalendar(str(calendar))
            if reply.attendee_email in sender_addresses
        )
    return replies


def _parse_icalendar(content: str) -> list[CalendarReply]:
    unfolded: list[str] = []
    for line in content.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line.startswith((" ", "\t")) and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)

    method = next(
        (
            line.split(":", 1)[1].strip().upper()
            for line in unfolded
            if line.upper().startswith("METHOD:") and ":" in line
        ),
        None,
    )
    if method != "REPLY":
        return []

    results: list[CalendarReply] = []
    inside_event = False
    uid: str | None = None
    attendees: list[tuple[str, str]] = []

    def flush_event() -> None:
        if not uid:
            return
        meeting_id = uid.split("@", 1)[0]
        for email, status in attendees:
            results.append(CalendarReply(meeting_id, email, status))

    for line in unfolded:
        upper = line.upper()
        if upper == "BEGIN:VEVENT":
            inside_event, uid, attendees = True, None, []
        elif upper == "END:VEVENT" and inside_event:
            flush_event()
            inside_event = False
        elif inside_event and ":" in line:
            prop, value = line.split(":", 1)
            key_parts = prop.split(";")
            key = key_parts[0].upper()
            if key == "UID":
                uid = value.strip()
            elif key == "ATTENDEE":
                partstat = next(
                    (
                        item.split("=", 1)[1].upper()
                        for item in key_parts[1:]
                        if item.upper().startswith("PARTSTAT=")
                    ),
                    "NEEDS-ACTION",
                )
                email = value.strip()
                if email.lower().startswith("mailto:"):
                    email = email[7:]
                status = {
                    "ACCEPTED": "accepted",
                    "TENTATIVE": "tentative",
                    "DECLINED": "declined",
                }.get(partstat)
                if status and "@" in email:
                    attendees.append((email.lower(), status))
    return results


class RSVPTransferServer:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        recipient: str,
        on_message: Callable[[bytes], Awaitable[None]],
    ) -> None:
        self._host = host
        self._port = port
        self._recipient = recipient.strip().lower()
        self._on_message = on_message
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self._host, self._port)
        LOGGER.info("RSVP SMTP/LMTP listener is accepting mail on %s:%d", self._host, self._port)

    async def close(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        is_lmtp = False
        hello_done = False
        has_sender = False
        recipients: list[str] = []
        await self._reply(writer, "220 premday-bot ESMTP/LMTP service ready")
        try:
            while line := await asyncio.wait_for(reader.readline(), timeout=300):
                command = line.decode("ascii", errors="replace").strip()
                verb, _, argument = command.partition(" ")
                verb = verb.upper()
                if verb == "LHLO":
                    is_lmtp = verb == "LHLO"
                    hello_done = True
                    await self._reply_capabilities(writer)
                elif verb in {"EHLO", "HELO"}:
                    if is_lmtp:
                        await self._reply(writer, "500 5.5.1 Use LHLO with LMTP")
                    elif verb == "HELO":
                        hello_done = True
                        await self._reply(writer, "250 premday-bot")
                    else:
                        hello_done = True
                        await self._reply_capabilities(writer)
                elif verb == "MAIL":
                    if not hello_done:
                        await self._reply(writer, "503 5.5.1 Send LHLO or EHLO first")
                        continue
                    recipients = []
                    has_sender = True
                    await self._reply(writer, "250 2.1.0 Sender accepted")
                elif verb == "RCPT":
                    address = _smtp_path(argument).lower()
                    if not has_sender:
                        await self._reply(writer, "503 5.5.1 Need MAIL first")
                    elif address != self._recipient:
                        await self._reply(writer, "550 5.1.1 Recipient not accepted")
                    else:
                        recipients.append(address)
                        await self._reply(writer, "250 2.1.5 Recipient accepted")
                elif verb == "DATA":
                    if not has_sender or not recipients:
                        await self._reply(writer, "503 5.5.1 Need MAIL and RCPT first")
                        continue
                    await self._reply(writer, "354 End data with <CR><LF>.<CR><LF>")
                    raw = await self._read_data(reader)
                    if raw is None:
                        await self._respond_delivery(
                            writer, is_lmtp, recipients, "552 5.3.4 Message too large"
                        )
                    else:
                        try:
                            await self._on_message(raw)
                        except Exception:
                            LOGGER.exception("Could not process inbound RSVP email")
                            await self._respond_delivery(
                                writer,
                                is_lmtp,
                                recipients,
                                "451 4.3.0 Temporary processing error",
                            )
                        else:
                            await self._respond_delivery(
                                writer,
                                is_lmtp,
                                recipients,
                                "250 2.0.0 Message accepted",
                            )
                    has_sender = False
                    recipients = []
                elif verb == "RSET":
                    has_sender = False
                    recipients = []
                    await self._reply(writer, "250 2.0.0 Reset")
                elif verb == "NOOP":
                    await self._reply(writer, "250 2.0.0 OK")
                elif verb == "QUIT":
                    await self._reply(writer, "221 2.0.0 Bye")
                    return
                else:
                    await self._reply(writer, "502 5.5.1 Command not implemented")
        except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception:
            LOGGER.exception("Failed while processing inbound RSVP email")
            with suppress(ConnectionError):
                await self._reply(writer, "451 4.3.0 Temporary processing error")
        finally:
            writer.close()
            await writer.wait_closed()

    @staticmethod
    async def _read_data(reader: asyncio.StreamReader) -> bytes | None:
        chunks: list[bytes] = []
        size = 0
        while line := await asyncio.wait_for(reader.readline(), timeout=300):
            if line in (b".\r\n", b".\n"):
                return b"".join(chunks)
            if line.startswith(b".."):
                line = line[1:]
            size += len(line)
            if size > MAX_MESSAGE_SIZE:
                while line not in (b".\r\n", b".\n"):
                    line = await reader.readline()
                    if not line:
                        return None
                return None
            chunks.append(line)
        return None

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, text: str) -> None:
        writer.write(text.encode("ascii") + b"\r\n")
        await writer.drain()

    @staticmethod
    async def _reply_capabilities(writer: asyncio.StreamWriter) -> None:
        writer.write(
            b"250-premday-bot\r\n"
            b"250-PIPELINING\r\n"
            b"250-ENHANCEDSTATUSCODES\r\n"
            b"250-8BITMIME\r\n"
            b"250 SIZE "
            + str(MAX_MESSAGE_SIZE).encode()
            + b"\r\n"
        )
        await writer.drain()

    @classmethod
    async def _respond_delivery(
        cls,
        writer: asyncio.StreamWriter,
        is_lmtp: bool,
        recipients: list[str],
        response: str,
    ) -> None:
        response_count = len(recipients) if is_lmtp else 1
        for _ in range(response_count):
            await cls._reply(writer, response)


def _smtp_path(argument: str) -> str:
    match = re.search(r"<([^>]*)>", argument)
    return match.group(1) if match else ""
