import asyncio
from typing import cast

from premday_bot.rsvp_mail import RSVPTransferServer


def test_lmtp_uses_lhlo_and_returns_one_status_per_recipient() -> None:
    class FakeReader:
        def __init__(self, lines: list[bytes]) -> None:
            self.lines = iter(lines)

        async def readline(self) -> bytes:
            return next(self.lines, b"")

    class FakeWriter:
        def __init__(self) -> None:
            self.output = bytearray()

        def write(self, data: bytes) -> None:
            self.output.extend(data)

        async def drain(self) -> None:
            pass

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def exercise() -> None:
        received: list[bytes] = []

        async def handle_message(raw_message: bytes) -> None:
            received.append(raw_message)

        server = RSVPTransferServer(
            host="127.0.0.1",
            port=2525,
            recipient="rsvp@example.com",
            on_message=handle_message,
        )
        reader = FakeReader(
            [
                b"LHLO opensmtpd\r\n",
                b"EHLO opensmtpd\r\n",
                b"MAIL FROM:<attendee@example.com>\r\n",
                b"RCPT TO:<rsvp@example.com>\r\n",
                b"RCPT TO:<rsvp@example.com>\r\n",
                b"DATA\r\n",
                b"From: attendee@example.com\r\n",
                b"Subject: RSVP\r\n",
                b"\r\n",
                b"reply\r\n",
                b".\r\n",
                b"QUIT\r\n",
            ]
        )
        writer = FakeWriter()
        await server._handle_client(
            cast(asyncio.StreamReader, reader), cast(asyncio.StreamWriter, writer)
        )

        output = bytes(writer.output)
        assert output.startswith(b"220 ")
        assert b"250-PIPELINING\r\n" in output
        assert b"250-ENHANCEDSTATUSCODES\r\n" in output
        assert b"500 5.5.1 Use LHLO with LMTP\r\n" in output
        assert output.count(b"250 2.0.0 Message accepted\r\n") == 2
        assert len(received) == 1
        assert b"Subject: RSVP" in received[0]

    asyncio.run(exercise())
