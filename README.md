# Premday Bot

A small Slack app for organizing Premday usergroup meetings.

## Features

- `/meeting` opens a Slack modal with a default meeting one month from now at
  18:00 Europe/Paris, converted to the creator's Slack timezone. `PREMDAY_TIMEZONE`
  is used if Slack does not provide a valid timezone.
- The bot creates a Slack Canvas for each channel and meeting year, named
  `Premday meetings <year>`, then adds later meetings from that channel and year.
- The bot emails calendar invitations to channel members through SMTP.
- The bot posts a meeting message with the Proton Meet link, Canvas link, and a
  `Receive invitation` button for newcomers.
- Meetings are persisted in SQLite so button clicks still work after process restarts.
- RSVP replies to calendar invitations are accepted through an LMTP listener
  and update the meeting message with Going, Maybe, and Can't go counts.
- A `View RSVPs` button privately shows responder names in independently expandable
  Going, Absent, and Maybe sections. Expanded names appear in two columns, using Slack
  user mentions for members and email addresses for invitees without a Slack account.
- `/immap` computes aggregate infrastructure metrics across companies without anyone
  (including the bot) seeing individual values; see [IMMAP polls](#immap-polls).

## Setup

```bash
cp .env.example .env
```

Create a Slack app from [`slack/app-manifest.yaml`](slack/app-manifest.yaml), then set the
values in `.env`.

The app uses Socket Mode, so it does not need a public HTTP endpoint.

Required Slack scopes:

- `commands`
- `chat:write`
- `users:read`
- `users:read.email`
- `channels:read`
- `channels:history`
- `groups:read`
- `im:read`
- `mpim:read`
- `canvases:write`
- `canvases:read`

## Run

On a server with Docker Compose, create `.env` from `.env.example`, fill in the
Slack and SMTP settings, then start the bot:

```bash
cp .env.example .env
docker compose up -d --build
docker compose logs -f premday-bot
```

The SQLite database lives in the `premday_data` Docker volume, so it survives
container rebuilds and restarts. Compose sets `PREMDAY_DB_PATH` to
`/data/premday.sqlite3` inside the container. The app connects to Slack using Socket Mode;
Compose publishes the optional RSVP listener on host loopback port 2525 for the local
OpenSMTPD relay.

To receive calendar replies, configure `RSVP_EMAIL_ADDRESS` in `.env`. Docker publishes
the listener on host loopback port 2525 by default (`RSVP_SMTP_HOST_PORT` can change it).
Configure OpenSMTPD to deliver mail for `RSVP_EMAIL_ADDRESS` over LMTP to
`127.0.0.1:2525`. The listener only accepts that recipient and binds through a loopback-only
Docker port mapping; do not expose it directly to the Internet. `PREMDAY_EMAIL_FROM` should
use `RSVP_EMAIL_ADDRESS`, because calendar clients send replies to the organizer address.

For `RSVP_EMAIL_ADDRESS=rsvp@example.com`, add this action with your other actions and put
the match rule before broader recipient rules:

```conf
action "premday_rsvp" relay host lmtp://127.0.0.1:2525
match from any for rcpt-to "rsvp@example.com" action "premday_rsvp"
```

If moving an existing installation, stop the old bot and copy its database into
the volume **before the first Compose start**. This preserves the Canvas IDs used
to append meetings to the existing Canvas:

```bash
docker compose build
docker compose run --rm --no-deps \
  --volume "$PWD/premday.sqlite3:/tmp/old.sqlite3:ro" \
  --entrypoint sh premday-bot \
  -c 'cp /tmp/old.sqlite3 /data/premday.sqlite3'
docker compose up -d
```

To stop the bot, run `docker compose down` (leave the volume in place).

For a local run without Docker:

```bash
uv sync
uv run premday-bot
```

In Slack:

```text
/meeting
```

## Environment

| Variable | Required | Description |
| --- | --- | --- |
| `SLACK_BOT_TOKEN` | yes | Bot token, usually `xoxb-...`. |
| `SLACK_APP_TOKEN` | yes | Socket Mode app token, usually `xapp-...`. |
| `SLACK_TEAM_ID` | no | Team ID used to build a Canvas URL if Slack does not return one. |
| `PREMDAY_TIMEZONE` | no | Fallback timezone when Slack has no valid timezone for the creator; defaults to `Europe/Paris`. |
| `PREMDAY_DEFAULT_HOUR` | no | Defaults to `18`. |
| `PREMDAY_DEFAULT_DURATION_MINUTES` | no | Defaults to `90`. |
| `PREMDAY_DB_PATH` | no | Defaults to `premday.sqlite3`. |
| `SMTP_HOST` | yes | SMTP server hostname. |
| `SMTP_PORT` | no | Defaults to `587`. |
| `SMTP_USERNAME` | no | SMTP login. |
| `SMTP_PASSWORD` | no | SMTP password. |
| `SMTP_USE_TLS` | no | STARTTLS, defaults to `true`. |
| `SMTP_USE_SSL` | no | Implicit TLS, defaults to `false`. |
| `PREMDAY_EMAIL_FROM` | yes | Sender header for invitations. |
| `RSVP_EMAIL_ADDRESS` | no | Address in calendar invites and only recipient accepted by the RSVP listener. |
| `RSVP_SMTP_HOST_PORT` | no | Host loopback port published by Compose; defaults to `2525`. |
| `IMMAP_ADMIN_EMAILS` | no | Comma-separated Slack profile emails of IMMAP admins. Empty means nobody is admin. |
| `IMMAP_REMINDER_HOURS` | no | Hours between reminders to companies that have not submitted; defaults to `24`. |

## IMMAP polls

IMMAP lets companies add up infrastructure metrics (CPU cores, DIMM TiB, GPUs, ...) so that only
totals are ever revealed. Design and trust model: `docs/superpowers/specs/2026-10-16-immap-slack-design.md`.
The bot never sees a value: each company masks its numbers with pairwise secrets and seals the result
to the admins' keys; the bot only stores ciphertext.

Participants and admins run `src/premday_bot/immap.py` (standard library only, no installation):

```bash
python immap.py keygen                      # companies: writes immap.key, prints public key
python immap.py keygen --key admin.key      # admins: writes admin.key
```

**Companies:** enroll once with `/immap register <public_key>`; an admin then adds you to your company (several people can belong to one company; the first member holds the company key, so share the key file with colleagues). When a colleague submits for your company, the other members are mentioned in the poll thread. When a poll is started, save the
`poll.json` the bot posts in the thread, write `values.json` (every metric, integers, `0` for none),
then run `python immap.py submit poll.json values.json` and paste the printed line into **Submit**.
Compare the key fingerprints printed by the tool with the ones you registered.

**Admins** (emails in `IMMAP_ADMIN_EMAILS`): `/immap admin-register <public_key>` once (at most 5 admins).
- **Extend deadline** and **Validate** show a one-time nonce and the exact command to run:
  `python immap.py proof poll.json --action extend --argument YYYY-MM-DD --nonce N` or
  `python immap.py aggregate poll.json lines.txt --nonce N` (save the sealed lines the bot sends you
  as `lines.txt`). Paste the output back into the modal.
- Totals become visible with `/immap report <poll_id>` only after a poll is validated (`done`).

**Admins also manage the companies:** `/immap companies` lists them with their members and key fingerprint
and who has enrolled without a company; `/immap company add <id>`, and `remove <id>`
maintain the list, `/immap company attribute` (a modal: company + enrolled user) adds a member and
`/immap company unattribute` (a modal: user) removes one. A company's key is the key of its first member.
Removing a company or its key holder is refused while the company is in a poll that is not `done`, because
the key is snapshotted there; adding or removing other members is always possible.

**Poll templates:** a poll is created from a template, a fixed list of metrics with units (defined in
`immap.py`, `POLL_TEMPLATES`). The first one, `infra-footprint`, covers rooms, racks and rack units, power,
CDUs, hosts (also OpenBMC and 21"/OCP), CPU cores, DIMM, GPUs and VRAM, accelerators, disks by technology
(SATA HDD, SATA SSD, NVMe SSD), NICs, optics, cabling and PSU levels. A poll keeps the template version and
metrics it was created with, so changing a template never affects polls that already exist. To add one,
add a `PollTemplate` to `POLL_TEMPLATES`.

Poll statuses: `created` → `collecting` → `complete` → `done`; `incomplete` when the deadline passes
with answers missing (an admin can extend it, which resumes `collecting` and is badged *Extended*).
Missing companies are reminded every `IMMAP_REMINDER_HOURS`.

## Development

```bash
uv run ruff check .
uv run pyright
uv run pytest
```

## Ideas Not Implemented Yet

- Topic proposal and voting before each meeting.
- Automatic reminder messages one week and one day before the meeting.
- Speaker signup with agenda slots.
- Post-meeting recap generation from Canvas content.
- RSVP attendee names in the Slack message (currently only response counts are shown).
