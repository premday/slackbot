# IMMAP over Slack — design

Status: draft for review · Date: 2026-10-16
Evolves: https://github.com/premday/usergroup/pull/2 (IMMAP, "Infrastructure Metrics Masked Aggregation Protocol")

## Goal

Let Premday member companies compute aggregate infrastructure metrics (CPU cores, DIMM TiB, GPUs, ...)
through the existing Slack bot, so that **neither the bot (the "organizer") nor any participant
learns another company's individual values** — only the totals.

## Why not IMMAP as written

IMMAP has the organizer relay one running-total file from company to company. The organizer sees every
intermediate file, and `file[k] - file[k-1]` is exactly company *k*'s value (the mask cancels). So the
organizer *can* recover every individual value, contradicting "organizer MUST NOT receive individual
company values". A Slack bot that relays or stores those files would inherit the flaw, and Slack
workspace admins/exports can read the same messages.

## Protocol: single-round pairwise masking

Every company holds a Diffie-Hellman key pair, generated with the standard library only. For a poll with participants
`c_1 < c_2 < ... < c_N` (sorted by company id):

1. For each pair `(i, j)`, both sides derive the same shared secret `s_ij` from their keys.
2. For each metric `m`, the pair mask is `mask_ij(m) = SHAKE256(domain | poll_id | m | s_ij)[:8]` as an
   unsigned 64-bit integer.
3. Company *i* submits, per metric:
   `y_i(m) = v_i(m) + Σ_{j>i} mask_ij(m) − Σ_{j<i} mask_ji(m)  (mod 2^64)`
4. The bot computes `Σ_i y_i(m) mod 2^64`. Every mask appears once with `+` and once with `−`, so the
   result is `Σ_i v_i(m)`.

A single `y_i` is uniformly random to anyone who does not know the masks. Recovering company *i*'s value
requires all other N−1 companies to collude. The bot only ever sees public keys and `y_i` values.

Compared with IMMAP: no Company 1, no mask reveal, no participant order, no relay, no audit hash chain
(nothing is passed sequentially, so there is nothing to chain). One round; all companies submit in
parallel before a deadline.

### Parameters

- Group: RFC 3526 group 14 (2048-bit MODP, `g = 2`) via Python's `pow()`. Private exponent: 256 random
  bits. Peer public keys are rejected unless `2 <= y <= p-2`.
- Shared secret bytes: `s_ij` as big-endian bytes (256). Both sides hash identical input (the pair is
  ordered by company id).
- Values: non-negative integers in the unit of the metric, `0 <= v < 2^48`. Round up before submitting.
- Metrics (schema version 1) are the 12 from the PR, units unchanged. The list lives in one constant in
  `immap.py` and is copied into `poll.json`, so it can change with the PR review (VRAM, NVMe, ...)
  by bumping `schema_version`.

## Participant tool: `immap.py`

A single standard-library file with no imports from `premday_bot` (a test enforces this). It lives at
`src/premday_bot/immap.py` and is also what the bot imports for aggregation, so there is one
implementation.

```text
python immap.py keygen                       # writes immap.key (mode 600), prints public key + fingerprint
python immap.py submit poll.json values.json # prints one line: immap1.<poll_id>.<company_id>.<hex>
```

`values.json` maps metric id to integer. `submit` fails on missing/extra metrics, negative or too-large
values, a poll that does not contain your public key, and prints the fingerprint of every key in the poll
so participants can compare them out of band.

## Slack flow

One new slash command, `/immap`, no new OAuth scopes.

| Command | Behavior |
|---|---|
| `/immap register <company_id> <public_key>` | Stores or replaces the caller's company key. A `company_id` (`[a-z0-9-]{2,32}`) is owned by the first Slack user who registers it; others are refused. Reply is ephemeral. |
| `/immap poll` | Opens a modal: title, deadline date (end of day in `PREMDAY_TIMEZONE`, default +7 days), participants (multi-select of registered companies). Needs at least 3 participants; the card warns below 10 (IMMAP's recommendation). |
| `/immap` (anything else) | Ephemeral help text. |

On poll creation the bot posts a card in the channel and a thread reply containing `poll.json`
(poll id, schema version, metric ids/units, participants with public keys, deadline) in a code block,
plus a **Submit** button. The button opens a modal with one multiline field for the line printed by
`immap.py submit`.

Submission validation (errors shown in the modal): poll exists and is open; the submitter is the
registered owner of `company_id` in the line; `company_id` is a participant; payload is exactly
`8 × metrics` bytes of hex. Resubmitting before close replaces the previous line. The bot updates the
card with "k/N submitted" and names submitters (who submitted is not secret).

Closing: when all N have submitted, or the deadline passes. If all submitted, the bot posts the totals
table in the thread and stores them. If the deadline passes with submissions missing, the bot posts who
is missing and that the poll failed (partial sums are meaningless because masks do not cancel); the
organizer runs `/immap poll` again without them. Deadline expiry is checked by a periodic task started in
`run()` (every 60 s over open polls).

## Code layout

| File | Responsibility |
|---|---|
| `src/premday_bot/immap.py` | Pure crypto/protocol: constants, keygen, masks, `submit`, `aggregate`, line parse/format, CLI. Stdlib only. |
| `src/premday_bot/polls.py` | `PollStore` (same SQLite file and connection pattern as `MeetingStore`): `companies`, `immap_polls`, `immap_submissions`. Poll lifecycle: `open` → `done` / `failed`. |
| `src/premday_bot/slack_views.py` | Poll modal, submit modal, card and result blocks (additions only). |
| `src/premday_bot/app.py` | `/immap` command, poll and submit view handlers, Submit action, deadline sweeper. Wiring only. |
| `slack/app-manifest.yaml`, `README.md` | Register `/immap`; document usage and the trust model. |

Tables: `companies(company_id PK, name, owner_user_id, public_key)`;
`immap_polls(id PK, channel_id, creator_user_id, message_ts, title, schema_version, deadline, status,
participants JSON, totals JSON)`; `immap_submissions(poll_id, company_id, payload, submitted_at,
PK(poll_id, company_id))`. Meeting, canvas, email and RSVP code is untouched.

## Trust model and limitations

- Threat model: the bot operator is honest-but-curious. Confidentiality of company *i* holds unless all
  other N−1 participants collude. N < 10 allows educated guesses from the totals (IMMAP's limitation).
- **Key substitution:** the bot distributes public keys, so a malicious bot could swap in its own key
  for a participant and derive that participant's masks. Mitigation is out-of-band fingerprint
  comparison (printed by `keygen` and `submit`). Without that, participants trust the bot for key
  distribution.
- Static keys are reused across polls (masks differ per `poll_id`). Leaking a private key exposes that
  company's past submissions. Key rotation is re-running `keygen` and `/immap register`.
- A participant can submit a false number; nothing detects it (same as IMMAP).
- No dropout recovery: a missing company fails the poll and the organizer re-runs it.
- Not in scope: signatures, range proofs, audit trail, Canvas integration, poll cancellation, rounding
  or public ranges for results.

## Testing

- `immap.py`: masks cancel for N = 3..12 with random values; total equals plain sum; a single `y_i` never
  equals `v_i` for fixed seeds; order of participants does not change the total; invalid peer keys,
  bad values and wrong poll rejected; CLI `keygen`/`submit` round trip; module imports only stdlib.
- `polls.py`: company ownership rules; poll lifecycle; replacing a submission; closing on all-submitted
  and on deadline; failed poll names the missing companies.
- Slack handlers: validation errors for wrong owner, non-participant, bad length, closed poll
  (handler logic factored into functions testable without a Slack client, as the existing tests do).
- `ruff check`, `pyright`, `pytest` stay green.

## Proposed changes back to PR #2

Replace the sequential relay (steps 2–8, Company 1, audit chain) with the pairwise-masking round above,
and record the relay leak in the threat model. The metric table feedback from review (VRAM, NVMe/SATA
split, SSD total vs. intensity classes, racks, NICs, optics, 21"/OCP) stays an open decision for the
group; the bot takes whatever list is agreed through `schema_version`.
