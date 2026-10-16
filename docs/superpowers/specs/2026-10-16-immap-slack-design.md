# IMMAP over Slack — design

Status: draft for review · Date: 2026-10-16
Evolves: https://github.com/premday/usergroup/pull/2 (IMMAP, "Infrastructure Metrics Masked Aggregation Protocol")

## Goal

Let Premday member companies compute aggregate infrastructure metrics (CPU cores, DIMM TiB, GPUs, ...)
through the existing Slack bot, so that **neither the bot (the "organizer") nor any participant
learns another company's individual values** — only the totals, and only after an admin validates them.

## Why not IMMAP as written

IMMAP has the organizer relay one running-total file from company to company. The organizer sees every
intermediate file, and `file[k] - file[k-1]` is exactly company *k*'s value (the mask cancels). So the
organizer *can* recover every individual value, contradicting "organizer MUST NOT receive individual
company values". A Slack bot that relays or stores those files would inherit the flaw, and Slack
workspace admins/exports can read the same messages.

## Protocol: single-round pairwise masking

Every company holds a Diffie-Hellman key pair, generated with the standard library only. For a poll with
participants `c_1 < c_2 < ... < c_N` (sorted by company id):

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

**Equal answer counts.** A submission must contain every metric of the poll's schema, so every metric is
answered by exactly the same N companies by construction. This is also required for correctness: masks
only cancel when all N companies answer every metric. A company with nothing to report enters `0`
(meaning "none", not "not applicable").

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

## Poll lifecycle

```text
created ──start──▶ collecting ──all submitted──▶ complete ──admin validates──▶ done
                     │    ▲
        deadline     │    │  admin extends deadline
        passed,      ▼    │
        answers   incomplete
        missing

created ──admin extends deadline──▶ created (same state, new deadline, badged "extended")
collecting ──admin extends deadline──▶ collecting (same state, new deadline, badged "extended")
incomplete ──admin extends deadline──▶ collecting
```

| Status | Meaning | Submissions | Totals visible |
|---|---|---|---|
| `created` | Poll defined: title, schema, participants (fixed) and a mandatory future deadline. Card and `poll.json` are posted so companies can check key fingerprints and prepare. | rejected | no |
| `collecting` | Started by the creator or an admin (**Start collecting**). Reminders run. | accepted; resubmitting replaces the previous line | no |
| `complete` | All N companies submitted. Totals are computed and stored. Card says "awaiting validation". | rejected | no |
| `done` | An admin pressed **Mark done**. Terminal. | rejected | yes |
| `incomplete` | Deadline passed while answers were missing. Partial sums are meaningless (masks do not cancel). | rejected | no |

Rules:

- **Deadline** is mandatory: a date, end of day in `PREMDAY_TIMEZONE`, must be in the future at creation.
- **Extending** (admin only) is allowed from `created`, `collecting` and `incomplete`. It sets a new
  deadline later than the current one and moves an `incomplete` poll back to `collecting`. Participants
  stay fixed (the masks depend on the participant set) and existing submissions are kept. Missing
  companies can then submit. A company that must be dropped needs a new poll. The card is badged
  **Extended ×n** and shows the original deadline. `original_deadline` and `extension_count` are stored.
- **Start collecting** is rejected if the deadline has already passed (an admin must extend first).
- **Reminders:** while `collecting`, every `IMMAP_REMINDER_HOURS` (default 24) the bot mentions the Slack
  owner of each company that has not submitted, in the poll thread. `last_reminded_at` is stored so a
  restart does not re-ping. No reminders after the deadline, or in any other status.
- **Admin** = a user whose Slack profile email is in `IMMAP_ADMIN_EMAILS` (comma-separated,
  case-insensitive). The email comes from `users.info` (existing `users:read.email` scope). Admin actions
  are checked on the server for every click, not only hidden in the UI. In tests the admin fixture is
  Aurélien Rougemont (Criteo), `a.rougemont@criteo.com`; other fixture users are non-admins.
- **Visibility:** the totals of a poll are stored when it becomes `complete` but are never shown, posted
  or returned by any command until it is `done`.

## Slack flow

One new slash command, `/immap`, no new OAuth scopes.

| Command | Behavior |
|---|---|
| `/immap register <company_id> <public_key>` | Stores or replaces the caller's company key. A `company_id` (`[a-z0-9-]{2,32}`) is owned by the first Slack user who registers it; others are refused. Reply is ephemeral. |
| `/immap poll` | Opens a modal: title, deadline date (default +7 days), participants (multi-select of registered companies). Needs at least 3 participants; the card warns below 10 (IMMAP's recommendation). Creates a poll in `created`. |
| `/immap report [poll_id]` | Ephemeral. Without argument, lists `done` polls in this channel. With a poll id, shows its title, participants, deadline (and "Extended ×n" badge) and the totals table. Non-`done` polls are answered with "not validated yet". |
| `/immap` (anything else) | Ephemeral help text. |

The poll card in the channel has the buttons that apply to the current status: **Start collecting**
(creator or admin), **Submit** (participants' owners, while `collecting`), **Extend deadline**
(admin), **Mark done** (admin, when `complete`). A thread reply carries `poll.json` (poll id, schema
version, metric ids/units, participants with public keys and fingerprints, deadline) in a code block.
**Submit** opens a modal with one multiline field for the line printed by `immap.py submit`.

Submission validation (errors shown in the modal): poll is `collecting` and before its deadline; the
submitter is the registered owner of `company_id` in the line; `company_id` is a participant; payload is
exactly `8 × metrics` bytes of hex. The card shows "k/N submitted" and names submitters (who submitted
is not secret). When the Nth company submits the poll becomes `complete`.

A periodic task started in `run()` (every 60 s over `collecting` polls) moves polls past their deadline
to `incomplete` (posting who is missing) and sends due reminders.

## Code layout

| File | Responsibility |
|---|---|
| `src/premday_bot/immap.py` | Pure crypto/protocol: constants, keygen, masks, `submit`, `aggregate`, line parse/format, CLI. Stdlib only. |
| `src/premday_bot/polls.py` | `PollStore` (same SQLite file and connection pattern as `MeetingStore`) plus the lifecycle rules as plain functions (allowed transitions, extension, closing, reminders due). |
| `src/premday_bot/slack_views.py` | Poll modal, submit modal, extend modal, card (status-dependent buttons and badges) and report blocks (additions only). |
| `src/premday_bot/app.py` | `/immap` commands, view handlers, button actions with admin checks, sweeper. Wiring only. |
| `src/premday_bot/config.py` | `IMMAP_REMINDER_HOURS` (default 24), `IMMAP_ADMIN_EMAILS` (default empty: nobody is admin). |
| `slack/app-manifest.yaml`, `README.md`, `.env.example` | Register `/immap`; document usage, lifecycle and trust model. |

Tables: `companies(company_id PK, name, owner_user_id, public_key)`;
`immap_polls(id PK, channel_id, creator_user_id, message_ts, title, schema_version, status,
deadline, original_deadline, extension_count, participants JSON, totals JSON, last_reminded_at,
validated_by, validated_at)`; `immap_submissions(poll_id, company_id, payload, submitted_at,
PK(poll_id, company_id))`. Meeting, canvas, email and RSVP code is untouched.

## Trust model and limitations

- Threat model: the bot operator is honest-but-curious. Confidentiality of company *i* holds unless all
  other N−1 participants collude. N < 10 allows educated guesses from the totals (IMMAP's limitation).
- **Key substitution:** the bot distributes public keys, so a malicious bot could swap in its own key
  for a participant and derive that participant's masks. Mitigation is out-of-band fingerprint
  comparison (printed by `keygen` and `submit`, and shown on the card while `created`). Without that,
  participants trust the bot for key distribution.
- The validation gate is an access-control rule in the bot, not cryptography: whoever controls the bot's
  database can read stored totals before `done`.
- Static keys are reused across polls (masks differ per `poll_id`). Leaking a private key exposes that
  company's past submissions. Key rotation is re-running `keygen` and `/immap register`.
- A participant can submit a false number; nothing detects it (same as IMMAP). Resubmission while
  `collecting` is allowed, so a company can correct a typo.
- No dropout recovery: an `incomplete` poll is either extended or replaced by a new poll without the
  missing company.
- Not in scope: signatures, range proofs, audit trail, Canvas integration, poll cancellation, rounding
  or public ranges for results, per-metric optional answers.

## Testing

- `immap.py`: masks cancel for N = 3..12 with random values; total equals plain sum; a single `y_i` never
  equals `v_i` for fixed seeds; order of participants does not change the total; invalid peer keys,
  bad values, missing or extra metrics and wrong poll rejected; CLI `keygen`/`submit` round trip; module
  imports only stdlib.
- `polls.py` lifecycle: every allowed and forbidden transition; start rejected after deadline; extension
  from `created`, `collecting` and `incomplete` only, new deadline must be later, badge data updated;
  extended `incomplete` poll returns to `collecting` and keeps submissions; closing on the Nth submission;
  `incomplete` on deadline with the missing companies named; `done` only from `complete`.
- Visibility: totals are not returned by any read path for a non-`done` poll; `/immap report` refuses
  them.
- Reminders: due only in `collecting`, respect the configured period and `last_reminded_at`, mention
  only missing companies, stop after the deadline.
- Authorization: admin-only actions refused for non-admins; submit refused for non-owners and
  non-participants; company id ownership.
- Handler logic is factored into functions testable without a Slack client, as the existing tests do.
  `ruff check`, `pyright`, `pytest` stay green.

## Proposed changes back to PR #2

Replace the sequential relay (steps 2–8, Company 1, audit chain) with the pairwise-masking round above,
and record the relay leak in the threat model. The metric table feedback from review (VRAM, NVMe/SATA
split, SSD total vs. intensity classes, racks, NICs, optics, 21"/OCP) stays an open decision for the
group; the bot takes whatever list is agreed through `schema_version`. Kept as a local draft until you
ask for it to be published.
