# IMMAP over Slack — design

Status: draft for review · Date: 2026-10-16
Evolves: https://github.com/premday/usergroup/pull/2 (IMMAP, "Infrastructure Metrics Masked Aggregation Protocol")

## Goal

Let Premday member companies compute aggregate infrastructure metrics (CPU cores, DIMM TiB, GPUs, ...)
through the existing Slack bot, so that **neither the bot (the "organizer") nor any participant
learns another company's individual values**, and so that **totals are only readable after an admin
validates them** — the second rule enforced cryptographically, not only by access control.

## Why not IMMAP as written

IMMAP has the organizer relay one running-total file from company to company. The organizer sees every
intermediate file, and `file[k] - file[k-1]` is exactly company *k*'s value (the mask cancels). So the
organizer *can* recover every individual value, contradicting "organizer MUST NOT receive individual
company values". A Slack bot that relays or stores those files would inherit the flaw, and Slack
workspace admins/exports can read the same messages.

## Protocol

### 1. Pairwise masking (one round)

Every company holds a Diffie-Hellman key pair, generated with the standard library only. For a poll with
participants `c_1 < c_2 < ... < c_N` (sorted by company id):

1. For each pair `(i, j)`, both sides derive the same shared secret `s_ij` from their keys.
2. For each metric `m`, the pair mask is `mask_ij(m) = SHAKE256(domain | poll_id | m | s_ij)[:8]` as an
   unsigned 64-bit integer.
3. Company *i* computes, per metric:
   `y_i(m) = v_i(m) + Σ_{j>i} mask_ij(m) − Σ_{j<i} mask_ji(m)  (mod 2^64)`
4. Summing every `y_i(m)` mod 2^64 gives `Σ_i v_i(m)`: each mask appears once with `+` and once with `−`.

A single `y_i` is uniformly random to anyone who does not know the masks; recovering company *i*'s value
needs all other N−1 companies to collude. Compared with IMMAP: no Company 1, no mask reveal, no order,
no relay, no audit hash chain. All companies submit in parallel before a deadline.

**Equal answer counts.** A submission must contain every metric of the schema, so every metric is
answered by exactly the same N companies by construction (also required for correctness: masks only
cancel when all N companies answer every metric). Nothing to report means `0` ("none", not "n/a").

### 2. Sealing to the admin group

The bot must not be able to add the `y_i` up, otherwise "totals are hidden until validated" would hold
only as long as nobody dumps the database. So each company **seals** its `y_i` vector before it leaves
their machine: a random 256-bit key encrypts the payload (SHAKE256 stream) and is authenticated
(HMAC-SHA256); that key is wrapped separately for every admin public key listed in the poll, using a
Diffie-Hellman exchange with a one-time ephemeral key. Any single admin can open every submission; the
bot (and anyone with its database) cannot open any of them.

- Admins register a key with `/immap admin-register` (only emails in `IMMAP_ADMIN_EMAILS`, at most 5 keys
  so a sealed line stays under Slack's 3000-character modal limit).
- The admin keys of a poll are **snapshotted at creation** (sealing recipients and who may act on it).
  A poll cannot be created while no admin key is registered.
- Because the bot never sees any `y_i`, a bot that swaps companies' public keys learns nothing. Breaking
  confidentiality needs a compromised bot **and** a colluding admin.

### 3. Proof of the admin key

Admin actions that change what the group sees (**Extend**, **Mark done**) need proof of possession of the
admin private key on top of the Slack email check. At poll creation the bot generates a one-time key
pair for the poll (public half in `poll.json`, private half kept by the bot). The tag is
`HMAC-SHA256(key = SHAKE256(DH(admin_priv, bot_poll_pub)), poll_id | action | argument | nonce)`, where
`argument` is the new date for Extend and the SHA-256 digest of the canonical totals JSON for Mark done,
and `nonce` is issued by the bot per attempt (single use, 15 minutes). The bot verifies it with its
private half and the admin's snapshotted public key. **Start collecting** keeps only the Slack check
(creator or admin).

This is a keyed hash, not a signature (the standard library has none): whoever controls the bot's
database could forge a tag, but still cannot read the submissions.

### Parameters

- Group: RFC 3526 group 14 (2048-bit MODP, `g = 2`) via Python's `pow()`; private exponents 256 random
  bits; peer public keys must be hexadecimal digits only and satisfy `2 <= y <= p-2`.
- Values: non-negative integers in the metric's unit, `0 <= v < 2^48` (round up).
- Metrics come from the poll's template (next section); `immap.py` defines the templates once.

## Poll templates

A poll is created from a **template**: an id, title, description, integer `version` and an ordered list of
metrics with units, defined once in `immap.py` (`POLL_TEMPLATES`, `DEFAULT_TEMPLATE`). The poll stores the
template id, version and a **snapshot of its metrics**, so editing a template later never changes polls that
exist, and `poll.json` carries `template`, `schema_version` (= template version) and `metrics`. The create
modal has a template picker (which lists every template with its metric count). Adding a template means
adding an entry to `POLL_TEMPLATES`; the protocol itself takes whatever metrics the poll lists.

**Template `infra-footprint` v1** (23 metrics) is the PR's list amended with the PR review:

| Group | Metrics (unit) | Origin |
|---|---|---|
| Site | `datacenter_room_count` (rooms), `rack_count` (racks), `rack_unit_count` (RU), `global_power_consumption` (kW), `cdu_count` (units) | PR; racks asked by Arno500, RU added because rack height varies (superMario-HW) |
| Hosts | `host_count`, `openbmc_host_count`, `ocp_21in_host_count` (hosts) | PR; 21"/OCP by rgoncalvesse |
| Compute | `cpu_core_count` (cores), `dimm_memory` (TiB), `gpu_card_count` (cards), `gpu_vram` (TiB), `accelerator_card_count` (cards, e.g. QAT) | PR; VRAM by Arno500, accelerators by superMario-HW |
| Storage | `hdd_sata_capacity`, `ssd_sata_capacity`, `ssd_nvme_capacity` (TiB) | replaces HDD total and the three SSD endurance classes (superMario-HW, rgoncalvesse) |
| Network | `nic_count` (cards), `optics_count` (modules), `fiber_cable_count`, `copper_cable_count` (cables) | superMario-HW |
| Power supplies | `psu_silver_count`, `psu_gold_count`, `psu_platinum_count` (units) | superMario-HW |

Choices to confirm with the group: SAS disks count with SATA of the same medium; PSU levels beyond
silver/gold/platinum are not asked; the SSD endurance classes are dropped, as proposed in review. A sealed
line for this template with 5 admins is about 1.9 kB, under Slack's 3000-character field limit (tested).

## Tool: `immap.py`

A single standard-library file with no imports from `premday_bot` (a test enforces this), at
`src/premday_bot/immap.py`; the bot imports the same file, so there is one implementation.

```text
python immap.py keygen [--key FILE]                      # company or admin: new key pair (mode 600)
python immap.py submit poll.json values.json             # company: prints one sealed line
python immap.py aggregate poll.json lines.txt --nonce N  # admin: opens all lines, sums, proves
python immap.py proof poll.json --action extend --argument YYYY-MM-DD --nonce N   # admin
```

`submit` finds the company from the key, fails on missing/extra metrics, bad values, a key not in the
poll or a poll with no admin keys, and prints every participant's key fingerprint on stderr.
`aggregate` fails unless it has exactly one valid line per participant and prints
`{"totals": ..., "proof": ...}`.

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
| `created` | Poll defined: title, template, participants (fixed, keys snapshotted) and a mandatory future deadline. Card and `poll.json` are posted so companies can check key fingerprints and prepare. | rejected | no |
| `collecting` | Started by the creator or an admin. Reminders run. | accepted; resubmitting replaces the previous line | no |
| `complete` | All N companies submitted (N sealed lines the bot cannot read). Card says "awaiting validation". | rejected | no |
| `done` | An admin supplied the aggregate output and a valid proof. Terminal. | rejected | yes |
| `incomplete` | Deadline passed while answers were missing (partial sums are meaningless). | rejected | no |

Rules:

- **Deadline** is mandatory: a date, end of day in `PREMDAY_TIMEZONE`, in the future at creation.
- **Extending** (admin + proof) is allowed from `created`, `collecting`, `incomplete`: new deadline must be
  later than the current one and than now; `incomplete` goes back to `collecting`. Participants stay fixed
  (masks depend on them) and submissions are kept; a company that must be dropped needs a new poll. The
  card shows **Extended ×n** and the original deadline.
- **Start collecting** is refused if the deadline has passed (extend first).
- **Reminders:** while `collecting`, every `IMMAP_REMINDER_HOURS` (default 24, minimum 1), the bot mentions
  every member of the companies that have not submitted, in the poll thread. First reminder one period
  after starting; `last_reminded_at` survives restarts; none after the deadline or in other statuses.
- **Colleague notice:** when a member submits (or resubmits) for a company that has other members, the bot
  mentions those colleagues in the poll thread: who submitted, that they need not, and that a new
  submission before the deadline replaces it. Companies with a single member get no notice. The notice
  reveals nothing the card does not already show (which companies have submitted).
- **Admin** = Slack profile email in `IMMAP_ADMIN_EMAILS` (comma-separated, case-insensitive; empty means
  nobody). Any one admin suffices. Admin checks run on the server for every click. Test fixtures:
  Aurélien Rougemont (Criteo), `a.rougemont@criteo.com`, plus a second admin and a non-admin.
- **Sanity bound:** a total can never exceed N × 2^48. `aggregate` and the bot's `mark_done` refuse larger
  totals, which only a corrupted or tampered submission can produce. `poll.json` identifies admins by an
  opaque 8-hex id, never by email, because it is posted in a channel.
- **Validation:** an admin clicks **Validate**; the bot issues a nonce and releases the N sealed lines
  (privately, as chat messages), the admin runs `immap.py aggregate` offline and pastes its output into
  the modal. The bot checks the totals match the schema and the proof covers them, then stores them. The
  bot cannot check that the totals are the true sums: it trusts the admin, who is the validator.
- **Visibility:** totals never exist on the bot before `done`, and no read path returns them before then.

## Slack flow

One new slash command, `/immap`, no new OAuth scopes.

| Command | Behavior |
|---|---|
| `/immap register <public_key>` | **Enrollment**: any Slack user stores their public key (one key per user, a key belongs to one user; running it again rotates the key). The user then waits for an admin to add them to a company. |
| `/immap companies` | Admins only. Lists every company with its members (the first is the key holder) and key fingerprint, and the enrolled users who have no company yet. |
| `/immap company add <id>` / `remove <id>` | Admins only. Maintains the list of companies (`id` is `[a-z0-9-]{2,32}`). |
| `/immap company attribute` | Admins only. Modal: pick a company and an enrolled Slack user to add as a **member**. A company has several members, a user belongs to one company, and the first member is the **key holder**: the company's key is their enrolled key, which colleagues use by sharing the private key file. Any member can submit for the company. |
| `/immap company unattribute` | Admins only. Modal: pick a user to remove from their company. If the key holder leaves, the next member becomes holder; a company left without members cannot join a poll. |
| `/immap admin-register <public_key>` | Admins only: registers or replaces their admin key (max 5 admins with keys). |
| `/immap poll` | Modal: title (≤150 chars), template, deadline date (default +7 days), companies (multi-select). Needs ≥3 companies and ≥1 admin key; the card warns below 10 companies (IMMAP's recommendation). Creates a poll in `created`. |
| `/immap report [poll_id]` | Ephemeral. No argument: validated polls of this channel. With an id: title, companies, extension badge and totals. Anything not `done` is refused. |

The poll card has the buttons that fit its status: **Start collecting**, **Submit**, **Extend deadline**,
**Validate**. A thread reply carries `poll.json` (poll id, template, metrics, participants and admins with
public keys, one-time bot key, deadline) and every key's fingerprint. Extend and Validate open modals that
show the nonce and the exact command to run. Pasted text may carry Slack code markup (backticks or fences),
which is stripped.

A periodic task started in `run()` (every 60 s) moves `collecting` polls past their deadline to
`incomplete` (naming who is missing) and sends due reminders.

## Code layout

| File | Responsibility |
|---|---|
| `src/premday_bot/immap.py` | Protocol: constants, keys, masking, sealing, proofs, `submit`, `aggregate_sealed`, CLI. Stdlib only. |
| `src/premday_bot/polls.py` | `PollStore` (same SQLite file and connection pattern as `MeetingStore`) and `PollService`: every rule above, no Slack. |
| `src/premday_bot/immap_views.py` | Modals, poll card, `poll.json` message, report text, message chunking. |
| `src/premday_bot/immap_slack.py` | `/immap` command, view and button handlers (thin), sweeper. |
| `src/premday_bot/app.py`, `config.py` | Wiring; `IMMAP_REMINDER_HOURS`, `IMMAP_ADMIN_EMAILS`. |
| `slack/app-manifest.yaml`, `README.md`, `.env.example` | Command registration and docs. |

Tables: `enrollments(user_id PK, public_key UNIQUE)`; `companies(company_id PK)`; `company_members(user_id PK, company_id)` (the key of a company is the enrolled key of its oldest member); `admin_keys(admin_email PK, public_key)`;
`immap_polls(id PK, channel_id, creator_user_id, title, template, schema_version, metrics, status, deadline,
original_deadline, extension_count, participants JSON, admins JSON, bot_public_key, bot_private_key,
message_ts, started_at, last_reminded_at, totals JSON, validated_by, validated_at)`;
`immap_submissions(poll_id, company_id, line, submitted_at, PK(poll_id, company_id))`;
`immap_pending_actions(nonce PK, poll_id, action, admin_email, expires_at)`. Meeting, canvas, email and
RSVP code is untouched.

## Trust model and limitations

- Bot operator: honest-but-curious at worst. It never holds a readable `y_i`, so it learns nothing about
  any company, even if it substitutes public keys. A database dump before `done` contains only ciphertext.
- Admins: any admin can open all sealed submissions and so sees every `y_i` (random-looking). Admin plus
  N−1 colluding companies break company *i*; a compromised bot **and** a colluding admin can also break a
  company by swapping keys. Admin keys should be kept offline-ish and fingerprints compared out of band.
- N < 10 allows educated guesses from the totals (IMMAP's limitation).
- The bot trusts the admin's totals and cannot detect a dishonest or mistaken aggregate; the poll's sealed
  lines remain available to other admins to double-check.
- The proof is a keyed hash, forgeable by whoever holds the bot's database (see above).
- Static keys are reused across polls (masks differ per `poll_id`). Leaking a company key exposes that
  company's past values only together with the admin's ability to open its lines. Rotation is
  re-running `keygen` and `/immap register` (the attributed company follows the new key); existing polls keep their snapshot.
- A company can submit a false number; nothing detects it (same as IMMAP). Resubmission while
  `collecting` is allowed.
- Company management is by admin Slack identity only (no key proof): it decides who may answer for a
  company, and the key fingerprints on the poll card and in `poll.json` let companies detect a wrong
  attribution. A company that is in a `created` or `collecting` poll before its deadline cannot be removed, and its key
  holder can neither leave nor rotate their key (the key is snapshotted there; a complete or overdue poll no
  longer needs it). Adding a member or removing another one is always allowed, so a company
  can add a colleague who must answer while a poll is open.
- An admin whose key was registered after a poll's creation cannot open or act on that poll.
- No dropout recovery: an `incomplete` poll is extended or replaced by a new poll without the missing
  company.
- Not in scope: signatures, range proofs, audit trail, Canvas integration, poll cancellation, rounding or
  public ranges, per-metric optional answers, quorum above one admin.

## Testing

Pure logic is tested without Slack; handlers are thin and covered through `PollService`, view builders,
the sweeper (with a fake client) and a registration test on a real Bolt app.

- `immap.py`: masks cancel for N = 3..12; totals equal plain sums; one submission never equals its value;
  order independence; every admin opens every line, outsiders cannot; tampering is detected; bad input,
  bad keys (incl. `0x` prefixes and underscores) rejected; proofs bind poll, action, argument, nonce and
  key; CLI round trips; stdlib-only import check.
- `polls.py` lifecycle: every transition and refusal; extension from each allowed state; incomplete →
  collecting keeps submissions; completion on the Nth line; visibility gate for every non-`done` state;
  non-admin refusal everywhere; Slack email alone insufficient; another admin's proof refused; proof
  covers the totals; nonces single-use, expiring, bound to poll, action and admin; reminder timing.
- Colleague notice: the right people are mentioned (not the submitter), single-member companies get none, non-members are refused; reminders mention every member.
- Company management: enrollment rules, add/remove, several members per company, key-holder succession, admin-only refusals, freezing of the key while a poll is open, companies without a member cannot join a poll, only members can submit; the `/immap` command paths and the attribute modal are driven through a capturing fake Bolt app.
- Review-focus cases: duplicate public keys, pasted code fences, polls before setup, long titles.
- `ruff check`, `pyright`, `pytest` stay green.

## Proposed changes back to PR #2

Replace the sequential relay (steps 2–8, Company 1, audit chain) with the pairwise-masking round and the
admin sealing above, and record the relay leak in the threat model. The metric table feedback from
review (VRAM, NVMe/SATA split, SSD total vs. intensity classes, racks, NICs, optics, 21"/OCP) stays an
open decision for the group; the bot takes whatever list is agreed as a new template version (the first template, `infra-footprint`, already includes these requests). Kept as a
local draft until you ask for it to be published.
