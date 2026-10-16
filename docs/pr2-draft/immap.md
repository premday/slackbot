---
title: Processs
layout: default
---

<!--
LOCAL DRAFT of content/our_numbers/immap.md for premday/usergroup PR #2.
Not published. Do not push or post anywhere unless asked.
Source design: docs/superpowers/specs/2026-10-16-immap-slack-design.md
-->

# Infrastructure Metrics Masked Aggregation Protocol (IMMAP)

> “Aggregated infrastructure metrics collected through pairwise masking, so that no organizer and no participant sees another company's value.”

## Purpose

IMMAP lets multiple companies add infrastructure-scale metrics into a shared aggregate without disclosing
individual values to the poll organizer or to other participants.

It stays lightweight: one Python file with no dependencies, one message per company, and no ordering
between participants. The reference implementation runs through the Premday Slack bot (`/immap`), but the
protocol does not depend on Slack.

> **Revision note (v2).** The first version relayed one running-total file from company to company.
> That leaks: the organizer sees every intermediate file, and `file[k] − file[k−1]` is exactly company
> *k*'s value, because the mask cancels in the difference. This version replaces the relay with pairwise
> masking (see [Why the relay was replaced](#why-the-relay-was-replaced)).

---

# Security Objectives

| Property | Goal |
|---|---|
| Confidentiality | Individual company metrics stay private from the organizer, the bot, other companies and Slack |
| Aggregation only | Only final totals are disclosed, and only after an admin validates them |
| Operational simplicity | Standard-library Python only, one command per role |
| Tamper visibility | A modified submission fails authentication when it is opened |
| Limited trust model | The organizer cannot compute totals alone, and cannot read any submission |

---

# Metrics Collected

Polls are created from a **template**: a fixed list of metrics and units, versioned. A poll keeps the
metrics of the template version it was created with, so a template can evolve without touching running
polls. The first template, `infra-footprint` (v1), is the original list amended with the review comments
on this page:

| Metric | Unit | Note |
|---|---|---|
| Datacenter room count | rooms | |
| Rack count | racks | racks are a better footprint indicator than hosts alone |
| Rack unit count | RU | racks vary in height, so RU are asked as well |
| Global power consumption | kW | |
| CDU count | units | |
| Host count | hosts | |
| OpenBMC host count | hosts | |
| 21" / OCP host count | hosts | |
| CPU core count | cores | |
| DIMM memory | TiB | |
| GPU card count | cards | |
| GPU VRAM | TiB | |
| Accelerator card count | cards | e.g. QAT |
| HDD (SATA) capacity | TiB | replaces the HDD total |
| SSD (SATA) capacity | TiB | replaces the three endurance classes |
| SSD (NVMe) capacity | TiB | NVMe has its own line |
| NIC count | cards | |
| Optics count | modules | |
| Fiber cable count | cables | |
| Copper cable count | cables | |
| PSU Silver count | units | |
| PSU Gold count | units | |
| PSU Platinum count | units | |

Still open for the group: whether SAS disks count with SATA of the same medium, whether other PSU levels
are wanted, and whether to keep the endurance classes. Any change is a new template version (or a new
template); nothing else in the protocol moves.

All metrics and units MUST be fixed before a poll starts. Values are non-negative integers (round up),
below 2^48. **Every company answers every metric**; `0` means "none", never "n/a". This guarantees that
each metric is answered by the same set of companies, and it is also what makes the masks cancel.

---

# Roles

## Poll Organizer

- Defines the poll: title, metrics, participating companies, deadline.
- Collects sealed submissions and reminds late companies.
- **Cannot read any submission**, individually or in total.

## Participating Companies

Each company is a named entry in a list kept by the admins. A Slack user enrolls with the public half of a
long-lived key pair (`immap.py keygen`); an admin then **attributes** the company to that user. The user
computes and submits **one** sealed line per poll for their company.

## Admins

A small group (a few people, any one suffices). Each admin holds a key pair too. Admins:

- can open the sealed submissions and compute the totals offline;
- validate the poll (**Mark done**), which is the only way totals become visible;
- extend a deadline;
- manage the list of companies and who answers for each.

The two admin actions that change what the group sees need proof of possession of the admin private key
on top of the Slack identity check.

---

# Core Principle

For participants `c_1 … c_N`, every pair `(i, j)` derives the same shared secret from their
Diffie-Hellman keys, and from it a per-metric mask:

```text
mask_ij(m) = SHAKE256("immap" | poll_id | m | s_ij)[:8]      (unsigned 64-bit)
```

Company *i* submits, for each metric *m*:

```text
y_i(m) = v_i(m) + Σ_{j>i} mask_ij(m) − Σ_{j<i} mask_ji(m)    (mod 2^64)
```

Summing over all companies, every mask appears once with `+` and once with `−`:

```text
Σ_i y_i(m) = Σ_i v_i(m)    (mod 2^64)
```

A single `y_i` is uniformly random to anyone who does not know the pair masks. Recovering company *i*'s
value needs **all other N−1 companies** to collude. There is no Company 1 holding a secret, no mask reveal,
no order and no relay.

---

# Operational Flow

## Step 1 — Setup (once)

- Each user runs `python immap.py keygen` and enrolls its **public** key (`/immap register <public_key>`).
- Each admin does the same with `/immap admin-register`, and maintains the list of companies:
  add or remove a company, then attribute it to an enrolled user. A company in a poll that is not finished
  cannot change, because its key is part of the poll.

Keys are reused across polls; masks differ per `poll_id`.

## Step 2 — Poll creation

The organizer defines the poll: title, template, participants and a **mandatory deadline** (end of day, organizer
timezone). Participant and admin public keys are **snapshotted** and published as `poll.json`:

```json
{
  "poll_id": "premday-2026-infra",
  "template": "infra-footprint",
  "schema_version": 1,
  "metrics": {"cpu_core_count": "cores", "dimm_memory": "TiB", "...": "..."},
  "participants": [{"id": 3, "public_key": "..."}, "..."],
  "admins": [{"public_key": "..."}],
  "bot_public_key": "...",
  "deadline": "2026-06-30"
}
```

Companies compare the key fingerprints in the card with their own, out of band if they care.

## Step 3 — Collection

Once started, every company runs, locally:

```text
python immap.py submit poll.json values.json
```

`values.json` holds one integer per metric of the template. The tool computes `y_i`, **seals it to every admin public key**
and prints one line, which the company pastes into the poll. Sealing means: a random key encrypts the
vector (SHAKE256 stream) and authenticates it (HMAC-SHA256); that key is wrapped for each admin through a
Diffie-Hellman exchange with a one-time ephemeral key.

The organizer therefore stores only ciphertext. Resubmitting before the deadline replaces the previous line.
The organizer reminds the companies that have not answered, every few hours or days (configurable,
minimum one hour), until the deadline.

## Step 4 — Completion and validation

Poll lifecycle:

```text
created ──start──▶ collecting ──all submitted──▶ complete ──admin validates──▶ done
                     │    ▲
        deadline     │    │  admin extends deadline
        passed,      ▼    │
        answers   incomplete
        missing
```

- If the deadline passes with answers missing, the poll is **incomplete**: partial sums are meaningless
  because the masks no longer cancel. An admin extends the deadline (the poll returns to *collecting* and
  keeps the existing submissions), or a new poll is run.
- When all N sealed lines are in, the poll is **complete**. An admin takes the lines offline and runs:

```text
python immap.py aggregate poll.json lines.txt --nonce <nonce issued by the organizer>
```

  which opens every line with the admin key, sums them, and prints `{"totals": …, "proof": …}`.
- The admin pastes that output back. The organizer checks the proof, stores the totals and marks the
  poll **done**. Totals are readable only from this point.

## Step 5 — Publication

The organizer publishes only aggregated totals. No individual contribution is ever disclosed.

| Metric | Aggregate |
|---|---|
| CPU cores | 12,482,771 |
| DIMM memory | 918,221 TiB |
| GPUs | 48,172 |
| HDD capacity | 28.4 EiB |

---

# Why the relay was replaced

In version 1 the organizer relayed a running-total file, Company 1 held a secret mask and revealed it at
the end. The organizer saw `file[k]` and `file[k−1]` for every *k*, so it could compute each company's
value by subtraction, with no collusion at all. The threat model claimed "organizer seeing raw company data:
prevented", which was not true. Further costs of the relay: strictly sequential (one slow company blocks
everyone), a special Company 1 that must be trusted not to reveal early, and an audit hash chain that
detects accidents but not subtraction.

Pairwise masking fixes the leak and is simpler to run: one round, in parallel, one submission per company.
The SHA-256 audit trail is dropped; tampering is caught by the authentication on each sealed line, and
the organizer is no longer in the position to tamper unseen.

---

# Threat Model & Limitations

## Mitigated Risks

| Risk | Mitigation |
|---|---|
| Organizer or bot reading a company's value | Not possible: it holds only sealed lines, and each `y_i` is random on its own |
| Subtraction of consecutive files (v1 relay leak) | No intermediate totals exist |
| A participant learning another's value | Needs all other N−1 participants to collude |
| Totals read before validation | Not possible: lines are sealed to admin keys, and no read path exists until *done* |
| Accidental tampering | Detected when a sealed line is opened |
| A non-admin extending a poll or marking it done | Requires an admin Slack identity **and** proof of the admin private key |

## Remaining Limitations

- **Admin collusion.** Any admin can open all sealed lines and sees every `y_i` (random-looking). An admin
  plus N−1 colluding companies break company *i*. A compromised organizer **and** a colluding admin can
  also break a company by substituting public keys, so compare key fingerprints out of band. Keep admin
  keys offline-ish.
- **Admin is trusted for the totals.** The organizer cannot verify that the pasted totals are the true
  sums. The sealed lines stay available to the other admins to double-check.
- **The admin proof is a keyed hash, not a signature** (the standard library has none). Whoever controls the
  organizer's database could forge a tag, but still cannot read submissions.
- **Small pools.** With fewer than about 10 companies, totals allow educated guesses. The reference
  implementation requires at least 3 and warns below 10.
- **False numbers.** Nothing detects a company submitting a wrong value (as in v1).
- **Extreme outliers.** Unusually large footprints may be identifiable indirectly from the totals.
- **No dropout recovery.** A company that does not answer makes the poll incomplete; extend it or run a new
  poll without that company.
- **Static keys.** Keys are reused across polls; masks differ per `poll_id`. Rotation means running
  `keygen` and registering again; existing polls keep their snapshot.

---

# Recommended Operational Practices

| Practice | Recommendation |
|---|---|
| Minimum participants | ≥ 10 |
| Minimum metric granularity | Large-scale only |
| No per-region splits | Avoid deanonymization |
| Use ranges publicly | Optional |
| Fixed deadlines | Mandatory |
| Fingerprint check out of band | Yes, for companies and admins |
| Independent audit | Optional (a second admin recomputes the totals) |

---

# Optional Hardening

Possible later work: real signatures for the admin proof, range proofs on submitted values, per-metric
optional answers, a quorum above one admin, dropout recovery with secret sharing, and a name that cannot be
confused with IMAP.
