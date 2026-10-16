# IMMAP over Slack Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Premday companies compute aggregate infrastructure metrics through the Slack bot so that nobody (bot, other companies) sees individual values and totals are only readable after an admin validates them.

**Architecture:** A stdlib-only protocol module (`immap.py`: pairwise masking, sealing to an admin key group, admin proofs, participant/admin CLI), a Slack-free rules layer (`polls.py`: SQLite store + `PollService` with the poll lifecycle), and thin Slack layers (`immap_views.py`, `immap_slack.py`) wired into the existing `app.py`.

**Tech Stack:** Python 3.12+, slack-bolt (async, Socket Mode), SQLite, pytest, ruff, pyright, uv.

**Spec:** `docs/superpowers/specs/2026-10-16-immap-slack-design.md`

## Global Constraints

- Python `>=3.12`; ruff line length 100 with rule sets `E,F,I,UP,B,SIM,RUF`; pyright `standard`. Match the existing code style (no formatter is configured; keep lines ≤ 100).
- `src/premday_bot/immap.py` imports **only the standard library** and nothing from `premday_bot` (participants run it standalone). A test enforces it.
- No new dependencies and no new Slack OAuth scopes.
- **Never push to GitHub, open or comment on PRs, or write to any remote.** Commits stay local.
- Every commit message ends with the line `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (the commands below pass it as a second `-m`).
- Group: RFC 3526 group 14 (2048-bit MODP, `g = 2`); private exponents 256 random bits; masks and sums are mod `2^64`; values are integers `0 <= v < 2^48`.
- Poll templates: a poll is created from a template, a fixed ordered list of metrics (`immap.POLL_TEMPLATES`, default `immap.DEFAULT_TEMPLATE`). The poll stores a snapshot of the template's metrics and version, so later template edits never change an existing poll. The first template, `infra-footprint` v1, has 23 metrics: the 12 of the PR (SSD split by technology instead of endurance class) plus what the reviewers of PR #2 asked for (GPU VRAM, racks and rack units, NICs, accelerators, PSU levels, optics, cabling, 21"/OCP servers).
- Poll rules: at least 3 companies (the card warns below 10); mandatory future deadline = end of day in `PREMDAY_TIMEZONE`; at most 5 admin keys; titles at most 150 characters; nonces single-use, 15 minutes.
- Statuses are exactly `created`, `collecting`, `complete`, `incomplete`, `done`.
- Admin = Slack profile email in `IMMAP_ADMIN_EMAILS` (comma-separated, case-insensitive); any one admin suffices. Test fixtures: Aurélien Rougemont (Criteo) `a.rougemont@criteo.com`, a second admin, a non-admin.
- Totals must not exist in the bot (database or memory) before a poll is `done`.
- Baseline: `uv run ruff check .` reports exactly three pre-existing `E501` errors in `src/premday_bot/templates.py` (lines 75, 78, 84). Leave them alone; there must be no other errors. Run all commands from the repository root. The suite must stay green after every task.

## Review Focus

Inputs and conditions the spec implies but does not spell out. Each has a test in the task that owns the code.

1. **Two users enrolling the same public key** — `submit` would seal as whichever company matches first. Expected: the second enrollment is refused with a clear message. Test `test_two_users_cannot_share_a_public_key` (Task 2).
2. **Values pasted from a Slack code block** (backticks or ``` fences around a line, a proof, or the aggregate JSON). Expected: accepted and stored clean. Tests `test_unfence_strips_slack_code_markup` (Task 2), `test_a_submission_pasted_from_a_slack_code_block_is_accepted` (Task 3), `test_a_proof_and_totals_pasted_with_code_fences_are_accepted` (Task 4).
3. **`/immap poll` before setup is complete** (fewer than 3 companies with a member, or no admin key). Expected: a plain message instead of a Slack API failure on an empty option list. Test `test_polls_cannot_start_before_enough_companies_and_an_admin_key_exist` (Task 2).
4. **Sloppy hexadecimal in public keys** (`0x` prefix, underscores, signs, spaces; Python's `int(x, 16)` accepts several). Expected: refused. Tests `test_public_key_validation` (Task 1) and `test_pasted_keys_may_carry_backticks_but_not_hex_prefixes` (Task 2).
5. **Very long poll titles** (Slack block text limits). Expected: refused above 150 characters, and the modal input is limited too. Test `test_titles_are_limited_in_length` (Task 2).

## File Structure

| File | Responsibility |
|---|---|
| `src/premday_bot/immap.py` (new) | Protocol: poll templates, keys, masking, sealing, proofs, `submit`, `aggregate_sealed`, CLI |
| `src/premday_bot/polls.py` (new) | `PollStore` (SQLite) and `PollService` (all rules, no Slack) |
| `src/premday_bot/immap_views.py` (new) | Modals, poll card, `poll.json` message, report text, chunking |
| `src/premday_bot/immap_slack.py` (new) | `/immap` command, view/button handlers, sweeper |
| `src/premday_bot/config.py`, `app.py` | `IMMAP_REMINDER_HOURS`, `IMMAP_ADMIN_EMAILS`; wiring and sweeper start |
| `slack/app-manifest.yaml`, `README.md`, `.env.example` | Command registration and docs |
| `tests/helpers.py` (new) | Clock, fixtures (`make_world`), admin fixture Aurélien Rougemont |
| `tests/test_immap.py`, `test_polls_setup.py`, `test_polls_collecting.py`, `test_polls_admin.py`, `test_immap_views.py`, `test_config.py`, `test_immap_slack.py`, `test_app_wiring.py` (new) | One per concern |

---
### Task 1: Protocol module `immap.py`

**Files:**
- Create: `src/premday_bot/immap.py`
- Test: `tests/test_immap.py`

**Interfaces:**
- Consumes: nothing (standard library only).
- Produces (used by every later task):
  - constants `PROTOCOL: str`, `MODULUS: int`, `MAX_VALUE: int`, `PollTemplate` (frozen dataclass: `id, title, version, description, metrics: dict[str, str]`), `POLL_TEMPLATES: dict[str, PollTemplate]`, `DEFAULT_TEMPLATE: str`
  - `metric_ids(metrics) -> list[str]`, `generate_private_key() -> int`, `public_key(private_key: int) -> str` (lowercase hex), `parse_public_key(value: str) -> int` (raises `ValueError`), `fingerprint(public_key_hex: str) -> str`, `fingerprints(poll: dict) -> dict[str, str]`
  - `seal(plaintext: bytes, admins: list[dict]) -> dict`, `unseal(envelope: dict, private_key: int) -> bytes`
  - `submit(poll: dict, private_key: int, values: dict[str, Any]) -> str` (returns `immap2.<poll_id>.<company_id>.<base64url envelope>`)
  - `parse_line(line: str) -> tuple[str, str, dict]`, `check_envelope(envelope: dict, metric_count: int, admin_fingerprints: set[str]) -> None`, `open_line(line, private_key) -> tuple[str, str, list[int]]`
  - `aggregate(metrics, submissions) -> dict[str, int]`, `aggregate_sealed(poll: dict, lines: list[str], private_key: int, nonce: str) -> dict` (`{"totals", "proof"}`)
  - `totals_digest(totals) -> str`, `make_proof(private_key, poll, action, argument, nonce) -> str`, `check_proof(bot_private_key, admin_public_key, *, poll_id, action, argument, nonce, proof) -> bool`
  - `main(argv=None) -> int` with subcommands `keygen`, `submit`, `aggregate`, `proof`
  - The `poll` dict ("poll.json") has keys `poll_id`, `template`, `schema_version`, `metrics`, `participants` (`[{company_id, public_key}]`), `admins` (`[{admin_id, public_key}]`), `bot_public_key`, `deadline`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_immap.py`:

````python
import ast
import json
import random
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from premday_bot import immap

TEMPLATE_METRICS = immap.POLL_TEMPLATES[immap.DEFAULT_TEMPLATE].metrics


def make_poll(count: int, admin_count: int = 2):
    company_keys = {f"co-{i:02d}": immap.generate_private_key() for i in range(count)}
    admin_keys = [immap.generate_private_key() for _ in range(admin_count)]
    bot_key = immap.generate_private_key()
    poll = {
        "poll_id": "poll1",
        "schema_version": 1,
        "metrics": dict(TEMPLATE_METRICS),
        "participants": [
            {"company_id": c, "public_key": immap.public_key(k)} for c, k in company_keys.items()
        ],
        "admins": [
            {"admin_id": f"admin{i}", "public_key": immap.public_key(k)}
            for i, k in enumerate(admin_keys)
        ],
        "bot_public_key": immap.public_key(bot_key),
    }
    return poll, company_keys, admin_keys, bot_key


def random_values(rng: random.Random) -> dict[str, int]:
    return {name: rng.randrange(10**6) for name in TEMPLATE_METRICS}


def test_group_prime_is_a_safe_prime() -> None:
    prime = immap._P
    assert prime.bit_length() == 2048
    assert pow(2, prime - 1, prime) == 1
    half = (prime - 1) // 2
    assert pow(2, half - 1, half) == 1


@pytest.mark.parametrize("count", [3, 7, 12])
def test_masks_cancel_and_totals_equal_the_plain_sum(count: int) -> None:
    rng = random.Random(count)
    poll, company_keys, admin_keys, _ = make_poll(count)
    values = {c: random_values(rng) for c in company_keys}
    lines = [immap.submit(poll, key, values[c]) for c, key in company_keys.items()]
    result = immap.aggregate_sealed(poll, lines, admin_keys[0], "nonce1")
    expected = {n: sum(v[n] for v in values.values()) for n in TEMPLATE_METRICS}
    assert result["totals"] == expected


def test_every_admin_can_open_the_submissions() -> None:
    poll, company_keys, admin_keys, _ = make_poll(3)
    values = random_values(random.Random(1))
    lines = [immap.submit(poll, key, values) for key in company_keys.values()]
    first = immap.aggregate_sealed(poll, lines, admin_keys[0], "n")["totals"]
    second = immap.aggregate_sealed(poll, lines, admin_keys[1], "n")["totals"]
    assert first == second


def test_a_single_submission_does_not_reveal_the_value() -> None:
    poll, company_keys, admin_keys, _ = make_poll(4)
    key = next(iter(company_keys.values()))
    values = {name: 5 for name in TEMPLATE_METRICS}
    _, _, numbers = immap.open_line(immap.submit(poll, key, values), admin_keys[0])
    assert all(number != 5 for number in numbers)


def test_participant_order_does_not_change_the_result() -> None:
    poll, company_keys, admin_keys, _ = make_poll(4)
    values = {c: random_values(random.Random(i)) for i, c in enumerate(company_keys)}
    shuffled = {**poll, "participants": list(reversed(poll["participants"]))}
    lines = [immap.submit(shuffled, key, values[c]) for c, key in company_keys.items()]
    totals = immap.aggregate_sealed(poll, lines, admin_keys[0], "n")["totals"]
    assert totals == {n: sum(v[n] for v in values.values()) for n in TEMPLATE_METRICS}


def test_non_admin_cannot_open_a_submission() -> None:
    poll, company_keys, _, _ = make_poll(3)
    line = immap.submit(poll, next(iter(company_keys.values())), random_values(random.Random(0)))
    with pytest.raises(ValueError, match="not sealed to your key"):
        immap.open_line(line, immap.generate_private_key())


def test_tampered_submission_fails_its_integrity_check() -> None:
    poll, company_keys, admin_keys, _ = make_poll(3)
    line = immap.submit(poll, next(iter(company_keys.values())), random_values(random.Random(0)))
    poll_id, company_id, envelope = immap.parse_line(line)
    envelope["ct"] = ("00" if envelope["ct"][:2] != "00" else "01") + envelope["ct"][2:]
    import base64

    encoded = base64.urlsafe_b64encode(json.dumps(envelope).encode()).decode().rstrip("=")
    with pytest.raises(ValueError, match="integrity"):
        immap.open_line(f"immap2.{poll_id}.{company_id}.{encoded}", admin_keys[0])


def test_submit_rejects_bad_input() -> None:
    poll, company_keys, _, _ = make_poll(3)
    key = next(iter(company_keys.values()))
    good: dict[str, Any] = {name: 1 for name in TEMPLATE_METRICS}
    with pytest.raises(ValueError, match="missing"):
        immap.submit(poll, key, {k: v for k, v in good.items() if k != "host_count"})
    with pytest.raises(ValueError, match="extra"):
        immap.submit(poll, key, {**good, "racks": 3})
    with pytest.raises(ValueError, match="between"):
        immap.submit(poll, key, {**good, "host_count": -1})
    with pytest.raises(ValueError, match="between"):
        immap.submit(poll, key, {**good, "host_count": immap.MAX_VALUE})
    with pytest.raises(ValueError, match="integer"):
        immap.submit(poll, key, {**good, "host_count": 1.5})
    with pytest.raises(ValueError, match="integer"):
        immap.submit(poll, key, {**good, "host_count": True})
    with pytest.raises(ValueError, match="not in this poll"):
        immap.submit(poll, immap.generate_private_key(), good)
    with pytest.raises(ValueError, match="no admin keys"):
        immap.submit({**poll, "admins": []}, key, good)


def test_public_key_validation() -> None:
    sloppy = ("0x" + format(5, "x"), "1_0", "", "  ", "+5", "-5", "5 5")
    for bad in ("zz", "0", "1", format(immap._P - 1, "x"), format(immap._P, "x"), *sloppy):
        with pytest.raises(ValueError):
            immap.parse_public_key(bad)
    assert immap.parse_public_key(immap.public_key(immap.generate_private_key())) > 2


def test_parse_line_rejects_garbage() -> None:
    for bad in ("", "nope", "immap1.a.b.00", "immap2.a.b", "immap2.a.b.!!!", "immap2.a.b.AAAA"):
        with pytest.raises(ValueError):
            immap.parse_line(bad)


def test_check_envelope_accepts_good_and_rejects_bad() -> None:
    poll, company_keys, _, _ = make_poll(3)
    line = immap.submit(poll, next(iter(company_keys.values())), random_values(random.Random(0)))
    _, _, envelope = immap.parse_line(line)
    fingerprints = {immap.fingerprint(a["public_key"]) for a in poll["admins"]}
    immap.check_envelope(envelope, len(TEMPLATE_METRICS), fingerprints)
    with pytest.raises(ValueError, match="number of values"):
        immap.check_envelope(envelope, 3, fingerprints)
    with pytest.raises(ValueError, match="admin keys"):
        immap.check_envelope(envelope, len(TEMPLATE_METRICS), set())
    with pytest.raises(ValueError, match="malformed"):
        immap.check_envelope({}, len(TEMPLATE_METRICS), fingerprints)


def test_aggregate_requires_every_participant_exactly_once() -> None:
    poll, company_keys, admin_keys, _ = make_poll(3)
    lines = [immap.submit(poll, k, random_values(random.Random(0))) for k in company_keys.values()]
    with pytest.raises(ValueError, match="missing"):
        immap.aggregate_sealed(poll, lines[:2], admin_keys[0], "n")
    with pytest.raises(ValueError, match="duplicate"):
        immap.aggregate_sealed(poll, [lines[0], lines[0], *lines], admin_keys[0], "n")
    other = {**poll, "poll_id": "other"}
    with pytest.raises(ValueError, match="another poll"):
        immap.aggregate_sealed(other, lines, admin_keys[0], "n")


def test_proofs_bind_poll_action_argument_nonce_and_key() -> None:
    poll, _, admin_keys, bot_key = make_poll(3)
    proof = immap.make_proof(admin_keys[0], poll, "extend", "2026-12-01", "n1")
    kwargs = {"poll_id": "poll1", "action": "extend", "argument": "2026-12-01", "nonce": "n1"}
    admin_public = immap.public_key(admin_keys[0])
    assert immap.check_proof(bot_key, admin_public, proof=proof, **kwargs)
    for field, value in (
        ("poll_id", "x"),
        ("action", "done"),
        ("argument", "2026-12-02"),
        ("nonce", "n2"),
    ):
        assert not immap.check_proof(bot_key, admin_public, proof=proof, **{**kwargs, field: value})
    other_admin = immap.public_key(admin_keys[1])
    assert not immap.check_proof(bot_key, other_admin, proof=proof, **kwargs)


def test_cli_round_trip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    poll, _, _, _ = make_poll(3)
    admin_key_path = tmp_path / "admin.key"
    company_key_path = tmp_path / "immap.key"
    assert immap.main(["keygen", "--key", str(admin_key_path)]) == 0
    assert immap.main(["keygen", "--key", str(company_key_path)]) == 0
    assert immap.main(["keygen", "--key", str(company_key_path)]) == 1  # no overwrite
    assert oct(company_key_path.stat().st_mode & 0o777) == "0o600"
    out = capsys.readouterr().out
    public_keys = [line.split(": ")[1] for line in out.splitlines() if line.startswith("public")]
    own_company = {"company_id": "me", "public_key": public_keys[1]}
    poll["participants"].append(own_company)
    poll["admins"] = [{"admin_id": "me-admin", "public_key": public_keys[0]}]
    (tmp_path / "poll.json").write_text(json.dumps(poll))
    (tmp_path / "values.json").write_text(json.dumps({n: 2 for n in TEMPLATE_METRICS}))
    capsys.readouterr()
    assert (
        immap.main(
            [
                "submit",
                str(tmp_path / "poll.json"),
                str(tmp_path / "values.json"),
                "--key",
                str(company_key_path),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert "me:" in captured.err
    poll_id, company_id, envelope = immap.parse_line(captured.out.strip())
    assert (poll_id, company_id) == ("poll1", "me")
    assert set(envelope) == {"eph", "ct", "mac", "wraps"}


def test_cli_aggregate_and_proof(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    poll, company_keys, admin_keys, bot_key = make_poll(3, admin_count=1)
    (tmp_path / "poll.json").write_text(json.dumps(poll))
    lines = [immap.submit(poll, k, {n: 1 for n in TEMPLATE_METRICS}) for k in company_keys.values()]
    (tmp_path / "lines.txt").write_text("\n".join(lines) + "\n")
    (tmp_path / "admin.key").write_text(format(admin_keys[0], "x") + "\n")
    base = [str(tmp_path / "poll.json")]
    assert (
        immap.main(
            [
                "aggregate",
                *base,
                str(tmp_path / "lines.txt"),
                "--nonce",
                "n9",
                "--key",
                str(tmp_path / "admin.key"),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert set(result["totals"].values()) == {3}
    assert immap.check_proof(
        bot_key,
        immap.public_key(admin_keys[0]),
        poll_id="poll1",
        action="done",
        argument=immap.totals_digest(result["totals"]),
        nonce="n9",
        proof=result["proof"],
    )
    assert (
        immap.main(
            [
                "proof",
                *base,
                "--action",
                "extend",
                "--argument",
                "2026-12-01",
                "--nonce",
                "n9",
                "--key",
                str(tmp_path / "admin.key"),
            ]
        )
        == 0
    )
    assert immap.check_proof(
        bot_key,
        immap.public_key(admin_keys[0]),
        poll_id="poll1",
        action="extend",
        argument="2026-12-01",
        nonce="n9",
        proof=capsys.readouterr().out.strip(),
    )
    assert immap.main(["aggregate", *base, str(tmp_path / "missing.txt"), "--nonce", "n"]) == 1


def test_module_uses_only_the_standard_library() -> None:
    source = (Path(__file__).parent.parent / "src" / "premday_bot" / "immap.py").read_text()
    imported = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= set(sys.stdlib_module_names)


def test_templates_are_well_formed() -> None:
    assert immap.DEFAULT_TEMPLATE in immap.POLL_TEMPLATES
    for key, template in immap.POLL_TEMPLATES.items():
        assert template.id == key and template.version >= 1 and template.title
        assert template.metrics and len(template.metrics) <= 64
        for metric, unit in template.metrics.items():
            assert re.fullmatch(r"[a-z][a-z0-9_]*", metric) and unit


def test_infra_footprint_covers_the_pr_and_its_review() -> None:
    metrics = immap.POLL_TEMPLATES["infra-footprint"].metrics
    original = {
        "cpu_core_count",
        "dimm_memory",
        "gpu_card_count",
        "cdu_count",
        "openbmc_host_count",
        "host_count",
        "global_power_consumption",
        "datacenter_room_count",
    }
    review = {
        "gpu_vram",  # GPUs need VRAM too
        "rack_count",
        "rack_unit_count",  # racks, with RU because rack height varies
        "hdd_sata_capacity",
        "ssd_sata_capacity",
        "ssd_nvme_capacity",  # disks by technology
        "nic_count",
        "accelerator_card_count",
        "optics_count",
        "fiber_cable_count",
        "copper_cable_count",
        "psu_silver_count",
        "psu_gold_count",
        "psu_platinum_count",
        "ocp_21in_host_count",
    }
    assert original | review == set(metrics)
    assert not {m for m in metrics if "read_intensive" in m or "write_intensive" in m}
    assert metrics["gpu_vram"] == "TiB" and metrics["rack_unit_count"] == "RU"


def test_sealed_line_with_the_largest_template_and_five_admins_fits_a_modal_field() -> None:
    metrics = immap.POLL_TEMPLATES["infra-footprint"].metrics
    company = immap.generate_private_key()
    others = [immap.generate_private_key() for _ in range(2)]
    poll = {
        "poll_id": "abc123abc123",
        "schema_version": 1,
        "metrics": metrics,
        "participants": [
            {"company_id": f"c{i}", "public_key": immap.public_key(key)}
            for i, key in enumerate([company, *others])
        ],
        "admins": [
            {"admin_id": f"a{i}", "public_key": immap.public_key(immap.generate_private_key())}
            for i in range(5)
        ],
        "bot_public_key": immap.public_key(immap.generate_private_key()),
        "deadline": "2026-12-01",
    }
    assert len(immap.submit(poll, company, dict.fromkeys(metrics, 1))) < 3000
````

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_immap.py`
Expected: collection error `ImportError: cannot import name 'immap' from 'premday_bot'`.

- [ ] **Step 3: Write the implementation**

Create `src/premday_bot/immap.py` (this file was checked in a prototype: group-14 prime is a safe prime, all tests below pass):

````python
"""IMMAP pairwise-masking protocol.

Standard library only: participants run this file directly (``python immap.py --help``).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROTOCOL = "immap2"
MODULUS = 1 << 64
MAX_VALUE = 1 << 48


@dataclass(frozen=True)
class PollTemplate:
    """A fixed list of metrics a poll asks every company; ``version`` changes with the list."""

    id: str
    title: str
    version: int
    description: str
    metrics: dict[str, str]  # metric id -> unit


# Metrics of the original IMMAP proposal (premday/usergroup PR #2), amended with what the
# reviewers of that PR asked for: GPU VRAM, racks (with rack units, since racks vary in height),
# disks split by technology instead of endurance class, NICs, accelerators, PSU levels, optics,
# cabling and 21"/OCP servers.
INFRA_FOOTPRINT = PollTemplate(
    id="infra-footprint",
    title="Infrastructure footprint",
    version=1,
    description=(
        "Fleet size, compute, memory, storage, network and power. Count what you run in "
        "production, round capacities up to whole TiB, and answer 0 for \"none\"."
    ),
    metrics={
        "datacenter_room_count": "rooms",
        "rack_count": "racks",
        "rack_unit_count": "RU",
        "global_power_consumption": "kW",
        "cdu_count": "units",
        "host_count": "hosts",
        "openbmc_host_count": "hosts",
        "ocp_21in_host_count": "hosts",
        "cpu_core_count": "cores",
        "dimm_memory": "TiB",
        "gpu_card_count": "cards",
        "gpu_vram": "TiB",
        "accelerator_card_count": "cards",
        "hdd_sata_capacity": "TiB",
        "ssd_sata_capacity": "TiB",
        "ssd_nvme_capacity": "TiB",
        "nic_count": "cards",
        "optics_count": "modules",
        "fiber_cable_count": "cables",
        "copper_cable_count": "cables",
        "psu_silver_count": "units",
        "psu_gold_count": "units",
        "psu_platinum_count": "units",
    },
)

POLL_TEMPLATES: dict[str, PollTemplate] = {INFRA_FOOTPRINT.id: INFRA_FOOTPRINT}
DEFAULT_TEMPLATE = INFRA_FOOTPRINT.id

# RFC 3526 group 14 (2048-bit MODP), generator 2.
_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_G = 2
_KEY_BYTES = 256


def metric_ids(metrics: dict[str, str]) -> list[str]:
    return sorted(metrics)


def generate_private_key() -> int:
    return secrets.randbits(256) + 2


def public_key(private_key: int) -> str:
    return format(pow(_G, private_key, _P), "x")


def parse_public_key(value: str) -> int:
    text = value.strip()
    if not text or any(char not in "0123456789abcdefABCDEF" for char in text):
        raise ValueError("public key is not hexadecimal")
    key = int(text, 16)
    if not 2 <= key <= _P - 2:
        raise ValueError("public key is out of range")
    return key


def fingerprint(public_key_hex: str) -> str:
    digest = hashlib.sha256(parse_public_key(public_key_hex).to_bytes(_KEY_BYTES, "big"))
    short = digest.hexdigest()[:16]
    return "-".join(short[i : i + 4] for i in range(0, 16, 4))


def _mask(secret: bytes, poll_id: str, metric: str) -> int:
    material = b"|".join([PROTOCOL.encode(), poll_id.encode(), metric.encode(), secret])
    return int.from_bytes(hashlib.shake_256(material).digest(8), "big")


def _shared_secret(private_key: int, peer_public_key_hex: str) -> bytes:
    peer = parse_public_key(peer_public_key_hex)
    return pow(peer, private_key, _P).to_bytes(_KEY_BYTES, "big")


def _check_values(metrics: dict[str, str], values: dict[str, Any]) -> None:
    missing = set(metrics) - set(values)
    extra = set(values) - set(metrics)
    if missing or extra:
        raise ValueError(
            "values must match the poll metrics "
            f"(missing: {sorted(missing)}, extra: {sorted(extra)})"
        )
    for name, value in values.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
        if not 0 <= value < MAX_VALUE:
            raise ValueError(f"{name} must be between 0 and {MAX_VALUE - 1}")


def find_company(poll: dict, private_key: int) -> str:
    own = parse_public_key(public_key(private_key))
    for participant in poll["participants"]:
        if parse_public_key(participant["public_key"]) == own:
            return participant["company_id"]
    raise ValueError("your public key is not in this poll")


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _stream(key: bytes, label: bytes, length: int) -> bytes:
    return hashlib.shake_256(b"|".join([PROTOCOL.encode(), label, key])).digest(length)


def seal(plaintext: bytes, admins: list[dict]) -> dict:
    """Encrypt ``plaintext`` so that any one of ``admins`` (``{"public_key": hex}``) can open it."""
    if not admins:
        raise ValueError("the poll has no admin keys")
    key = secrets.token_bytes(32)
    ephemeral = generate_private_key()
    ciphertext = _xor(plaintext, _stream(key, b"enc", len(plaintext)))
    wraps = {}
    for admin in admins:
        secret = _shared_secret(ephemeral, admin["public_key"])
        wraps[fingerprint(admin["public_key"])] = _xor(key, _stream(secret, b"wrap", 32)).hex()
    return {
        "eph": public_key(ephemeral),
        "ct": ciphertext.hex(),
        "mac": hmac.new(key, ciphertext, hashlib.sha256).hexdigest(),
        "wraps": wraps,
    }


def unseal(envelope: dict, private_key: int) -> bytes:
    own = fingerprint(public_key(private_key))
    try:
        wrapped = bytes.fromhex(envelope["wraps"][own])
    except KeyError as error:
        raise ValueError("this envelope is not sealed to your key") from error
    secret = _shared_secret(private_key, envelope["eph"])
    key = _xor(wrapped, _stream(secret, b"wrap", 32))
    ciphertext = bytes.fromhex(envelope["ct"])
    expected = hmac.new(key, ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, envelope["mac"]):
        raise ValueError("the envelope failed its integrity check")
    return _xor(ciphertext, _stream(key, b"enc", len(ciphertext)))


def submit(poll: dict, private_key: int, values: dict[str, Any]) -> str:
    """Return the one-line sealed submission for ``poll``; the company is found from the key."""
    metrics = poll["metrics"]
    _check_values(metrics, values)
    company_id = find_company(poll, private_key)
    ids = metric_ids(metrics)
    masked = {name: values[name] for name in ids}
    for other in poll["participants"]:
        other_id = other["company_id"]
        if other_id == company_id:
            continue
        secret = _shared_secret(private_key, other["public_key"])
        sign = 1 if company_id < other_id else -1
        for name in ids:
            masked[name] += sign * _mask(secret, poll["poll_id"], name)
    payload = b"".join((masked[name] % MODULUS).to_bytes(8, "big") for name in ids)
    envelope = seal(payload, poll["admins"])
    encoded = base64.urlsafe_b64encode(json.dumps(envelope, separators=(",", ":")).encode())
    return f"{PROTOCOL}.{poll['poll_id']}.{company_id}.{encoded.decode().rstrip('=')}"


def parse_line(line: str) -> tuple[str, str, dict]:
    parts = line.strip().split(".")
    if len(parts) != 4 or parts[0] != PROTOCOL:
        raise ValueError(f"this is not an {PROTOCOL} submission line")
    try:
        raw = base64.urlsafe_b64decode(parts[3] + "=" * (-len(parts[3]) % 4))
        envelope = json.loads(raw)
    except ValueError as error:
        raise ValueError("the submission payload is not valid") from error
    if not isinstance(envelope, dict):
        raise ValueError("the submission payload is not valid")
    return parts[1], parts[2], envelope


def check_envelope(envelope: dict, metric_count: int, admin_fingerprints: set[str]) -> None:
    """Structural checks the bot can do without being able to read the payload."""
    try:
        parse_public_key(envelope["eph"])
        if len(bytes.fromhex(envelope["ct"])) != 8 * metric_count:
            raise ValueError("the submission has the wrong number of values")
        if len(bytes.fromhex(envelope["mac"])) != 32:
            raise ValueError("the submission integrity tag is invalid")
        wraps = envelope["wraps"]
        if set(wraps) != admin_fingerprints or any(
            len(bytes.fromhex(item)) != 32 for item in wraps.values()
        ):
            raise ValueError("the submission is not sealed to this poll's admin keys")
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("the submission payload is malformed") from error


def open_line(line: str, private_key: int) -> tuple[str, str, list[int]]:
    poll_id, company_id, envelope = parse_line(line)
    payload = unseal(envelope, private_key)
    numbers = [int.from_bytes(payload[i : i + 8], "big") for i in range(0, len(payload), 8)]
    return poll_id, company_id, numbers


def totals_digest(totals: dict[str, int]) -> str:
    canonical = json.dumps(totals, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _proof_tag(secret: bytes, poll_id: str, action: str, argument: str, nonce: str) -> str:
    message = "|".join([poll_id, action, argument, nonce]).encode()
    return hmac.new(_stream(secret, b"proof", 32), message, hashlib.sha256).hexdigest()


def make_proof(private_key: int, poll: dict, action: str, argument: str, nonce: str) -> str:
    secret = _shared_secret(private_key, poll["bot_public_key"])
    return _proof_tag(secret, poll["poll_id"], action, argument, nonce)


def check_proof(
    bot_private_key: int,
    admin_public_key: str,
    *,
    poll_id: str,
    action: str,
    argument: str,
    nonce: str,
    proof: str,
) -> bool:
    secret = _shared_secret(bot_private_key, admin_public_key)
    return hmac.compare_digest(_proof_tag(secret, poll_id, action, argument, nonce), proof)


def aggregate_sealed(poll: dict, lines: list[str], private_key: int, nonce: str) -> dict:
    """Admin side: open every sealed line, sum, and prove the result with the admin key."""
    rows: dict[str, list[int]] = {}
    for line in lines:
        poll_id, company_id, numbers = open_line(line, private_key)
        if poll_id != poll["poll_id"]:
            raise ValueError(f"a line belongs to another poll ({poll_id})")
        if company_id in rows:
            raise ValueError(f"duplicate line for {company_id}")
        if len(numbers) != len(poll["metrics"]):
            raise ValueError(f"wrong number of values for {company_id}")
        rows[company_id] = numbers
    expected = {p["company_id"] for p in poll["participants"]}
    if set(rows) != expected:
        missing = sorted(expected - set(rows))
        raise ValueError(f"lines do not cover the participants (missing: {missing})")
    totals = aggregate(poll["metrics"], list(rows.values()))
    proof = make_proof(private_key, poll, "done", totals_digest(totals), nonce)
    return {"totals": totals, "proof": proof}


def aggregate(metrics: dict[str, str], submissions: list[list[int]]) -> dict[str, int]:
    ids = metric_ids(metrics)
    return {
        name: sum(row[index] for row in submissions) % MODULUS for index, name in enumerate(ids)
    }


def fingerprints(poll: dict) -> dict[str, str]:
    return {p["company_id"]: fingerprint(p["public_key"]) for p in poll["participants"]}


def _keygen(key_path: Path) -> int:
    if key_path.exists():
        print(f"{key_path} already exists; refusing to overwrite it", file=sys.stderr)
        return 1
    private_key = generate_private_key()
    descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(format(private_key, "x") + "\n")
    key = public_key(private_key)
    print(f"public key: {key}")
    print(f"fingerprint: {fingerprint(key)}")
    return 0


def _submit(poll_path: Path, values_path: Path, key_path: Path) -> int:
    try:
        poll = json.loads(poll_path.read_text())
        values = json.loads(values_path.read_text())
        private_key = int(key_path.read_text().strip(), 16)
        line = submit(poll, private_key, values)
    except (OSError, ValueError, KeyError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    for company_id, print_ in fingerprints(poll).items():
        print(f"{company_id}: {print_}", file=sys.stderr)
    print(line)
    return 0


def _read_key(key_path: Path) -> int:
    return int(key_path.read_text().strip(), 16)


def _aggregate(poll_path: Path, lines_path: Path, key_path: Path, nonce: str) -> int:
    try:
        poll = json.loads(poll_path.read_text())
        lines = [item.strip() for item in lines_path.read_text().splitlines() if item.strip()]
        result = aggregate_sealed(poll, lines, _read_key(key_path), nonce)
    except (OSError, ValueError, KeyError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def _proof(poll_path: Path, key_path: Path, action: str, argument: str, nonce: str) -> int:
    try:
        poll = json.loads(poll_path.read_text())
        print(make_proof(_read_key(key_path), poll, action, argument, nonce))
    except (OSError, ValueError, KeyError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IMMAP participant tool")
    commands = parser.add_subparsers(dest="command", required=True)
    keygen = commands.add_parser("keygen", help="create a key pair")
    keygen.add_argument("--key", type=Path, default=Path("immap.key"))
    submit_parser = commands.add_parser("submit", help="print your masked submission line")
    submit_parser.add_argument("poll", type=Path)
    submit_parser.add_argument("values", type=Path)
    submit_parser.add_argument("--key", type=Path, default=Path("immap.key"))
    aggregate_parser = commands.add_parser("aggregate", help="admin: open all lines and sum them")
    aggregate_parser.add_argument("poll", type=Path)
    aggregate_parser.add_argument("lines", type=Path)
    aggregate_parser.add_argument("--nonce", required=True)
    aggregate_parser.add_argument("--key", type=Path, default=Path("admin.key"))
    proof_parser = commands.add_parser("proof", help="admin: prove an action with your key")
    proof_parser.add_argument("poll", type=Path)
    proof_parser.add_argument("--action", required=True)
    proof_parser.add_argument("--argument", required=True)
    proof_parser.add_argument("--nonce", required=True)
    proof_parser.add_argument("--key", type=Path, default=Path("admin.key"))
    args = parser.parse_args(argv)
    if args.command == "keygen":
        return _keygen(args.key)
    if args.command == "aggregate":
        return _aggregate(args.poll, args.lines, args.key, args.nonce)
    if args.command == "proof":
        return _proof(args.poll, args.key, args.action, args.argument, args.nonce)
    return _submit(args.poll, args.values, args.key)


if __name__ == "__main__":
    raise SystemExit(main())
````

- [ ] **Step 4: Run tests, lint and types**

Run: `uv run pytest tests/test_immap.py && uv run ruff check . && uv run pyright`
Expected: 21 tests pass. `uv run ruff check .` reports exactly three pre-existing `E501` errors in `src/premday_bot/templates.py` (lines 75, 78, 84). Leave them alone; there must be no other errors.

- [ ] **Step 5: Commit**

```bash
git add src/premday_bot/immap.py tests/test_immap.py
git commit -m "Keep the crypto testable apart from Slack and runnable by anyone" -m "Add immap.py: poll templates, pairwise masks, admin sealing, proofs, CLI." -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---
### Task 2: Poll storage, enrollment, company list, admin keys, poll creation

**Files:**
- Create: `tests/helpers.py`, `src/premday_bot/polls.py`
- Test: `tests/test_polls_setup.py`

**Interfaces:**
- Consumes: from Task 1 `immap.generate_private_key`, `public_key`, `parse_public_key`, `fingerprint`, `POLL_TEMPLATES`, `DEFAULT_TEMPLATE`.
- Produces:
  - constants `CREATED, COLLECTING, COMPLETE, INCOMPLETE, DONE`, `MIN_PARTICIPANTS`, `RECOMMENDED_PARTICIPANTS`, `MAX_ADMIN_KEYS`, `MAX_TITLE_LENGTH`, `NONCE_TTL`, `EXTENDABLE`, `ACTION_EXTEND`, `ACTION_DONE`
  - `PollError(Exception)` (messages are safe to show users), frozen dataclasses `Company(company_id, members: tuple[str, ...], public_key | None)` (members oldest first; the key is the first member's enrolled key, the "key holder") and `Poll(id, channel_id, creator_user_id, title, template, schema_version, metrics, status, deadline, original_deadline, extension_count, participants, admins, bot_public_key, bot_private_key, message_ts, started_at, last_reminded_at, totals, validated_by, validated_at)` with property `participant_ids`
  - `unfence(text) -> str`, `is_admin(email, admin_emails) -> bool`, `poll_document(poll) -> dict` (the `poll.json`, never containing `bot_private_key`)
  - `PollStore(db_path)` with `upsert_enrollment`, `enrollments`, `add_company`, `delete_company`, `add_member`, `remove_member`, `get_company`, `list_companies`, `upsert_admin_key`, `admin_keys() -> dict[email, key]`, `save_poll`, `get_poll`, `list_polls(status=None, channel_id=None)`, `put_submission`, `submission_lines(poll_id) -> dict[company_id, line]`, `add_pending`, `pop_pending`
  - `PollService(store, *, timezone: str, admin_emails: frozenset[str] = frozenset(), clock=...)` with `is_admin`, `enroll(*, user_id, public_key) -> str` (fingerprint), admin-only `add_company`, `remove_company`, `attribute_company(*, email, company_id, user_id) -> Company` (adds a member), `unattribute_user(*, email, user_id) -> str`, `company_of(user_id) -> str | None`, `members_of(company_id) -> list[str]`, `companies(*, email) -> list[Company]`, `unattributed_users(*, email) -> list[str]` (all keyword-only with `email`), `pollable_company_ids() -> list[str]`, `register_admin_key(*, email, public_key) -> str` (fingerprint), `create_poll(*, channel_id, creator_user_id, title, deadline_day: date, participants: list[str], template: str = immap.DEFAULT_TEMPLATE) -> Poll` (unknown template raises `PollError`), `get(poll_id) -> Poll`, `set_message_ts(poll_id, message_ts) -> Poll`
  - test helpers: `Clock`, `World` (fields `service, store, clock, company_keys, admin_keys`; methods `new_poll`, `collecting_poll`, `line`, `submit`, `complete_poll`, `admin_totals`, `expected_totals`, `extend_proof`), `make_world(tmp_path)`, constants `ADMIN_EMAIL` (Aurélien Rougemont, `a.rougemont@criteo.com`), `SECOND_ADMIN_EMAIL`, `NOT_ADMIN_EMAIL`, `ADMIN_EMAILS`, `COMPANIES`, `owner(company_id)`, `values_for(company_id)`

- [ ] **Step 1: Write the test helpers and the failing tests**

Create `tests/helpers.py` (importable from tests as `from helpers import ...`):

````python
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from premday_bot import immap
from premday_bot.polls import Poll, PollService, PollStore, poll_document

ADMIN_EMAIL = "a.rougemont@criteo.com"  # Aurélien Rougemont (Criteo)
SECOND_ADMIN_EMAIL = "second.admin@example.com"
NOT_ADMIN_EMAIL = "someone@example.com"
ADMIN_EMAILS = frozenset({ADMIN_EMAIL, SECOND_ADMIN_EMAIL})
COMPANIES = ("acme", "bolt", "corp")
TEMPLATE_METRICS = immap.POLL_TEMPLATES[immap.DEFAULT_TEMPLATE].metrics
START = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self, now: datetime = START) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


def owner(company_id: str) -> str:
    return f"U_{company_id.upper()}"


def values_for(company_id: str) -> dict[str, int]:
    base = sum(company_id.encode())
    return {name: base + index for index, name in enumerate(sorted(TEMPLATE_METRICS))}


@dataclass
class World:
    service: PollService
    store: PollStore
    clock: Clock
    company_keys: dict[str, int]
    admin_keys: dict[str, int]
    polls: list[Poll] = field(default_factory=list)

    def new_poll(
        self, participants: list[str] | None = None, days: int = 7, title: str = "Infra 2026"
    ) -> Poll:
        poll = self.service.create_poll(
            channel_id="C1",
            creator_user_id=owner("acme"),
            title=title,
            deadline_day=(self.clock.now + timedelta(days=days)).date(),
            participants=participants or list(COMPANIES),
        )
        self.polls.append(poll)
        return poll

    def collecting_poll(self, participants: list[str] | None = None, days: int = 7) -> Poll:
        poll = self.new_poll(participants, days)
        return self.service.start(poll.id, user_id=owner("acme"), email=None)

    def line(self, poll: Poll, company_id: str) -> str:
        return immap.submit(
            poll_document(poll), self.company_keys[company_id], values_for(company_id)
        )

    def submit(self, poll: Poll, company_id: str) -> Poll:
        line = self.line(poll, company_id)
        return self.service.submit(poll.id, user_id=owner(company_id), line=line)

    def complete_poll(self) -> Poll:
        poll = self.collecting_poll()
        for company_id in COMPANIES:
            poll = self.submit(poll, company_id)
        return poll

    def admin_totals(self, poll: Poll, email: str, nonce: str) -> dict:
        """What an admin gets by running ``immap.py aggregate`` on the released lines."""
        lines = self.service.submission_lines(poll.id, email=email)
        return immap.aggregate_sealed(
            poll_document(poll), lines, self.admin_keys[email], nonce
        )

    def expected_totals(self) -> dict[str, int]:
        return {
            name: sum(values_for(c)[name] for c in COMPANIES) for name in TEMPLATE_METRICS
        }

    def extend_proof(self, poll: Poll, email: str, day: date, nonce: str) -> str:
        return immap.make_proof(
            self.admin_keys[email], poll_document(poll), "extend", day.isoformat(), nonce
        )


def enroll_and_attribute(service: PollService, company_id: str, public_key: str) -> None:
    """A user enrolls, an admin adds the company and attributes it to that user."""
    service.enroll(user_id=owner(company_id), public_key=public_key)
    service.add_company(email=ADMIN_EMAIL, company_id=company_id)
    service.attribute_company(email=ADMIN_EMAIL, company_id=company_id, user_id=owner(company_id))


def make_world(tmp_path: Path, companies: tuple[str, ...] = COMPANIES) -> World:
    store = PollStore(tmp_path / "polls.sqlite3")
    clock = Clock()
    service = PollService(
        store, timezone="Europe/Paris", admin_emails=ADMIN_EMAILS, clock=clock
    )
    company_keys = {c: immap.generate_private_key() for c in companies}
    for company_id, key in company_keys.items():
        enroll_and_attribute(service, company_id, immap.public_key(key))
    admin_keys = {e: immap.generate_private_key() for e in (ADMIN_EMAIL, SECOND_ADMIN_EMAIL)}
    for email, key in admin_keys.items():
        service.register_admin_key(email=email, public_key=immap.public_key(key))
    return World(service, store, clock, company_keys, admin_keys)
````

Create `tests/test_polls_setup.py`:

````python
from dataclasses import replace
from datetime import date, timedelta

import pytest

from helpers import (
    ADMIN_EMAIL,
    ADMIN_EMAILS,
    COMPANIES,
    NOT_ADMIN_EMAIL,
    SECOND_ADMIN_EMAIL,
    TEMPLATE_METRICS,
    enroll_and_attribute,
    make_world,
    owner,
)
from premday_bot import immap
from premday_bot.polls import (
    CREATED,
    MAX_ADMIN_KEYS,
    MAX_TITLE_LENGTH,
    PollError,
    PollService,
    PollStore,
    is_admin,
    poll_document,
    unfence,
)


def test_admin_is_decided_by_email_case_insensitively() -> None:
    assert is_admin("A.Rougemont@Criteo.com", ADMIN_EMAILS)
    assert is_admin(SECOND_ADMIN_EMAIL, ADMIN_EMAILS)
    assert not is_admin(NOT_ADMIN_EMAIL, ADMIN_EMAILS)
    assert not is_admin(None, ADMIN_EMAILS)
    assert not is_admin("a.rougemont@criteo.com", frozenset())


def members_of(service: PollService, company_id: str) -> tuple[str, ...]:
    companies = {c.company_id: c for c in service.companies(email=ADMIN_EMAIL)}
    return companies[company_id].members


def test_enrolling_needs_a_valid_key_and_unique_keys(tmp_path) -> None:
    world = make_world(tmp_path)
    key = immap.public_key(immap.generate_private_key())
    assert world.service.enroll(user_id="U_NEW", public_key=key) == immap.fingerprint(key)
    with pytest.raises(PollError, match="already enrolled"):
        world.service.enroll(user_id="U_OTHER", public_key=key)
    with pytest.raises(PollError, match="Invalid public key"):
        world.service.enroll(user_id="U_NEW", public_key="zz")
    # Enrolling again replaces your key (rotation); the company follows its key holder.
    new_key = immap.public_key(immap.generate_private_key())
    world.service.enroll(user_id=owner("acme"), public_key=new_key)
    company = next(c for c in world.service.companies(email=ADMIN_EMAIL) if c.company_id == "acme")
    assert company.public_key == new_key and company.members == (owner("acme"),)


def test_admins_manage_the_list_of_companies(tmp_path) -> None:
    world = make_world(tmp_path)
    service = world.service
    service.add_company(email=ADMIN_EMAIL, company_id="newco")
    with pytest.raises(PollError, match="already exists"):
        service.add_company(email=ADMIN_EMAIL, company_id="newco")
    for bad_id in ("A", "x", "has space", "UPPER", "a" * 33):
        with pytest.raises(PollError, match="company id"):
            service.add_company(email=ADMIN_EMAIL, company_id=bad_id)
    listed = {c.company_id: c for c in service.companies(email=SECOND_ADMIN_EMAIL)}
    assert set(listed) == {*COMPANIES, "newco"}
    assert listed["newco"].members == () and listed["newco"].public_key is None
    service.remove_company(email=ADMIN_EMAIL, company_id="newco")
    assert "newco" not in {c.company_id for c in service.companies(email=ADMIN_EMAIL)}
    with pytest.raises(PollError, match="does not exist"):
        service.remove_company(email=ADMIN_EMAIL, company_id="newco")


def test_admins_add_enrolled_users_to_a_company_and_the_first_holds_the_key(tmp_path) -> None:
    world = make_world(tmp_path)
    service = world.service
    first_key = immap.public_key(immap.generate_private_key())
    second_key = immap.public_key(immap.generate_private_key())
    service.add_company(email=ADMIN_EMAIL, company_id="newco")
    with pytest.raises(PollError, match="has not enrolled"):
        service.attribute_company(email=ADMIN_EMAIL, company_id="newco", user_id="U_ONE")
    service.enroll(user_id="U_ONE", public_key=first_key)
    service.enroll(user_id="U_TWO", public_key=second_key)
    assert service.unattributed_users(email=ADMIN_EMAIL) == ["U_ONE", "U_TWO"]
    service.attribute_company(email=ADMIN_EMAIL, company_id="newco", user_id="U_ONE")
    company = service.attribute_company(email=ADMIN_EMAIL, company_id="newco", user_id="U_TWO")
    assert company.members == ("U_ONE", "U_TWO") and company.public_key == first_key
    assert service.attribute_company(email=ADMIN_EMAIL, company_id="newco", user_id="U_ONE") == (
        company
    )
    assert service.unattributed_users(email=ADMIN_EMAIL) == []
    assert service.members_of("newco") == ["U_ONE", "U_TWO"]
    assert service.company_of("U_TWO") == "newco" and service.company_of("U_STRANGER") is None
    with pytest.raises(PollError, match="does not exist"):
        service.attribute_company(email=ADMIN_EMAIL, company_id="ghost", user_id="U_ONE")
    # A user belongs to one company.
    with pytest.raises(PollError, match="already belongs to `newco`"):
        service.attribute_company(email=ADMIN_EMAIL, company_id="acme", user_id="U_TWO")
    assert service.unattribute_user(email=ADMIN_EMAIL, user_id="U_ONE") == "newco"
    company = next(c for c in service.companies(email=ADMIN_EMAIL) if c.company_id == "newco")
    assert company.members == ("U_TWO",) and company.public_key == second_key  # key holder moves
    with pytest.raises(PollError, match="does not belong"):
        service.unattribute_user(email=ADMIN_EMAIL, user_id="U_ONE")
    service.attribute_company(email=ADMIN_EMAIL, company_id="acme", user_id="U_ONE")
    assert members_of(service, "acme") == (owner("acme"), "U_ONE")


def test_company_management_is_for_admins_only(tmp_path) -> None:
    world = make_world(tmp_path)
    service = world.service
    for email in (NOT_ADMIN_EMAIL, None):
        for call in (
            lambda e=email: service.add_company(email=e, company_id="newco"),
            lambda e=email: service.remove_company(email=e, company_id="acme"),
            lambda e=email: service.attribute_company(email=e, company_id="acme", user_id="U1"),
            lambda e=email: service.unattribute_user(email=e, user_id=owner("acme")),
            lambda e=email: service.companies(email=e),
            lambda e=email: service.unattributed_users(email=e),
        ):
            with pytest.raises(PollError, match="Only admins"):
                call()
    assert len(service.companies(email=ADMIN_EMAIL)) == len(COMPANIES)


def test_a_companys_key_cannot_change_while_it_is_in_an_open_poll(tmp_path) -> None:
    world = make_world(tmp_path)
    service = world.service
    poll = world.new_poll()
    service.enroll(user_id="U_NEW", public_key=immap.public_key(immap.generate_private_key()))
    for call in (
        lambda: service.remove_company(email=ADMIN_EMAIL, company_id="acme"),
        lambda: service.unattribute_user(email=ADMIN_EMAIL, user_id=owner("acme")),  # key holder
    ):
        with pytest.raises(PollError, match=f"open poll `{poll.id}`"):
            call()
    # Adding a colleague, and removing a non-holder, leave the key alone, so they stay possible.
    service.attribute_company(email=ADMIN_EMAIL, company_id="acme", user_id="U_NEW")
    assert service.unattribute_user(email=ADMIN_EMAIL, user_id="U_NEW") == "acme"
    # A company that is not in that poll is free to change.
    service.add_company(email=ADMIN_EMAIL, company_id="other")
    service.remove_company(email=ADMIN_EMAIL, company_id="other")


def test_a_company_without_a_member_cannot_join_a_poll(tmp_path) -> None:
    world = make_world(tmp_path)
    world.service.add_company(email=ADMIN_EMAIL, company_id="empty")
    with pytest.raises(PollError, match="no member"):
        world.new_poll(participants=[*COMPANIES, "empty"])
    assert "empty" not in world.service.pollable_company_ids()


def test_only_admins_can_register_admin_keys_and_the_number_is_capped(tmp_path) -> None:
    world = make_world(tmp_path)
    key = immap.public_key(immap.generate_private_key())
    with pytest.raises(PollError, match="Only admins"):
        world.service.register_admin_key(email=NOT_ADMIN_EMAIL, public_key=key)
    with pytest.raises(PollError, match="Only admins"):
        world.service.register_admin_key(email=None, public_key=key)
    assert world.service.register_admin_key(email=ADMIN_EMAIL, public_key=key) == (
        immap.fingerprint(key)
    )
    many = frozenset(f"admin{i}@example.com" for i in range(MAX_ADMIN_KEYS + 1))
    service = PollService(PollStore(tmp_path / "many.sqlite3"), timezone="UTC", admin_emails=many)
    for email in sorted(many)[:MAX_ADMIN_KEYS]:
        service.register_admin_key(
            email=email, public_key=immap.public_key(immap.generate_private_key())
        )
    with pytest.raises(PollError, match="At most"):
        service.register_admin_key(
            email=sorted(many)[-1], public_key=immap.public_key(immap.generate_private_key())
        )


def test_create_poll_snapshots_keys_and_starts_in_created(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    assert poll.status == CREATED
    assert poll.participant_ids == sorted(COMPANIES)
    assert [email for email, _ in poll.admins] == sorted([ADMIN_EMAIL, SECOND_ADMIN_EMAIL])
    assert poll.deadline.tzinfo is not None and poll.deadline == poll.original_deadline
    # Rotating a company key later does not change an existing poll.
    world.service.enroll(
        user_id=owner("acme"), public_key=immap.public_key(immap.generate_private_key())
    )
    assert world.service.get(poll.id).participants == poll.participants


def test_poll_document_never_contains_private_material(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    document = poll_document(poll)
    assert document["bot_public_key"] == poll.bot_public_key
    assert poll.bot_private_key not in str(document)
    assert set(document["metrics"]) == set(TEMPLATE_METRICS)
    assert [p["company_id"] for p in document["participants"]] == sorted(COMPANIES)


def test_create_poll_validation(tmp_path) -> None:
    world = make_world(tmp_path)
    service = world.service
    day = (world.clock.now + timedelta(days=3)).date()
    base = {"channel_id": "C1", "creator_user_id": "U1", "title": "t", "deadline_day": day}
    with pytest.raises(PollError, match="at least 3"):
        service.create_poll(**base, participants=["acme", "bolt"])
    with pytest.raises(PollError, match="at least 3"):
        service.create_poll(**base, participants=["acme", "acme", "bolt"])
    with pytest.raises(PollError, match="does not exist"):
        service.create_poll(**base, participants=["acme", "bolt", "ghost"])
    with pytest.raises(PollError, match="title"):
        service.create_poll(**{**base, "title": "  "}, participants=list(COMPANIES))
    yesterday = (world.clock.now - timedelta(days=1)).date()
    with pytest.raises(PollError, match="future"):
        service.create_poll(**{**base, "deadline_day": yesterday}, participants=list(COMPANIES))


def test_create_poll_needs_an_admin_key(tmp_path) -> None:
    store = PollStore(tmp_path / "noadmin.sqlite3")
    service = PollService(store, timezone="UTC", admin_emails=ADMIN_EMAILS)
    for company_id in COMPANIES:
        enroll_and_attribute(service, company_id, immap.public_key(immap.generate_private_key()))

    with pytest.raises(PollError, match="admin"):
        service.create_poll(
            channel_id="C1",
            creator_user_id="U1",
            title="t",
            deadline_day=date(2999, 1, 1),
            participants=list(COMPANIES),
        )


def test_pollable_companies_are_listed_sorted(tmp_path) -> None:
    world = make_world(tmp_path)
    assert world.service.pollable_company_ids() == sorted(COMPANIES)


def test_polls_cannot_start_before_enough_companies_and_an_admin_key_exist(tmp_path) -> None:
    store = PollStore(tmp_path / "early.sqlite3")
    service = PollService(store, timezone="UTC", admin_emails=ADMIN_EMAILS)
    with pytest.raises(PollError, match="At least 3 companies need a member"):
        service.pollable_company_ids()
    for company_id in COMPANIES:
        enroll_and_attribute(service, company_id, immap.public_key(immap.generate_private_key()))
    with pytest.raises(PollError, match="No admin has registered a key"):
        service.pollable_company_ids()
    service.register_admin_key(
        email=ADMIN_EMAIL, public_key=immap.public_key(immap.generate_private_key())
    )
    assert service.pollable_company_ids() == sorted(COMPANIES)


def test_two_users_cannot_share_a_public_key(tmp_path) -> None:
    world = make_world(tmp_path)
    shared = immap.public_key(world.company_keys["acme"])
    with pytest.raises(PollError, match="already enrolled by another"):
        world.service.enroll(user_id="U_TWIN", public_key=shared)
    # Enrolling your own key again is fine.
    world.service.enroll(user_id=owner("acme"), public_key=shared)


def test_pasted_keys_may_carry_backticks_but_not_hex_prefixes(tmp_path) -> None:
    world = make_world(tmp_path)
    key = immap.public_key(immap.generate_private_key())
    world.service.enroll(user_id="U_NEW", public_key=f"`{key}`")
    world.service.add_company(email=ADMIN_EMAIL, company_id="newco")
    company = world.service.attribute_company(
        email=ADMIN_EMAIL, company_id="newco", user_id="U_NEW"
    )
    assert company.public_key == key
    for bad in ("0x" + key, key[:10] + "_" + key[10:], "", "   "):
        with pytest.raises(PollError, match="Invalid public key"):
            world.service.enroll(user_id="U_O", public_key=bad)


def test_titles_are_limited_in_length(tmp_path) -> None:
    world = make_world(tmp_path)
    with pytest.raises(PollError, match="too long"):
        world.new_poll(title="x" * (MAX_TITLE_LENGTH + 1))
    assert world.new_poll(title="x" * MAX_TITLE_LENGTH).title == "x" * MAX_TITLE_LENGTH


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("abc", "abc"),
        ("  abc\n", "abc"),
        ("`abc`", "abc"),
        ("```abc```", "abc"),
        ("```\nabc\n```", "abc"),
        ('```json\n{"a": 1}\n```', '{"a": 1}'),
    ],
)
def test_unfence_strips_slack_code_markup(raw: str, expected: str) -> None:
    assert unfence(raw) == expected


def test_poll_snapshots_its_template(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    template = immap.POLL_TEMPLATES[immap.DEFAULT_TEMPLATE]
    assert (poll.template, poll.schema_version) == (template.id, template.version)
    assert poll.metrics == template.metrics
    assert poll_document(poll)["template"] == template.id
    # A later edit of the template must not change a poll that already exists.
    edited = {**template.metrics, "extra_metric": "units"}
    immap.POLL_TEMPLATES[template.id] = replace(template, version=2, metrics=edited)
    try:
        stored = world.service.get(poll.id)
        assert stored.metrics == template.metrics and stored.schema_version == 1
        assert "extra_metric" not in poll_document(stored)["metrics"]
    finally:
        immap.POLL_TEMPLATES[template.id] = template


def test_create_poll_rejects_an_unknown_template(tmp_path) -> None:
    world = make_world(tmp_path)
    with pytest.raises(PollError, match="template"):
        world.service.create_poll(
            channel_id="C1",
            creator_user_id=owner("acme"),
            title="Infra",
            deadline_day=date(2026, 12, 1),
            participants=list(COMPANIES),
            template="nope",
        )
````

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_polls_setup.py`
Expected: collection error `ModuleNotFoundError: No module named 'premday_bot.polls'`.

- [ ] **Step 3: Write the implementation**

Create `src/premday_bot/polls.py`. This is the first third of the file: later tasks insert the lifecycle methods at the `# -- internals` marker.

````python
from __future__ import annotations

import json
import re
import secrets
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from premday_bot import immap

CREATED = "created"
COLLECTING = "collecting"
COMPLETE = "complete"
INCOMPLETE = "incomplete"
DONE = "done"

MIN_PARTICIPANTS = 3
RECOMMENDED_PARTICIPANTS = 10
MAX_ADMIN_KEYS = 5
MAX_TITLE_LENGTH = 150
NONCE_TTL = timedelta(minutes=15)
EXTENDABLE = (CREATED, COLLECTING, INCOMPLETE)
ACTION_EXTEND = "extend"
ACTION_DONE = "done"

_COMPANY_ID = re.compile(r"^[a-z0-9-]{2,32}$")


class PollError(Exception):
    """A rule violation whose message is safe to show to the user."""


@dataclass(frozen=True)
class Company:
    company_id: str
    members: tuple[str, ...]  # Slack users attributed to the company, oldest first
    public_key: str | None  # enrolled key of the first member (key holder); None without members


@dataclass(frozen=True)
class Poll:
    id: str
    channel_id: str
    creator_user_id: str
    title: str
    template: str
    schema_version: int  # version of the template the poll was created from
    metrics: dict[str, str]  # snapshot of the template's metrics (metric id -> unit)
    status: str
    deadline: datetime
    original_deadline: datetime
    extension_count: int
    participants: tuple[tuple[str, str], ...]  # (company_id, public_key), sorted by company id
    admins: tuple[tuple[str, str], ...]  # (admin email, public_key), snapshot at creation
    bot_public_key: str
    bot_private_key: str
    message_ts: str | None = None
    started_at: datetime | None = None
    last_reminded_at: datetime | None = None
    totals: dict[str, int] | None = None
    validated_by: str | None = None
    validated_at: datetime | None = None

    @property
    def participant_ids(self) -> list[str]:
        return [company_id for company_id, _ in self.participants]


def unfence(text: str) -> str:
    """Strip whitespace and the code-fence or backtick markup people copy along from Slack."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned[3:]
        first, _, rest = cleaned.partition("\n")
        cleaned = rest if first.strip().isalpha() else cleaned
        cleaned = cleaned.removesuffix("```")
    return cleaned.strip().strip("`").strip()


def is_admin(email: str | None, admin_emails: frozenset[str]) -> bool:
    return email is not None and email.strip().lower() in admin_emails


def poll_document(poll: Poll) -> dict:
    """The ``poll.json`` participants feed to ``immap.py``; never includes private material."""
    return {
        "poll_id": poll.id,
        "template": poll.template,
        "schema_version": poll.schema_version,
        "metrics": dict(poll.metrics),
        "participants": [
            {"company_id": company_id, "public_key": key} for company_id, key in poll.participants
        ],
        "admins": [{"admin_id": email, "public_key": key} for email, key in poll.admins],
        "bot_public_key": poll.bot_public_key,
        "deadline": poll.deadline.isoformat(),
    }


class PollStore:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._db_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _init_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS enrollments (
                    user_id TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL UNIQUE
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS companies (
                    company_id TEXT PRIMARY KEY
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS company_members (
                    user_id TEXT PRIMARY KEY,
                    company_id TEXT NOT NULL REFERENCES companies (company_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS admin_keys (
                    admin_email TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS immap_polls (
                    id TEXT PRIMARY KEY,
                    channel_id TEXT NOT NULL,
                    creator_user_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    template TEXT NOT NULL,
                    schema_version INTEGER NOT NULL,
                    metrics TEXT NOT NULL,
                    status TEXT NOT NULL,
                    deadline TEXT NOT NULL,
                    original_deadline TEXT NOT NULL,
                    extension_count INTEGER NOT NULL DEFAULT 0,
                    participants TEXT NOT NULL,
                    admins TEXT NOT NULL,
                    bot_public_key TEXT NOT NULL,
                    bot_private_key TEXT NOT NULL,
                    message_ts TEXT,
                    started_at TEXT,
                    last_reminded_at TEXT,
                    totals TEXT,
                    validated_by TEXT,
                    validated_at TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS immap_submissions (
                    poll_id TEXT NOT NULL REFERENCES immap_polls(id) ON DELETE CASCADE,
                    company_id TEXT NOT NULL,
                    line TEXT NOT NULL,
                    submitted_at TEXT NOT NULL,
                    PRIMARY KEY (poll_id, company_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS immap_pending_actions (
                    nonce TEXT PRIMARY KEY,
                    poll_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    admin_email TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """
            )

    def upsert_enrollment(self, user_id: str, public_key: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO enrollments (user_id, public_key) VALUES (?, ?)
                ON CONFLICT(user_id) DO UPDATE SET public_key = excluded.public_key
                """,
                (user_id, public_key),
            )

    def enrollments(self) -> dict[str, str]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM enrollments ORDER BY user_id").fetchall()
        return {row["user_id"]: row["public_key"] for row in rows}

    def add_company(self, company_id: str) -> None:
        with self._connect() as connection:
            connection.execute("INSERT INTO companies (company_id) VALUES (?)", (company_id,))

    def delete_company(self, company_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM company_members WHERE company_id = ?", (company_id,))
            connection.execute("DELETE FROM companies WHERE company_id = ?", (company_id,))

    def add_member(self, company_id: str, user_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO company_members (user_id, company_id) VALUES (?, ?)",
                (user_id, company_id),
            )

    def remove_member(self, user_id: str) -> None:
        with self._connect() as connection:
            connection.execute("DELETE FROM company_members WHERE user_id = ?", (user_id,))

    def get_company(self, company_id: str) -> Company | None:
        return next((c for c in self.list_companies() if c.company_id == company_id), None)

    def list_companies(self) -> list[Company]:
        with self._connect() as connection:
            companies = connection.execute(
                "SELECT company_id FROM companies ORDER BY company_id"
            ).fetchall()
            members = connection.execute(
                "SELECT company_id, user_id FROM company_members ORDER BY rowid"
            ).fetchall()
            keys = {
                row["user_id"]: row["public_key"]
                for row in connection.execute("SELECT * FROM enrollments").fetchall()
            }
        by_company: dict[str, list[str]] = {}
        for row in members:
            by_company.setdefault(row["company_id"], []).append(row["user_id"])
        result = []
        for row in companies:
            users = by_company.get(row["company_id"], [])
            result.append(
                Company(row["company_id"], tuple(users), keys.get(users[0]) if users else None)
            )
        return result

    def upsert_admin_key(self, admin_email: str, public_key: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO admin_keys (admin_email, public_key) VALUES (?, ?)
                ON CONFLICT(admin_email) DO UPDATE SET public_key = excluded.public_key
                """,
                (admin_email, public_key),
            )

    def admin_keys(self) -> dict[str, str]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM admin_keys ORDER BY admin_email").fetchall()
        return {row["admin_email"]: row["public_key"] for row in rows}

    def save_poll(self, poll: Poll) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO immap_polls (
                    id, channel_id, creator_user_id, title, template, schema_version, metrics,
                    status, deadline, original_deadline, extension_count, participants, admins,
                    bot_public_key, bot_private_key, message_ts, started_at, last_reminded_at,
                    totals, validated_by, validated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    poll.id,
                    poll.channel_id,
                    poll.creator_user_id,
                    poll.title,
                    poll.template,
                    poll.schema_version,
                    json.dumps(poll.metrics),
                    poll.status,
                    poll.deadline.isoformat(),
                    poll.original_deadline.isoformat(),
                    poll.extension_count,
                    json.dumps(poll.participants),
                    json.dumps(poll.admins),
                    poll.bot_public_key,
                    poll.bot_private_key,
                    poll.message_ts,
                    _iso(poll.started_at),
                    _iso(poll.last_reminded_at),
                    json.dumps(poll.totals) if poll.totals is not None else None,
                    poll.validated_by,
                    _iso(poll.validated_at),
                ),
            )

    def get_poll(self, poll_id: str) -> Poll | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM immap_polls WHERE id = ?", (poll_id,)
            ).fetchone()
        return _row_to_poll(row) if row else None

    def list_polls(self, *, status: str | None = None, channel_id: str | None = None) -> list[Poll]:
        query = "SELECT * FROM immap_polls WHERE 1 = 1"
        arguments: list[str] = []
        if status is not None:
            query += " AND status = ?"
            arguments.append(status)
        if channel_id is not None:
            query += " AND channel_id = ?"
            arguments.append(channel_id)
        with self._connect() as connection:
            rows = connection.execute(query + " ORDER BY rowid", arguments).fetchall()
        return [_row_to_poll(row) for row in rows]

    def put_submission(self, poll_id: str, company_id: str, line: str, at: datetime) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO immap_submissions VALUES (?, ?, ?, ?)",
                (poll_id, company_id, line, at.isoformat()),
            )

    def submission_lines(self, poll_id: str) -> dict[str, str]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT company_id, line FROM immap_submissions WHERE poll_id = ? "
                "ORDER BY company_id",
                (poll_id,),
            ).fetchall()
        return {row["company_id"]: row["line"] for row in rows}

    def add_pending(
        self, nonce: str, poll_id: str, action: str, admin_email: str, expires_at: datetime
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO immap_pending_actions VALUES (?, ?, ?, ?, ?)",
                (nonce, poll_id, action, admin_email, expires_at.isoformat()),
            )

    def pop_pending(self, nonce: str) -> sqlite3.Row | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM immap_pending_actions WHERE nonce = ?", (nonce,)
            ).fetchone()
            connection.execute("DELETE FROM immap_pending_actions WHERE nonce = ?", (nonce,))
        return row


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _parse(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _row_to_poll(row: sqlite3.Row) -> Poll:
    return Poll(
        id=row["id"],
        channel_id=row["channel_id"],
        creator_user_id=row["creator_user_id"],
        title=row["title"],
        template=row["template"],
        schema_version=row["schema_version"],
        metrics=json.loads(row["metrics"]),
        status=row["status"],
        deadline=datetime.fromisoformat(row["deadline"]),
        original_deadline=datetime.fromisoformat(row["original_deadline"]),
        extension_count=row["extension_count"],
        participants=tuple((c, k) for c, k in json.loads(row["participants"])),
        admins=tuple((e, k) for e, k in json.loads(row["admins"])),
        bot_public_key=row["bot_public_key"],
        bot_private_key=row["bot_private_key"],
        message_ts=row["message_ts"],
        started_at=_parse(row["started_at"]),
        last_reminded_at=_parse(row["last_reminded_at"]),
        totals=json.loads(row["totals"]) if row["totals"] else None,
        validated_by=row["validated_by"],
        validated_at=_parse(row["validated_at"]),
    )


def _utcnow() -> datetime:
    return datetime.now(UTC)


class PollService:
    """Poll rules. Slack handlers call this; it knows nothing about Slack."""

    def __init__(
        self,
        store: PollStore,
        *,
        timezone: str,
        admin_emails: frozenset[str] = frozenset(),
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._store = store
        self._tz = ZoneInfo(timezone)
        self._admin_emails = admin_emails
        self._clock = clock

    # -- identity ---------------------------------------------------------------------------

    def is_admin(self, email: str | None) -> bool:
        return is_admin(email, self._admin_emails)

    def _require_admin(self, email: str | None) -> str:
        if not email or not self.is_admin(email):
            raise PollError("Only admins can do this.")
        return email.strip().lower()

    def enroll(self, *, user_id: str, public_key: str) -> str:
        """A Slack user enrolls with their key; an admin then attributes a company to them."""
        key = _normalized_key(public_key)
        for other_user, other_key in self._store.enrollments().items():
            if other_key == key and other_user != user_id:
                raise PollError("This public key is already enrolled by another Slack user.")
        self._store.upsert_enrollment(user_id, key)
        return immap.fingerprint(key)

    def add_company(self, *, email: str | None, company_id: str) -> None:
        self._require_admin(email)
        if not _COMPANY_ID.match(company_id):
            raise PollError("A company id uses 2-32 lowercase letters, digits or dashes.")
        if self._store.get_company(company_id):
            raise PollError(f"`{company_id}` already exists.")
        self._store.add_company(company_id)

    def remove_company(self, *, email: str | None, company_id: str) -> None:
        self._require_admin(email)
        self._existing_company(company_id)
        self._require_no_open_poll(company_id)
        self._store.delete_company(company_id)

    def attribute_company(self, *, email: str | None, company_id: str, user_id: str) -> Company:
        """Add an enrolled Slack user to a company. The first member is the key holder."""
        self._require_admin(email)
        company = self._existing_company(company_id)
        if user_id not in self._store.enrollments():
            raise PollError(
                f"<@{user_id}> has not enrolled yet (`/immap register <public_key>`)."
            )
        for other in self._store.list_companies():
            if user_id in other.members:
                if other.company_id == company_id:
                    return company
                raise PollError(
                    f"<@{user_id}> already belongs to `{other.company_id}`; remove them first."
                )
        self._store.add_member(company_id, user_id)
        return self._existing_company(company_id)

    def unattribute_user(self, *, email: str | None, user_id: str) -> str:
        """Remove a user from their company; returns the company id."""
        self._require_admin(email)
        company = next(
            (c for c in self._store.list_companies() if user_id in c.members), None
        )
        if company is None:
            raise PollError(f"<@{user_id}> does not belong to a company.")
        if company.members[0] == user_id:
            self._require_no_open_poll(company.company_id)  # the company key would change
        self._store.remove_member(user_id)
        return company.company_id

    def companies(self, *, email: str | None) -> list[Company]:
        self._require_admin(email)
        return self._store.list_companies()

    def unattributed_users(self, *, email: str | None) -> list[str]:
        """Enrolled Slack users no company is attributed to yet."""
        self._require_admin(email)
        members = {user for c in self._store.list_companies() for user in c.members}
        return [user for user in self._store.enrollments() if user not in members]

    def pollable_company_ids(self) -> list[str]:
        """Companies a poll can include; fails early when a poll could not be created."""
        companies = [c.company_id for c in self._store.list_companies() if c.public_key]
        if len(companies) < MIN_PARTICIPANTS:
            raise PollError(
                f"At least {MIN_PARTICIPANTS} companies need a member "
                "(`/immap companies`, `/immap company attribute`)."
            )
        if not any(email in self._admin_emails for email in self._store.admin_keys()):
            raise PollError("No admin has registered a key yet (`/immap admin-register`).")
        return companies

    def _existing_company(self, company_id: str) -> Company:
        company = self._store.get_company(company_id)
        if company is None:
            raise PollError(f"`{company_id}` does not exist.")
        return company

    def _require_no_open_poll(self, company_id: str) -> None:
        """A company's key is snapshotted in its polls, so it cannot change until they are done."""
        for poll in self._store.list_polls():
            if poll.status != DONE and company_id in poll.participant_ids:
                raise PollError(
                    f"`{company_id}` is part of the open poll `{poll.id}`; wait until it is done."
                )

    def register_admin_key(self, *, email: str | None, public_key: str) -> str:
        admin = self._require_admin(email)
        key = _normalized_key(public_key)
        keys = self._store.admin_keys()
        if admin not in keys and len(keys) >= MAX_ADMIN_KEYS:
            raise PollError(f"At most {MAX_ADMIN_KEYS} admin keys can be registered.")
        self._store.upsert_admin_key(admin, key)
        return immap.fingerprint(key)

    def company_of(self, user_id: str) -> str | None:
        return next(
            (c.company_id for c in self._store.list_companies() if user_id in c.members), None
        )

    def members_of(self, company_id: str) -> list[str]:
        company = self._store.get_company(company_id)
        return list(company.members) if company else []

    # -- creating and starting ----------------------------------------------------------------

    def create_poll(
        self,
        *,
        channel_id: str,
        creator_user_id: str,
        title: str,
        deadline_day: date,
        participants: list[str],
        template: str = immap.DEFAULT_TEMPLATE,
    ) -> Poll:
        poll_template = immap.POLL_TEMPLATES.get(template)
        if poll_template is None:
            raise PollError("Choose one of the poll templates.")
        title = title.strip()
        if not title:
            raise PollError("Add a title.")
        if len(title) > MAX_TITLE_LENGTH:
            raise PollError(f"The title is too long (at most {MAX_TITLE_LENGTH} characters).")
        unique = sorted(set(participants))
        if len(unique) < MIN_PARTICIPANTS:
            raise PollError(f"A poll needs at least {MIN_PARTICIPANTS} companies.")
        pairs: list[tuple[str, str]] = []
        for company_id in unique:
            company = self._store.get_company(company_id)
            if company is None:
                raise PollError(f"`{company_id}` does not exist.")
            if company.public_key is None:
                raise PollError(f"`{company_id}` has no member yet.")
            pairs.append((company.company_id, company.public_key))
        admins = tuple(
            (email, key)
            for email, key in self._store.admin_keys().items()
            if email in self._admin_emails
        )
        if not admins:
            raise PollError("No admin has registered a key yet (`/immap admin-register`).")
        deadline = self._end_of_day(deadline_day)
        if deadline <= self._clock():
            raise PollError("The deadline must be in the future.")
        bot_private = immap.generate_private_key()
        poll = Poll(
            id=secrets.token_hex(6),
            channel_id=channel_id,
            creator_user_id=creator_user_id,
            title=title,
            template=poll_template.id,
            schema_version=poll_template.version,
            metrics=dict(poll_template.metrics),
            status=CREATED,
            deadline=deadline,
            original_deadline=deadline,
            extension_count=0,
            participants=tuple(pairs),
            admins=admins,
            bot_public_key=immap.public_key(bot_private),
            bot_private_key=format(bot_private, "x"),
        )
        self._store.save_poll(poll)
        return poll

    def get(self, poll_id: str) -> Poll:
        return self._get(poll_id)

    def set_message_ts(self, poll_id: str, message_ts: str) -> Poll:
        return self._save(replace(self._get(poll_id), message_ts=message_ts))

    # -- internals ------------------------------------------------------------------------------

    def _get(self, poll_id: str) -> Poll:
        poll = self._store.get_poll(poll_id)
        if poll is None:
            raise PollError("I could not find that poll.")
        return poll

    def _save(self, poll: Poll) -> Poll:
        self._store.save_poll(poll)
        return poll

    def _end_of_day(self, day: date) -> datetime:
        return datetime.combine(day, time(23, 59, 59), tzinfo=self._tz)


def _normalized_key(public_key: str) -> str:
    try:
        return format(immap.parse_public_key(unfence(public_key)), "x")
    except ValueError as error:
        raise PollError(f"Invalid public key: {error}.") from error
````

- [ ] **Step 4: Run tests, lint and types**

Run: `uv run pytest tests/test_immap.py tests/test_polls_setup.py && uv run ruff check . && uv run pyright`
Expected: all tests pass. `uv run ruff check .` reports exactly three pre-existing `E501` errors in `src/premday_bot/templates.py` (lines 75, 78, 84). Leave them alone; there must be no other errors.

- [ ] **Step 5: Commit**

```bash
git add src/premday_bot/polls.py tests/helpers.py tests/test_polls_setup.py
git commit -m "Give polls a durable home and let admins own the company list" -m "Add PollStore/PollService: enrollment, company list and attribution, admin keys, poll creation from a template." -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---
### Task 3: Starting a poll and collecting sealed submissions

**Files:**
- Modify: `src/premday_bot/polls.py` (insert one block)
- Test: `tests/test_polls_collecting.py`

**Interfaces:**
- Consumes: Task 2 (`PollService`, `PollStore`, `Poll`, `PollError`, `unfence`, `CREATED`, `COLLECTING`, `COMPLETE`, helpers `make_world`, `owner`, `values_for`), Task 1 (`immap.parse_line`, `immap.check_envelope`, `immap.fingerprint`, `immap.seal`; tests use `helpers.TEMPLATE_METRICS`).
- Produces: `PollService.start(poll_id, *, user_id, email) -> Poll`, `submit(poll_id, *, user_id, line) -> Poll` (moves the poll to `complete` when the last company submits; the bot never decrypts anything), `missing(poll) -> list[str]`, `submitted(poll) -> list[str]`, (only members of a company may submit for it; `members_of`, `company_of` come from Task 2).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_polls_collecting.py`:

````python
import base64
import json
from datetime import timedelta

import pytest

from helpers import ADMIN_EMAIL, COMPANIES, NOT_ADMIN_EMAIL, TEMPLATE_METRICS, make_world, owner
from premday_bot import immap
from premday_bot.polls import COLLECTING, COMPLETE, CREATED, PollError


def test_start_rules(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    with pytest.raises(PollError, match="creator or an admin"):
        world.service.start(poll.id, user_id="U_RANDOM", email=NOT_ADMIN_EMAIL)
    started = world.service.start(poll.id, user_id="U_RANDOM", email=ADMIN_EMAIL)
    assert started.status == COLLECTING and started.started_at == world.clock.now
    with pytest.raises(PollError, match="already collecting"):
        world.service.start(poll.id, user_id=owner("acme"), email=None)


def test_start_is_refused_after_the_deadline(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll(days=1)
    world.clock.advance(timedelta(days=3))
    with pytest.raises(PollError, match="extend"):
        world.service.start(poll.id, user_id=owner("acme"), email=None)
    assert world.service.get(poll.id).status == CREATED


def test_submissions_are_refused_before_start(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    with pytest.raises(PollError, match="created"):
        world.submit(poll, "acme")


def test_submit_tracks_progress_and_completes_on_the_last_company(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    poll = world.submit(poll, "acme")
    assert poll.status == COLLECTING
    assert world.service.missing(poll) == ["bolt", "corp"]
    assert world.service.submitted(poll) == ["acme"]
    world.submit(poll, "bolt")
    final = world.submit(poll, "corp")
    assert final.status == COMPLETE
    assert world.service.get(poll.id).totals is None  # never computed by the bot


def test_resubmitting_replaces_the_previous_line(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    world.submit(poll, "acme")
    world.submit(poll, "acme")
    assert world.service.submitted(poll) == ["acme"]
    assert len(world.store.submission_lines(poll.id)) == 1


def test_submit_validation(tmp_path) -> None:
    world = make_world(tmp_path, companies=(*COMPANIES, "dyna"))
    poll = world.collecting_poll(participants=list(COMPANIES))
    good = world.line(poll, "acme")
    with pytest.raises(PollError, match="not a member of"):
        world.service.submit(poll.id, user_id=owner("bolt"), line=good)
    with pytest.raises(PollError, match="not part of this poll"):
        world.service.submit(poll.id, user_id=owner("dyna"), line=good.replace(".acme.", ".dyna."))
    with pytest.raises(PollError, match="different poll"):
        world.service.submit(poll.id, user_id=owner("acme"), line=good.replace(poll.id, "other"))
    with pytest.raises(PollError, match="not an immap2"):
        world.service.submit(poll.id, user_id=owner("acme"), line="hello")
    # Wrong number of values: seal a short payload to the right admin keys.
    from premday_bot.polls import poll_document

    document = poll_document(poll)
    short = immap.seal(b"\x00" * 8, document["admins"])
    encoded = base64.urlsafe_b64encode(json.dumps(short).encode()).decode().rstrip("=")
    with pytest.raises(PollError, match="number of values"):
        world.service.submit(
            poll.id, user_id=owner("acme"), line=f"immap2.{poll.id}.acme.{encoded}"
        )
    # Sealed to a different admin: the bot can tell without reading it.
    stranger = {"public_key": immap.public_key(1234567)}
    foreign = immap.seal(b"\x00" * 8 * len(TEMPLATE_METRICS), [stranger])
    encoded = base64.urlsafe_b64encode(json.dumps(foreign).encode()).decode().rstrip("=")
    with pytest.raises(PollError, match="admin keys"):
        world.service.submit(
            poll.id, user_id=owner("acme"), line=f"immap2.{poll.id}.acme.{encoded}"
        )
    assert world.service.submitted(poll) == []


def test_submit_after_the_deadline_is_refused_even_before_the_sweeper_runs(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll(days=1)
    line = world.line(poll, "acme")
    world.clock.advance(timedelta(days=3))
    with pytest.raises(PollError, match="deadline"):
        world.service.submit(poll.id, user_id=owner("acme"), line=line)


def test_the_bot_stores_only_ciphertext(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    world.submit(poll, "acme")
    stored = world.store.submission_lines(poll.id)["acme"]
    _, _, envelope = immap.parse_line(stored)
    from helpers import values_for

    plain = b"".join(v.to_bytes(8, "big") for _, v in sorted(values_for("acme").items()))
    assert bytes.fromhex(envelope["ct"]) != plain


@pytest.mark.parametrize("wrap", ["`{}`", "```{}```", "```\n{}\n```", "  {}\n"])
def test_a_submission_pasted_from_a_slack_code_block_is_accepted(tmp_path, wrap) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    line = world.line(poll, "acme")
    world.service.submit(poll.id, user_id=owner("acme"), line=wrap.format(line))
    assert world.store.submission_lines(poll.id)["acme"] == line  # stored clean
````

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_polls_collecting.py`
Expected: failures `AttributeError: 'PollService' object has no attribute 'start'` (or `submit`).

- [ ] **Step 3: Write the implementation**

In `src/premday_bot/polls.py`, insert this block immediately **before** the line that starts with `    # -- internals` (inside `class PollService`, after `set_message_ts`):

````python
    def start(self, poll_id: str, *, user_id: str, email: str | None) -> Poll:
        poll = self._get(poll_id)
        if user_id != poll.creator_user_id and not self.is_admin(email):
            raise PollError("Only the poll creator or an admin can start collecting.")
        if poll.status != CREATED:
            raise PollError(f"This poll is already {poll.status}.")
        now = self._clock()
        if poll.deadline <= now:
            raise PollError("The deadline has passed. An admin must extend it first.")
        return self._save(replace(poll, status=COLLECTING, started_at=now, last_reminded_at=None))

    # -- collecting ---------------------------------------------------------------------------

    def submit(self, poll_id: str, *, user_id: str, line: str) -> Poll:
        poll = self._get(poll_id)
        if poll.status != COLLECTING:
            raise PollError(f"This poll is {poll.status}; it is not accepting submissions.")
        if poll.deadline <= self._clock():
            raise PollError("The deadline has passed.")
        try:
            line = unfence(line)
            line_poll_id, company_id, envelope = immap.parse_line(line)
            if line_poll_id != poll.id:
                raise PollError("This line was made for a different poll.")
            if company_id not in poll.participant_ids:
                raise PollError(f"`{company_id}` is not part of this poll.")
            immap.check_envelope(
                envelope,
                len(poll.metrics),
                {immap.fingerprint(key) for _, key in poll.admins},
            )
        except ValueError as error:
            raise PollError(str(error)) from error
        company = self._store.get_company(company_id)
        if company is None or user_id not in company.members:
            raise PollError(f"You are not a member of `{company_id}`.")
        self._store.put_submission(poll.id, company_id, line, self._clock())
        if not self.missing(poll):
            poll = self._save(replace(poll, status=COMPLETE))
        return poll

    def missing(self, poll: Poll) -> list[str]:
        submitted = set(self._store.submission_lines(poll.id))
        return [company_id for company_id in poll.participant_ids if company_id not in submitted]

    def submitted(self, poll: Poll) -> list[str]:
        return sorted(set(poll.participant_ids) - set(self.missing(poll)))
````

- [ ] **Step 4: Run tests, lint and types**

Run: `uv run pytest tests/test_immap.py tests/test_polls_setup.py tests/test_polls_collecting.py && uv run ruff check . && uv run pyright`
Expected: all tests pass. `uv run ruff check .` reports exactly three pre-existing `E501` errors in `src/premday_bot/templates.py` (lines 75, 78, 84). Leave them alone; there must be no other errors.

- [ ] **Step 5: Commit**

```bash
git add src/premday_bot/polls.py tests/test_polls_collecting.py
git commit -m "Collect submissions the bot cannot read" -m "Add start and sealed submission handling with completion detection." -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---
### Task 4: Admin actions, validation gate, extensions, deadline and reminders

**Files:**
- Modify: `src/premday_bot/polls.py` (insert two blocks)
- Test: `tests/test_polls_admin.py`

**Interfaces:**
- Consumes: Tasks 1-3 (`immap.check_proof`, `immap.totals_digest`, `immap.MODULUS`, `Poll.metrics`, `PollService.missing`, `unfence`, `EXTENDABLE`, `NONCE_TTL`, `ACTION_*`, statuses, helpers `World.admin_totals`, `World.extend_proof`).
- Produces: `PollService.begin_admin_action(poll_id, *, email, action) -> str` (nonce), `submission_lines(poll_id, *, email) -> list[str]` (only for a `complete` poll), `extend(poll_id, *, email, new_day: date, nonce, proof) -> Poll`, `mark_done(poll_id, *, email, nonce, totals: dict[str, int], proof) -> Poll`, `report(poll_id) -> Poll` (refuses anything but `done`), `done_polls(channel_id) -> list[Poll]`, `expire_overdue() -> list[tuple[Poll, list[str]]]`, `due_reminders(period: timedelta) -> list[tuple[Poll, list[str]]]`, internal `_consume_nonce`, `_verify`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_polls_admin.py`:

````python
from datetime import timedelta
from typing import Any

import pytest

from helpers import (
    ADMIN_EMAIL,
    COMPANIES,
    NOT_ADMIN_EMAIL,
    SECOND_ADMIN_EMAIL,
    TEMPLATE_METRICS,
    make_world,
    owner,
)
from premday_bot import immap
from premday_bot.polls import (
    ACTION_DONE,
    ACTION_EXTEND,
    COLLECTING,
    COMPLETE,
    CREATED,
    DONE,
    INCOMPLETE,
    NONCE_TTL,
    PollError,
    poll_document,
)


def extend(world, poll, email, days, *, nonce=None, proof=None):
    new_day = (world.clock.now + timedelta(days=days)).date()
    nonce = nonce or world.service.begin_admin_action(poll.id, email=email, action=ACTION_EXTEND)
    proof = proof or world.extend_proof(poll, email, new_day, nonce)
    return world.service.extend(poll.id, email=email, new_day=new_day, nonce=nonce, proof=proof)


def validate(world, poll, email=ADMIN_EMAIL):
    nonce = world.service.begin_admin_action(poll.id, email=email, action=ACTION_DONE)
    result = world.admin_totals(poll, email, nonce)
    return world.service.mark_done(
        poll.id, email=email, nonce=nonce, totals=result["totals"], proof=result["proof"]
    )


# -- the full happy path, by either admin ----------------------------------------------------


@pytest.mark.parametrize("email", [ADMIN_EMAIL, SECOND_ADMIN_EMAIL])
def test_any_admin_can_validate_and_totals_become_readable(tmp_path, email) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    done = validate(world, poll, email)
    assert done.status == DONE and done.validated_by == email
    assert world.service.report(poll.id).totals == world.expected_totals()
    assert [p.id for p in world.service.done_polls("C1")] == [poll.id]
    assert world.service.done_polls("C_OTHER") == []


# -- visibility gate --------------------------------------------------------------------------


@pytest.mark.parametrize("stage", [CREATED, COLLECTING, COMPLETE, INCOMPLETE])
def test_report_refuses_every_status_but_done(tmp_path, stage) -> None:
    world = make_world(tmp_path)
    if stage == COMPLETE:
        poll = world.complete_poll()
    else:
        poll = world.new_poll(days=1) if stage in (CREATED, INCOMPLETE) else world.collecting_poll()
        if stage == INCOMPLETE:
            world.service.start(poll.id, user_id=owner("acme"), email=None)
            world.clock.advance(timedelta(days=3))
            world.service.expire_overdue()
    assert world.service.get(poll.id).status == stage
    with pytest.raises(PollError, match="not been validated"):
        world.service.report(poll.id)
    assert world.service.done_polls("C1") == []


def test_report_of_unknown_poll(tmp_path) -> None:
    with pytest.raises(PollError, match="could not find"):
        make_world(tmp_path).service.report("nope")


# -- authorization ----------------------------------------------------------------------------


@pytest.mark.parametrize("email", [NOT_ADMIN_EMAIL, None])
def test_non_admins_cannot_use_admin_actions(tmp_path, email) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    for action in (ACTION_EXTEND, ACTION_DONE):
        with pytest.raises(PollError, match="Only admins"):
            world.service.begin_admin_action(poll.id, email=email, action=action)
    with pytest.raises(PollError, match="Only admins"):
        world.service.submission_lines(poll.id, email=email)
    with pytest.raises(PollError, match="Only admins"):
        world.service.mark_done(poll.id, email=email, nonce="x", totals={}, proof="x")
    with pytest.raises(PollError, match="Only admins"):
        world.service.extend(
            poll.id, email=email, new_day=world.clock.now.date(), nonce="x", proof="x"
        )


def test_slack_email_alone_is_not_enough_for_done(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    result = world.admin_totals(poll, ADMIN_EMAIL, nonce)
    with pytest.raises(PollError, match="proof is invalid"):
        world.service.mark_done(
            poll.id, email=ADMIN_EMAIL, nonce=nonce, totals=result["totals"], proof="0" * 64
        )
    assert world.service.get(poll.id).status == COMPLETE


def test_a_proof_made_with_another_admins_key_is_refused(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    forged = world.admin_totals(poll, SECOND_ADMIN_EMAIL, nonce)  # second admin's proof
    with pytest.raises(PollError, match="proof is invalid"):
        world.service.mark_done(
            poll.id, email=ADMIN_EMAIL, nonce=nonce, totals=forged["totals"], proof=forged["proof"]
        )


def test_done_proof_covers_the_totals(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    result = world.admin_totals(poll, ADMIN_EMAIL, nonce)
    tampered = {**result["totals"], "host_count": result["totals"]["host_count"] + 1}
    with pytest.raises(PollError, match="proof is invalid"):
        world.service.mark_done(
            poll.id, email=ADMIN_EMAIL, nonce=nonce, totals=tampered, proof=result["proof"]
        )


def test_totals_must_match_the_metrics(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    bad_totals: list[dict[str, Any]] = [
        {},
        {"host_count": 1},
        {**dict.fromkeys(TEMPLATE_METRICS, 1), "x": 1},
        dict.fromkeys(TEMPLATE_METRICS, -1),
        dict.fromkeys(TEMPLATE_METRICS, "1"),
    ]
    for totals in bad_totals:
        nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
        with pytest.raises(PollError, match="do not match"):
            world.service.mark_done(
                poll.id, email=ADMIN_EMAIL, nonce=nonce, totals=totals, proof="x"
            )


def test_an_admin_key_registered_after_creation_cannot_act_on_older_polls(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    late = "late.admin@example.com"
    world.service._admin_emails = world.service._admin_emails | {late}
    late_key = immap.generate_private_key()
    world.service.register_admin_key(email=late, public_key=immap.public_key(late_key))
    nonce = world.service.begin_admin_action(poll.id, email=late, action=ACTION_EXTEND)
    day = (world.clock.now + timedelta(days=30)).date()
    proof = immap.make_proof(late_key, poll_document(poll), ACTION_EXTEND, day.isoformat(), nonce)
    with pytest.raises(PollError, match="not registered when this poll was created"):
        world.service.extend(poll.id, email=late, new_day=day, nonce=nonce, proof=proof)


# -- nonces -------------------------------------------------------------------------------------


def test_nonces_are_single_use_expiring_and_bound(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    updated = extend(world, poll, ADMIN_EMAIL, 14)
    # Reusing the spent nonce fails.
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    new_day = (world.clock.now + timedelta(days=20)).date()
    proof = world.extend_proof(updated, ADMIN_EMAIL, new_day, nonce)
    world.service.extend(poll.id, email=ADMIN_EMAIL, new_day=new_day, nonce=nonce, proof=proof)
    with pytest.raises(PollError, match="expired or was already used"):
        world.service.extend(poll.id, email=ADMIN_EMAIL, new_day=new_day, nonce=nonce, proof=proof)
    # A nonce issued to one admin cannot be used by the other.
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    day = (world.clock.now + timedelta(days=40)).date()
    with pytest.raises(PollError, match="expired or was already used"):
        world.service.extend(
            poll.id,
            email=SECOND_ADMIN_EMAIL,
            new_day=day,
            nonce=nonce,
            proof=world.extend_proof(updated, SECOND_ADMIN_EMAIL, day, nonce),
        )
    # An expired nonce fails.
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    world.clock.advance(NONCE_TTL + timedelta(seconds=1))
    with pytest.raises(PollError, match="expired or was already used"):
        world.service.extend(
            poll.id,
            email=ADMIN_EMAIL,
            new_day=day,
            nonce=nonce,
            proof=world.extend_proof(updated, ADMIN_EMAIL, day, nonce),
        )
    # A nonce is bound to its poll and action: an extend nonce cannot validate another poll.
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    other = world.complete_poll()
    with pytest.raises(PollError, match="expired or was already used"):
        world.service.mark_done(
            other.id, email=ADMIN_EMAIL, nonce=nonce, totals=world.expected_totals(), proof="x"
        )


def test_begin_admin_action_checks_status_and_action(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    with pytest.raises(PollError, match="complete poll"):
        world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    with pytest.raises(PollError, match="Unknown"):
        world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action="delete")
    complete = world.complete_poll()
    with pytest.raises(PollError, match="cannot be extended"):
        world.service.begin_admin_action(complete.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)


def test_submissions_are_released_only_for_a_complete_poll(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    world.submit(poll, "acme")
    with pytest.raises(PollError, match="complete poll"):
        world.service.submission_lines(poll.id, email=ADMIN_EMAIL)
    complete = world.complete_poll()
    assert len(world.service.submission_lines(complete.id, email=ADMIN_EMAIL)) == len(COMPANIES)


def test_a_done_poll_cannot_be_validated_or_extended_again(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = validate(world, world.complete_poll())
    with pytest.raises(PollError):
        world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    with pytest.raises(PollError, match="cannot be extended"):
        world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)


# -- extending ----------------------------------------------------------------------------------


def test_extend_from_created_and_collecting_keeps_the_state_and_badges_it(tmp_path) -> None:
    world = make_world(tmp_path)
    created = world.new_poll(days=2)
    extended = extend(world, created, ADMIN_EMAIL, 9)
    assert extended.status == CREATED and extended.extension_count == 1
    assert extended.deadline > extended.original_deadline == created.deadline
    collecting = world.collecting_poll()
    extended = extend(world, collecting, SECOND_ADMIN_EMAIL, 30)
    assert extended.status == COLLECTING and extended.extension_count == 1
    extended = extend(world, extended, ADMIN_EMAIL, 40)
    assert extended.extension_count == 2


def test_extend_from_incomplete_resumes_collecting_and_keeps_submissions(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll(days=1)
    world.submit(poll, "acme")
    world.submit(poll, "bolt")
    world.clock.advance(timedelta(days=3))
    [(expired, missing)] = world.service.expire_overdue()
    assert expired.status == INCOMPLETE and missing == ["corp"]
    with pytest.raises(PollError, match="incomplete"):
        world.submit(poll, "corp")
    resumed = extend(world, expired, ADMIN_EMAIL, 5)
    assert resumed.status == COLLECTING and resumed.extension_count == 1
    assert resumed.last_reminded_at == world.clock.now
    assert world.service.submitted(resumed) == ["acme", "bolt"]
    final = world.submit(resumed, "corp")
    assert final.status == COMPLETE


def test_extend_rejects_earlier_or_past_deadlines(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll(days=10)
    for days in (10, 3, -1):
        with pytest.raises(PollError, match="later than the current"):
            extend(world, poll, ADMIN_EMAIL, days)
    assert world.service.get(poll.id).extension_count == 0


def test_extend_after_deadline_needs_a_future_date(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll(days=1)
    world.clock.advance(timedelta(days=5))
    world.service.expire_overdue()
    with pytest.raises(PollError, match="later than the current"):
        extend(world, world.service.get(poll.id), ADMIN_EMAIL, -1)
    resumed = extend(world, world.service.get(poll.id), ADMIN_EMAIL, 0)  # later today is fine
    assert resumed.status == COLLECTING


def test_extend_needs_a_valid_proof(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    day = (world.clock.now + timedelta(days=30)).date()
    with pytest.raises(PollError, match="proof is invalid"):
        world.service.extend(poll.id, email=ADMIN_EMAIL, new_day=day, nonce=nonce, proof="0" * 64)
    other_day = day + timedelta(days=1)  # proof is bound to the date it was made for
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    with pytest.raises(PollError, match="proof is invalid"):
        world.service.extend(
            poll.id, email=ADMIN_EMAIL, new_day=other_day, nonce=nonce,
            proof=world.extend_proof(poll, ADMIN_EMAIL, day, nonce),
        )
    assert world.service.get(poll.id).extension_count == 0


# -- deadline and reminders ---------------------------------------------------------------------


def test_expiry_only_touches_overdue_collecting_polls(tmp_path) -> None:
    world = make_world(tmp_path)
    overdue = world.collecting_poll(days=1)
    fresh = world.collecting_poll(days=10)
    created = world.new_poll(days=1)
    world.clock.advance(timedelta(days=3))
    expired = world.service.expire_overdue()
    assert [(p.id, m) for p, m in expired] == [(overdue.id, sorted(COMPANIES))]
    assert world.service.get(fresh.id).status == COLLECTING
    assert world.service.get(created.id).status == CREATED
    assert world.service.expire_overdue() == []


def test_reminders_follow_the_period_and_only_name_missing_companies(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll(days=10)
    period = timedelta(hours=24)
    assert world.service.due_reminders(period) == []
    world.clock.advance(timedelta(hours=23))
    assert world.service.due_reminders(period) == []
    world.submit(poll, "acme")
    world.clock.advance(timedelta(hours=1))
    [(reminded, missing)] = world.service.due_reminders(period)
    assert reminded.id == poll.id and missing == ["bolt", "corp"]
    assert world.service.due_reminders(period) == []  # not again until a period has passed
    world.clock.advance(timedelta(hours=24))
    assert len(world.service.due_reminders(period)) == 1
    world.clock.advance(timedelta(hours=6))
    assert world.service.due_reminders(timedelta(hours=6)) != []  # period is configurable


def test_no_reminders_outside_collecting_or_after_the_deadline(tmp_path) -> None:
    world = make_world(tmp_path)
    world.new_poll(days=10)  # created
    complete = world.complete_poll()  # complete
    overdue = world.collecting_poll(days=1)
    world.clock.advance(timedelta(days=2))
    assert world.service.due_reminders(timedelta(hours=1)) == []
    assert world.service.get(complete.id).status == COMPLETE
    assert world.service.get(overdue.id).status == COLLECTING  # sweeper has not run yet


def test_a_proof_and_totals_pasted_with_code_fences_are_accepted(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.complete_poll()
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    result = world.admin_totals(poll, ADMIN_EMAIL, nonce)
    done = world.service.mark_done(
        poll.id,
        email=ADMIN_EMAIL,
        nonce=nonce,
        totals=result["totals"],
        proof=f"```{result['proof']}```",
    )
    assert done.status == DONE
````

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_polls_admin.py`
Expected: failures `AttributeError: 'PollService' object has no attribute 'begin_admin_action'` (or `report`, `expire_overdue`).

- [ ] **Step 3: Write the implementation**

In `src/premday_bot/polls.py`, insert this block immediately **before** the line that starts with `    # -- internals` (after the block added in Task 3):

````python
    # -- admin actions (Slack email check + admin key proof) -----------------------------------

    def begin_admin_action(self, poll_id: str, *, email: str | None, action: str) -> str:
        admin = self._require_admin(email)
        poll = self._get(poll_id)
        if action == ACTION_EXTEND and poll.status not in EXTENDABLE:
            raise PollError(f"A {poll.status} poll cannot be extended.")
        if action == ACTION_DONE and poll.status != COMPLETE:
            raise PollError("Only a complete poll can be validated.")
        if action not in (ACTION_EXTEND, ACTION_DONE):
            raise PollError("Unknown admin action.")
        nonce = secrets.token_hex(4)
        self._store.add_pending(nonce, poll.id, action, admin, self._clock() + NONCE_TTL)
        return nonce

    def submission_lines(self, poll_id: str, *, email: str | None) -> list[str]:
        self._require_admin(email)
        poll = self._get(poll_id)
        if poll.status != COMPLETE:
            raise PollError("Submissions are only released for a complete poll.")
        return list(self._store.submission_lines(poll.id).values())

    def extend(
        self, poll_id: str, *, email: str | None, new_day: date, nonce: str, proof: str
    ) -> Poll:
        admin = self._require_admin(email)
        poll = self._get(poll_id)
        self._consume_nonce(nonce, poll.id, ACTION_EXTEND, admin)
        if poll.status not in EXTENDABLE:
            raise PollError(f"A {poll.status} poll cannot be extended.")
        now = self._clock()
        new_deadline = self._end_of_day(new_day)
        if new_deadline <= max(poll.deadline, now):
            raise PollError("The new deadline must be later than the current one.")
        self._verify(poll, admin, ACTION_EXTEND, new_day.isoformat(), nonce, proof)
        updated = replace(
            poll, deadline=new_deadline, extension_count=poll.extension_count + 1
        )
        if poll.status == INCOMPLETE:
            updated = replace(updated, status=COLLECTING, last_reminded_at=now)
        return self._save(updated)

    def mark_done(
        self, poll_id: str, *, email: str | None, nonce: str, totals: dict[str, int], proof: str
    ) -> Poll:
        admin = self._require_admin(email)
        poll = self._get(poll_id)
        self._consume_nonce(nonce, poll.id, ACTION_DONE, admin)
        if poll.status != COMPLETE:
            raise PollError("Only a complete poll can be validated.")
        valid = set(totals) == set(poll.metrics) and all(
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value < immap.MODULUS
            for value in totals.values()
        )
        if not valid:
            raise PollError("The totals do not match the poll's metrics.")
        self._verify(poll, admin, ACTION_DONE, immap.totals_digest(totals), nonce, proof)
        return self._save(
            replace(
                poll,
                status=DONE,
                totals=totals,
                validated_by=admin,
                validated_at=self._clock(),
            )
        )

    # -- reading results ----------------------------------------------------------------------

    def report(self, poll_id: str) -> Poll:
        poll = self._get(poll_id)
        if poll.status != DONE:
            raise PollError("This poll has not been validated yet.")
        return poll

    def done_polls(self, channel_id: str) -> list[Poll]:
        return self._store.list_polls(status=DONE, channel_id=channel_id)

    # -- time-driven transitions ---------------------------------------------------------------

    def expire_overdue(self) -> list[tuple[Poll, list[str]]]:
        now = self._clock()
        expired = []
        for poll in self._store.list_polls(status=COLLECTING):
            if poll.deadline <= now:
                missing = self.missing(poll)
                expired.append((self._save(replace(poll, status=INCOMPLETE)), missing))
        return expired

    def due_reminders(self, period: timedelta) -> list[tuple[Poll, list[str]]]:
        now = self._clock()
        due = []
        for poll in self._store.list_polls(status=COLLECTING):
            reference = poll.last_reminded_at or poll.started_at
            missing = self.missing(poll)
            if poll.deadline > now and missing and reference and now - reference >= period:
                due.append((self._save(replace(poll, last_reminded_at=now)), missing))
        return due
````

Then insert this block at the end of `class PollService`, right after the `_end_of_day` method and before the module-level `_normalized_key` function:

````python
    def _consume_nonce(self, nonce: str, poll_id: str, action: str, admin: str) -> None:
        row = self._store.pop_pending(nonce)
        valid = (
            row is not None
            and row["poll_id"] == poll_id
            and row["action"] == action
            and row["admin_email"] == admin
            and datetime.fromisoformat(row["expires_at"]) > self._clock()
        )
        if not valid:
            raise PollError("This admin step expired or was already used. Start it again.")

    def _verify(
        self, poll: Poll, admin: str, action: str, argument: str, nonce: str, proof: str
    ) -> None:
        keys = dict(poll.admins)
        if admin not in keys:
            raise PollError("Your admin key was not registered when this poll was created.")
        ok = immap.check_proof(
            int(poll.bot_private_key, 16),
            keys[admin],
            poll_id=poll.id,
            action=action,
            argument=argument,
            nonce=nonce,
            proof=unfence(proof),
        )
        if not ok:
            raise PollError("The admin key proof is invalid.")
````

- [ ] **Step 4: Run tests, lint and types**

Run: `uv run pytest && uv run ruff check . && uv run pyright`
Expected: the whole suite passes (the 8 original tests plus the new ones). `uv run ruff check .` reports exactly three pre-existing `E501` errors in `src/premday_bot/templates.py` (lines 75, 78, 84). Leave them alone; there must be no other errors.

- [ ] **Step 5: Commit**

```bash
git add src/premday_bot/polls.py tests/test_polls_admin.py
git commit -m "Keep results hidden until an admin validates them" -m "Add admin-proof actions, validation gate, extensions, expiry and reminders." -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---
### Task 5: Slack views

**Files:**
- Create: `src/premday_bot/immap_views.py`
- Test: `tests/test_immap_views.py`

**Interfaces:**
- Consumes: Task 2/4 (`Poll`, `poll_document`, statuses, `RECOMMENDED_PARTICIPANTS`, `MAX_TITLE_LENGTH`), Task 1 (`immap.POLL_TEMPLATES`, `immap.fingerprint`).
- Produces: callback/action id constants `POLL_CALLBACK_ID, SUBMIT_CALLBACK_ID, EXTEND_CALLBACK_ID, DONE_CALLBACK_ID, START_ACTION_ID, SUBMIT_ACTION_ID, EXTEND_ACTION_ID, VALIDATE_ACTION_ID`, `HELP_TEXT`, `escape(str) -> str`, `poll_modal(*, channel_id, company_ids, default_deadline: date) -> dict` (title, template select, deadline, companies), `poll_template_label(poll) -> str`, `companies_text(companies, unattributed) -> str`, `answered_text(company_id, submitter, colleagues) -> str`, `attribute_modal(company_ids)`, `unattribute_modal()`, `notice_modal(title, text)`, `submit_modal(*, poll_id, title)`, `extend_modal(*, poll_id, nonce, current_deadline: date)`, `validate_modal(*, poll_id, nonce)`, `poll_card(poll, *, submitted, missing) -> tuple[str, list[dict]]`, `poll_json_message(poll) -> str`, `chunk_lines(lines, limit=3500) -> list[str]`, `report_text(poll) -> str` (requires `poll.totals`), `done_list_text(polls) -> str`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_immap_views.py`:

````python
from datetime import date, timedelta

from helpers import ADMIN_EMAIL, COMPANIES, make_world
from premday_bot import immap
from premday_bot.immap_views import (
    EXTEND_ACTION_ID,
    HELP_TEXT,
    START_ACTION_ID,
    SUBMIT_ACTION_ID,
    VALIDATE_ACTION_ID,
    answered_text,
    attribute_modal,
    chunk_lines,
    companies_text,
    done_list_text,
    extend_modal,
    poll_card,
    poll_json_message,
    poll_modal,
    report_text,
    submit_modal,
    unattribute_modal,
    validate_modal,
)
from premday_bot.polls import ACTION_DONE, ACTION_EXTEND, poll_document


def actions(blocks) -> list[str]:
    return [e["action_id"] for b in blocks if b["type"] == "actions" for e in b["elements"]]


def validated(world, poll):
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_DONE)
    result = world.admin_totals(poll, ADMIN_EMAIL, nonce)
    return world.service.mark_done(
        poll.id, email=ADMIN_EMAIL, nonce=nonce, totals=result["totals"], proof=result["proof"]
    )


def card(world, poll):
    return poll_card(
        poll,
        submitted=world.service.submitted(poll),
        missing=world.service.missing(poll),
    )


def test_buttons_follow_the_status(tmp_path) -> None:
    world = make_world(tmp_path)
    created = world.new_poll(days=1)
    assert actions(card(world, created)[1]) == [START_ACTION_ID, EXTEND_ACTION_ID]
    collecting = world.collecting_poll()
    assert actions(card(world, collecting)[1]) == [SUBMIT_ACTION_ID, EXTEND_ACTION_ID]
    complete = world.complete_poll()
    assert actions(card(world, complete)[1]) == [VALIDATE_ACTION_ID]
    stale = world.collecting_poll(days=1)
    world.clock.advance(timedelta(days=3))
    world.service.expire_overdue()
    incomplete = world.service.get(stale.id)
    assert actions(card(world, incomplete)[1]) == [EXTEND_ACTION_ID]
    done = validated(world, complete)
    assert actions(card(world, done)[1]) == []


def test_card_shows_progress_extension_badge_and_small_pool_warning(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.collecting_poll()
    world.submit(poll, "acme")
    text, _ = card(world, poll)
    assert "Submitted 1/3: acme" in text and "Missing: bolt, corp" in text
    assert "fewer than 10" in text and "Extended" not in text
    email = ADMIN_EMAIL
    nonce = world.service.begin_admin_action(poll.id, email=email, action=ACTION_EXTEND)
    day = (world.clock.now + timedelta(days=30)).date()
    extended = world.service.extend(
        poll.id,
        email=email,
        new_day=day,
        nonce=nonce,
        proof=world.extend_proof(poll, email, day, nonce),
    )
    text, _ = card(world, extended)
    assert "Extended \u00d71" in text and "original:" in text


def test_card_escapes_the_title_and_hides_results(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll(title="<!channel> & friends")
    text, _ = card(world, poll)
    assert "&lt;!channel&gt; &amp; friends" in text and "<!channel>" not in text


def test_complete_card_says_results_are_hidden(tmp_path) -> None:
    world = make_world(tmp_path)
    text, _ = card(world, world.complete_poll())
    assert "hidden until an admin validates" in text
    assert "Missing" not in text


def test_poll_json_message_has_fingerprints_and_no_private_key(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    message = poll_json_message(poll)
    assert poll.bot_private_key not in message
    for _, key in poll.participants:
        assert immap.fingerprint(key) in message
    assert f'"poll_id": "{poll.id}"' in message


def test_chunk_lines_keeps_lines_whole_and_under_the_limit() -> None:
    lines = ["a" * 40, "b" * 40, "c" * 40, "d" * 10]
    chunks = chunk_lines(lines, limit=85)
    assert chunks == ["a" * 40 + "\n" + "b" * 40, "c" * 40 + "\n" + "d" * 10]
    assert chunk_lines([]) == []
    assert chunk_lines(["x" * 200], limit=50) == ["x" * 200]  # never splits a line


def test_modals_carry_what_the_handlers_need() -> None:
    modal = poll_modal(
        channel_id="C1", company_ids=["acme", "bolt"], default_deadline=date(2026, 12, 1)
    )
    assert [b["block_id"] for b in modal["blocks"]] == [
        "title",
        "template",
        "deadline",
        "participants",
    ]
    template = modal["blocks"][1]["element"]
    assert [o["value"] for o in template["options"]] == list(immap.POLL_TEMPLATES)
    assert template["initial_option"] == template["options"][0]
    assert [o["value"] for o in modal["blocks"][3]["element"]["options"]] == ["acme", "bolt"]
    many = poll_modal(
        channel_id="C1",
        company_ids=[f"co-{i:03d}" for i in range(150)],
        default_deadline=date(2026, 12, 1),
    )
    assert len(many["blocks"][3]["element"]["options"]) == 100
    assert "pid" in submit_modal(poll_id="pid", title="t")["private_metadata"]
    extend = extend_modal(poll_id="pid", nonce="n0nce", current_deadline=date(2026, 12, 1))
    assert "n0nce" in extend["private_metadata"] and "n0nce" in str(extend["blocks"][0])
    validate = validate_modal(poll_id="pid", nonce="n0nce")
    assert "n0nce" in validate["private_metadata"] and "aggregate" in str(validate["blocks"][0])


def test_report_text_lists_totals_and_done_list(tmp_path) -> None:
    world = make_world(tmp_path)
    complete = world.complete_poll()
    done = validated(world, complete)
    text = report_text(done)
    assert f"host_count: {world.expected_totals()['host_count']:,} hosts" in text
    assert "validated by a.rougemont@criteo.com" in text
    assert done.id in done_list_text([done])
    assert "No validated polls" in done_list_text([])
    assert poll_document(done)["poll_id"] == done.id
    assert set(COMPANIES) <= set(text.replace(",", " ").split())


def test_card_and_report_follow_the_polls_template(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = world.new_poll()
    text, _ = poll_card(poll, submitted=[], missing=list(COMPANIES))
    assert "Template: Infrastructure footprint v1 (23 metrics)" in text
    done = validated(world, world.complete_poll())
    lines = report_text(done).split("```")[1].strip().splitlines()
    assert [line.split(":")[0] for line in lines] == list(done.metrics)  # template order


def test_companies_text_lists_members_key_holder_and_users_without_a_company(tmp_path) -> None:
    world = make_world(tmp_path)
    world.service.add_company(email=ADMIN_EMAIL, company_id="empty")
    world.service.enroll(user_id="U_COLLEAGUE", public_key=immap.public_key(7654321))
    world.service.attribute_company(email=ADMIN_EMAIL, company_id="acme", user_id="U_COLLEAGUE")
    world.service.enroll(user_id="U_WAITING", public_key=immap.public_key(1234567))
    text = companies_text(
        world.service.companies(email=ADMIN_EMAIL),
        world.service.unattributed_users(email=ADMIN_EMAIL),
    )
    assert "*Companies (4)*" in text
    key = immap.public_key(world.company_keys["acme"])
    assert f"`acme`: <@U_ACME> (key holder, key `{immap.fingerprint(key)}`), <@U_COLLEAGUE>" in text
    assert "`empty`: _no member_" in text
    assert "*Enrolled, without a company:* <@U_WAITING>" in text
    assert "none yet" in companies_text([], [])


def test_answered_text_mentions_the_colleagues_and_names_the_submitter() -> None:
    text = answered_text("acme", "U_ONE", ["U_TWO", "U_THREE"])
    assert text.startswith("<@U_TWO> <@U_THREE> <@U_ONE> submitted the values of *acme*")
    assert "replaces it" in text
    assert "&lt;" in answered_text("a<b", "U_ONE", ["U_TWO"])


def test_attribute_modal_and_help_cover_company_management() -> None:
    modal = attribute_modal(["acme", "bolt"])
    assert [b["block_id"] for b in modal["blocks"]] == ["company", "user"]
    assert [o["value"] for o in modal["blocks"][0]["element"]["options"]] == ["acme", "bolt"]
    assert modal["blocks"][1]["element"]["type"] == "users_select"
    assert unattribute_modal()["blocks"][0]["element"]["type"] == "users_select"
    for command in ("register <public_key>", "companies", "company add", "company remove",
                    "company attribute", "company unattribute"):
        assert f"/immap {command}" in HELP_TEXT
````

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_immap_views.py`
Expected: collection error `ModuleNotFoundError: No module named 'premday_bot.immap_views'`.

- [ ] **Step 3: Write the implementation**

Create `src/premday_bot/immap_views.py`:

````python
from __future__ import annotations

import json
from datetime import date

from premday_bot import immap
from premday_bot.polls import (
    COLLECTING,
    COMPLETE,
    CREATED,
    DONE,
    INCOMPLETE,
    MAX_TITLE_LENGTH,
    RECOMMENDED_PARTICIPANTS,
    Company,
    Poll,
    poll_document,
)

POLL_CALLBACK_ID = "immap_poll"
SUBMIT_CALLBACK_ID = "immap_submit"
EXTEND_CALLBACK_ID = "immap_extend"
DONE_CALLBACK_ID = "immap_done"
ATTRIBUTE_CALLBACK_ID = "immap_attribute"
UNATTRIBUTE_CALLBACK_ID = "immap_unattribute"
START_ACTION_ID = "immap_start"
SUBMIT_ACTION_ID = "immap_submit_open"
EXTEND_ACTION_ID = "immap_extend_open"
VALIDATE_ACTION_ID = "immap_validate_open"

TIMES = "\N{MULTIPLICATION SIGN}"
MAX_SELECT_OPTIONS = 100
SLACK_CHUNK_LIMIT = 3500

STATUS_LABELS = {
    CREATED: ":hourglass: Created, not started",
    COLLECTING: ":inbox_tray: Collecting",
    COMPLETE: ":lock: Complete, awaiting admin validation",
    INCOMPLETE: ":warning: Incomplete, deadline passed",
    DONE: ":white_check_mark: Done",
}

HELP_TEXT = (
    "*IMMAP polls*\n"
    "• `/immap register <public_key>` enrolls you; an admin then adds you to your company\n"
    "• `/immap poll` creates a poll\n"
    "• `/immap report [poll_id]` shows validated results\n"
    "*Admins only*\n"
    "• `/immap admin-register <public_key>` registers an admin key\n"
    "• `/immap companies` lists the companies, their members and who has no company yet\n"
    "• `/immap company add <company_id>` and `/immap company remove <company_id>`\n"
    "• `/immap company attribute` adds an enrolled user to a company (first = key holder)\n"
    "• `/immap company unattribute` removes a member from their company"
)


def escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _plain(text: str) -> dict[str, str]:
    return {"type": "plain_text", "text": text}


def _text_input(block_id: str, label: str, *, multiline: bool = False, max_length: int = 3000):
    return {
        "type": "input",
        "block_id": block_id,
        "label": _plain(label),
        "element": {
            "type": "plain_text_input",
            "action_id": "value",
            "multiline": multiline,
            "max_length": max_length,
        },
    }


def companies_text(companies: list[Company], unattributed: list[str]) -> str:
    rows = []
    for company in companies:
        if company.members and company.public_key:
            holder, *others = company.members
            people = [f"<@{holder}> (key holder, key `{immap.fingerprint(company.public_key)}`)"]
            people += [f"<@{user}>" for user in others]
            rows.append(f"• `{company.company_id}`: " + ", ".join(people))
        else:
            rows.append(f"• `{company.company_id}`: _no member_")
    lines = [f"*Companies ({len(companies)})*", *(rows or ["_none yet: `/immap company add`_"])]
    if unattributed:
        mentions = " ".join(f"<@{user}>" for user in unattributed)
        lines.append(f"*Enrolled, without a company:* {mentions}")
    return "\n".join(lines)


def answered_text(company_id: str, submitter: str, colleagues: list[str]) -> str:
    """Tells the other members of a company that a colleague submitted for it."""
    mentions = " ".join(f"<@{user}>" for user in colleagues)
    return (
        f"{mentions} <@{submitter}> submitted the values of *{escape(company_id)}*; "
        "you do not need to. A new submission before the deadline replaces it."
    )


def attribute_modal(company_ids: list[str]) -> dict:
    options = [{"text": _plain(company), "value": company} for company in company_ids]
    return {
        "type": "modal",
        "callback_id": ATTRIBUTE_CALLBACK_ID,
        "title": _plain("Attribute a company"),
        "submit": _plain("Attribute"),
        "close": _plain("Cancel"),
        "blocks": [
            {
                "type": "input",
                "block_id": "company",
                "label": _plain("Company"),
                "element": {
                    "type": "static_select",
                    "action_id": "value",
                    "placeholder": _plain("Choose a company"),
                    "options": options[:MAX_SELECT_OPTIONS],
                },
            },
            {
                "type": "input",
                "block_id": "user",
                "label": _plain("Enrolled user to add as a member"),
                "element": {"type": "users_select", "action_id": "value"},
            },
        ],
    }


def unattribute_modal() -> dict:
    return {
        "type": "modal",
        "callback_id": UNATTRIBUTE_CALLBACK_ID,
        "title": _plain("Remove a member"),
        "submit": _plain("Remove"),
        "close": _plain("Cancel"),
        "blocks": [
            {
                "type": "input",
                "block_id": "user",
                "label": _plain("Member to remove from their company"),
                "element": {"type": "users_select", "action_id": "value"},
            }
        ],
    }


def notice_modal(title: str, text: str) -> dict:
    return {
        "type": "modal",
        "title": _plain(title),
        "close": _plain("Close"),
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
    }


def poll_modal(*, channel_id: str, company_ids: list[str], default_deadline: date) -> dict:
    options = [{"text": _plain(company), "value": company} for company in company_ids]
    template_options = [
        {
            "text": _plain(f"{template.title} ({len(template.metrics)} metrics)"),
            "value": template.id,
        }
        for template in immap.POLL_TEMPLATES.values()
    ]
    return {
        "type": "modal",
        "callback_id": POLL_CALLBACK_ID,
        "title": _plain("IMMAP poll"),
        "submit": _plain("Create"),
        "close": _plain("Cancel"),
        "private_metadata": json.dumps({"channel_id": channel_id}),
        "blocks": [
            {
                "type": "input",
                "block_id": "title",
                "label": _plain("Title"),
                "element": {
                    "type": "plain_text_input",
                    "action_id": "value",
                    "initial_value": "Infrastructure metrics",
                    "max_length": MAX_TITLE_LENGTH,
                },
            },
            {
                "type": "input",
                "block_id": "template",
                "label": _plain("Template"),
                "element": {
                    "type": "static_select",
                    "action_id": "value",
                    "initial_option": template_options[0],
                    "options": template_options,
                },
            },
            {
                "type": "input",
                "block_id": "deadline",
                "label": _plain("Deadline (end of day)"),
                "element": {
                    "type": "datepicker",
                    "action_id": "value",
                    "initial_date": default_deadline.isoformat(),
                },
            },
            {
                "type": "input",
                "block_id": "participants",
                "label": _plain("Companies"),
                "element": {
                    "type": "multi_static_select",
                    "action_id": "value",
                    "placeholder": _plain("Choose registered companies"),
                    "options": options[:MAX_SELECT_OPTIONS],
                },
            },
        ],
    }


def submit_modal(*, poll_id: str, title: str) -> dict:
    return {
        "type": "modal",
        "callback_id": SUBMIT_CALLBACK_ID,
        "title": _plain("Submit your values"),
        "submit": _plain("Submit"),
        "close": _plain("Cancel"),
        "private_metadata": json.dumps({"poll_id": poll_id}),
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{escape(title)}*\nPaste the line printed by "
                        "`python immap.py submit poll.json values.json`."
                    ),
                },
            },
            _text_input("line", "Submission line", multiline=True),
        ],
    }


def extend_modal(*, poll_id: str, nonce: str, current_deadline: date) -> dict:
    return {
        "type": "modal",
        "callback_id": EXTEND_CALLBACK_ID,
        "title": _plain("Extend deadline"),
        "submit": _plain("Extend"),
        "close": _plain("Cancel"),
        "private_metadata": json.dumps({"poll_id": poll_id, "nonce": nonce}),
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"Current deadline: *{current_deadline.isoformat()}*. Pick the new date, "
                        "then prove it with your admin key:\n"
                        f"```python immap.py proof poll.json --action extend "
                        f"--argument YYYY-MM-DD --nonce {nonce} --key admin.key```"
                    ),
                },
            },
            {
                "type": "input",
                "block_id": "date",
                "label": _plain("New deadline"),
                "element": {"type": "datepicker", "action_id": "value"},
            },
            _text_input("proof", "Proof", max_length=200),
        ],
    }


def validate_modal(*, poll_id: str, nonce: str) -> dict:
    return {
        "type": "modal",
        "callback_id": DONE_CALLBACK_ID,
        "title": _plain("Validate results"),
        "submit": _plain("Mark done"),
        "close": _plain("Cancel"),
        "private_metadata": json.dumps({"poll_id": poll_id, "nonce": nonce}),
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "I sent you the sealed submissions privately. Save them to `lines.txt` "
                        "(one per line), then run:\n"
                        f"```python immap.py aggregate poll.json lines.txt --nonce {nonce} "
                        "--key admin.key```\nPaste its whole output below."
                    ),
                },
            },
            _text_input("result", "Aggregate output", multiline=True),
        ],
    }


def poll_template_label(poll: Poll) -> str:
    template = immap.POLL_TEMPLATES.get(poll.template)
    title = template.title if template else poll.template
    return f"{escape(title)} v{poll.schema_version} ({len(poll.metrics)} metrics)"


def poll_card(poll: Poll, *, submitted: list[str], missing: list[str]) -> tuple[str, list[dict]]:
    label = STATUS_LABELS[poll.status]
    lines = [f"*{escape(poll.title)}* · `{poll.id}` · {label}"]
    deadline = f"Deadline: {poll.deadline.date().isoformat()}"
    if poll.extension_count:
        deadline += (
            f" · *Extended {TIMES}{poll.extension_count}* "
            f"(original: {poll.original_deadline.date().isoformat()})"
        )
    lines.append(deadline)
    lines.append(f"Template: {poll_template_label(poll)}")
    total = len(poll.participants)
    if poll.status in (COLLECTING, COMPLETE, INCOMPLETE):
        lines.append(f"Submitted {len(submitted)}/{total}: {', '.join(submitted) or 'nobody yet'}")
        if missing and poll.status != COMPLETE:
            lines.append(f"Missing: {', '.join(missing)}")
    else:
        lines.append(f"Companies ({total}): {', '.join(poll.participant_ids)}")
    if poll.status == COMPLETE:
        lines.append("Results stay hidden until an admin validates them.")
    if total < RECOMMENDED_PARTICIPANTS:
        lines.append(
            f":information_source: With fewer than {RECOMMENDED_PARTICIPANTS} companies the "
            "totals may allow educated guesses."
        )
    text = "\n".join(lines)
    blocks: list[dict] = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
    buttons = _buttons(poll)
    if buttons:
        blocks.append({"type": "actions", "elements": buttons})
    return text, blocks


def _button(text: str, action_id: str, poll_id: str, style: str | None = None) -> dict:
    button = {"type": "button", "text": _plain(text), "action_id": action_id, "value": poll_id}
    if style:
        button["style"] = style
    return button


def _buttons(poll: Poll) -> list[dict]:
    if poll.status == CREATED:
        return [
            _button("Start collecting", START_ACTION_ID, poll.id, "primary"),
            _button("Extend deadline", EXTEND_ACTION_ID, poll.id),
        ]
    if poll.status == COLLECTING:
        return [
            _button("Submit", SUBMIT_ACTION_ID, poll.id, "primary"),
            _button("Extend deadline", EXTEND_ACTION_ID, poll.id),
        ]
    if poll.status == COMPLETE:
        return [_button("Validate", VALIDATE_ACTION_ID, poll.id, "primary")]
    if poll.status == INCOMPLETE:
        return [_button("Extend deadline", EXTEND_ACTION_ID, poll.id, "primary")]
    return []


def poll_json_message(poll: Poll) -> str:
    document = poll_document(poll)
    fingerprints = [
        f"• {item['company_id']}: `{immap.fingerprint(item['public_key'])}`"
        for item in document["participants"]
    ] + [
        f"• admin {item['admin_id']}: `{immap.fingerprint(item['public_key'])}`"
        for item in document["admins"]
    ]
    return (
        f"Poll `{poll.id}`: save this as `poll.json`, then follow the README. Check that the "
        "fingerprint of *your* key matches the one you registered:\n"
        + "\n".join(fingerprints)
        + f"\n```{json.dumps(document, indent=2)}```"
    )


def chunk_lines(lines: list[str], limit: int = SLACK_CHUNK_LIMIT) -> list[str]:
    """Group whole lines into messages no longer than ``limit`` characters."""
    chunks: list[str] = []
    current: list[str] = []
    size = 0
    for line in lines:
        if current and size + len(line) + 1 > limit:
            chunks.append("\n".join(current))
            current, size = [], 0
        current.append(line)
        size += len(line) + 1
    if current:
        chunks.append("\n".join(current))
    return chunks


def report_text(poll: Poll) -> str:
    assert poll.totals is not None
    rows = [
        f"{name}: {poll.totals[name]:,} {unit}" for name, unit in poll.metrics.items()
    ]
    validator = escape(poll.validated_by or "?")
    header = f"*{escape(poll.title)}* · `{poll.id}` · validated by {validator}"
    if poll.extension_count:
        header += f" · Extended {TIMES}{poll.extension_count}"
    return f"{header}\nCompanies: {', '.join(poll.participant_ids)}\n```" + "\n".join(rows) + "```"


def done_list_text(polls: list[Poll]) -> str:
    if not polls:
        return "No validated polls in this channel yet."
    rows = [
        f"• `{poll.id}` {escape(poll.title)} (deadline {poll.deadline.date()})" for poll in polls
    ]
    footer = "Use `/immap report <poll_id>` for the totals."
    return "*Validated polls*\n" + "\n".join(rows) + "\n" + footer
````

- [ ] **Step 4: Run tests, lint and types**

Run: `uv run pytest && uv run ruff check . && uv run pyright`
Expected: all tests pass. `uv run ruff check .` reports exactly three pre-existing `E501` errors in `src/premday_bot/templates.py` (lines 75, 78, 84). Leave them alone; there must be no other errors.

- [ ] **Step 5: Commit**

```bash
git add src/premday_bot/immap_views.py tests/test_immap_views.py
git commit -m "Let people drive polls from Slack" -m "Add modals, poll card, poll.json message, company list and reports." -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---
### Task 6: Settings, Slack handlers and sweeper

**Files:**
- Modify: `src/premday_bot/config.py`
- Create: `src/premday_bot/immap_slack.py`
- Test: `tests/test_config.py`, `tests/test_immap_slack.py`

**Interfaces:**
- Consumes: Tasks 2-5 (`PollService` methods, `PollError`, `unfence`, views and id constants), `Settings`.
- Produces: `Settings.immap_reminder_hours: int = 24` and `Settings.immap_admin_emails: frozenset[str] = frozenset()` (lowercased); in `immap_slack`: `parse_command(text) -> tuple[str, list[str]]`, `poll_error_block(message) -> str`, `extend_error_block(message) -> str`, `email_of(client, user_id) -> str | None`, `refresh_card(client, polls, poll_id)`, `post_in_thread(client, polls, poll_id, text)`, `sweep_once(client, polls, reminder_period: timedelta)`, `run_sweeper(client, polls, reminder_period)`, `register_immap(app, polls, settings)` (registers `/immap`, six views and four button actions: 11 listeners).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_config.py`:

````python
import pytest

from premday_bot.config import Settings


@pytest.fixture(autouse=True)
def slack_tokens(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)  # no stray .env
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    monkeypatch.setenv("SLACK_APP_TOKEN", "xapp-test")
    monkeypatch.delenv("IMMAP_REMINDER_HOURS", raising=False)
    monkeypatch.delenv("IMMAP_ADMIN_EMAILS", raising=False)


def test_immap_settings_defaults() -> None:
    settings = Settings.from_env()
    assert settings.immap_reminder_hours == 24
    assert settings.immap_admin_emails == frozenset()


def test_immap_settings_are_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IMMAP_REMINDER_HOURS", "6")
    monkeypatch.setenv("IMMAP_ADMIN_EMAILS", " A.Rougemont@Criteo.com, second@example.org ,,")
    settings = Settings.from_env()
    assert settings.immap_reminder_hours == 6
    assert settings.immap_admin_emails == {"a.rougemont@criteo.com", "second@example.org"}


@pytest.mark.parametrize("value", ["0", "-3"])
def test_reminder_period_must_be_positive(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("IMMAP_REMINDER_HOURS", value)
    with pytest.raises(RuntimeError, match="at least 1"):
        Settings.from_env()
````

Create `tests/test_immap_slack.py`:

````python
import asyncio
import json
from datetime import timedelta
from typing import Any, cast

from slack_bolt.async_app import AsyncApp
from slack_sdk.web.async_client import AsyncWebClient

from helpers import ADMIN_EMAIL, make_world, owner
from premday_bot import immap
from premday_bot.config import Settings
from premday_bot.immap_slack import (
    email_of,
    extend_error_block,
    parse_command,
    poll_error_block,
    refresh_card,
    register_immap,
    sweep_once,
)
from premday_bot.immap_views import (
    ATTRIBUTE_CALLBACK_ID,
    SUBMIT_CALLBACK_ID,
    UNATTRIBUTE_CALLBACK_ID,
)
from premday_bot.polls import ACTION_EXTEND, COLLECTING, INCOMPLETE


class FakeClient:
    def __init__(self) -> None:
        self.updates: list[dict] = []
        self.messages: list[dict] = []
        self.profile_email: str | None = ADMIN_EMAIL
        self.fail_profile = False

    async def chat_update(self, **kwargs) -> None:
        self.updates.append(kwargs)

    async def chat_postMessage(self, **kwargs) -> dict:
        self.messages.append(kwargs)
        return {"ts": "1.1"}

    async def users_info(self, user: str) -> dict:
        if self.fail_profile:
            raise RuntimeError("slack down")
        return {"user": {"profile": {"email": self.profile_email}}}


def web(client: FakeClient) -> AsyncWebClient:
    return cast(AsyncWebClient, client)


def with_card(world, poll):
    return world.service.set_message_ts(poll.id, "9.9")


def run(coroutine):
    return asyncio.run(coroutine)


def test_parse_command() -> None:
    assert parse_command("") == ("", [])
    assert parse_command("  Register acme abc ") == ("register", ["acme", "abc"])
    assert parse_command("poll") == ("poll", [])


def test_error_messages_are_routed_to_the_right_input() -> None:
    assert poll_error_block("Add a title.") == "title"
    assert poll_error_block("Choose one of the poll templates.") == "template"
    assert poll_error_block("The deadline must be in the future.") == "deadline"
    assert poll_error_block("A poll needs at least 3 companies.") == "participants"
    assert extend_error_block("The new deadline must be later than the current one.") == "date"
    assert extend_error_block("The admin key proof is invalid.") == "proof"


def test_email_of_reads_the_profile_and_survives_failures() -> None:
    client = FakeClient()
    assert run(email_of(web(client), "U1")) == ADMIN_EMAIL
    client.profile_email = None
    assert run(email_of(web(client), "U1")) is None
    client.fail_profile = True
    assert run(email_of(web(client), "U1")) is None


def test_refresh_card_updates_the_poll_message(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = with_card(world, world.collecting_poll())
    client = FakeClient()
    run(refresh_card(web(client), world.service, poll.id))
    assert client.updates[0]["ts"] == "9.9" and client.updates[0]["channel"] == "C1"
    world2 = make_world(tmp_path / "other")
    run(refresh_card(web(client), world2.service, world2.new_poll().id))  # no card yet: no call
    assert len(client.updates) == 1


def test_sweep_expires_overdue_polls_and_announces_who_is_missing(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = with_card(world, world.collecting_poll(days=1))
    world.submit(poll, "acme")
    world.clock.advance(timedelta(days=3))
    client = FakeClient()
    run(sweep_once(web(client), world.service, timedelta(hours=24)))
    assert world.service.get(poll.id).status == INCOMPLETE
    assert "bolt, corp" in client.messages[0]["text"] and client.messages[0]["thread_ts"] == "9.9"
    assert len(client.updates) == 1
    run(sweep_once(web(client), world.service, timedelta(hours=24)))
    assert len(client.messages) == 1  # nothing more to do


def test_sweep_pings_the_owners_of_missing_companies_once_per_period(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = with_card(world, world.collecting_poll(days=10))
    world.submit(poll, "acme")
    client = FakeClient()
    period = timedelta(hours=24)
    run(sweep_once(web(client), world.service, period))
    assert client.messages == []
    world.clock.advance(timedelta(hours=25))
    run(sweep_once(web(client), world.service, period))
    [message] = client.messages
    assert f"<@{owner('bolt')}>" in message["text"] and f"<@{owner('corp')}>" in message["text"]
    assert f"<@{owner('acme')}>" not in message["text"]
    run(sweep_once(web(client), world.service, period))
    assert len(client.messages) == 1


def test_an_extended_poll_is_reminded_again(tmp_path) -> None:
    world = make_world(tmp_path)
    poll = with_card(world, world.collecting_poll(days=1))
    world.clock.advance(timedelta(days=3))
    client = FakeClient()
    run(sweep_once(web(client), world.service, timedelta(hours=24)))
    day = (world.clock.now + timedelta(days=5)).date()
    nonce = world.service.begin_admin_action(poll.id, email=ADMIN_EMAIL, action=ACTION_EXTEND)
    world.service.extend(
        poll.id, email=ADMIN_EMAIL, new_day=day, nonce=nonce,
        proof=world.extend_proof(world.service.get(poll.id), ADMIN_EMAIL, day, nonce),
    )
    assert world.service.get(poll.id).status == COLLECTING
    world.clock.advance(timedelta(hours=25))
    client.messages.clear()
    run(sweep_once(web(client), world.service, timedelta(hours=24)))
    assert "Reminder" in client.messages[0]["text"]


def test_handlers_register_on_a_bolt_app(tmp_path) -> None:
    world = make_world(tmp_path)
    app = AsyncApp(token="xoxb-test")
    settings = Settings(
        slack_bot_token="xoxb-test", slack_app_token="xapp-test", slack_team_id=None,
        timezone="Europe/Paris", default_hour=18, default_duration_minutes=90,
        db_path=tmp_path / "x.sqlite3", smtp_host=None, smtp_port=587, smtp_username=None,
        smtp_password=None, smtp_use_tls=True, smtp_use_ssl=False, email_from=None,
    )
    register_immap(app, world.service, settings)
    # one command, six views and four buttons
    assert len(app._async_listeners) == 11


class CapturingApp:
    """Collects the handlers `register_immap` declares so tests can call them directly."""

    def __init__(self) -> None:
        self.handlers: dict[str, object] = {}

    def command(self, name):
        return self._remember(name)

    def view(self, callback_id):
        return self._remember(callback_id)

    def action(self, action_id):
        return self._remember(action_id)

    def _remember(self, key):
        def decorator(function):
            self.handlers[key] = function
            return function

        return decorator


class Reply:
    def __init__(self) -> None:
        self.texts: list[str] = []
        self.acks: list[dict] = []

    async def respond(self, text: str, response_type: str) -> None:
        self.texts.append(text)

    async def ack(self, **kwargs) -> None:
        self.acks.append(kwargs)


def command_driver(tmp_path):
    world = make_world(tmp_path)
    app = CapturingApp()
    settings = Settings(
        slack_bot_token="xoxb-test", slack_app_token="xapp-test", slack_team_id=None,
        timezone="Europe/Paris", default_hour=18, default_duration_minutes=90,
        db_path=tmp_path / "x.sqlite3", smtp_host=None, smtp_port=587, smtp_username=None,
        smtp_password=None, smtp_use_tls=True, smtp_use_ssl=False, email_from=None,
    )
    register_immap(cast(AsyncApp, app), world.service, settings)
    client = FakeClient()
    opened: list[dict] = []

    async def views_open(**kwargs) -> None:
        opened.append(kwargs)

    client.views_open = views_open  # type: ignore[attr-defined]

    def say(user_id: str, text: str, email: str | None = ADMIN_EMAIL) -> Reply:
        client.profile_email = email
        reply = Reply()
        body = {"user_id": user_id, "channel_id": "C1", "trigger_id": "T1"}
        handler = cast(Any, app.handlers["/immap"])
        run(handler(reply.ack, body, {"text": text}, reply.respond, web(client)))
        return reply

    return world, app, client, opened, say


def test_users_enroll_and_admins_manage_companies_through_the_command(tmp_path) -> None:
    _, _, _, opened, say = command_driver(tmp_path)
    key = immap.public_key(immap.generate_private_key())
    assert "Enrolled" in say("U_NEW", f"register {key}", email=None).texts[0]
    assert "Only admins" in say("U_NEW", "companies", email="x@example.com").texts[0]
    assert "<@U_NEW>" in say("U_ADMIN", "companies").texts[0]  # listed as not attributed
    assert "Added `newco`" in say("U_ADMIN", "company add newco").texts[0]
    assert "already exists" in say("U_ADMIN", "company add newco").texts[0]
    assert "Only admins" in say("U_NEW", "company add other", email="x@example.com").texts[0]
    say("U_ADMIN", "company attribute")
    modal = opened[0]["view"]
    assert [o["value"] for o in modal["blocks"][0]["element"]["options"]][-1] == "newco"
    assert "Removed `newco`" in say("U_ADMIN", "company remove newco").texts[0]
    say("U_ADMIN", "company unattribute")
    assert opened[1]["view"]["callback_id"] == UNATTRIBUTE_CALLBACK_ID
    assert "Only admins" in say("U_NEW", "company unattribute", email="x@example.com").texts[0]
    assert "Only admins" in say("U_ADMIN", "company attribute", email=None).texts[0]
    assert "IMMAP polls" in say("U_NEW", "register acme abc").texts[0]  # the old 2-arg form


def test_the_attribute_modal_attributes_and_reports_errors(tmp_path) -> None:
    world, app, client, _, _ = command_driver(tmp_path)
    world.service.add_company(email=ADMIN_EMAIL, company_id="newco")
    world.service.enroll(user_id="U_NEW", public_key=immap.public_key(1234567))
    handler = cast(Any, app.handlers[ATTRIBUTE_CALLBACK_ID])

    def submit(company: str, user: str, email: str | None = ADMIN_EMAIL) -> Reply:
        client.profile_email = email
        view = {"state": {"values": {
            "company": {"value": {"selected_option": {"value": company}}},
            "user": {"value": {"selected_user": user}},
        }}}
        reply = Reply()
        run(handler(reply.ack, {"user": {"id": "U_ADMIN"}}, view, web(client)))
        return reply

    assert "not enrolled" in submit("newco", "U_STRANGER").acks[0]["errors"]["user"]
    refused = submit("newco", "U_NEW", email="x@example.com")
    assert "Only admins" in refused.acks[0]["errors"]["user"]
    done = submit("newco", "U_NEW").acks[0]
    assert done["response_action"] == "update" and "<@U_NEW>" in str(done["view"])
    assert world.service.members_of("newco") == ["U_NEW"]


def test_removing_a_member_through_the_modal(tmp_path) -> None:
    _, app, client, _, _ = command_driver(tmp_path)
    handler = cast(Any, app.handlers[UNATTRIBUTE_CALLBACK_ID])

    def submit(user: str, email: str | None = ADMIN_EMAIL) -> Reply:
        client.profile_email = email
        view = {"state": {"values": {"user": {"value": {"selected_user": user}}}}}
        reply = Reply()
        run(handler(reply.ack, {"user": {"id": "U_ADMIN"}}, view, web(client)))
        return reply

    assert "does not belong" in submit("U_STRANGER").acks[0]["errors"]["user"]
    assert "Only admins" in submit(owner("bolt"), email="x@example.com").acks[0]["errors"]["user"]
    done = submit(owner("bolt")).acks[0]
    assert done["response_action"] == "update" and "bolt" in str(done["view"])


def test_colleagues_learn_when_a_member_of_their_company_submits(tmp_path) -> None:
    world, app, client, _, _ = command_driver(tmp_path)
    world.service.enroll(user_id="U_ACME_2", public_key=immap.public_key(1111111))
    world.service.enroll(user_id="U_ACME_3", public_key=immap.public_key(2222222))
    for user in ("U_ACME_2", "U_ACME_3"):
        world.service.attribute_company(email=ADMIN_EMAIL, company_id="acme", user_id=user)
    poll = with_card(world, world.collecting_poll())
    handler = cast(Any, app.handlers[SUBMIT_CALLBACK_ID])

    def submit(user: str, company_id: str) -> Reply:
        view = {
            "private_metadata": json.dumps({"poll_id": poll.id}),
            "state": {"values": {"line": {"value": {"value": world.line(poll, company_id)}}}},
        }
        reply = Reply()
        run(handler(reply.ack, {"user": {"id": user}}, view, web(client)))
        return reply

    # A colleague (not the key holder) submits for acme: the other two members are told.
    assert submit("U_ACME_2", "acme").acks == [{}]
    notices = [m for m in client.messages if m.get("thread_ts") == "9.9"]
    assert len(notices) == 1
    assert "<@U_ACME> <@U_ACME_3> <@U_ACME_2> submitted the values of *acme*" in notices[0]["text"]
    assert notices[0]["channel"] == poll.channel_id
    # A company with a single member has nobody to tell.
    client.messages.clear()
    submit(owner("bolt"), "bolt")
    assert [m for m in client.messages if "submitted the values" in m["text"]] == []
    # Someone outside the company cannot answer for it.
    refused = submit(owner("corp"), "acme")
    assert "not a member of `acme`" in refused.acks[0]["errors"]["line"]


def test_reminders_mention_every_member_of_a_missing_company(tmp_path) -> None:
    world = make_world(tmp_path)
    world.service.enroll(user_id="U_ACME_2", public_key=immap.public_key(1111111))
    world.service.attribute_company(email=ADMIN_EMAIL, company_id="acme", user_id="U_ACME_2")
    poll = with_card(world, world.collecting_poll())
    client = FakeClient()
    world.clock.advance(timedelta(hours=25))
    run(sweep_once(web(client), world.service, timedelta(hours=24)))
    reminder = next(m["text"] for m in client.messages if "Reminder" in m["text"])
    assert "<@U_ACME> <@U_ACME_2>" in reminder and poll.id
````

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_config.py tests/test_immap_slack.py`
Expected: `test_config` fails with `AttributeError: 'Settings' object has no attribute 'immap_reminder_hours'`; `test_immap_slack` fails at collection with `ModuleNotFoundError: No module named 'premday_bot.immap_slack'`.

- [ ] **Step 3: Write the implementation**

Apply these four edits to `src/premday_bot/config.py`.

Add before `@dataclass(frozen=True)\nclass Settings:`:

````python
def _email_set_env(name: str) -> frozenset[str]:
    raw = os.getenv(name, "")
    return frozenset(item.strip().lower() for item in raw.split(",") if item.strip())


````

Add two fields after `rsvp_smtp_port: int = 8025`:

````python
    immap_reminder_hours: int = 24
    immap_admin_emails: frozenset[str] = frozenset()
````

Replace the start of `from_env`:

````python
    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv()
        reminder_hours = _int_env("IMMAP_REMINDER_HOURS", 24)
        if reminder_hours < 1:
            raise RuntimeError("IMMAP_REMINDER_HOURS must be at least 1")
        return cls(
````

and add two arguments after `rsvp_smtp_port=_int_env("RSVP_SMTP_PORT", 8025),`:

````python
            immap_reminder_hours=reminder_hours,
            immap_admin_emails=_email_set_env("IMMAP_ADMIN_EMAILS"),
````

Create `src/premday_bot/immap_slack.py`:

````python
from __future__ import annotations

import asyncio
import json
import logging
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from slack_bolt.async_app import AsyncApp
from slack_sdk.web.async_client import AsyncWebClient

from premday_bot.config import Settings
from premday_bot.immap_views import (
    ATTRIBUTE_CALLBACK_ID,
    DONE_CALLBACK_ID,
    EXTEND_ACTION_ID,
    EXTEND_CALLBACK_ID,
    HELP_TEXT,
    POLL_CALLBACK_ID,
    START_ACTION_ID,
    SUBMIT_ACTION_ID,
    SUBMIT_CALLBACK_ID,
    UNATTRIBUTE_CALLBACK_ID,
    VALIDATE_ACTION_ID,
    answered_text,
    attribute_modal,
    chunk_lines,
    companies_text,
    done_list_text,
    extend_modal,
    notice_modal,
    poll_card,
    poll_json_message,
    poll_modal,
    report_text,
    submit_modal,
    unattribute_modal,
    validate_modal,
)
from premday_bot.polls import (
    ACTION_DONE,
    ACTION_EXTEND,
    COMPLETE,
    PollError,
    PollService,
    unfence,
)

LOGGER = logging.getLogger(__name__)
SWEEP_INTERVAL_SECONDS = 60


def parse_command(text: str) -> tuple[str, list[str]]:
    """Split ``/immap`` text into a lowercase subcommand and its arguments."""
    parts = (text or "").split()
    return (parts[0].lower(), parts[1:]) if parts else ("", [])


def poll_error_block(message: str) -> str:
    """Pick the poll-modal input an error message belongs to."""
    lowered = message.lower()
    if "title" in lowered:
        return "title"
    if "template" in lowered:
        return "template"
    if "deadline" in lowered:
        return "deadline"
    return "participants"


def extend_error_block(message: str) -> str:
    return "date" if "deadline" in message.lower() else "proof"


async def email_of(client: AsyncWebClient, user_id: str) -> str | None:
    try:
        response = await client.users_info(user=user_id)
    except Exception:
        LOGGER.warning("Could not read the Slack profile of %s", user_id)
        return None
    email = response.get("user", {}).get("profile", {}).get("email")
    return email if isinstance(email, str) else None


async def refresh_card(client: AsyncWebClient, polls: PollService, poll_id: str) -> None:
    poll = polls.get(poll_id)
    if not poll.message_ts:
        return
    text, blocks = poll_card(
        poll, submitted=polls.submitted(poll), missing=polls.missing(poll)
    )
    await client.chat_update(channel=poll.channel_id, ts=poll.message_ts, text=text, blocks=blocks)


async def post_in_thread(
    client: AsyncWebClient, polls: PollService, poll_id: str, text: str
) -> None:
    poll = polls.get(poll_id)
    if poll.message_ts:
        await client.chat_postMessage(
            channel=poll.channel_id, thread_ts=poll.message_ts, text=text
        )


async def sweep_once(
    client: AsyncWebClient, polls: PollService, reminder_period: timedelta
) -> None:
    """Move overdue polls to incomplete and send due reminders."""
    for poll, missing in polls.expire_overdue():
        await refresh_card(client, polls, poll.id)
        await post_in_thread(
            client,
            polls,
            poll.id,
            f"The deadline passed and these companies have not submitted: {', '.join(missing)}. "
            "An admin can extend the deadline.",
        )
    for poll, missing in polls.due_reminders(reminder_period):
        users = [user for company in missing for user in polls.members_of(company)]
        mentions = " ".join(f"<@{user}>" for user in users)
        await post_in_thread(
            client,
            polls,
            poll.id,
            f"Reminder: {mentions} please submit for *{', '.join(missing)}* "
            f"before {poll.deadline.date().isoformat()}.",
        )


async def run_sweeper(
    client: AsyncWebClient, polls: PollService, reminder_period: timedelta
) -> None:
    while True:
        try:
            await sweep_once(client, polls, reminder_period)
        except Exception:
            LOGGER.exception("IMMAP sweep failed")
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)


def register_immap(app: AsyncApp, polls: PollService, settings: Settings) -> None:
    async def tell(client: AsyncWebClient, body: dict, text: str) -> None:
        await client.chat_postEphemeral(
            channel=body["channel"]["id"], user=body["user"]["id"], text=text
        )

    @app.command("/immap")
    async def handle_command(ack, body, command, respond, client: AsyncWebClient) -> None:
        await ack()
        user_id = body["user_id"]
        subcommand, args = parse_command(command.get("text", ""))
        try:
            if subcommand == "register" and len(args) == 1:
                fingerprint = polls.enroll(user_id=user_id, public_key=args[0])
                text = (
                    f"Enrolled. Key fingerprint: `{fingerprint}`. An admin will attribute "
                    "your company to you."
                )
            elif subcommand == "companies" and not args:
                email = await email_of(client, user_id)
                text = companies_text(
                    polls.companies(email=email), polls.unattributed_users(email=email)
                )
            elif subcommand == "company" and args and args[0].lower() == "attribute":
                email = await email_of(client, user_id)
                await client.views_open(
                    trigger_id=body["trigger_id"],
                    view=attribute_modal([c.company_id for c in polls.companies(email=email)]),
                )
                return
            elif subcommand == "company" and args and args[0].lower() == "unattribute":
                polls.companies(email=await email_of(client, user_id))  # admins only
                await client.views_open(trigger_id=body["trigger_id"], view=unattribute_modal())
                return
            elif subcommand == "company" and len(args) == 2:
                email = await email_of(client, user_id)
                action, company_id = args[0].lower(), args[1]
                if action == "add":
                    polls.add_company(email=email, company_id=company_id)
                    text = f"Added `{company_id}`. Add members with `/immap company attribute`."
                elif action == "remove":
                    polls.remove_company(email=email, company_id=company_id)
                    text = f"Removed `{company_id}`."
                else:
                    text = HELP_TEXT
            elif subcommand == "admin-register" and len(args) == 1:
                fingerprint = polls.register_admin_key(
                    email=await email_of(client, user_id), public_key=args[0]
                )
                text = f"Admin key registered. Fingerprint: `{fingerprint}`"
            elif subcommand == "poll":
                today = datetime.now(ZoneInfo(settings.timezone)).date()
                await client.views_open(
                    trigger_id=body["trigger_id"],
                    view=poll_modal(
                        channel_id=body["channel_id"],
                        company_ids=polls.pollable_company_ids(),
                        default_deadline=today + timedelta(days=7),
                    ),
                )
                return
            elif subcommand == "report" and len(args) <= 1:
                if args:
                    text = report_text(polls.report(args[0]))
                else:
                    text = done_list_text(polls.done_polls(body["channel_id"]))
            else:
                text = HELP_TEXT
        except PollError as error:
            text = str(error)
        await respond(text=text, response_type="ephemeral")

    @app.view(ATTRIBUTE_CALLBACK_ID)
    async def handle_attribute(ack, body, view, client: AsyncWebClient) -> None:
        values = view["state"]["values"]
        company_id = values["company"]["value"]["selected_option"]["value"]
        user_id = values["user"]["value"]["selected_user"]
        try:
            polls.attribute_company(
                email=await email_of(client, body["user"]["id"]),
                company_id=company_id,
                user_id=user_id,
            )
        except PollError as error:
            await ack(response_action="errors", errors={"user": str(error)})
            return
        await ack(
            response_action="update",
            view=notice_modal("Attributed", f"<@{user_id}> now answers for `{company_id}`."),
        )

    @app.view(UNATTRIBUTE_CALLBACK_ID)
    async def handle_unattribute(ack, body, view, client: AsyncWebClient) -> None:
        user_id = view["state"]["values"]["user"]["value"]["selected_user"]
        try:
            company_id = polls.unattribute_user(
                email=await email_of(client, body["user"]["id"]), user_id=user_id
            )
        except PollError as error:
            await ack(response_action="errors", errors={"user": str(error)})
            return
        await ack(
            response_action="update",
            view=notice_modal("Removed", f"<@{user_id}> no longer belongs to `{company_id}`."),
        )

    @app.view(POLL_CALLBACK_ID)
    async def handle_poll_submission(ack, body, view, client: AsyncWebClient) -> None:
        values = view["state"]["values"]
        metadata = json.loads(view["private_metadata"])
        try:
            poll = polls.create_poll(
                channel_id=metadata["channel_id"],
                creator_user_id=body["user"]["id"],
                title=values["title"]["value"]["value"] or "",
                template=values["template"]["value"]["selected_option"]["value"],
                deadline_day=date.fromisoformat(values["deadline"]["value"]["selected_date"]),
                participants=[
                    option["value"]
                    for option in values["participants"]["value"]["selected_options"]
                ],
            )
        except PollError as error:
            await ack(
                response_action="errors", errors={poll_error_block(str(error)): str(error)}
            )
            return
        await ack()
        text, blocks = poll_card(
            poll, submitted=polls.submitted(poll), missing=polls.missing(poll)
        )
        posted = await client.chat_postMessage(
            channel=poll.channel_id, text=text, blocks=blocks
        )
        polls.set_message_ts(poll.id, str(posted["ts"]))
        await post_in_thread(client, polls, poll.id, poll_json_message(poll))

    @app.action(START_ACTION_ID)
    async def handle_start(ack, body, action, client: AsyncWebClient) -> None:
        await ack()
        try:
            polls.start(
                action["value"],
                user_id=body["user"]["id"],
                email=await email_of(client, body["user"]["id"]),
            )
        except PollError as error:
            await tell(client, body, str(error))
            return
        await refresh_card(client, polls, action["value"])
        await post_in_thread(
            client, polls, action["value"], "Collecting has started. Use the Submit button."
        )

    @app.action(SUBMIT_ACTION_ID)
    async def handle_submit_open(ack, body, action, client: AsyncWebClient) -> None:
        await ack()
        poll = polls.get(action["value"])
        await client.views_open(
            trigger_id=body["trigger_id"], view=submit_modal(poll_id=poll.id, title=poll.title)
        )

    @app.view(SUBMIT_CALLBACK_ID)
    async def handle_submit_view(ack, body, view, client: AsyncWebClient) -> None:
        poll_id = json.loads(view["private_metadata"])["poll_id"]
        line = view["state"]["values"]["line"]["value"]["value"] or ""
        try:
            poll = polls.submit(poll_id, user_id=body["user"]["id"], line=line)
        except PollError as error:
            await ack(response_action="errors", errors={"line": str(error)})
            return
        await ack()
        await refresh_card(client, polls, poll_id)
        submitter = body["user"]["id"]
        company_id = polls.company_of(submitter)
        colleagues = [u for u in polls.members_of(company_id or "") if u != submitter]
        if company_id and colleagues:
            await post_in_thread(
                client, polls, poll_id, answered_text(company_id, submitter, colleagues)
            )
        if poll.status == COMPLETE:
            await post_in_thread(
                client,
                polls,
                poll_id,
                "Every company has submitted. An admin must validate before results are shown.",
            )

    @app.action(EXTEND_ACTION_ID)
    async def handle_extend_open(ack, body, action, client: AsyncWebClient) -> None:
        await ack()
        poll_id = action["value"]
        try:
            nonce = polls.begin_admin_action(
                poll_id,
                email=await email_of(client, body["user"]["id"]),
                action=ACTION_EXTEND,
            )
        except PollError as error:
            await tell(client, body, str(error))
            return
        await client.views_open(
            trigger_id=body["trigger_id"],
            view=extend_modal(
                poll_id=poll_id, nonce=nonce, current_deadline=polls.get(poll_id).deadline.date()
            ),
        )

    @app.view(EXTEND_CALLBACK_ID)
    async def handle_extend_view(ack, body, view, client: AsyncWebClient) -> None:
        metadata = json.loads(view["private_metadata"])
        values = view["state"]["values"]
        selected = values["date"]["value"]["selected_date"]
        if not selected:
            await ack(response_action="errors", errors={"date": "Pick the new deadline."})
            return
        try:
            poll = polls.extend(
                metadata["poll_id"],
                email=await email_of(client, body["user"]["id"]),
                new_day=date.fromisoformat(selected),
                nonce=metadata["nonce"],
                proof=values["proof"]["value"]["value"] or "",
            )
        except PollError as error:
            await ack(response_action="errors", errors={extend_error_block(str(error)): str(error)})
            return
        await ack()
        await refresh_card(client, polls, poll.id)
        await post_in_thread(
            client,
            polls,
            poll.id,
            f"Deadline extended to {poll.deadline.date().isoformat()} "
            f"(extension {poll.extension_count}).",
        )

    @app.action(VALIDATE_ACTION_ID)
    async def handle_validate_open(ack, body, action, client: AsyncWebClient) -> None:
        await ack()
        poll_id = action["value"]
        email = await email_of(client, body["user"]["id"])
        try:
            nonce = polls.begin_admin_action(poll_id, email=email, action=ACTION_DONE)
            lines = polls.submission_lines(poll_id, email=email)
        except PollError as error:
            await tell(client, body, str(error))
            return
        # Open the modal first: the trigger id expires within seconds.
        await client.views_open(
            trigger_id=body["trigger_id"], view=validate_modal(poll_id=poll_id, nonce=nonce)
        )
        for chunk in chunk_lines(lines):
            await tell(client, body, f"```{chunk}```")

    @app.view(DONE_CALLBACK_ID)
    async def handle_done_view(ack, body, view, client: AsyncWebClient) -> None:
        metadata = json.loads(view["private_metadata"])
        raw = unfence(view["state"]["values"]["result"]["value"]["value"] or "")
        try:
            result = json.loads(raw)
            totals, proof = result["totals"], result["proof"]
        except (ValueError, KeyError, TypeError):
            await ack(
                response_action="errors",
                errors={"result": "Paste the full JSON printed by `immap.py aggregate`."},
            )
            return
        try:
            poll = polls.mark_done(
                metadata["poll_id"],
                email=await email_of(client, body["user"]["id"]),
                nonce=metadata["nonce"],
                totals=totals,
                proof=str(proof),
            )
        except PollError as error:
            await ack(response_action="errors", errors={"result": str(error)})
            return
        await ack()
        await refresh_card(client, polls, poll.id)
        await post_in_thread(
            client,
            polls,
            poll.id,
            f"Validated by <@{body['user']['id']}>. Use `/immap report {poll.id}` for the totals.",
        )
````

- [ ] **Step 4: Run tests, lint and types**

Run: `uv run pytest && uv run ruff check . && uv run pyright`
Expected: all tests pass. `uv run ruff check .` reports exactly three pre-existing `E501` errors in `src/premday_bot/templates.py` (lines 75, 78, 84). Leave them alone; there must be no other errors.

- [ ] **Step 5: Commit**

```bash
git add src/premday_bot/config.py src/premday_bot/immap_slack.py tests/test_config.py tests/test_immap_slack.py
git commit -m "Make polls usable through one slash command" -m "Add settings, /immap handlers and the deadline/reminder sweeper." -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---
### Task 7: Wire into the app and the manifest

**Files:**
- Modify: `src/premday_bot/app.py`, `slack/app-manifest.yaml`
- Test: `tests/test_app_wiring.py`

**Interfaces:**
- Consumes: Task 6 (`register_immap`, `run_sweeper`), Task 2 (`PollService`, `PollStore`), `Settings`.
- Produces: `Runtime.polls: PollService`, `_build_runtime(settings) -> Runtime`; `build_app` registers the IMMAP handlers; `run()` starts the sweeper task and cancels it on shutdown; the manifest declares `/immap`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_app_wiring.py`:

````python
from premday_bot.app import build_app
from premday_bot.config import Settings


def test_build_app_registers_meeting_and_immap_handlers(tmp_path) -> None:
    settings = Settings(
        slack_bot_token="xoxb-test",
        slack_app_token="xapp-test",
        slack_team_id=None,
        timezone="Europe/Paris",
        default_hour=18,
        default_duration_minutes=90,
        db_path=tmp_path / "premday.sqlite3",
        smtp_host=None,
        smtp_port=587,
        smtp_username=None,
        smtp_password=None,
        smtp_use_tls=True,
        smtp_use_ssl=False,
        email_from=None,
    )
    app = build_app(settings)
    # /meeting + schedule view + two meeting buttons, then /immap + 6 views + 4 buttons
    assert len(app._async_listeners) == 4 + 11
````

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_app_wiring.py`
Expected: FAIL, `assert 4 == 15` (only the 4 meeting listeners exist).

- [ ] **Step 3: Write the implementation**

Apply these edits to `src/premday_bot/app.py`.

1. After `from dataclasses import dataclass, field` add `from datetime import timedelta`.
2. After `from premday_bot.dates import combine_local_date_time, default_meeting_start` add `from premday_bot.immap_slack import register_immap, run_sweeper`.
3. After `from premday_bot.organizer import MeetingOrganizer, new_meeting_id` add `from premday_bot.polls import PollService, PollStore`.
4. Replace the `Runtime` dataclass fields and the start of `build_app`:

````python
    store: MeetingStore
    polls: PollService
    canvas_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


def _build_runtime(settings: Settings) -> Runtime:
    return Runtime(
        settings=settings,
        store=MeetingStore(settings.db_path),
        polls=PollService(
            PollStore(settings.db_path),
            timezone=settings.timezone,
            admin_emails=settings.immap_admin_emails,
        ),
    )


def build_app(settings: Settings | None = None) -> AsyncApp:
    resolved_settings = settings or Settings.from_env()
    runtime = _build_runtime(resolved_settings)
````

(the old `runtime = Runtime(settings=resolved_settings, store=MeetingStore(resolved_settings.db_path),)` statement is removed).

5. In `build_app`, replace the final `    return app` (right after the `handle_show_rsvps` handler) with:

````python
    register_immap(app, runtime.polls, runtime.settings)
    return app
````

6. In `run()`, replace `    runtime = Runtime(settings=settings, store=MeetingStore(settings.db_path))` with `    runtime = _build_runtime(settings)`.
7. In `start_socket_mode`, replace

````python
        try:
            await handler.start_async()
        finally:
            if rsvp_server:
                await rsvp_server.close()
````

with

````python
        sweeper = asyncio.create_task(
            run_sweeper(
                app.client,
                runtime.polls,
                timedelta(hours=settings.immap_reminder_hours),
            )
        )
        try:
            await handler.start_async()
        finally:
            sweeper.cancel()
            if rsvp_server:
                await rsvp_server.close()
````

Edit `slack/app-manifest.yaml`: after the `/meeting` command entry (after its `should_escape: false` line, before `oauth_config:`) add:

````yaml
    - command: /immap
      description: Aggregate infrastructure metrics without revealing individual values
      usage_hint: "register | companies | company | admin-register | poll | report"
      should_escape: false
````

- [ ] **Step 4: Run tests, lint and types**

Run: `uv run pytest && uv run ruff check . && uv run pyright`
Expected: all tests pass. `uv run ruff check .` reports exactly three pre-existing `E501` errors in `src/premday_bot/templates.py` (lines 75, 78, 84). Leave them alone; there must be no other errors.

- [ ] **Step 5: Commit**

```bash
git add src/premday_bot/app.py slack/app-manifest.yaml tests/test_app_wiring.py
git commit -m "Ship the feature in the running bot" -m "Wire handlers and sweeper into app.py and declare /immap in the manifest." -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---
### Task 8: Documentation and final verification

**Files:**
- Modify: `README.md`, `.env.example`

**Interfaces:**
- Consumes: everything above. Produces: user and admin documentation only.

- [ ] **Step 1: Document the feature**

In `README.md`, add this bullet at the end of the `## Features` list:

````markdown
- `/immap` computes aggregate infrastructure metrics across companies without anyone
  (including the bot) seeing individual values; see [IMMAP polls](#immap-polls).
````

Add two rows to the `## Environment` table, after the `RSVP_SMTP_HOST_PORT` row:

````markdown
| `IMMAP_ADMIN_EMAILS` | no | Comma-separated Slack profile emails of IMMAP admins. Empty means nobody is admin. |
| `IMMAP_REMINDER_HOURS` | no | Hours between reminders to companies that have not submitted; defaults to `24`. |
````

Insert this section immediately before `## Development`:

````markdown
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

````

Append to `.env.example`:

````bash

# IMMAP polls
IMMAP_ADMIN_EMAILS=a.rougemont@criteo.com
IMMAP_REMINDER_HOURS=24
````

- [ ] **Step 2: Run the full verification**

Run: `uv run pytest && uv run ruff check . && uv run pyright`
Expected: the whole suite passes. `uv run ruff check .` reports exactly three pre-existing `E501` errors in `src/premday_bot/templates.py` (lines 75, 78, 84). Leave them alone; there must be no other errors.
Also run a standalone smoke test of the participant tool, outside the package:

```bash
cd "$(mktemp -d)" && cp "$OLDPWD/src/premday_bot/immap.py" . && python3 immap.py keygen && ls -l immap.key
```

Expected: a `public key:` and `fingerprint:` line, and `immap.key` with mode `-rw-------`.

- [ ] **Step 3: Commit**

```bash
git add README.md .env.example
git commit -m "Tell users and admins how to run a poll" -m "Document IMMAP in the README and .env.example." -m "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 4: Report**

Summarize to the user what was built and verified (test count, lint/type status). Do **not** push, open a PR, or comment on PR #2.
