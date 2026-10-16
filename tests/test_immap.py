import ast
import base64
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


def test_aggregate_refuses_totals_no_set_of_honest_values_could_make() -> None:
    poll, company_keys, admin_keys, _ = make_poll(3)
    lines = [immap.submit(poll, k, {n: 1 for n in TEMPLATE_METRICS}) for k in company_keys.values()]
    garbage = immap.seal(b"\xff" * 8 * len(TEMPLATE_METRICS), poll["admins"])
    first = next(iter(company_keys))
    encoded = base64.urlsafe_b64encode(json.dumps(garbage, separators=(",", ":")).encode())
    forged = f"immap2.{poll['poll_id']}.{first}.{encoded.decode().rstrip('=')}"
    with pytest.raises(ValueError, match="out of range"):
        immap.aggregate_sealed(poll, [forged, *lines[1:]], admin_keys[0], "n0nce")
