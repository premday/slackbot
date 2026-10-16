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
    limit = len(rows) * MAX_VALUE
    totals = aggregate(poll["metrics"], list(rows.values()))
    bad = sorted(name for name, total in totals.items() if total >= limit)
    if bad:
        raise ValueError(
            f"totals out of range for {bad}: a submission was corrupted or tampered with"
        )
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
