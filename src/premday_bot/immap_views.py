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
