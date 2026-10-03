"""Handoff packet parsing and rendering.

Packets are plain text/markdown that Eric copies between Glow and Mini Glow by
hand. There is no automatic connection.

Incoming (Glow -> Mini Glow) fields:
  GOAL, YOUR JOB, CONTEXT, INPUT, RULES, OUTPUT FORMAT, DONE WHEN, NEXT STOP
Optional extras: TITLE, REF (Glow's own task reference), PRIORITY (1-9, 1 = most urgent)
ACTIONS lists what the task needs, one per line as `category: target`, e.g.
  read_file: C:/Users/Eric/practice_files
  write_file: C:/Users/Eric/practice_files/out
A task with no ACTIONS, or an unknown category, pauses for clarification.

A field starts on a line like `GOAL:` or `## GOAL` and runs until the next field.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

FIELDS = [
    "TITLE", "REF", "PRIORITY", "GOAL", "YOUR JOB", "CONTEXT", "INPUT",
    "ACTIONS", "RULES", "OUTPUT FORMAT", "DONE WHEN", "NEXT STOP",
]
REQUIRED = ["GOAL", "YOUR JOB"]

_KEYS = "|".join(re.escape(f) for f in FIELDS)
# A field header is either a markdown heading ("## GOAL") or "KEY:" (optionally bold).
# A bare word like "Input data..." inside a field is NOT treated as a header.
_FIELD_RE = re.compile(
    r"^\s*(?:#{1,6}\s*(?P<h>" + _KEYS + r")\s*:?|(?:\*\*)?(?P<c>" + _KEYS + r")(?:\*\*)?\s*:(?:\*\*)?)\s*(?P<rest>.*)$",
    re.IGNORECASE,
)


class PacketError(ValueError):
    pass


def parse_packet(text: str) -> dict:
    fields: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        m = _FIELD_RE.match(line)
        if m:
            current = (m.group("h") or m.group("c")).upper()
            fields.setdefault(current, [])
            rest = m.group("rest").strip()
            if rest:
                fields[current].append(rest)
        elif current is not None:
            fields[current].append(line)
    out = {k: "\n".join(v).strip() for k, v in fields.items()}
    missing = [r for r in REQUIRED if not out.get(r)]
    if missing:
        raise PacketError("Packet is missing required field(s): " + ", ".join(missing))
    if not out.get("TITLE"):
        first = out["GOAL"].splitlines()[0]
        out["TITLE"] = first[:80]
    prio = out.get("PRIORITY", "5") or "5"
    if not prio.isdigit() or not 1 <= int(prio) <= 9:
        raise PacketError("PRIORITY must be a number from 1 to 9")
    out["PRIORITY"] = prio
    return out


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")


BANNER = "(Manual relay: Eric copies this between Glow and Mini Glow. No automatic connection exists.)"


def parse_actions(text: str) -> list[tuple[str, str]]:
    """Parse 'category: target' lines. A line with no colon becomes (line, '') and will pause."""
    out = []
    for raw in (text or "").splitlines():
        line = raw.strip().lstrip("-*").strip()
        if not line:
            continue
        if ":" in line:
            cat, _, target = line.partition(":")
            out.append((cat.strip().lower(), target.strip()))
        else:
            out.append((line.lower(), ""))
    return out


def render_return_packet(task: dict, events: list[dict], evidence: list[dict],
                         actions: list[dict] | None = None, next_stop: str = "Glow") -> str:
    lines = [
        "MINI GLOW -> GLOW  |  RETURN PACKET",
        BANNER,
        "",
        f"TASK: {task['id']}  {task['title']}",
        f"GLOW REF: {task.get('glow_ref') or '-'}",
        f"STATUS: {task['status']}",
        f"GENERATED: {_now()}",
        "",
        "SUMMARY:",
        task.get("result_summary") or "(no summary recorded yet)",
        "",
        "DECLARED ACTIONS:",
    ]
    lines += [f"  - {a['category']}: {a['target'] or '(none)'}" for a in (actions or [])] or ["  (none)"]
    lines += ["", "PROGRESS LOG:"]
    progress = [n for n in events if n["kind"] == "note"]
    lines += [f"  - [{n['ts'][:16]}] {n['detail']}" for n in progress] or ["  (none)"]
    lines += ["", "EVIDENCE:"]
    for e in evidence:
        bits = [x for x in (e.get("text"), f"file={e['rel_path']} sha256={e['sha256']}" if e.get("rel_path") else None) if x]
        lines.append(f"  - [{e['ts'][:16]}] " + " | ".join(bits))
    if not evidence:
        lines.append("  (none)")
    lines += ["", "ASSUMPTIONS / LIMITS:"]
    assumptions = [n for n in events if n["kind"] == "assumption"]
    lines += [f"  - {n['detail']}" for n in assumptions] or ["  (none recorded)"]
    lines += ["", "DONE WHEN (from Glow):", task.get("done_when") or "(not specified)", ""]
    lines += [f"NEXT STOP: {next_stop}  (Eric remains final authority)"]
    return "\n".join(lines) + "\n"


def render_help_request(task: dict, question: str, tried: str, events: list[dict]) -> str:
    recent = [n for n in events if n["kind"] == "note"][-5:]
    lines = [
        "MINI GLOW -> GLOW  |  HELP REQUEST (blocked)",
        BANNER,
        "",
        f"TASK: {task['id']}  {task['title']}",
        f"GLOW REF: {task.get('glow_ref') or '-'}",
        f"GENERATED: {_now()}",
        "",
        "WHERE I AM STUCK:",
        question,
        "",
        "WHAT I ALREADY TRIED:",
        tried or "(nothing recorded)",
        "",
        "RECENT PROGRESS:",
    ]
    lines += [f"  - {n['detail']}" for n in recent] or ["  (none)"]
    lines += [
        "",
        "WHAT I NEED FROM GLOW: a decision or instruction that unblocks the task.",
        "NEXT STOP: Glow  (Eric reviews and relays; Eric remains final authority)",
    ]
    return "\n".join(lines) + "\n"
