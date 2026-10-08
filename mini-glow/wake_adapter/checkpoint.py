"""The adapter's checkpoint: its only persistent write, one JSON file in the MiniGlow folder.

It advances only from a validated Receipt (at-least-once). Writes go to NAME.tmp, are flushed, then
atomically replace NAME. A leftover NAME.tmp, a linked file, or any unexpected content fails closed.
"""
import json
import os
import re
import stat

from . import events as ev
from .paths import DB_RE, Refused, Stopped
from .transport import validate_receipt

FORMAT = "miniglow.wake_adapter.checkpoint"
VERSION = 2  # 2: adds seeded_history (version 1 cannot prove its history and is refused)
TOP_KEYS = frozenset({"format", "version", "revision", "created_at", "updated_at", "high_water",
                      "seeded_history", "confirmed", "gap_reported"})
SEED_KEYS = frozenset({"sources", "keys"})
ENTRY_KEYS = frozenset({"kind", "keys", "confirmed_at", "transport", "db"})
HIGH_WATER_RE = re.compile(r"^R2G-\d{3}\Z")
EVENT_ID_RE = re.compile(r"^[0-9a-f]{64}\Z")
KEY_RE = re.compile(r"^R2G-\d{3}\|[^\n]+\Z")
MAX_BYTES = 4 * 1024 * 1024


def _str(value):
    return isinstance(value, str)


def validate(data):
    """Return data unchanged if it is a well-formed checkpoint; otherwise raise Refused."""
    if not isinstance(data, dict) or set(data) != TOP_KEYS:
        raise Refused("checkpoint keys are not the expected ones")
    if data["format"] != FORMAT or type(data["version"]) is not int or data["version"] != VERSION:
        raise Refused("unknown checkpoint format or version")
    if type(data["revision"]) is not int or data["revision"] < 0:
        raise Refused("bad checkpoint revision")
    if not (_str(data["created_at"]) and _str(data["updated_at"])):
        raise Refused("bad checkpoint timestamps")
    if not (_str(data["high_water"]) and HIGH_WATER_RE.match(data["high_water"])):
        raise Refused("bad high_water: %r" % (data["high_water"],))
    _validate_seed(data["seeded_history"], data["high_water"])
    if not isinstance(data["confirmed"], dict):
        raise Refused("checkpoint confirmed must be an object")
    for event_id, entry in data["confirmed"].items():
        if not EVENT_ID_RE.match(event_id):
            raise Refused("bad event id in checkpoint: %r" % (event_id,))
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise Refused("bad checkpoint entry for " + event_id)
        if entry["kind"] not in ev.ROUTES or not isinstance(entry["keys"], list) or \
                not all(_str(k) and KEY_RE.match(k) for k in entry["keys"]):
            raise Refused("bad checkpoint entry for " + event_id)
        if not (_str(entry["confirmed_at"]) and _str(entry["transport"]) and
                (entry["db"] is None or _str(entry["db"]))):
            raise Refused("bad checkpoint entry for " + event_id)
    gap = data["gap_reported"]
    if not isinstance(gap, list) or not all(_str(k) and KEY_RE.match(k) for k in gap) or len(set(gap)) != len(gap):
        raise Refused("bad gap_reported list")
    return data


def _validate_seed(seed, high_water):
    """seeded_history: the packet identities present at or below high_water when the checkpoint was made."""
    if not isinstance(seed, dict) or set(seed) != SEED_KEYS:
        raise Refused("bad seeded_history")
    sources, keys = seed["sources"], seed["keys"]
    if not isinstance(sources, list) or not all(_str(s) and DB_RE.match(s) for s in sources) or \
            sources != sorted(set(sources)):
        raise Refused("bad seeded_history sources")
    if not isinstance(keys, list) or not all(_str(k) and KEY_RE.match(k) for k in keys) or keys != sorted(set(keys)):
        raise Refused("bad seeded_history keys")
    if HIGH_WATER_RE.match(high_water or "") and \
            any(ev.packet_number(k.split("|", 1)[0]) > ev.packet_number(high_water) for k in keys):
        raise Refused("seeded_history holds a packet above high_water")
    if keys and not sources:
        raise Refused("seeded_history keys without a source")


def make_seed(keys, sources):
    return {"sources": sorted(set(sources)), "keys": sorted(set(keys))}


def seed_from_snapshots(snapshots, high_water):
    """Seed from finished poller databases: every packet identity at or below high_water, in any state."""
    if not HIGH_WATER_RE.match(high_water or ""):
        raise Refused("bad high_water: %r" % (high_water,))
    if not snapshots:
        raise Refused("seeding needs at least one poller database")
    open_runs = [s.db for s in snapshots if s.waiting]
    if open_runs:
        raise Refused("seed database has no finished run: " + ", ".join(open_runs))
    high = ev.packet_number(high_water)
    keys = [ev.packet_key(p["packet_id"], p["drive_file_id"])
            for s in snapshots for p in s.packets if ev.packet_number(p["packet_id"]) <= high]
    return make_seed(keys, [s.db for s in snapshots])


def empty(high_water, now, seeded_history=None):
    """A fresh checkpoint in memory (used by init, and by a dry-run plan that writes nothing).

    Without a seed every packet at or below high_water is LATE_BELOW_BOUNDARY: missing proof is never history.
    """
    seed = seeded_history if seeded_history is not None else make_seed([], [])
    return validate({"format": FORMAT, "version": VERSION, "revision": 0, "created_at": now, "updated_at": now,
                     "high_water": high_water, "seeded_history": seed, "confirmed": {}, "gap_reported": []})


def _plain_file(path):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise Refused("checkpoint missing: " + path + " (creating it needs Eric's approval)")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise Refused("checkpoint is linked or not a plain file: " + path)


def load(path):
    _plain_file(path)
    with open(path, "rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise Refused("checkpoint too large")
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refused("checkpoint is not valid JSON")
    return validate(parsed)


def _write(path, data):
    tmp = path + ".tmp"
    if os.path.lexists(tmp):
        raise Refused("leftover temporary checkpoint (review it, then remove it): " + tmp)
    payload = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.lexists(tmp):
            os.remove(tmp)  # our own temporary file; the real checkpoint is untouched
        raise


def init(path, high_water, seeded_history, now):
    """Create the checkpoint with its seeded history. Refuses if one already exists or the seed is empty."""
    if os.path.lexists(path):
        raise Refused("checkpoint already exists: " + path)
    data = empty(high_water, now, seeded_history)
    if not data["seeded_history"]["sources"] or (not data["seeded_history"]["keys"] and high_water != "R2G-000"):
        raise Refused("seeded_history is empty: initialisation needs the history present at or below " + high_water)
    _write(path, data)
    return data


def commit(path, loaded, events, receipt, stop_check, now):
    """Record the confirmed events of one batch. Returns the checkpoint now on disk."""
    confirmed = validate_receipt(tuple(events), receipt)
    found = stop_check()
    if found:
        raise Stopped(found)
    current = load(path)
    if current["revision"] != loaded["revision"]:
        raise Refused("checkpoint changed since it was loaded (revision %d, now %d)"
                      % (loaded["revision"], current["revision"]))
    if not confirmed:
        return current
    new = json.loads(json.dumps(current))
    gap = set(new["gap_reported"])
    for e in events:
        if e.event_id not in confirmed:
            continue
        if e.kind == ev.OFFLINE_GAP:
            keys = list(e.gap["members"])
            gap.update(keys)
        else:
            keys = [ev.packet_key(e.packet_id, e.drive_file_id)] if e.packet_id else []
        new["confirmed"][e.event_id] = {"kind": e.kind, "keys": keys, "confirmed_at": receipt.confirmed_at,
                                        "transport": receipt.transport, "db": e.source["db"]}
    new["gap_reported"] = sorted(gap)
    new["revision"] += 1
    new["updated_at"] = now
    validate(new)
    _write(path, new)
    return new
