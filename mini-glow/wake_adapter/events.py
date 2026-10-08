"""WakeEvent: a notification that something is recorded in a poller database.

It is never an instruction and never an authorisation (authority is always NOTIFICATION_ONLY).
It carries no packet text: the adapter reads only the database, never the Bridge files.
The event_id is the SHA-256 of a canonical identity string, so a redelivery has the same id.
"""
import hashlib
import json
from dataclasses import dataclass
from types import MappingProxyType

SCHEMA = "miniglow.wake_event/1"
AUTHORITY = "NOTIFICATION_ONLY"
NEW, ESCALATE, OFFLINE_GAP = "NEW", "ESCALATE", "OFFLINE_GAP"
ROUTES = {NEW: "GLOW", ESCALATE: "ERIC", OFFLINE_GAP: "ERIC"}
REASONS = frozenset({"NEEDS_ERIC_ROW", "LATE_BELOW_BOUNDARY", "RUN_ERROR", "RUN_STOP", "RUN_HEALTH_NEEDS_ERIC",
                     "RUN_SUSPECT_LISTINGS"})
FIELDS = ("schema", "event_id", "kind", "route", "authority", "packet_id", "drive_file_id", "reason",
          "source", "packet", "gap", "produced_at")


def packet_key(packet_id, drive_file_id):
    """Downstream identity of one packet file: packet_id + drive_file_id."""
    return packet_id + "|" + drive_file_id


def packet_number(packet_id):
    return int(packet_id[len("R2G-"):])


def make_event_id(identity):
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


def _thaw(value):
    if isinstance(value, MappingProxyType):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thaw(v) for v in value]
    return value


@dataclass(frozen=True)
class WakeEvent:
    event_id: str
    kind: str
    route: str
    packet_id: object
    drive_file_id: object
    reason: object
    source: object
    packet: object
    gap: object
    produced_at: str
    schema: str = SCHEMA
    authority: str = AUTHORITY

    def __post_init__(self):
        if self.kind not in ROUTES or self.route != ROUTES[self.kind]:
            raise ValueError("kind and route do not match: %s %s" % (self.kind, self.route))
        if self.schema != SCHEMA or self.authority != AUTHORITY:
            raise ValueError("schema and authority are fixed")
        if self.reason is not None and self.reason not in REASONS:
            raise ValueError("unknown reason: %s" % self.reason)
        for name in ("source", "packet", "gap"):
            object.__setattr__(self, name, _freeze(getattr(self, name)))

    def to_dict(self):
        return {name: _thaw(getattr(self, name)) for name in FIELDS}

    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=False)


def _source(db, run):
    return {"db": db, "run_id": run["run_id"], "run_ended_at": run["ended_at"]}


def _packet(row):
    return {"state": row["state"], "drive_created_time": row["drive_created_time"],
            "detected_at": row["detected_at"], "check_number": row["check_number"]}


def new_event(row, db, run, produced_at):
    pid, fid = row["packet_id"], row["drive_file_id"]
    return WakeEvent(make_event_id("NEW|" + packet_key(pid, fid)), NEW, ROUTES[NEW], pid, fid, None,
                     _source(db, run), _packet(row), None, produced_at)


def packet_escalation(row, db, run, produced_at):
    pid, fid = row["packet_id"], row["drive_file_id"]
    return WakeEvent(make_event_id("ESC|NEEDS_ERIC|" + packet_key(pid, fid)), ESCALATE, ROUTES[ESCALATE],
                     pid, fid, "NEEDS_ERIC_ROW", _source(db, run), _packet(row), None, produced_at)


def late_escalation(row, db, run, produced_at):
    """A packet at or below high_water whose identity was not in the seeded history: evidence, never history."""
    pid, fid = row["packet_id"], row["drive_file_id"]
    return WakeEvent(make_event_id("ESC|LATE_BELOW_BOUNDARY|" + packet_key(pid, fid)), ESCALATE,
                     ROUTES[ESCALATE], pid, fid, "LATE_BELOW_BOUNDARY", _source(db, run), _packet(row), None,
                     produced_at)


def run_escalation(reason, db, run, produced_at):
    identity = "ESC|%s|%s|%s" % (reason, db, run["run_id"])
    return WakeEvent(make_event_id(identity), ESCALATE, ROUTES[ESCALATE], None, None, reason,
                     _source(db, run), None, None, produced_at)


def gap_event(members, produced_at):
    """One summary event for packets that arrived while no poller was watching.

    members: list of (packet_id, drive_file_id, db). Only a summary: no packet is replayed or acted on.
    """
    members = sorted(members, key=lambda m: (packet_number(m[0]), m[1]))
    keys = [packet_key(pid, fid) for pid, fid, _ in members]
    numbers = sorted({packet_number(pid) for pid, _, _ in members})
    first, last = numbers[0], numbers[-1]
    gap = {
        "first": "R2G-%03d" % first,
        "last": "R2G-%03d" % last,
        "count": len(members),
        "members": keys,
        "missing_numbers": ["R2G-%03d" % n for n in range(first, last + 1) if n not in set(numbers)],
        "dbs": sorted({db for _, _, db in members}),
    }
    identity = "GAP|" + "\n".join(sorted(keys))
    return WakeEvent(make_event_id(identity), OFFLINE_GAP, ROUTES[OFFLINE_GAP], None, None, None,
                     {"db": None, "run_id": None, "run_ended_at": None}, None, gap, produced_at)
