"""Wake Transport v0.2: the local outbox. Nothing leaves this PC.

Delivery writes each event to MiniGlow\\outbox\\<route>\\<event_id>.json with a fresh one-time delivery code.
Delivery is not acknowledgment: the checkpoint advances only when the route's recipient acknowledges an event
by quoting its event_id AND current code (Eric: the ack command plus typed YES; Glow: an "ACK <id> <code>" line in
its reply, entered by Eric plus typed YES). One event per acknowledgment. An unacknowledged event is delivered
again on the next run with a new code, up to MAX_ATTEMPTS; after that it is marked STUCK and one STUCK_DELIVERY
escalation goes to Eric. Retries happen only when someone runs delivery: no background service, no schedule.
"""
import json
import os
import re
import secrets
import stat

from . import audit, checkpoint
from . import events as ev
from .paths import Refused, Stopped, is_inside
from .transport import Receipt, batch_id

SCHEMA = "miniglow.wake_outbox/1"
NAME = "local-outbox"
MAX_ATTEMPTS = 3
ROUTE_NAMES = ("ERIC", "GLOW")
STATUSES = frozenset({"PENDING", "STUCK", "ACKED"})
RECORD_KEYS = frozenset({"schema", "event", "route", "attempt", "code", "delivered_at", "status"})
CODE_RE = re.compile(r"^[0-9a-f]{8}\Z")
EVENT_ID_RE = re.compile(r"^[0-9a-f]{64}\Z")
GLOW_ACK_RE = re.compile(r"^\s*ACK\s+([0-9a-f]{64})\s+([0-9a-f]{8})\s*$", re.M)
MAX_BYTES = 1024 * 1024


def record_path(outbox, route, event_id):
    if route not in ROUTE_NAMES or not EVENT_ID_RE.match(event_id or ""):
        raise Refused("bad route or event id")
    path = os.path.join(outbox, route, event_id + ".json")
    if not is_inside(path, outbox):
        raise Refused("record outside the outbox")
    return path


def _plain(path):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise Refused("outbox record is linked or not a plain file: " + path)


def load_record(path):
    """A validated outbox record with its WakeEvent rebuilt and checked against its event_id."""
    _plain(path)
    with open(path, "rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise Refused("outbox record too large")
    try:
        rec = json.loads(data.decode("utf-8"))
        event = ev.from_dict(rec["event"]) if isinstance(rec, dict) and "event" in rec else None
    except (UnicodeDecodeError, ValueError, KeyError, TypeError) as err:
        raise Refused("outbox record invalid: %s (%s)" % (os.path.basename(path), err))
    if event is None or set(rec) != RECORD_KEYS or rec["schema"] != SCHEMA or rec["route"] != event.route or \
            rec["status"] not in STATUSES or not CODE_RE.match(rec["code"] or "") or \
            type(rec["attempt"]) is not int or not 1 <= rec["attempt"] <= MAX_ATTEMPTS or \
            os.path.basename(path) != event.event_id + ".json" or \
            os.path.basename(os.path.dirname(path)) != event.route:
        raise Refused("outbox record invalid: " + os.path.basename(path))
    rec["event"] = event
    return rec


def _write(path, rec):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    if os.path.lexists(tmp):
        raise Refused("leftover temporary outbox record: " + tmp)
    payload = dict(rec, event=rec["event"].to_dict())
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if os.path.lexists(path):
            _plain(path)
        os.replace(tmp, path)
    except BaseException:
        if os.path.lexists(tmp):
            os.remove(tmp)
        raise


def records(outbox, route=None):
    """All valid records (any invalid one refuses the whole listing: fail closed)."""
    found = []
    for r in ROUTE_NAMES:
        if route and r != route:
            continue
        folder = os.path.join(outbox, r)
        if not os.path.isdir(folder):
            continue
        for name in sorted(os.listdir(folder)):
            if name.endswith(".json"):
                found.append(load_record(os.path.join(folder, name)))
    return found


class LocalOutboxTransport:
    """Implements the Transport contract. deliver() never confirms anything: delivery is not acknowledgment."""
    name = NAME
    routes = frozenset(ROUTE_NAMES)

    def __init__(self, outbox, audit_log, stop_check, now, token=lambda: secrets.token_hex(4)):
        self.outbox, self.audit_log, self.stop_check, self.now, self.token = outbox, audit_log, stop_check, now, token
        self.delivered, self.stuck, self.skipped = [], [], []

    def deliver(self, events):
        events = tuple(events)
        if self.stop_check():  # STOP gate #3 inside the transport too: write nothing, confirm nothing
            return Receipt(self.name, batch_id(events), (), (), self.now())
        audit.read(self.audit_log)  # a broken audit chain refuses before any record is written
        for e in events:
            path = record_path(self.outbox, e.route, e.event_id)
            prev = load_record(path) if os.path.lexists(path) else None
            if prev and prev["status"] in ("STUCK", "ACKED"):
                self.skipped.append(e)
                continue
            attempt = prev["attempt"] + 1 if prev else 1
            if attempt > MAX_ATTEMPTS:
                prev["status"] = "STUCK"
                _write(path, prev)
                audit.append(self.audit_log, "STUCK", self.now(), event_id=e.event_id, route=e.route,
                             attempt=prev["attempt"])
                self.stuck.append((e, prev["attempt"]))
                continue
            code = self.token()
            if not CODE_RE.match(code):
                raise Refused("bad delivery code generated")
            _write(path, {"schema": SCHEMA, "event": e, "route": e.route, "attempt": attempt, "code": code,
                          "delivered_at": self.now(), "status": "PENDING"})
            audit.append(self.audit_log, "DELIVERED", self.now(), event_id=e.event_id, route=e.route,
                         attempt=attempt, code_sha256=audit.code_hash(code))
            self.delivered.append((e, attempt, code))
        return Receipt(self.name, batch_id(events), (), (), self.now())


def parse_glow_ack(text):
    """Exactly one "ACK <event_id> <code>" line; anything else (none, several) is refused: no batch acks."""
    found = GLOW_ACK_RE.findall(text or "")
    if len(found) != 1:
        raise Refused("Glow's reply must contain exactly one line 'ACK <event_id> <code>' (found %d)" % len(found))
    return found[0]


def _acked_ids(entries):
    return {x["event_id"] for x in entries if x["action"] in ("ACKED", "ALREADY_CONFIRMED")}


def reconcile(entries, cp, recs):
    """Cross-check the audit log, the checkpoint and the outbox. Returns problems; empty means consistent.

    Finds the traces an interruption can leave: a delivery written without its DELIVERED entry, and an event
    confirmed by this transport without its ACKED entry. Repairs: run deliver again (redelivery is audited), or
    acknowledge the event again (records ALREADY_CONFIRMED without a second commit).
    """
    problems = []
    acked = _acked_ids(entries)
    for eid, entry in sorted(cp["confirmed"].items()):
        if entry["transport"] == NAME and eid not in acked:
            problems.append("confirmed in the checkpoint without an ACKED audit entry (interrupted "
                            "acknowledgment; acknowledge it again): " + eid)
    last_code = {}
    for x in entries:
        if x["action"] == "DELIVERED":
            last_code[x["event_id"]] = x.get("code_sha256")
    for r in recs:
        eid = r["event"].event_id
        if r["status"] in ("PENDING", "STUCK") and last_code.get(eid) != audit.code_hash(r["code"]):
            problems.append("outbox delivery without its DELIVERED audit entry (interrupted delivery; run "
                            "deliver again): " + eid)
        if r["status"] != "ACKED" and eid in cp["confirmed"] and eid not in acked:
            problems.append("confirmed but its outbox record is still %s: %s" % (r["status"], eid))
    return problems


def acknowledge(outbox, audit_log, cp_path, route, event_id, code, actor, confirm, stop_check, now):
    """Accept one acknowledgment and advance the checkpoint for that one event. Returns the new checkpoint."""
    found = stop_check()  # STOP gate #4: before an acknowledgment is accepted
    if found:
        raise Stopped(found)
    entries = audit.read(audit_log)  # a broken audit chain refuses before anything is accepted
    path = record_path(outbox, route, event_id)
    if not os.path.lexists(path):
        raise Refused("no %s delivery for event %s" % (route, event_id))
    rec = load_record(path)
    e = rec["event"]
    if rec["status"] == "ACKED" and event_id in _acked_ids(entries):
        raise Refused("event already acknowledged")
    # An ACKED record without its audit entry (an interrupted acknowledgment) may be acknowledged again: the
    # checkpoint already holds it, so this only adds the missing ALREADY_CONFIRMED evidence.
    if not CODE_RE.match(code or "") or not secrets.compare_digest(code, rec["code"]):
        audit.append(audit_log, "REJECTED", now(), event_id=event_id, route=route, actor=actor,
                     attempt=rec["attempt"], detail="wrong or superseded delivery code")
        raise Refused("delivery code does not match the current delivery")
    if not confirm(e, rec):
        raise Refused("not confirmed (YES was not typed)")
    loaded = checkpoint.load(cp_path)
    if event_id in loaded["confirmed"]:
        rec["status"] = "ACKED"
        _write(path, rec)
        audit.append(audit_log, "ALREADY_CONFIRMED", now(), event_id=event_id, route=route, actor=actor,
                     revision_before=loaded["revision"], revision_after=loaded["revision"])
        return loaded
    receipt = Receipt(NAME, batch_id((e,)), (event_id,), (), now())
    new = checkpoint.commit(cp_path, loaded, (e,), receipt, stop_check, now())  # STOP gate #5 inside commit
    rec["status"] = "ACKED"
    _write(path, rec)
    audit.append(audit_log, "ACKED", now(), event_id=event_id, route=route, actor=actor, attempt=rec["attempt"],
                 code_sha256=audit.code_hash(code), revision_before=loaded["revision"],
                 revision_after=new["revision"])
    return new
