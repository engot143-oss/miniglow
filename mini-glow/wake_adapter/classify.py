"""Classification, cross-run deduplication, and the adapter's fixed order of steps.

Order: STOP gate #1 -> checkpoint -> read-only snapshots -> classify/dedup -> STOP gate #2 -> WakeEvent[].
"""
from dataclasses import dataclass
from datetime import datetime, timezone

from . import checkpoint as cp_mod
from . import events as ev
from . import paths, snapshot, stop

KIND_ORDER = {ev.ESCALATE: 0, ev.OFFLINE_GAP: 1, ev.NEW: 2}


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class AdapterResult:
    events: tuple  # WakeEvent, deliverable
    waiting: tuple  # database names with no finished run yet (WAIT: never delivered)


def _run_reasons(run):
    reasons = []
    if run["end_reason"] == "ERROR":
        reasons.append("RUN_ERROR")
    if run["end_reason"] == "STOP":
        reasons.append("RUN_STOP")
    if run["health"] != "OK":
        reasons.append("RUN_HEALTH_NEEDS_ERIC")
    if run["suspect_listings"] > 0:
        reasons.append("RUN_SUSPECT_LISTINGS")
    return reasons


def classify(snapshots, checkpoint, produced_at):
    """Turn snapshots into events not yet confirmed in the checkpoint.

    - NEW: a NEW_LOGGED row above high_water, its packet key not yet confirmed or gap-reported.
    - ESCALATE: every NEEDS_ERIC row, and every unhealthy run (ERROR, STOP, health, suspect listings).
      Escalations are never treated as history.
    - OFFLINE_GAP: all BACKLOG rows above high_water that are not confirmed, not gap-reported and not
      NEW_LOGGED in any database of this call, as ONE summary event.
    - LATE_BELOW_BOUNDARY (ESCALATE): a row at or below high_water, in any state, whose identity
      (packet_id + drive_file_id) is not in seeded_history. The sequence number alone never proves history.
    - WAIT: a database without a finished run; nothing from it is used.
    Rows at or below high_water whose identity is in seeded_history are history: nothing is produced
    (a NEEDS_ERIC row still escalates as NEEDS_ERIC_ROW).
    """
    high = ev.packet_number(checkpoint["high_water"])
    seeded = set(checkpoint["seeded_history"]["keys"])
    done_ids = set(checkpoint["confirmed"])
    done_keys = {k for entry in checkpoint["confirmed"].values() for k in entry["keys"]}
    reported = set(checkpoint["gap_reported"])
    finished = sorted((s for s in snapshots if not s.waiting), key=lambda s: s.db)
    waiting = tuple(sorted(s.db for s in snapshots if s.waiting))
    logged_new = {ev.packet_key(p["packet_id"], p["drive_file_id"])
                  for s in finished for p in s.packets if p["state"] == "NEW_LOGGED"}
    found = {}
    gap = {}

    def add(event):
        if event.event_id not in done_ids:
            found.setdefault(event.event_id, event)  # same event from two databases: keep the earliest

    for s in finished:
        last = s.runs[-1]
        for run in s.runs:
            for reason in _run_reasons(run):
                add(ev.run_escalation(reason, s.db, run, produced_at))
        for p in s.packets:
            key = ev.packet_key(p["packet_id"], p["drive_file_id"])
            above = ev.packet_number(p["packet_id"]) > high
            if not above and key not in seeded:
                add(ev.late_escalation(p, s.db, last, produced_at))
            if p["state"] == "NEEDS_ERIC":
                add(ev.packet_escalation(p, s.db, last, produced_at))
            elif p["state"] == "NEW_LOGGED":
                if above and key not in done_keys and key not in reported:
                    add(ev.new_event(p, s.db, last, produced_at))
            elif above and key not in done_keys and key not in reported and key not in logged_new:
                gap.setdefault(key, (p["packet_id"], p["drive_file_id"], s.db))
    if gap:
        add(ev.gap_event(list(gap.values()), produced_at))
    ordered = sorted(found.values(), key=lambda e: (KIND_ORDER[e.kind], e.packet_id or "", e.event_id))
    return tuple(ordered), waiting


def produce(db_names, base=None, bridge_root=paths.BRIDGE_ROOT, checkpoint=None, stop_check=None,
            now=utcnow, environ=None):
    """Run the adapter once. Reads only. Returns AdapterResult; raises Stopped or Refused.

    checkpoint=None loads the checkpoint file (it must exist); a dict is used as given and never written.
    """
    base = base or paths.miniglow_base(environ)
    stop_check = stop_check or (lambda: stop.stop_present(bridge_root, base))
    found = stop_check()  # STOP gate #1: before the checkpoint or any database is opened
    if found:
        raise paths.Stopped(found)
    if checkpoint is None:
        checkpoint = cp_mod.load(paths.checkpoint_path(base, bridge_root))
    else:
        cp_mod.validate(checkpoint)
    names = list(db_names)
    if not names or len(set(names)) != len(names):
        raise paths.Refused("give one or more distinct database names")
    snapshots = [snapshot.take(paths.db_path(base, n, bridge_root), n) for n in names]
    events, waiting = classify(snapshots, checkpoint, now())
    found = stop_check()  # STOP gate #2: immediately before WakeEvent[] leaves the adapter
    if found:
        raise paths.Stopped(found)
    return AdapterResult(events=events, waiting=waiting)
