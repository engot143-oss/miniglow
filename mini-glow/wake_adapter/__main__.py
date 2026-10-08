"""Command line. Nothing here sends anything off this PC.

  py -3.14 -B -m wake_adapter init --high-water R2G-nnn --seed-db NAME.sqlite [--seed-db ...]
      Create the checkpoint in %LOCALAPPDATA%\\MiniGlow, seeded with the packet identities at or below the
      high water found in the given finished poller databases. Production use needs Eric's approval.
  py -3.14 -B -m wake_adapter plan --db NAME.sqlite [--db ...] [--assume-high-water R2G-nnn [--seed-db ...]]
      Dry run: print the events that would be produced. Writes nothing. --assume-high-water uses an
      in-memory checkpoint instead of the checkpoint file; without --seed-db its seed is empty, so every
      packet at or below the high water is reported as LATE_BELOW_BOUNDARY.
  py -3.14 -B -m wake_adapter deliver --db NAME.sqlite [--db ...]
      v0.2 local outbox: write each unconfirmed event (and every still-pending earlier delivery) to
      MiniGlow\\outbox\\<route>\\ with a fresh delivery code. Delivery never confirms anything.
  py -3.14 -B -m wake_adapter inbox [--route ERIC|GLOW]
      Read-only list of pending deliveries with their codes.
  py -3.14 -B -m wake_adapter ack EVENT_ID CODE
      Eric acknowledges one ERIC event; asks for typed YES. Only this advances the checkpoint for it.
  py -3.14 -B -m wake_adapter ack-glow [--text "..."]
      Eric enters Glow's reply (one line "ACK <event_id> <code>"; from --text or standard input) for one GLOW
      event; asks for typed YES.
  py -3.14 -B -m wake_adapter audit-verify
      Check the audit log's hash chain, then reconcile it with the checkpoint and the outbox (finds what an
      interrupted delivery or acknowledgment left behind, and says how to repair it).
Exit codes: 0 done, 2 refused or STOP.
"""
import argparse
import json
import os
import sys

from . import audit, checkpoint, outbox, paths, snapshot, stop
from . import events as ev
from .classify import produce, utcnow
from .transport import hand_over


def _seed(base, bridge_root, names, high_water):
    found = stop.stop_present(bridge_root, base)  # STOP before any seed database is opened
    if found:
        raise paths.Stopped(found)
    if len(set(names)) != len(names):
        raise paths.Refused("give distinct seed database names")
    snaps = [snapshot.take(paths.db_path(base, n, bridge_root), n) for n in names]
    return checkpoint.seed_from_snapshots(snaps, high_water)


def _summary(e):
    if e.kind == ev.OFFLINE_GAP:
        return "OFFLINE_GAP %s..%s count %d" % (e.gap["first"], e.gap["last"], e.gap["count"])
    return "%s %s %s" % (e.kind, e.reason or "", e.packet_id or "")


def _deliver(base, bridge_root, db_names, out, new_only=False):
    """new_only (used by the scheduled bridge cycle): deliver only events with no outbox record yet, so automatic
    runs never use up the retry attempts. Retries stay with a manual deliver run."""
    stop_check = lambda: stop.stop_present(bridge_root, base)
    result = produce(db_names, base=base, bridge_root=bridge_root, stop_check=stop_check)  # gates #1 and #2
    box, log = paths.outbox_dir(base, bridge_root), paths.audit_path(base, bridge_root)
    confirmed = set(checkpoint.load(paths.checkpoint_path(base, bridge_root))["confirmed"])
    produced = {e.event_id for e in result.events}
    existing = outbox.records(box)
    if new_only:
        known = {r["event"].event_id for r in existing}
        events, pending = tuple(e for e in result.events if e.event_id not in known), ()
    else:
        events = tuple(result.events)
        pending = tuple(r["event"] for r in existing
                        if r["status"] == "PENDING" and r["event"].event_id not in produced | confirmed)
    transport = outbox.LocalOutboxTransport(box, log, stop_check, utcnow)
    batch = events + pending
    if batch:
        hand_over(transport, batch, stop_check)  # STOP gate #3, route check, receipt validation
    escalations = tuple(ev.stuck_escalation(e, n, utcnow()) for e, n in transport.stuck
                        if e.reason != "STUCK_DELIVERY")
    if escalations:
        hand_over(transport, escalations, stop_check)
    for e, attempt, code in transport.delivered:
        out("DELIVERED to local outbox: %s attempt %d/%d  %s  event %s  code %s"
            % (e.route, attempt, outbox.MAX_ATTEMPTS, _summary(e), e.event_id, code))
    for e, n in transport.stuck:
        out("STUCK after %d attempts: %s event %s" % (n, _summary(e), e.event_id))
    out("delivered %d, stuck %d, waiting databases %s. Nothing was sent off this PC; nothing is confirmed until "
        "acknowledged." % (len(transport.delivered), len(transport.stuck), list(result.waiting)))


def _inbox(base, bridge_root, route, out):
    box = paths.outbox_dir(base, bridge_root)
    confirmed = set(checkpoint.load(paths.checkpoint_path(base, bridge_root))["confirmed"])
    shown = 0
    for r in outbox.records(box, route):
        if r["status"] == "ACKED":
            continue
        e = r["event"]
        shown += 1
        out("%s %-7s attempt %d/%d  %s\n   event %s\n   code  %s%s"
            % (e.route, r["status"], r["attempt"], outbox.MAX_ATTEMPTS, _summary(e), e.event_id, r["code"],
               "\n   (already confirmed in the checkpoint)" if e.event_id in confirmed else ""))
    out("%d delivery(ies) waiting for acknowledgment" % shown)


def _ack(base, bridge_root, route, event_id, code, actor, ask, out):
    stop_check = lambda: stop.stop_present(bridge_root, base)

    def confirm(e, rec):
        out("Acknowledge %s delivery (attempt %d): %s\n   event %s\nThis records that %s has seen it. It "
            "authorises nothing else." % (route, rec["attempt"], _summary(e), e.event_id, route))
        return (ask("Type YES to acknowledge: ") or "").strip() == "YES"

    new = outbox.acknowledge(paths.outbox_dir(base, bridge_root), paths.audit_path(base, bridge_root),
                             paths.checkpoint_path(base, bridge_root), route, event_id, code, actor, confirm,
                             stop_check, utcnow)
    out("ACKNOWLEDGED: checkpoint revision %d, %d confirmed event(s)" % (new["revision"], len(new["confirmed"])))


def _link(base, bridge_root):
    from .bridge import Link
    return Link(base, bridge_root, paths.audit_path(base, bridge_root), lambda: stop.stop_present(bridge_root, base),
                utcnow)


def _all_dbs(base):
    return sorted(n for n in os.listdir(base) if paths.DB_RE.match(n) and os.path.isfile(os.path.join(base, n)))


def _bridge_cycle(base, bridge_root, db_names, out):
    """One automatic round: read replies, deliver NEW events only, send packets for pending GLOW deliveries."""
    link = _link(base, bridge_root)
    for name, outcome in link.receive():
        out("REPLY %s: %s" % (name, outcome))
    if db_names:
        _deliver(base, bridge_root, db_names, out, new_only=True)
    for packet_id in link.send_pending(paths.outbox_dir(base, bridge_root)):
        out("SENT %s to Claude-to-Glow" % packet_id)
    out("bridge cycle done")


def _bridge_status(base, bridge_root, out):
    state = _link(base, bridge_root).status()
    for packet_id, s in sorted(state["sent"].items()):
        out("%s %-10s %-13s %s%s" % (packet_id, s["kind"], s["status"], s["file"],
                                     ("  reply " + s["reply_file"] + " (" + s.get("sender", "") + ")")
                                     if s.get("reply_file") else ""))
    waiting = [p for p, s in state["sent"].items() if s["status"] == "AWAITING_ERIC"]
    out("%d sent, %d answered, %d waiting for Eric's confirmation%s"
        % (len(state["sent"]), sum(1 for s in state["sent"].values() if s["status"] != "SENT"), len(waiting),
           (": " + ", ".join(sorted(waiting))) if waiting else ""))


def main(argv=None, environ=None, bridge_root=paths.BRIDGE_ROOT, out=print, ask=input, stdin=None):
    parser = argparse.ArgumentParser(prog="wake_adapter", description="Wake Adapter and local Wake Transport")
    sub = parser.add_subparsers(dest="command", required=True)
    p_init = sub.add_parser("init", help="create the checkpoint (needs Eric's approval in production)")
    p_init.add_argument("--high-water", required=True)
    p_init.add_argument("--seed-db", action="append", required=True,
                        help="finished poller database (NAME.sqlite in the MiniGlow folder) holding the history")
    p_plan = sub.add_parser("plan", help="dry run: print events, write nothing")
    p_plan.add_argument("--db", action="append", required=True, help="NAME.sqlite in the MiniGlow folder")
    p_plan.add_argument("--assume-high-water", help="use an in-memory checkpoint at this high water")
    p_plan.add_argument("--seed-db", action="append", default=[], help="seed for the in-memory checkpoint")
    p_del = sub.add_parser("deliver", help="write unconfirmed events to the local outbox")
    p_del.add_argument("--db", action="append", required=True, help="NAME.sqlite in the MiniGlow folder")
    p_inbox = sub.add_parser("inbox", help="list deliveries waiting for acknowledgment (read-only)")
    p_inbox.add_argument("--route", choices=outbox.ROUTE_NAMES)
    p_ack = sub.add_parser("ack", help="Eric acknowledges one ERIC event")
    p_ack.add_argument("event_id")
    p_ack.add_argument("code")
    p_glow = sub.add_parser("ack-glow", help="enter Glow's acknowledgment of one GLOW event")
    p_glow.add_argument("--text", help="Glow's reply (else read from standard input)")
    sub.add_parser("audit-verify", help="check the audit log's hash chain")
    p_ping = sub.add_parser("bridge-ping", help="send one harmless test packet to Glow through the Bridge")
    p_ping.add_argument("--note", help="text for the test packet")
    p_cycle = sub.add_parser("bridge-cycle", help="read replies, deliver new events, send pending GLOW packets")
    g_cycle = p_cycle.add_mutually_exclusive_group()
    g_cycle.add_argument("--db", action="append", help="NAME.sqlite in the MiniGlow folder")
    g_cycle.add_argument("--all-dbs", action="store_true", help="every NAME.sqlite in the MiniGlow folder")
    sub.add_parser("bridge-status", help="sent packets and replies (read-only)")
    p_conf = sub.add_parser("bridge-confirm", help="Eric confirms Glow's acknowledgment of one WakeEvent")
    p_conf.add_argument("packet_id")
    args = parser.parse_args(argv)
    environ = os.environ if environ is None else environ
    try:
        base = paths.miniglow_base(environ)
        user = (environ.get("USERNAME") or "unknown").strip()
        if args.command == "init":
            seed = _seed(base, bridge_root, args.seed_db, args.high_water)
            path = paths.checkpoint_path(base, bridge_root)
            checkpoint.init(path, args.high_water, seed, utcnow())
            out("INIT: checkpoint created at high water %s with %d seeded packet identities from %s: %s"
                % (args.high_water, len(seed["keys"]), ", ".join(seed["sources"]), path))
            return 0
        if args.command == "deliver":
            _deliver(base, bridge_root, args.db, out)
            return 0
        if args.command == "inbox":
            _inbox(base, bridge_root, args.route, out)
            return 0
        if args.command == "ack":
            _ack(base, bridge_root, "ERIC", args.event_id, args.code, "eric (" + user + ")", ask, out)
            return 0
        if args.command == "ack-glow":
            text = args.text if args.text is not None else (stdin or sys.stdin).read()
            event_id, code = outbox.parse_glow_ack(text)
            _ack(base, bridge_root, "GLOW", event_id, code, "glow (entered by " + user + ")", ask, out)
            return 0
        if args.command == "bridge-ping":
            kw = {"note": args.note} if args.note else {}
            packet_id = _link(base, bridge_root).send_ping(**kw)
            out("SENT %s (PING) to Glow-Ray-Bridge/Claude-to-Glow" % packet_id)
            return 0
        if args.command == "bridge-cycle":
            _bridge_cycle(base, bridge_root, _all_dbs(base) if args.all_dbs else (args.db or []), out)
            return 0
        if args.command == "bridge-status":
            _bridge_status(base, bridge_root, out)
            return 0
        if args.command == "bridge-confirm":
            def confirm(e, rec):
                out("Glow acknowledged %s (%s, event %s) through the Bridge.\nConfirming records it in the "
                    "checkpoint. It authorises nothing else." % (args.packet_id, _summary(e), e.event_id))
                return (ask("Type YES to confirm: ") or "").strip() == "YES"
            new = _link(base, bridge_root).confirm(args.packet_id, paths.outbox_dir(base, bridge_root),
                                                   paths.checkpoint_path(base, bridge_root),
                                                   "glow via bridge, confirmed by eric (" + user + ")", confirm)
            out("CONFIRMED: checkpoint revision %d" % new["revision"])
            return 0
        if args.command == "audit-verify":
            ok, count, problem = audit.verify(paths.audit_path(base, bridge_root))
            out("AUDIT %s: %s" % ("OK" if ok else "BROKEN", "%d entries" % count if ok else problem))
            if not ok:
                return 2
            problems = outbox.reconcile(audit.read(paths.audit_path(base, bridge_root)),
                                        checkpoint.load(paths.checkpoint_path(base, bridge_root)),
                                        outbox.records(paths.outbox_dir(base, bridge_root)))
            out("RECONCILIATION %s" % ("OK: audit log, checkpoint and outbox agree" if not problems else
                                       "INCOMPLETE:\n   " + "\n   ".join(problems)))
            return 0 if not problems else 2
        if args.seed_db and not args.assume_high_water:
            raise paths.Refused("--seed-db in plan needs --assume-high-water (the checkpoint file has its own seed)")
        assumed = None
        if args.assume_high_water:
            seed = _seed(base, bridge_root, args.seed_db, args.assume_high_water) if args.seed_db else None
            assumed = checkpoint.empty(args.assume_high_water, utcnow(), seed)
        result = produce(args.db, base=base, bridge_root=bridge_root, checkpoint=assumed)
        out(json.dumps({"dry_run": True,
                        "checkpoint": ("in-memory %s, %d seeded" % (args.assume_high_water,
                                                                    len(assumed["seeded_history"]["keys"])))
                        if assumed else "file",
                        "waiting": list(result.waiting),
                        "event_count": len(result.events),
                        "events": [e.to_dict() for e in result.events]}, indent=2))
        return 0
    except paths.Stopped as err:
        out("STOPPED: " + ", ".join(err.found))
        return 2
    except paths.Refused as err:
        out("REFUSED: " + str(err))
        return 2


if __name__ == "__main__":
    sys.exit(main())
