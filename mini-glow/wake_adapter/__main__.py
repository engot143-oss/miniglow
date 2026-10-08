"""Command line: exactly two commands, and no commit (v0.1 has no transport).

  py -3.14 -B -m wake_adapter init --high-water R2G-nnn --seed-db NAME.sqlite [--seed-db ...]
      Create the checkpoint in %LOCALAPPDATA%\\MiniGlow, seeded with the packet identities at or below the
      high water found in the given finished poller databases. Production use needs Eric's approval.
  py -3.14 -B -m wake_adapter plan --db NAME.sqlite [--db ...] [--assume-high-water R2G-nnn [--seed-db ...]]
      Dry run: print the events that would be produced. Writes nothing. --assume-high-water uses an
      in-memory checkpoint instead of the checkpoint file; without --seed-db its seed is empty, so every
      packet at or below the high water is reported as LATE_BELOW_BOUNDARY.
Exit codes: 0 done, 2 refused or STOP.
"""
import argparse
import json
import sys

from . import checkpoint, paths, snapshot, stop
from .classify import produce, utcnow


def _seed(base, bridge_root, names, high_water):
    found = stop.stop_present(bridge_root, base)  # STOP before any seed database is opened
    if found:
        raise paths.Stopped(found)
    if len(set(names)) != len(names):
        raise paths.Refused("give distinct seed database names")
    snaps = [snapshot.take(paths.db_path(base, n, bridge_root), n) for n in names]
    return checkpoint.seed_from_snapshots(snaps, high_water)


def main(argv=None, environ=None, bridge_root=paths.BRIDGE_ROOT, out=print):
    parser = argparse.ArgumentParser(prog="wake_adapter", description="Wake Adapter v0.1 (staging)")
    sub = parser.add_subparsers(dest="command", required=True)
    p_init = sub.add_parser("init", help="create the checkpoint (needs Eric's approval in production)")
    p_init.add_argument("--high-water", required=True)
    p_init.add_argument("--seed-db", action="append", required=True,
                        help="finished poller database (NAME.sqlite in the MiniGlow folder) holding the history")
    p_plan = sub.add_parser("plan", help="dry run: print events, write nothing")
    p_plan.add_argument("--db", action="append", required=True, help="NAME.sqlite in the MiniGlow folder")
    p_plan.add_argument("--assume-high-water", help="use an in-memory checkpoint at this high water")
    p_plan.add_argument("--seed-db", action="append", default=[], help="seed for the in-memory checkpoint")
    args = parser.parse_args(argv)
    try:
        base = paths.miniglow_base(environ)
        if args.command == "init":
            seed = _seed(base, bridge_root, args.seed_db, args.high_water)
            path = paths.checkpoint_path(base, bridge_root)
            checkpoint.init(path, args.high_water, seed, utcnow())
            out("INIT: checkpoint created at high water %s with %d seeded packet identities from %s: %s"
                % (args.high_water, len(seed["keys"]), ", ".join(seed["sources"]), path))
            return 0
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
