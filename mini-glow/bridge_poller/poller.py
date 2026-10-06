"""Read-only dry-run poller for the Ray-to-Glow Bridge folder.

Rules (from the approved scope):
- STOP is checked before every cycle.
- Packets already in the folder at startup are BACKLOG, never "new". One exception: a file that an
  earlier run saw INCOMPLETE is read again at startup and, if complete by then, logged NEW (check 0).
- At most 10 checks, one per interval (default 60 seconds).
- A completely empty listing, when packets are already known, is a suspect read:
  no packet row changes. Two suspect checks in a row set the RUN health to NEEDS_ERIC.
- Logs only: Drive createdTime, detection time, packet id, state.
- Sends nothing and creates nothing in Drive. The reader has no write function.
- --live reads only a LOCAL copy of the Bridge given by --folder-path and --root-path.
  Without both, --live stays BLOCKED. The database may never sit inside a watched folder.
- --live-api reads Google Drive read-only with a service-account key (Phase 3, design A1).
  Without a key file it stays BLOCKED; an unsafe or invalid key file stops it before any network use.
- A packet-named file seen incomplete INCOMPLETE_LIMIT times in a row is logged as NEEDS_ERIC. The streak is
  kept in the database, so it carries over to the next run: at startup such a file is read again instead of
  being taken as BACKLOG. A listing without the file ends its streak.
- From the command line the interval is 60 to 3600 seconds, and any unexpected problem ends as ERROR (exit 3).
"""
import argparse
import os
import sys
import time
from datetime import datetime, timezone

from . import config, drive_api_reader, packet_rules
from .drive_reader import BlockedError, FakeDrive, RealDrive
from .local_reader import LocalFolderReader, ReaderError, is_inside
from .store import SUSPECT_LIMIT, Store

HARD_MAX_CHECKS = 10
MIN_INTERVAL = 60
MAX_INTERVAL = 3600
INCOMPLETE_LIMIT = 3  # consecutive checks a packet-named file may stay incomplete before NEEDS_ERIC


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_suspect(listing, store):
    """A completely empty listing is suspect when the database already knows packets."""
    return len(listing) == 0 and store.packet_count() > 0


def _examine(reader, store, f, packet_id, check_number, now, seen_incomplete):
    """Read one packet-named file that is not in the database yet. Returns True if it was logged as new."""
    text = reader.read_text(f["id"])
    if not packet_rules.is_complete(text):
        # Not ready yet: recheck next time. Escalate only if it stays incomplete too long.
        seen_incomplete.add(f["id"])
        if store.bump_incomplete(f["id"], packet_id) >= INCOMPLETE_LIMIT:
            store.insert_packet(packet_id, f["id"], f["createdTime"], now(), check_number, "NEEDS_ERIC")
        return False
    if packet_rules.header_packet_id(text) != packet_id:
        state = "NEEDS_ERIC"  # filename and header disagree
    else:
        state = "NEW_LOGGED"
    store.insert_packet(packet_id, f["id"], f["createdTime"], now(), check_number, state)
    return state == "NEW_LOGGED"


def _take_baseline(reader, store, folder_id, now):
    """Returns (suspect, new_count). A suspect baseline changes nothing."""
    listing = reader.list_folder(folder_id)
    if _is_suspect(listing, store):
        return True, 0
    new_count = 0
    seen_incomplete = set()
    for f in listing:
        packet_id = packet_rules.packet_id_from_name(f["name"])
        if packet_id is None:
            continue
        if store.has_packet(packet_id) or store.has_file(f["id"]):
            continue
        if store.is_incomplete(f["id"]):
            # Seen incomplete in an earlier run: keep watching it instead of calling it BACKLOG.
            new_count += _examine(reader, store, f, packet_id, 0, now, seen_incomplete)
            continue
        store.insert_packet(packet_id, f["id"], f["createdTime"], None, 0, "BACKLOG")
    if listing:  # an empty listing never ends streaks (it may be a bad read)
        store.keep_incomplete(seen_incomplete)
    # A sighting at startup resets miss counters, but a baseline is not a check: no misses are counted.
    store.record_listing({f["id"] for f in listing}, count_misses=False)
    return False, new_count


def _process_listing(reader, store, listing, check_number, now):
    new_count = 0
    seen_incomplete = set()
    for f in listing:
        packet_id = packet_rules.packet_id_from_name(f["name"])
        if packet_id is None:
            continue
        if store.has_packet(packet_id) or store.has_file(f["id"]):
            continue
        new_count += _examine(reader, store, f, packet_id, check_number, now, seen_incomplete)
    if listing:  # an empty listing never ends streaks (it may be a bad read)
        store.keep_incomplete(seen_incomplete)
    store.record_listing({f["id"] for f in listing})
    return new_count


def run(reader, store, folder_id=None, root_id=None,
        max_checks=HARD_MAX_CHECKS, interval=60, sleep=None, now=utcnow):
    sleep = sleep or time.sleep
    folder_id, root_id = config.resolve_ids(folder_id, root_id)
    max_checks = max(0, min(int(max_checks), HARD_MAX_CHECKS))
    run_id = store.start_run(now())
    checks_done = 0
    new_count = 0
    end_reason = "WINDOW_DONE"
    suspect_total = 0  # suspect listings this run, baseline included
    suspect_streak = 0  # consecutive suspect CHECKS (the baseline is not a check)
    health = "OK"
    try:
        if reader.stop_present(root_id):
            end_reason = "STOP"
        else:
            suspect, new_count = _take_baseline(reader, store, folder_id, now)
            if suspect:
                suspect_total += 1
            store.set_baseline(run_id, now())
            for n in range(1, max_checks + 1):
                sleep(interval)
                if hasattr(reader, "advance"):
                    reader.advance(n)
                if reader.stop_present(root_id):
                    end_reason = "STOP"
                    break
                listing = reader.list_folder(folder_id)
                if _is_suspect(listing, store):
                    # Do not touch packet rows; record the read condition and go on to the next check.
                    suspect_total += 1
                    suspect_streak += 1
                    if suspect_streak >= SUSPECT_LIMIT:
                        health = "NEEDS_ERIC"  # run-level escalation; stays set for this run
                else:
                    suspect_streak = 0
                    new_count += _process_listing(reader, store, listing, n, now)
                checks_done = n
    except Exception:
        store.end_run(run_id, now(), checks_done, new_count, "ERROR", suspect_total, health)
        raise
    store.end_run(run_id, now(), checks_done, new_count, end_reason, suspect_total, health)
    return {"run_id": run_id, "checks_done": checks_done, "new_count": new_count, "end_reason": end_reason,
            "suspect_listings": suspect_total, "health": health}


def _interval(value):
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number of seconds")
    if not MIN_INTERVAL <= seconds <= MAX_INTERVAL:  # also refuses NaN and infinity
        raise argparse.ArgumentTypeError("must be from %d to %d seconds" % (MIN_INTERVAL, MAX_INTERVAL))
    return seconds


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only Bridge dry-run poller")
    parser.add_argument("--fixture", help="JSON scenario for FakeDrive (no credentials)")
    parser.add_argument("--live", action="store_true",
                        help="Read a LOCAL read-only copy of the Bridge (needs both --folder-path and --root-path)")
    parser.add_argument("--db", help="SQLite file (else env BRIDGE_POLLER_DB, else a per-user local path)")
    parser.add_argument("--max-checks", type=int, default=HARD_MAX_CHECKS)
    parser.add_argument("--interval", type=_interval, default=MIN_INTERVAL,
                        help="Seconds between checks (%d to %d)" % (MIN_INTERVAL, MAX_INTERVAL))
    parser.add_argument("--folder-id", help="Ray-to-Glow folder id (else env BRIDGE_POLLER_FOLDER_ID, else default)")
    parser.add_argument("--root-id", help="Bridge root folder id for STOP (else env BRIDGE_POLLER_ROOT_ID, else default)")
    parser.add_argument("--folder-path", help="Local Ray-to-Glow folder (else env BRIDGE_POLLER_FOLDER_PATH)")
    parser.add_argument("--root-path", help="Local Bridge root folder (else env BRIDGE_POLLER_ROOT_PATH)")
    parser.add_argument("--live-api", action="store_true",
                        help="Read Google Drive through the API with a service-account key (needs --key-file)")
    parser.add_argument("--key-file", help="Service-account key file (else env BRIDGE_POLLER_KEY_FILE)")
    args = parser.parse_args(argv)
    if sum(1 for mode in (args.fixture, args.live, args.live_api) if mode) != 1:
        parser.error("choose exactly one of --fixture, --live or --live-api")
    folder_id, root_id = args.folder_id, args.root_id
    if args.live_api:
        key_file = config.resolve_key_file(args.key_file)
        if not key_file:
            print("BLOCKED: --live-api needs a service-account key file (--key-file or BRIDGE_POLLER_KEY_FILE).")
            return 2
        folder_id, root_id = config.resolve_ids(folder_id, root_id)
        try:
            reader = drive_api_reader.build_reader(key_file, folder_id, root_id)
        except ReaderError as err:
            print("ERROR:", err)
            return 3
    elif args.live:
        folder_path, root_path = config.resolve_paths(args.folder_path, args.root_path)
        if not (folder_path and root_path):
            try:
                RealDrive()  # no local copy configured: stay fail-closed
            except BlockedError as err:
                print("BLOCKED:", err)
                return 2
        try:
            reader = LocalFolderReader(folder_path, root_path)
        except ReaderError as err:
            print("ERROR:", err)
            return 3
        folder_id, root_id = reader.folder_path, reader.root_path
    else:
        reader = FakeDrive.from_json(args.fixture)
    db_path = os.path.abspath(args.db or config.default_db())
    if args.live and (is_inside(db_path, reader.root_path) or is_inside(db_path, reader.folder_path)):
        print("ERROR: the database must not be inside a watched folder:", db_path)
        return 3
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    store = Store(db_path)
    try:
        summary = run(reader, store, folder_id=folder_id, root_id=root_id,
                      max_checks=args.max_checks, interval=args.interval)
    except ReaderError as err:
        print("ERROR:", err)
        return 3
    except Exception as err:  # anything unexpected still ends cleanly as ERROR (the run row says ERROR too)
        print("ERROR: unexpected problem:", err.__class__.__name__)
        return 3
    finally:
        store.close()
    print(
        "run={run_id} end_reason={end_reason} checks_done={checks_done} new_count={new_count} "
        "suspect_listings={suspect_listings} health={health}".format(**summary)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
