"""Read-only snapshot of one bridge_poller database.

Never imports bridge_poller (its Store creates tables and upgrades columns on open, which are writes).
The database is opened with ?mode=ro and query_only, read in one short transaction, and closed at once,
so a running poller is never kept waiting.
"""
import pathlib
import re
import sqlite3
from dataclasses import dataclass

from .paths import Refused

PACKET_ID_RE = re.compile(r"^R2G-\d{3}\Z")
STATES = frozenset({"BACKLOG", "NEW_LOGGED", "NEEDS_ERIC"})
END_REASONS = frozenset({"WINDOW_DONE", "STOP", "ERROR"})
HEALTH = frozenset({"OK", "NEEDS_ERIC"})

# Columns of bridge_poller at 08df577. The columns bridge_poller adds to older databases when it opens them
# are optional here, read with the same defaults (an older database is read as it is, never upgraded).
# Anything else is refused.
REQUIRED = {
    "packets": {"packet_id", "drive_file_id", "drive_created_time", "detected_at", "check_number", "state"},
    "runs": {"run_id", "started_at", "baseline_at", "ended_at", "checks_done", "new_count", "end_reason"},
    "incomplete": {"drive_file_id", "packet_id", "streak"},
}
OPTIONAL = {
    "packets": {"missing_count": "0"},
    "runs": {"suspect_listings": "0", "health": "'OK'"},
    "incomplete": {},
}
ALLOWED_EXTRA_TABLES = frozenset({"sqlite_sequence"})


@dataclass(frozen=True)
class Snapshot:
    db: str
    runs: tuple  # dicts, ordered by run_id
    packets: tuple  # dicts, ordered by packet_id

    @property
    def waiting(self):
        """Only finished runs are used: a database with no run, or an open one, is WAIT."""
        return not self.runs or any(r["ended_at"] is None for r in self.runs)


def _connect(path):
    uri = pathlib.Path(path).resolve().as_uri() + "?mode=ro"
    return sqlite3.connect(uri, uri=True, timeout=1.0, isolation_level=None)


def _check_schema(conn):
    """Return the optional columns present per table; refuse anything unexpected."""
    objects = conn.execute("SELECT type, name FROM sqlite_master").fetchall()
    tables = {name for kind, name in objects if kind == "table"}
    for kind, name in objects:
        if kind == "index" and name.startswith("sqlite_autoindex_"):
            continue
        if kind != "table":
            raise Refused("unexpected %s in database: %s" % (kind, name))
    missing = set(REQUIRED) - tables
    if missing:
        raise Refused("table missing: " + ", ".join(sorted(missing)))
    extra = tables - set(REQUIRED) - ALLOWED_EXTRA_TABLES
    if extra:
        raise Refused("unknown table: " + ", ".join(sorted(extra)))
    present = {}
    for table, required in REQUIRED.items():
        columns = {r[1] for r in conn.execute("PRAGMA table_info(%s)" % table)}
        if required - columns:
            raise Refused("column missing in %s: %s" % (table, ", ".join(sorted(required - columns))))
        unknown = columns - required - set(OPTIONAL[table])
        if unknown:
            raise Refused("unknown column in %s: %s" % (table, ", ".join(sorted(unknown))))
        present[table] = columns & set(OPTIONAL[table])
    return present


def _select(table, columns, present):
    parts = sorted(columns) + [c if c in present[table] else "%s AS %s" % (default, c)
                               for c, default in sorted(OPTIONAL[table].items())]
    return "SELECT %s FROM %s" % (", ".join(parts), table)


def _is_int(value):
    return type(value) is int


def _is_text(value):
    return isinstance(value, str) and value != ""


def _check_packet(p):
    if not (isinstance(p["packet_id"], str) and PACKET_ID_RE.match(p["packet_id"])):
        raise Refused("malformed packet_id: %r" % (p["packet_id"],))
    if not _is_text(p["drive_file_id"]) or "\n" in p["drive_file_id"]:
        raise Refused("malformed drive_file_id for " + p["packet_id"])
    if p["state"] not in STATES:
        raise Refused("unknown state for %s: %r" % (p["packet_id"], p["state"]))
    if not _is_text(p["drive_created_time"]) or not (p["detected_at"] is None or _is_text(p["detected_at"])):
        raise Refused("malformed timestamp for " + p["packet_id"])
    if not (_is_int(p["check_number"]) and p["check_number"] >= 0 and _is_int(p["missing_count"])):
        raise Refused("malformed counter for " + p["packet_id"])


def _check_run(r):
    if not _is_int(r["run_id"]):
        raise Refused("malformed run_id: %r" % (r["run_id"],))
    if r["end_reason"] is not None and r["end_reason"] not in END_REASONS:
        raise Refused("unknown end_reason in run %s: %r" % (r["run_id"], r["end_reason"]))
    if r["health"] not in HEALTH:
        raise Refused("unknown health in run %s: %r" % (r["run_id"], r["health"]))
    if not (_is_int(r["suspect_listings"]) and r["suspect_listings"] >= 0):
        raise Refused("malformed suspect_listings in run %s" % r["run_id"])
    if r["ended_at"] is not None and (not _is_text(r["ended_at"]) or r["end_reason"] is None):
        raise Refused("run %s ended without an end_reason" % r["run_id"])


def take(path, name):
    """Snapshot of one database. Any read or schema problem raises Refused (fail closed)."""
    try:
        conn = _connect(path)
    except sqlite3.Error as err:
        raise Refused("cannot open database read-only: %s (%s)" % (name, err))
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        conn.execute("BEGIN")  # one read transaction: runs and packets come from the same moment
        present = _check_schema(conn)
        runs = [dict(r) for r in conn.execute(_select("runs", REQUIRED["runs"], present) + " ORDER BY run_id")]
        packets = [dict(r) for r in conn.execute(
            _select("packets", REQUIRED["packets"], present) + " ORDER BY packet_id")]
        conn.execute("ROLLBACK")
    except sqlite3.Error as err:
        raise Refused("cannot read database: %s (%s)" % (name, err))
    finally:
        conn.close()
    for r in runs:
        _check_run(r)
    for p in packets:
        _check_packet(p)
    return Snapshot(db=name, runs=tuple(runs), packets=tuple(packets))
