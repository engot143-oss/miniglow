"""Criteria 5 (read-only proof) and 6 (fail closed on schema and values)."""
import os
import sqlite3

from wake_adapter import paths, snapshot
from wake_adapter.paths import Refused

from .support import (FINISHED_RUN, INCOMPLETE, LOOSE_PACKETS, LOOSE_RUNS, TempTree, fingerprint, make_open_db,
                      pfile, raw_db)


class ReadOnlyTests(TempTree):
    def test_snapshot_leaves_database_byte_identical(self):
        name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 6)])
        path = os.path.join(self.base, name)
        before = fingerprint(path)
        snap = snapshot.take(path, name)
        self.assertEqual(len(snap.packets), 5)
        self.assertEqual(fingerprint(path), before)
        self.assertEqual(sorted(os.listdir(self.base)), [name])  # no journal or other file left behind

    def test_write_through_adapter_connection_raises(self):
        name = self.db("t4_a.sqlite", files=[pfile(1)])
        path = os.path.join(self.base, name)
        before = fingerprint(path)
        conn = snapshot._connect(path)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("INSERT INTO runs (started_at) VALUES ('x')")
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("CREATE TABLE evil (x)")
        finally:
            conn.close()
        self.assertEqual(fingerprint(path), before)

    def test_missing_database_refused_and_not_created(self):
        with self.assertRaises(Refused):
            paths.db_path(self.base, "t4_missing.sqlite", self.bridge)
        missing = os.path.join(self.base, "t4_missing.sqlite")
        with self.assertRaises(Refused):
            snapshot.take(missing, "t4_missing.sqlite")
        self.assertFalse(os.path.exists(missing))

    def test_older_layout_read_without_upgrade(self):
        old_packets = ("CREATE TABLE packets (packet_id TEXT PRIMARY KEY, drive_file_id TEXT UNIQUE NOT NULL, "
                       "drive_created_time TEXT NOT NULL, detected_at TEXT, check_number INTEGER NOT NULL, "
                       "state TEXT NOT NULL)")
        old_runs = ("CREATE TABLE runs (run_id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, "
                    "baseline_at TEXT, ended_at TEXT, checks_done INTEGER, new_count INTEGER, end_reason TEXT)")
        path = raw_db(os.path.join(self.base, "old.sqlite"), [
            old_packets, old_runs, INCOMPLETE, FINISHED_RUN,
            "INSERT INTO packets VALUES ('R2G-001', 'local:a', 't', NULL, 0, 'BACKLOG')"])
        before = fingerprint(path)
        snap = snapshot.take(path, "old.sqlite")
        self.assertEqual(snap.packets[0]["missing_count"], 0)
        self.assertEqual(snap.runs[0]["health"], "OK")
        self.assertEqual(snap.runs[0]["suspect_listings"], 0)
        self.assertEqual(fingerprint(path), before)
        conn = sqlite3.connect(path)
        try:
            columns = {r[1] for r in conn.execute("PRAGMA table_info(packets)")}
        finally:
            conn.close()
        self.assertNotIn("missing_count", columns)  # not upgraded

    def test_lock_released_after_snapshot(self):
        name = self.db("t4_a.sqlite", files=[pfile(1)])
        path = os.path.join(self.base, name)
        snapshot.take(path, name)
        writer = sqlite3.connect(path, timeout=0, isolation_level=None)
        try:
            writer.execute("BEGIN EXCLUSIVE")  # a running poller could write at once
            writer.execute("ROLLBACK")
        finally:
            writer.close()

    def test_open_run_and_no_run_are_waiting(self):
        path = make_open_db(os.path.join(self.base, "open.sqlite"))
        self.assertTrue(snapshot.take(path, "open.sqlite").waiting)
        empty = raw_db(os.path.join(self.base, "norun.sqlite"), [LOOSE_PACKETS, LOOSE_RUNS, INCOMPLETE])
        self.assertTrue(snapshot.take(empty, "norun.sqlite").waiting)


class FailClosedTests(TempTree):
    def refuse(self, statements, fragment):
        path = raw_db(os.path.join(self.base, "bad.sqlite"), statements)
        with self.assertRaises(Refused) as caught:
            snapshot.take(path, "bad.sqlite")
        self.assertIn(fragment, str(caught.exception))

    def test_missing_table(self):
        self.refuse([LOOSE_PACKETS, LOOSE_RUNS], "table missing")

    def test_unknown_table(self):
        self.refuse([LOOSE_PACKETS, LOOSE_RUNS, INCOMPLETE, "CREATE TABLE extra (x)"], "unknown table")

    def test_unknown_column(self):
        self.refuse([LOOSE_PACKETS, LOOSE_RUNS, INCOMPLETE, "ALTER TABLE packets ADD COLUMN surprise TEXT"],
                    "unknown column")

    def test_missing_column(self):
        self.refuse(["CREATE TABLE packets (packet_id TEXT, drive_file_id TEXT, state TEXT)", LOOSE_RUNS,
                     INCOMPLETE], "column missing")

    def test_view_or_trigger(self):
        self.refuse([LOOSE_PACKETS, LOOSE_RUNS, INCOMPLETE, "CREATE VIEW v AS SELECT * FROM packets"],
                    "unexpected view")

    def test_unknown_state(self):
        self.refuse([LOOSE_PACKETS, LOOSE_RUNS, INCOMPLETE, FINISHED_RUN,
                     "INSERT INTO packets VALUES ('R2G-001', 'local:a', 't', NULL, 0, 'DONE', 0)"], "unknown state")

    def test_malformed_packet_id(self):
        self.refuse([LOOSE_PACKETS, LOOSE_RUNS, INCOMPLETE, FINISHED_RUN,
                     "INSERT INTO packets VALUES ('R2G-58', 'local:a', 't', NULL, 0, 'BACKLOG', 0)"],
                    "malformed packet_id")

    def test_unknown_end_reason_and_health(self):
        self.refuse([LOOSE_PACKETS, LOOSE_RUNS, INCOMPLETE,
                     "INSERT INTO runs (started_at, ended_at, end_reason) VALUES ('a', 'b', 'MAYBE')"],
                    "unknown end_reason")
        os.remove(os.path.join(self.base, "bad.sqlite"))
        self.refuse([LOOSE_PACKETS, LOOSE_RUNS, INCOMPLETE,
                     "INSERT INTO runs (started_at, ended_at, end_reason, health) VALUES ('a', 'b', 'WINDOW_DONE', 'MEH')"],
                    "unknown health")

    def test_not_a_database(self):
        path = os.path.join(self.base, "junk.sqlite")
        with open(path, "wb") as handle:
            handle.write(b"this is not sqlite" * 100)
        with self.assertRaises(Refused):
            snapshot.take(path, "junk.sqlite")

    def test_bad_database_names_and_places(self):
        for name in ("../x.sqlite", "x.db", "a b.sqlite", "", None, "x" * 65 + ".sqlite"):
            with self.assertRaises(Refused):
                paths.db_path(self.base, name, self.bridge)
        inside = os.path.join(self.bridge, "MiniGlow")
        os.makedirs(inside)
        self.db("t4_a.sqlite")
        os.replace(os.path.join(self.base, "t4_a.sqlite"), os.path.join(inside, "t4_a.sqlite"))
        with self.assertRaises(Refused) as caught:
            paths.db_path(inside, "t4_a.sqlite", self.bridge)
        self.assertIn("inside the Bridge", str(caught.exception))
