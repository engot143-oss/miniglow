"""Test helpers. Databases are made by bridge_poller's own run() with its FakeDrive, in temporary folders.

Tests need the verified MiniGlow code on the import path (PYTHONPATH=<repo>\\mini-glow); they import it
read-only and never write there.
"""
import hashlib
import os
import shutil
import sqlite3
import tempfile
import unittest

from bridge_poller import poller
from bridge_poller.drive_reader import FakeDrive
from bridge_poller.store import Store

from wake_adapter import checkpoint, paths
from wake_adapter.transport import Receipt, batch_id

NOW = "2026-10-08T12:00:00+00:00"


def packet_text(header_id):
    return ("PACKET_ID: %s\nFROM: Ray\nTO: Glow\nREPLY_TO: Glow-to-Ray\nSTATUS: TEST\n"
            "MESSAGE: SECRET-BODY-%s must never appear in an event\nEND_OF_PACKET\n" % (header_id, header_id))


def pfile(n, header=None, created="2026-10-07T00:00:00+00:00", suffix="TEST"):
    pid = "R2G-%03d" % n
    name = "%s_%s.txt" % (pid, suffix)
    return {"id": "local:" + name, "name": name, "createdTime": created, "text": packet_text(header or pid)}


def key(n, suffix="TEST"):
    return "R2G-%03d|local:R2G-%03d_%s.txt" % (n, n, suffix)


class Clock:
    def __init__(self):
        self.t = 0

    def __call__(self):
        self.t += 1
        return "2026-10-07T03:%02d:%02d+00:00" % (self.t // 60 % 60, self.t % 60)


class FailingDrive(FakeDrive):
    """Raises on the given listing (1 = baseline, 2 = check 1, ...), which ends the run as ERROR."""

    def __init__(self, fail_on_listing, **kw):
        super().__init__(**kw)
        self.fail_on_listing = fail_on_listing
        self.listings = 0

    def list_folder(self, folder_id):
        self.listings += 1
        if self.listings == self.fail_on_listing:
            raise RuntimeError("simulated read failure")
        return super().list_folder(folder_id)


def make_db(path, files=(), schedule=None, remove=None, stop_at=None, max_checks=0, fail_on_listing=None):
    """One bounded poller run into a fresh database, exactly as T4 does (but with FakeDrive)."""
    kw = dict(files=list(files), schedule=schedule, remove=remove, stop_at=stop_at)
    reader = FailingDrive(fail_on_listing, **kw) if fail_on_listing else FakeDrive(**kw)
    store = Store(path)
    try:
        poller.run(reader, store, folder_id="RAY-TO-GLOW", root_id="BRIDGE", max_checks=max_checks,
                   interval=60, sleep=lambda s: None, now=Clock())
    except RuntimeError:
        if not fail_on_listing:
            raise
    finally:
        store.close()
    return path


def make_open_db(path, n=59):
    """A run that has started but not ended (the poller is still running): WAIT."""
    store = Store(path)
    try:
        store.start_run(NOW)
        f = pfile(n)
        store.insert_packet(f["name"][:7], f["id"], f["createdTime"], NOW, 1, "NEW_LOGGED")
    finally:
        store.close()
    return path


def raw_db(path, statements):
    """A database made by hand (for schemas bridge_poller would never write)."""
    conn = sqlite3.connect(path)
    try:
        for sql in statements:
            conn.execute(sql)
        conn.commit()
    finally:
        conn.close()
    return path


# Same columns as bridge_poller at 08df577 but without CHECK constraints, so tests can store bad values.
LOOSE_PACKETS = ("CREATE TABLE packets (packet_id TEXT PRIMARY KEY, drive_file_id TEXT UNIQUE NOT NULL, "
                 "drive_created_time TEXT NOT NULL, detected_at TEXT, check_number INTEGER NOT NULL, "
                 "state TEXT NOT NULL, missing_count INTEGER NOT NULL DEFAULT 0)")
LOOSE_RUNS = ("CREATE TABLE runs (run_id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, "
              "baseline_at TEXT, ended_at TEXT, checks_done INTEGER, new_count INTEGER, end_reason TEXT, "
              "suspect_listings INTEGER NOT NULL DEFAULT 0, health TEXT NOT NULL DEFAULT 'OK')")
INCOMPLETE = "CREATE TABLE incomplete (drive_file_id TEXT PRIMARY KEY, packet_id TEXT NOT NULL, streak INTEGER NOT NULL)"
FINISHED_RUN = ("INSERT INTO runs (started_at, baseline_at, ended_at, checks_done, new_count, end_reason) "
                "VALUES ('a', 'a', 'b', 0, 0, 'WINDOW_DONE')")


def sha256(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def fingerprint(path):
    st = os.stat(path)
    return sha256(path), st.st_size, st.st_mtime_ns


def tree(path):
    """{relative path: sha256} of every file under path."""
    result = {}
    for root, _dirs, files in os.walk(path):
        for name in files:
            full = os.path.join(root, name)
            result[os.path.relpath(full, path)] = sha256(full)
    return result


class RecordingTransport:
    """Test-only transport. Delivers nowhere; records batches and confirms what it is told to."""

    def __init__(self, name="recording", routes=("GLOW", "ERIC"), confirm=None, raise_error=False):
        self.name = name
        self.routes = frozenset(routes)
        self.confirm = confirm  # None: confirm all; else a function event -> bool
        self.raise_error = raise_error
        self.delivered = []

    def deliver(self, events):
        if self.raise_error:
            raise ConnectionError("simulated transport failure")
        self.delivered.append(tuple(events))
        ok = [e.event_id for e in events if self.confirm is None or self.confirm(e)]
        failed = tuple((e.event_id, "not confirmed") for e in events if e.event_id not in ok)
        return Receipt(self.name, batch_id(events), tuple(ok), failed, NOW)


class TempTree(unittest.TestCase):
    """A temporary LOCALAPPDATA with a MiniGlow folder, and a temporary Bridge with Ray-to-Glow."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wake_adapter_test_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.local = os.path.join(self.tmp, "Local")
        self.base = os.path.join(self.local, "MiniGlow")
        self.bridge = os.path.join(self.tmp, "Bridge")
        os.makedirs(self.base)
        os.makedirs(os.path.join(self.bridge, "Ray-to-Glow"))
        self.cp_path = os.path.join(self.base, paths.CHECKPOINT_NAME)

    def db(self, name, **kw):
        make_db(os.path.join(self.base, name), **kw)
        return name

    def no_stop(self):
        return []

    def init_checkpoint(self, high_water="R2G-058"):
        return checkpoint.init(self.cp_path, high_water, history_seed(high_water), NOW)


def history_seed(high_water="R2G-058"):
    """The seed of the usual test history: R2G-001 .. high_water, each as its default test file."""
    return checkpoint.make_seed([key(n) for n in range(1, int(high_water[4:]) + 1)], ["t4_seed.sqlite"])


def seeded(high_water="R2G-058"):
    """In-memory checkpoint at high_water whose seeded history is R2G-001 .. high_water."""
    return checkpoint.empty(high_water, NOW, history_seed(high_water))
