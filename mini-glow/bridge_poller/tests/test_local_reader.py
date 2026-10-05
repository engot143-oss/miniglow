"""Step 1 tests: local read-only adapter. Temporary practice folders only; no network, no account."""
import contextlib
import hashlib
import io
import os
import tempfile
import unittest
from unittest import mock

from bridge_poller import config, local_reader, poller
from bridge_poller.local_reader import LocalFolderReader, ReaderError
from bridge_poller.store import Store


def packet(pid, end=True):
    text = ("PACKET_ID: %s\nFROM: RAY\nTO: GLOW\nREPLY_TO: G2R-001\nSTATUS: RESPONSE\n\nMESSAGE:\nhello\n" % pid)
    return text + ("END_OF_PACKET\n" if end else "")


class Bridge:
    """A practice Bridge: <tmp>/Glow-Ray-Bridge/Ray-to-Glow, plus a separate state folder."""

    def __init__(self, case):
        tmp = tempfile.TemporaryDirectory()
        case.addCleanup(tmp.cleanup)
        self.root = os.path.join(tmp.name, "Glow-Ray-Bridge")
        self.folder = os.path.join(self.root, "Ray-to-Glow")
        self.state = os.path.join(tmp.name, "state")
        os.makedirs(self.folder)
        os.makedirs(self.state)

    def add(self, name, text):
        with open(os.path.join(self.folder, name), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)

    def snapshot(self):
        """Every path, size, mtime and hash under the root, to prove nothing changed."""
        snap = {}
        for base, dirs, files in os.walk(self.root):
            for name in dirs + files:
                path = os.path.join(base, name)
                st = os.stat(path)
                digest = "dir"
                if os.path.isfile(path):
                    with open(path, "rb") as handle:
                        digest = hashlib.sha256(handle.read()).hexdigest()
                snap[os.path.relpath(path, self.root)] = (st.st_size, st.st_mtime_ns, digest)
        return snap


def run_local(bridge, store, max_checks=3, on_sleep=None):
    reader = LocalFolderReader(bridge.folder, bridge.root)
    calls = {"n": 0}

    def sleep(_seconds):
        calls["n"] += 1
        if on_sleep:
            on_sleep(calls["n"])

    return poller.run(reader, store, folder_id=reader.folder_path, root_id=reader.root_path,
                      max_checks=max_checks, interval=60, sleep=sleep, now=lambda: "t")


class LocalReaderTests(unittest.TestCase):
    def new_store(self):
        store = Store()
        self.addCleanup(store.close)
        return store

    def rows(self, store):
        return {r["packet_id"]: r for r in store.all_packets()}

    def test_listing_and_baseline(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        b.add("R2G-002_x.txt", packet("R2G-002"))
        b.add("notes.txt", "not a packet")
        os.makedirs(os.path.join(b.folder, "R2G-003_subfolder"))
        store = self.new_store()
        summary = run_local(b, store, 2)
        self.assertEqual(sorted(self.rows(store)), ["R2G-001", "R2G-002"])
        self.assertTrue(all(r["state"] == "BACKLOG" for r in store.all_packets()))
        self.assertEqual(summary["new_count"], 0)
        listing = LocalFolderReader(b.folder, b.root).list_folder(b.folder)
        self.assertEqual({f["name"] for f in listing}, {"R2G-001_x.txt", "R2G-002_x.txt", "notes.txt"})
        self.assertTrue(all(f["createdTime"].endswith("+00:00") for f in listing))

    def test_new_packet_logged_once_and_rerun_is_idempotent(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        store = self.new_store()
        summary = run_local(b, store, 3, on_sleep=lambda n: n == 2 and b.add("R2G-002_x.txt", packet("R2G-002")))
        self.assertEqual(summary["new_count"], 1)
        self.assertEqual(self.rows(store)["R2G-002"]["state"], "NEW_LOGGED")
        before = store.all_packets()
        summary2 = run_local(b, store, 3)
        self.assertEqual(summary2["new_count"], 0)
        self.assertEqual(store.all_packets(), before)

    def test_partial_file_waits_until_complete(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        store = self.new_store()

        def grow(n):
            if n == 1:
                b.add("R2G-002_x.txt", packet("R2G-002", end=False))
            if n == 3:
                b.add("R2G-002_x.txt", packet("R2G-002"))

        summary = run_local(b, store, 4, on_sleep=grow)
        self.assertEqual(self.rows(store)["R2G-002"]["check_number"], 3)
        self.assertEqual(summary["new_count"], 1)

    def test_undecodable_bytes_are_treated_as_incomplete(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        store = self.new_store()

        def bad(n):
            if n == 1:
                with open(os.path.join(b.folder, "R2G-002_x.txt"), "wb") as handle:
                    handle.write(b"PACKET_ID: R2G-002\n\xff\xfe")

        summary = run_local(b, store, 2, on_sleep=bad)
        self.assertNotIn("R2G-002", self.rows(store))
        self.assertEqual(summary["new_count"], 0)

    def test_stop_before_start_and_mid_run(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        open(os.path.join(b.root, "STOP"), "w").close()
        store = self.new_store()
        summary = run_local(b, store, 3)
        self.assertEqual((summary["end_reason"], summary["checks_done"]), ("STOP", 0))
        self.assertEqual(store.all_packets(), [])
        os.remove(os.path.join(b.root, "STOP"))
        summary = run_local(b, store, 5, on_sleep=lambda n: n == 3 and open(os.path.join(b.root, "STOP"), "w").close())
        self.assertEqual((summary["end_reason"], summary["checks_done"]), ("STOP", 2))

    def test_stop_inside_ray_to_glow_is_not_the_stop_signal(self):
        b = Bridge(self)
        b.add("STOP", "")
        summary = run_local(b, self.new_store(), 1)
        self.assertEqual(summary["end_reason"], "WINDOW_DONE")

    def test_missing_or_wrong_paths_fail_closed(self):
        b = Bridge(self)
        with self.assertRaises(ReaderError):
            LocalFolderReader(os.path.join(b.root, "nope"), b.root)
        with self.assertRaises(ReaderError):
            LocalFolderReader(b.folder, os.path.join(b.root, "nope"))
        with self.assertRaises(ReaderError):
            LocalFolderReader(None, b.root)
        with self.assertRaises(ReaderError):
            LocalFolderReader(b.root, b.root)
        with self.assertRaises(ReaderError):
            LocalFolderReader(b.root, b.folder)  # swapped
        b.add("R2G-001_x.txt", "x")
        with self.assertRaises(ReaderError):
            LocalFolderReader(os.path.join(b.folder, "R2G-001_x.txt"), b.root)  # a file, not a folder

    def test_folder_disappearing_mid_run_ends_as_error(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        store = self.new_store()

        def vanish(n):
            if n == 2:
                os.rename(b.folder, b.folder + "_gone")

        with self.assertRaises(ReaderError):
            run_local(b, store, 3, on_sleep=vanish)
        self.assertEqual(store.last_run()["end_reason"], "ERROR")
        self.assertEqual(self.rows(store)["R2G-001"]["state"], "BACKLOG")

    def test_unreadable_file_ends_as_error(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        store = self.new_store()
        real_open = open

        def deny(path, mode="r", *a, **k):
            if str(path).endswith("R2G-002_x.txt") and mode == "rb":  # only the reader's read is refused
                raise PermissionError("locked")
            return real_open(path, mode, *a, **k)

        def add(n):
            if n == 1:
                b.add("R2G-002_x.txt", packet("R2G-002"))

        with mock.patch("builtins.open", deny):
            with self.assertRaises(ReaderError):
                run_local(b, store, 2, on_sleep=add)
        self.assertEqual(store.last_run()["end_reason"], "ERROR")
        self.assertNotIn("R2G-002", self.rows(store))

    def test_oversized_file_ends_as_error(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        store = self.new_store()
        with mock.patch.object(local_reader, "MAX_BYTES", 10):
            with self.assertRaises(ReaderError):
                run_local(b, store, 1, on_sleep=lambda n: b.add("R2G-002_x.txt", packet("R2G-002")))

    def test_unsafe_ids_and_mismatched_paths_are_refused(self):
        b = Bridge(self)
        reader = LocalFolderReader(b.folder, b.root)
        for bad in ("R2G-001_x.txt", "local:../STOP", "local:", "local:..", "local:sub/R2G-001.txt"):
            with self.assertRaises(ReaderError):
                reader.read_text(bad)
        with self.assertRaises(ReaderError):
            reader.list_folder(b.root)
        with self.assertRaises(ReaderError):
            reader.stop_present(b.folder)

    def test_symlinks_are_ignored(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        target = os.path.join(b.state, "outside.txt")
        with open(target, "w") as handle:
            handle.write(packet("R2G-009"))
        try:
            os.symlink(target, os.path.join(b.folder, "R2G-009_link.txt"))
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not available here")
        store = self.new_store()
        run_local(b, store, 1)
        self.assertNotIn("R2G-009", self.rows(store))

    def test_empty_local_folder_uses_suspect_rule(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        store = self.new_store()
        summary = run_local(b, store, 3, on_sleep=lambda n: n == 1 and os.remove(os.path.join(b.folder, "R2G-001_x.txt")))
        self.assertEqual(summary["health"], "NEEDS_ERIC")
        self.assertEqual(self.rows(store)["R2G-001"]["state"], "BACKLOG")

    def test_watched_folders_never_change(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        b.add("R2G-002_x.txt", packet("R2G-002", end=False))
        before = b.snapshot()
        db = os.path.join(b.state, "p.sqlite")
        with contextlib.redirect_stdout(io.StringIO()):
            code = poller.main(["--live", "--folder-path", b.folder, "--root-path", b.root,
                                "--db", db, "--max-checks", "3", "--interval", "0"])
        self.assertEqual(code, 0)
        self.assertEqual(b.snapshot(), before)

    def test_source_has_no_write_calls(self):
        with open(local_reader.__file__, encoding="ascii") as handle:
            source = handle.read()
        for forbidden in ('"w"', "'w'", '"a"', "'a'", '"wb"', "'wb'", "remove(", "unlink(", "rename(",
                          "replace(", "rmdir(", "makedirs(", "mkdir(", "write(", "shutil"):
            self.assertNotIn(forbidden, source, forbidden)
        public = {m for m in dir(LocalFolderReader) if not m.startswith("_")}
        self.assertEqual(public, {"list_folder", "read_text", "stop_present"})


class LiveCliTests(unittest.TestCase):
    def main(self, argv, env=None):
        out = io.StringIO()
        clean = {k: v for k, v in os.environ.items() if not k.startswith("BRIDGE_POLLER_")}
        clean.update(env or {})
        with mock.patch.dict(os.environ, clean, clear=True), contextlib.redirect_stdout(out):
            code = poller.main(argv)
        return code, out.getvalue()

    def test_live_without_paths_stays_blocked(self):
        b = Bridge(self)
        db = os.path.join(b.state, "x.sqlite")
        code, out = self.main(["--live", "--db", db])
        self.assertEqual(code, 2)
        self.assertIn("BLOCKED", out)
        self.assertFalse(os.path.exists(db))
        code, _ = self.main(["--live", "--db", db, "--folder-path", b.folder])  # only one path
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(db))

    def test_live_with_paths_runs(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        db = os.path.join(b.state, "x.sqlite")
        code, out = self.main(["--live", "--folder-path", b.folder, "--root-path", b.root,
                               "--db", db, "--max-checks", "2", "--interval", "0"])
        self.assertEqual(code, 0)
        self.assertIn("end_reason=WINDOW_DONE checks_done=2 new_count=0 suspect_listings=0 health=OK", out)

    def test_paths_from_environment(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        env = {config.ENV_FOLDER_PATH: b.folder, config.ENV_ROOT_PATH: b.root,
               config.ENV_DB: os.path.join(b.state, "env.sqlite")}
        code, _ = self.main(["--live", "--max-checks", "1", "--interval", "0"], env)
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(os.path.join(b.state, "env.sqlite")))

    def test_database_inside_watched_folder_is_refused(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        for db in (os.path.join(b.folder, "p.sqlite"), os.path.join(b.root, "p.sqlite"),
                   os.path.join(b.root, "deeper", "p.sqlite")):
            code, out = self.main(["--live", "--folder-path", b.folder, "--root-path", b.root,
                                   "--db", db, "--max-checks", "1", "--interval", "0"])
            self.assertEqual(code, 3)
            self.assertIn("must not be inside a watched folder", out)
            self.assertFalse(os.path.exists(db))
        self.assertFalse(os.path.exists(os.path.join(b.root, "deeper")))

    def test_bad_path_returns_error_without_database(self):
        b = Bridge(self)
        db = os.path.join(b.state, "x.sqlite")
        code, out = self.main(["--live", "--folder-path", os.path.join(b.root, "nope"),
                               "--root-path", b.root, "--db", db])
        self.assertEqual(code, 3)
        self.assertIn("ERROR", out)
        self.assertFalse(os.path.exists(db))

    def test_vanishing_folder_returns_error_code(self):
        b = Bridge(self)
        b.add("R2G-001_x.txt", packet("R2G-001"))
        db = os.path.join(b.state, "x.sqlite")
        real_run = poller.run

        def run_then_vanish(reader, store, **kw):
            kw["sleep"] = lambda s: os.path.isdir(b.folder) and os.rename(b.folder, b.folder + "_gone")
            return real_run(reader, store, **kw)

        with mock.patch.object(poller, "run", run_then_vanish):
            code, out = self.main(["--live", "--folder-path", b.folder, "--root-path", b.root,
                                   "--db", db, "--max-checks", "2", "--interval", "0"])
        self.assertEqual(code, 3)
        self.assertIn("ERROR", out)
        check = Store(db)
        self.addCleanup(check.close)
        self.assertEqual(check.last_run()["end_reason"], "ERROR")

    def test_default_database_path_is_absolute_and_outside_repo(self):
        win = config.default_db(environ={"LOCALAPPDATA": "C:\\Users\\x\\AppData\\Local"}, platform="nt")
        self.assertTrue(win.startswith("C:\\Users\\x\\AppData\\Local"))
        self.assertTrue(win.endswith("bridge_poller.sqlite"))
        self.assertIn("MiniGlow", win)
        posix = config.default_db(environ={}, platform="posix")
        self.assertTrue(os.path.isabs(posix))
        self.assertEqual(config.default_db(environ={config.ENV_DB: "/tmp/chosen.sqlite"}), "/tmp/chosen.sqlite")


if __name__ == "__main__":
    unittest.main()
