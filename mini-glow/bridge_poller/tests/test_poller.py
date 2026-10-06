import contextlib
import io
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from bridge_poller import config, packet_rules, poller
from bridge_poller.drive_reader import BlockedError, DriveReader, FakeDrive, RealDrive
from bridge_poller.store import Store

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "backlog_4.json")


def packet(pid, status="RESPONSE", message="hello", end=True, body=True):
    lines = [f"PACKET_ID: {pid}", "FROM: RAY", "TO: GLOW", "REPLY_TO: G2R-001",
             f"STATUS: {status}", "", "MESSAGE:"]
    if body:
        lines.append(message)
    if end:
        lines.append("END_OF_PACKET")
    return "\n".join(lines) + "\n"


def f(pid, name=None, text=None):
    return {"id": f"id-{pid}", "name": name or f"{pid}_RAY_to_GLOW_x.txt",
            "createdTime": "2026-10-05T00:00:00Z", "text": text if text is not None else packet(pid)}


def base():
    return [f(f"R2G-00{i}") for i in range(1, 5)]


def run_poller(fake, store, max_checks=5):
    sleeps = []
    ticks = iter(range(1000, 5000))
    summary = poller.run(fake, store, max_checks=max_checks, interval=60,
                         sleep=sleeps.append, now=lambda: f"t{next(ticks)}")
    return summary, sleeps


def setUpModule():
    # Command-line runs now need --interval 60 or more; tests never really wait.
    patcher = mock.patch("time.sleep", lambda _seconds: None)
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)


class PollerTests(unittest.TestCase):
    def new_store(self):
        store = Store()
        self.addCleanup(store.close)
        return store

    def test_t1_baseline_is_backlog_not_new(self):
        fake, store = FakeDrive(files=base()), self.new_store()
        summary, _ = run_poller(fake, store, 2)
        rows = store.all_packets()
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(r["state"] == "BACKLOG" and r["check_number"] == 0 for r in rows))
        self.assertEqual(summary["new_count"], 0)

    def test_t2_rerun_changes_nothing(self):
        fake, store = FakeDrive(files=base()), self.new_store()
        run_poller(fake, store, 2)
        before = store.all_packets()
        summary, _ = run_poller(fake, store, 2)
        self.assertEqual(store.all_packets(), before)
        self.assertEqual(summary["new_count"], 0)

    def test_t3_stop_before_start(self):
        fake, store = FakeDrive(files=base(), stop_at=0), self.new_store()
        summary, _ = run_poller(fake, store)
        self.assertEqual(summary["end_reason"], "STOP")
        self.assertEqual(summary["checks_done"], 0)
        self.assertEqual(store.all_packets(), [])
        self.assertNotIn("list_folder", fake.calls)

    def test_t3_stop_mid_run(self):
        fake, store = FakeDrive(files=base(), stop_at=2), self.new_store()
        summary, _ = run_poller(fake, store)
        self.assertEqual(summary["end_reason"], "STOP")
        self.assertEqual(summary["checks_done"], 1)
        self.assertEqual(fake.calls.count("list_folder"), 2)  # baseline + check 1 only

    def test_t4_new_packet_logged_once_at_check_3(self):
        fake = FakeDrive(files=base(), schedule={3: [f("R2G-005")]})
        store = self.new_store()
        summary, _ = run_poller(fake, store, 5)
        rows = {r["packet_id"]: r for r in store.all_packets()}
        self.assertEqual(len(rows), 5)
        self.assertEqual(rows["R2G-005"]["state"], "NEW_LOGGED")
        self.assertEqual(rows["R2G-005"]["check_number"], 3)
        self.assertEqual(summary["new_count"], 1)
        self.assertEqual(summary["end_reason"], "WINDOW_DONE")
        self.assertEqual(summary["checks_done"], 5)

    def test_t5_incomplete_not_logged_until_complete(self):
        partial = f("R2G-005", text=packet("R2G-005", end=False))
        fake = FakeDrive(files=base(), schedule={2: [partial]},
                         text_updates={4: {"id-R2G-005": packet("R2G-005")}})
        store = self.new_store()
        summary, _ = run_poller(fake, store, 5)
        rows = {r["packet_id"]: r for r in store.all_packets()}
        self.assertEqual(rows["R2G-005"]["check_number"], 4)
        self.assertEqual(summary["new_count"], 1)

    def test_t5_empty_body_never_logged(self):
        empty = f("R2G-005", text=packet("R2G-005", body=False))
        fake = FakeDrive(files=base(), schedule={2: [empty]})
        store = self.new_store()
        summary, _ = run_poller(fake, store, 3)
        self.assertEqual(len(store.all_packets()), 4)
        self.assertEqual(summary["new_count"], 0)

    def test_t6_non_matching_names_ignored(self):
        extras = [f("X1", name="notes.txt"), f("X2", name="MSG-002_RAY_to_GLOW_ARIP.txt"),
                  f("X3", name="R2G-xyz_bad.txt"), f("X4", name="R2G-9999_bad.txt")]
        fake = FakeDrive(files=base(), schedule={1: extras})
        store = self.new_store()
        summary, _ = run_poller(fake, store, 3)
        self.assertEqual(len(store.all_packets()), 4)
        self.assertEqual(summary["new_count"], 0)

    def test_t7_repeated_listing_single_row_single_read(self):
        fake = FakeDrive(files=base(), schedule={3: [f("R2G-005")]})
        store = self.new_store()
        run_poller(fake, store, 6)
        self.assertEqual(sum(1 for r in store.all_packets() if r["packet_id"] == "R2G-005"), 1)
        self.assertEqual(fake.calls.count("read_text"), 1)

    def test_t8_no_write_functions_exist(self):
        public = {m for m in dir(DriveReader) if not m.startswith("_")}
        self.assertEqual(public, {"list_folder", "read_text", "stop_present"})
        fake = FakeDrive(files=base(), schedule={3: [f("R2G-005")]})
        run_poller(fake, self.new_store(), 5)
        self.assertTrue(set(fake.calls) <= public)
        with self.assertRaises(BlockedError):
            RealDrive()

    def test_t9_window_ends_at_10_checks_and_interval_is_60(self):
        fake, store = FakeDrive(files=base()), self.new_store()
        summary, sleeps = run_poller(fake, store, 50)  # request 50, must cap at 10
        self.assertEqual(summary["checks_done"], 10)
        self.assertEqual(summary["end_reason"], "WINDOW_DONE")
        self.assertEqual(sleeps, [60] * 10)
        self.assertEqual(fake.calls.count("list_folder"), 11)  # 1 baseline + 10 checks

    def test_t10_vanished_file_needs_eric(self):
        fake = FakeDrive(files=base(), remove={2: ["id-R2G-001"]})
        store = self.new_store()
        summary, _ = run_poller(fake, store, 3)
        rows = {r["packet_id"]: r for r in store.all_packets()}
        self.assertEqual(rows["R2G-001"]["state"], "NEEDS_ERIC")
        self.assertEqual(summary["new_count"], 0)

    def test_t11_header_filename_mismatch_needs_eric(self):
        bad = f("R2G-005", text=packet("R2G-099"))
        fake = FakeDrive(files=base(), schedule={2: [bad]})
        store = self.new_store()
        summary, _ = run_poller(fake, store, 3)
        rows = {r["packet_id"]: r for r in store.all_packets()}
        self.assertEqual(rows["R2G-005"]["state"], "NEEDS_ERIC")
        self.assertEqual(summary["new_count"], 0)

    def test_t12_cli_live_blocked_and_fixture_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_live = os.path.join(tmp, "live.sqlite")
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = poller.main(["--live", "--db", db_live])
            self.assertEqual(code, 2)
            self.assertIn("BLOCKED", out.getvalue())
            self.assertFalse(os.path.exists(db_live))

            db_fix = os.path.join(tmp, "fix.sqlite")
            with contextlib.redirect_stdout(io.StringIO()):
                code = poller.main(["--fixture", FIXTURE, "--db", db_fix, "--max-checks", "3", "--interval", "60"])
            self.assertEqual(code, 0)
            check = Store(db_fix)
            rows = check.all_packets()
            check.close()
            self.assertEqual(len(rows), 5)
            self.assertEqual(sum(1 for r in rows if r["state"] == "NEW_LOGGED"), 1)

            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    poller.main([])


class MissCountTests(unittest.TestCase):
    def new_store(self):
        store = Store()
        self.addCleanup(store.close)
        return store

    @staticmethod
    def rows(store):
        return {r["packet_id"]: r for r in store.all_packets()}

    def test_one_miss_keeps_state_and_counts(self):
        fake = FakeDrive(files=base(), remove={2: ["id-R2G-001"]})
        store = self.new_store()
        run_poller(fake, store, 2)  # check 1 healthy, check 2 is the first miss
        row = self.rows(store)["R2G-001"]
        self.assertEqual(row["state"], "BACKLOG")
        self.assertEqual(row["missing_count"], 1)

    def test_one_miss_then_recovery_resets_to_zero(self):
        fake = FakeDrive(files=base(), remove={2: ["id-R2G-001"]}, schedule={3: [f("R2G-001")]})
        store = self.new_store()
        run_poller(fake, store, 3)
        row = self.rows(store)["R2G-001"]
        self.assertEqual(row["state"], "BACKLOG")
        self.assertEqual(row["missing_count"], 0)

    def test_two_consecutive_misses_flag_needs_eric(self):
        fake = FakeDrive(files=base(), remove={2: ["id-R2G-001"]})
        store = self.new_store()
        run_poller(fake, store, 3)  # misses at checks 2 and 3
        row = self.rows(store)["R2G-001"]
        self.assertEqual(row["state"], "NEEDS_ERIC")
        self.assertEqual(row["missing_count"], 2)

    def test_non_consecutive_misses_never_flag(self):
        fake = FakeDrive(files=base(), remove={2: ["id-R2G-001"], 4: ["id-R2G-001"]},
                         schedule={3: [f("R2G-001")]})
        store = self.new_store()
        run_poller(fake, store, 4)  # miss, recover, miss
        row = self.rows(store)["R2G-001"]
        self.assertEqual(row["state"], "BACKLOG")
        self.assertEqual(row["missing_count"], 1)

    def test_repeated_healthy_listings_stay_at_zero(self):
        fake = FakeDrive(files=base())
        store = self.new_store()
        run_poller(fake, store, 10)
        for row in store.all_packets():
            self.assertEqual(row["state"], "BACKLOG")
            self.assertEqual(row["missing_count"], 0)

    def test_new_logged_packet_uses_the_same_rule(self):
        fake = FakeDrive(files=base(), schedule={2: [f("R2G-005")]}, remove={4: ["id-R2G-005"]})
        store = self.new_store()
        summary, _ = run_poller(fake, store, 5)  # logged at 2, missing at 4 and 5
        row = self.rows(store)["R2G-005"]
        self.assertEqual(row["state"], "NEEDS_ERIC")
        self.assertEqual(summary["new_count"], 1)

    def test_needs_eric_is_not_cleared_automatically(self):
        fake = FakeDrive(files=base(), remove={2: ["id-R2G-001"]}, schedule={4: [f("R2G-001")]})
        store = self.new_store()
        run_poller(fake, store, 5)  # flagged at check 3, file returns at check 4
        self.assertEqual(self.rows(store)["R2G-001"]["state"], "NEEDS_ERIC")

    def test_baseline_sighting_resets_counter_without_counting_a_miss(self):
        store = self.new_store()
        run_poller(FakeDrive(files=base(), remove={2: ["id-R2G-001"]}), store, 2)
        self.assertEqual(self.rows(store)["R2G-001"]["missing_count"], 1)
        run_poller(FakeDrive(files=base()), store, 0)  # baseline only, no checks
        self.assertEqual(self.rows(store)["R2G-001"]["missing_count"], 0)
        incomplete = [f(f"R2G-00{i}") for i in range(2, 5)]  # R2G-001 absent at baseline
        run_poller(FakeDrive(files=incomplete), store, 0)
        self.assertEqual(self.rows(store)["R2G-001"]["missing_count"], 0)  # a baseline never counts a miss

    def test_old_database_is_migrated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old.sqlite")
            conn = sqlite3.connect(path)
            conn.executescript(
                "CREATE TABLE packets (packet_id TEXT PRIMARY KEY, drive_file_id TEXT UNIQUE NOT NULL, "
                "drive_created_time TEXT NOT NULL, detected_at TEXT, check_number INTEGER NOT NULL, "
                "state TEXT NOT NULL CHECK (state IN ('BACKLOG', 'NEW_LOGGED', 'NEEDS_ERIC')));"
                "INSERT INTO packets VALUES ('R2G-001', 'id-R2G-001', 't', NULL, 0, 'BACKLOG');"
            )
            conn.commit()
            conn.close()
            store = Store(path)
            rows = store.all_packets()
            store.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["missing_count"], 0)
        self.assertEqual(rows[0]["state"], "BACKLOG")


ALL_IDS = [f"id-R2G-00{i}" for i in range(1, 5)]


class EmptyListingTests(unittest.TestCase):
    def new_store(self):
        store = Store()
        self.addCleanup(store.close)
        return store

    def assert_rows_untouched(self, store):
        rows = store.all_packets()
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertEqual(row["state"], "BACKLOG")
            self.assertEqual(row["missing_count"], 0)

    def test_one_empty_listing_changes_no_packet_and_no_escalation(self):
        fake = FakeDrive(files=base(), remove={2: ALL_IDS}, schedule={3: base()})
        store = self.new_store()
        summary, _ = run_poller(fake, store, 3)
        self.assert_rows_untouched(store)
        self.assertEqual(summary["suspect_listings"], 1)
        self.assertEqual(summary["health"], "OK")
        self.assertEqual(summary["checks_done"], 3)

    def test_two_consecutive_empty_listings_escalate_run_not_rows(self):
        fake = FakeDrive(files=base(), remove={2: ALL_IDS})
        store = self.new_store()
        summary, _ = run_poller(fake, store, 3)  # empty at checks 2 and 3
        self.assert_rows_untouched(store)
        self.assertEqual(summary["health"], "NEEDS_ERIC")
        self.assertEqual(summary["suspect_listings"], 2)
        self.assertEqual(summary["end_reason"], "WINDOW_DONE")
        run = store.last_run()
        self.assertEqual(run["health"], "NEEDS_ERIC")
        self.assertEqual(run["suspect_listings"], 2)

    def test_run_continues_to_the_bounded_end_after_escalation(self):
        fake = FakeDrive(files=base(), remove={2: ALL_IDS})
        store = self.new_store()
        summary, sleeps = run_poller(fake, store, 10)
        self.assertEqual(summary["checks_done"], 10)
        self.assertEqual(summary["suspect_listings"], 9)
        self.assertEqual(sleeps, [60] * 10)
        self.assert_rows_untouched(store)

    def test_escalation_stays_set_after_recovery_in_the_same_run(self):
        fake = FakeDrive(files=base(), remove={2: ALL_IDS}, schedule={4: base()})
        store = self.new_store()
        summary, _ = run_poller(fake, store, 5)  # empty at 2 and 3, healthy at 4 and 5
        self.assertEqual(summary["health"], "NEEDS_ERIC")
        self.assert_rows_untouched(store)

    def test_empty_recover_empty_does_not_escalate(self):
        fake = FakeDrive(files=base(), remove={2: ALL_IDS, 4: ALL_IDS}, schedule={3: base()})
        store = self.new_store()
        summary, _ = run_poller(fake, store, 4)
        self.assertEqual(summary["health"], "OK")
        self.assertEqual(summary["suspect_listings"], 2)
        self.assert_rows_untouched(store)

    def test_empty_folder_with_empty_database_is_not_suspect(self):
        store = self.new_store()
        summary, _ = run_poller(FakeDrive(files=[]), store, 3)
        self.assertEqual(summary["suspect_listings"], 0)
        self.assertEqual(summary["health"], "OK")
        self.assertEqual(store.all_packets(), [])

    def test_empty_baseline_is_suspect_but_not_a_check(self):
        store = self.new_store()
        run_poller(FakeDrive(files=base()), store, 0)
        summary, _ = run_poller(FakeDrive(files=[]), store, 1)  # empty baseline + one empty check
        self.assertEqual(summary["suspect_listings"], 2)
        self.assertEqual(summary["health"], "OK")  # only one consecutive suspect CHECK
        self.assert_rows_untouched(store)

    def test_empty_listing_neither_counts_nor_resets_a_file_miss(self):
        others = [f"id-R2G-00{i}" for i in range(2, 5)]
        fake = FakeDrive(files=base(), remove={2: ["id-R2G-001"], 3: others},
                         schedule={4: [f(f"R2G-00{i}") for i in range(2, 5)]})
        store = self.new_store()
        run_poller(fake, store, 3)  # check 2 misses R2G-001, check 3 is empty
        row = {r["packet_id"]: r for r in store.all_packets()}["R2G-001"]
        self.assertEqual((row["state"], row["missing_count"]), ("BACKLOG", 1))
        fake2 = FakeDrive(files=base(), remove={2: ["id-R2G-001"], 3: others},
                          schedule={4: [f(f"R2G-00{i}") for i in range(2, 5)]})
        store2 = self.new_store()
        run_poller(fake2, store2, 4)  # check 4 is the second real miss
        row2 = {r["packet_id"]: r for r in store2.all_packets()}["R2G-001"]
        self.assertEqual((row2["state"], row2["missing_count"]), ("NEEDS_ERIC", 2))

    def test_old_runs_table_is_migrated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "old_runs.sqlite")
            conn = sqlite3.connect(path)
            conn.executescript(
                "CREATE TABLE runs (run_id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, "
                "baseline_at TEXT, ended_at TEXT, checks_done INTEGER, new_count INTEGER, "
                "end_reason TEXT CHECK (end_reason IN ('WINDOW_DONE', 'STOP', 'ERROR')));"
                "INSERT INTO runs (started_at, end_reason) VALUES ('t0', 'WINDOW_DONE');"
            )
            conn.commit()
            conn.close()
            store = Store(path)
            old = store.last_run()
            summary, _ = run_poller(FakeDrive(files=base()), store, 1)
            new = store.last_run()
            store.close()
        self.assertEqual((old["suspect_listings"], old["health"]), (0, "OK"))
        self.assertEqual((new["health"], summary["health"]), ("OK", "OK"))

    def test_cli_prints_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "h.sqlite")
            with contextlib.redirect_stdout(io.StringIO()) as out:
                poller.main(["--fixture", FIXTURE, "--db", db, "--max-checks", "2", "--interval", "60"])
        self.assertIn("suspect_listings=0 health=OK", out.getvalue())


class ConfigTests(unittest.TestCase):
    def test_defaults_when_nothing_is_set(self):
        self.assertEqual(config.resolve_ids(environ={}), (config.DEFAULT_FOLDER_ID, config.DEFAULT_ROOT_ID))

    def test_environment_is_used(self):
        env = {config.ENV_FOLDER_ID: "env-folder", config.ENV_ROOT_ID: "env-root"}
        self.assertEqual(config.resolve_ids(environ=env), ("env-folder", "env-root"))

    def test_command_line_beats_environment(self):
        env = {config.ENV_FOLDER_ID: "env-folder", config.ENV_ROOT_ID: "env-root"}
        self.assertEqual(config.resolve_ids("cli-folder", "cli-root", environ=env), ("cli-folder", "cli-root"))

    def test_blank_environment_value_is_ignored(self):
        env = {config.ENV_FOLDER_ID: "   ", config.ENV_ROOT_ID: ""}
        self.assertEqual(config.resolve_ids(environ=env), (config.DEFAULT_FOLDER_ID, config.DEFAULT_ROOT_ID))

    def test_run_passes_configured_ids_to_the_reader(self):
        fake = FakeDrive(files=base())
        store = Store()
        self.addCleanup(store.close)
        poller.run(fake, store, folder_id="F1", root_id="R1", max_checks=2, interval=0, sleep=lambda s: None)
        self.assertEqual(set(fake.folder_ids), {"F1"})
        self.assertEqual(set(fake.root_ids), {"R1"})

    def test_run_uses_environment_when_no_ids_are_given(self):
        fake = FakeDrive(files=base())
        store = Store()
        self.addCleanup(store.close)
        env = {config.ENV_FOLDER_ID: "env-folder", config.ENV_ROOT_ID: "env-root"}
        with mock.patch.dict(os.environ, env):
            poller.run(fake, store, max_checks=1, interval=0, sleep=lambda s: None)
        self.assertEqual(set(fake.folder_ids), {"env-folder"})
        self.assertEqual(set(fake.root_ids), {"env-root"})


class PacketRuleTests(unittest.TestCase):
    def test_complete_and_incomplete(self):
        self.assertTrue(packet_rules.is_complete(packet("R2G-001")))
        self.assertFalse(packet_rules.is_complete(""))
        self.assertFalse(packet_rules.is_complete(packet("R2G-001", end=False)))
        self.assertFalse(packet_rules.is_complete(packet("R2G-001", body=False)))
        self.assertFalse(packet_rules.is_complete("PACKET_ID: R2G-001\nMESSAGE:\nhi\nEND_OF_PACKET\n"))

    def test_name_pattern(self):
        self.assertEqual(packet_rules.packet_id_from_name("R2G-005_x.txt"), "R2G-005")
        self.assertIsNone(packet_rules.packet_id_from_name("G2R-005_x"))
        self.assertIsNone(packet_rules.packet_id_from_name("R2G-0005_x"))


if __name__ == "__main__":
    unittest.main()
