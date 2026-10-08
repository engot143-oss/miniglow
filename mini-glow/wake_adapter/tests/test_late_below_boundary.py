"""Finding 1: a packet at or below high_water is history only if its identity was seeded at initialisation.

Identity is packet_id + drive_file_id; the sequence number alone never proves prior processing.
"""
import json
import os

from wake_adapter import checkpoint, hand_over, produce, snapshot
from wake_adapter.__main__ import main
from wake_adapter.paths import Refused

from .support import NOW, RecordingTransport, TempTree, fingerprint, key, make_open_db, pfile


class LateBelowBoundaryTests(TempTree):
    def init_from(self, *names, high_water="R2G-058"):
        snaps = [snapshot.take(os.path.join(self.base, n), n) for n in names]
        return checkpoint.init(self.cp_path, high_water, checkpoint.seed_from_snapshots(snaps, high_water), NOW)

    def produce(self, names):
        return produce(names, base=self.base, bridge_root=self.bridge, stop_check=self.no_stop)

    def commit(self, events, transport):
        loaded = checkpoint.load(self.cp_path)
        receipt = hand_over(transport, events, self.no_stop)
        return checkpoint.commit(self.cp_path, loaded, events, receipt, self.no_stop, NOW)

    # A
    def test_a_050_seeded_at_initialisation_gives_no_event(self):
        seed = self.db("t4_seed.sqlite", files=[pfile(n) for n in range(1, 59)])
        cp = self.init_from(seed)
        self.assertIn(key(50), cp["seeded_history"]["keys"])
        later = self.db("t4_later.sqlite", files=[pfile(n) for n in range(1, 59)])
        self.assertEqual(self.produce([later]).events, ())

    # B
    def test_b_050_absent_at_initialisation_escalates_once_to_eric(self):
        seed = self.db("t4_seed.sqlite", files=[pfile(n) for n in range(1, 59) if n != 50])
        cp = self.init_from(seed)
        self.assertNotIn(key(50), cp["seeded_history"]["keys"])
        self.assertEqual(len(cp["seeded_history"]["keys"]), 57)
        later = self.db("t4_later.sqlite", files=[pfile(n) for n in range(1, 59)])
        events = self.produce([later]).events
        self.assertEqual(len(events), 1)
        (e,) = events
        self.assertEqual((e.kind, e.route, e.reason, e.authority), ("ESCALATE", "ERIC", "LATE_BELOW_BOUNDARY",
                                                                    "NOTIFICATION_ONLY"))
        self.assertEqual((e.packet_id, e.drive_file_id), ("R2G-050", "local:R2G-050_TEST.txt"))
        self.assertEqual(e.packet["state"], "BACKLOG")
        dumped = e.to_json()
        self.assertNotIn("SECRET-BODY", dumped)
        self.assertNotIn("END_OF_PACKET", dumped)

    # C
    def test_c_redelivered_until_a_receipt_confirms_it(self):
        seed = self.db("t4_seed.sqlite", files=[pfile(n) for n in range(1, 59) if n != 50])
        self.init_from(seed)
        later = self.db("t4_later.sqlite", files=[pfile(n) for n in range(1, 59)])
        (e,) = self.produce([later]).events
        before = fingerprint(self.cp_path)
        self.commit((e,), RecordingTransport(confirm=lambda x: False))  # delivered, not confirmed
        self.assertEqual(fingerprint(self.cp_path), before)
        self.assertEqual([x.event_id for x in self.produce([later]).events], [e.event_id])
        with self.assertRaises(ConnectionError):  # transport failure
            self.commit((e,), RecordingTransport(raise_error=True))
        self.assertEqual([x.event_id for x in self.produce([later]).events], [e.event_id])

    # D
    def test_d_once_confirmed_it_does_not_escalate_again(self):
        seed = self.db("t4_seed.sqlite", files=[pfile(n) for n in range(1, 59) if n != 50])
        self.init_from(seed)
        later = self.db("t4_later.sqlite", files=[pfile(n) for n in range(1, 59)])
        cp = self.commit(self.produce([later]).events, RecordingTransport())
        self.assertEqual([v["keys"] for v in cp["confirmed"].values()], [[key(50)]])
        self.assertEqual(self.produce([later]).events, ())
        again = self.db("t4_again.sqlite", files=[pfile(n) for n in range(1, 59)])  # a fresh database
        self.assertEqual(self.produce([later, again]).events, ())
        self.assertNotIn(key(50), cp["seeded_history"]["keys"])  # confirmation never rewrites the seed

    # E
    def test_e_same_packet_id_with_another_file_is_a_distinct_anomaly(self):
        seed = self.db("t4_seed.sqlite", files=[pfile(n) for n in range(1, 59)])
        self.init_from(seed)
        swapped = [pfile(n) for n in range(1, 59) if n != 50] + [pfile(50, suffix="OTHER")]
        later = self.db("t4_later.sqlite", files=swapped)
        (e,) = self.produce([later]).events
        self.assertEqual((e.reason, e.packet_id, e.drive_file_id),
                         ("LATE_BELOW_BOUNDARY", "R2G-050", "local:R2G-050_OTHER.txt"))
        self.commit((e,), RecordingTransport())
        third = [pfile(n) for n in range(1, 59) if n != 50] + [pfile(50, suffix="THIRD")]
        latest = self.db("t4_latest.sqlite", files=third)
        (f,) = self.produce([later, latest]).events
        self.assertEqual(f.drive_file_id, "local:R2G-050_THIRD.txt")
        self.assertNotEqual(f.event_id, e.event_id)

    def test_unseeded_new_logged_below_boundary_is_late_not_new(self):
        seed = self.db("t4_seed.sqlite", files=[pfile(n) for n in range(1, 59) if n != 50])
        self.init_from(seed)
        later = self.db("t4_later.sqlite", files=[pfile(n) for n in range(1, 59) if n != 50],
                        schedule={1: [pfile(50)]}, max_checks=1)
        (e,) = self.produce([later]).events
        self.assertEqual((e.kind, e.route, e.reason, e.packet["state"]),
                         ("ESCALATE", "ERIC", "LATE_BELOW_BOUNDARY", "NEW_LOGGED"))

    def test_seed_counts_any_state_including_new_logged(self):
        # The real shape of the newest database: 001-057 BACKLOG, 058 NEW_LOGGED.
        seed = self.db("t4_seed.sqlite", files=[pfile(n) for n in range(1, 58)], schedule={1: [pfile(58)]},
                       max_checks=1)
        cp = self.init_from(seed)
        self.assertEqual(len(cp["seeded_history"]["keys"]), 58)
        self.assertEqual(self.produce([seed]).events, ())

    def test_seeded_history_survives_commits(self):
        seed = self.db("t4_seed.sqlite", files=[pfile(n) for n in range(1, 59)])
        first = self.init_from(seed)
        later = self.db("t4_later.sqlite", files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(59)]},
                        max_checks=1)
        cp = self.commit(self.produce([later]).events, RecordingTransport())
        self.assertEqual(cp["seeded_history"], first["seeded_history"])
        self.assertEqual(checkpoint.load(self.cp_path)["seeded_history"], first["seeded_history"])

    def test_missing_seed_never_means_history(self):
        later = self.db("t4_later.sqlite", files=[pfile(n) for n in range(1, 59)])
        events = produce([later], base=self.base, bridge_root=self.bridge,
                         checkpoint=checkpoint.empty("R2G-058", NOW), stop_check=self.no_stop).events
        self.assertEqual(len(events), 58)
        self.assertEqual({e.reason for e in events}, {"LATE_BELOW_BOUNDARY"})


class SeedFailClosedTests(TempTree):
    def test_init_refuses_an_empty_seed(self):
        empty_seed = self.db("t4_seed.sqlite", files=[pfile(70)])  # nothing at or below R2G-058
        snaps = [snapshot.take(os.path.join(self.base, empty_seed), empty_seed)]
        with self.assertRaises(Refused):
            checkpoint.init(self.cp_path, "R2G-058", checkpoint.seed_from_snapshots(snaps, "R2G-058"), NOW)
        with self.assertRaises(Refused):
            checkpoint.init(self.cp_path, "R2G-058", checkpoint.make_seed([key(1)], []), NOW)  # no source
        with self.assertRaises(Refused):
            checkpoint.seed_from_snapshots([], "R2G-058")
        self.assertFalse(os.path.exists(self.cp_path))

    def test_init_refuses_a_seed_database_with_an_open_run(self):
        make_open_db(os.path.join(self.base, "t4_open.sqlite"), n=5)
        snaps = [snapshot.take(os.path.join(self.base, "t4_open.sqlite"), "t4_open.sqlite")]
        with self.assertRaises(Refused):
            checkpoint.seed_from_snapshots(snaps, "R2G-058")

    def test_bad_seeded_history_refused(self):
        good = checkpoint.empty("R2G-058", NOW, checkpoint.make_seed([key(1), key(2)], ["t4_seed.sqlite"]))
        bad_seeds = [
            None, [], {"sources": ["t4_seed.sqlite"]},
            {"sources": ["t4_seed.sqlite"], "keys": [key(59)]},  # above high_water
            {"sources": ["t4_seed.sqlite"], "keys": [key(2), key(1)]},  # not sorted
            {"sources": ["t4_seed.sqlite"], "keys": [key(1), key(1)]},  # duplicate
            {"sources": [], "keys": [key(1)]},  # keys without a source
            {"sources": ["../x.sqlite"], "keys": [key(1)]},  # bad source name
            {"sources": ["t4_seed.sqlite"], "keys": ["R2G-001"]},  # packet id without file id
            {"sources": ["t4_seed.sqlite"], "keys": [key(1)], "extra": 1},
        ]
        for seed in bad_seeds:
            with self.assertRaises(Refused, msg=repr(seed)):
                checkpoint.validate(dict(good, seeded_history=seed))
        old = dict(good, version=1)
        del old["seeded_history"]
        with self.assertRaises(Refused):  # a version 1 checkpoint cannot prove its history
            checkpoint.validate(old)

    def test_command_line_init_and_plan_seed(self):
        seed = self.db("t4_seed.sqlite", files=[pfile(n) for n in range(1, 59) if n != 50])
        later = self.db("t4_later.sqlite", files=[pfile(n) for n in range(1, 59)])
        env = {"LOCALAPPDATA": self.local}
        lines = []
        self.assertEqual(main(["plan", "--db", later, "--seed-db", seed], environ=env, bridge_root=self.bridge,
                              out=lines.append), 2)  # --seed-db in plan needs --assume-high-water
        lines.clear()
        self.assertEqual(main(["plan", "--db", later, "--assume-high-water", "R2G-058", "--seed-db", seed],
                              environ=env, bridge_root=self.bridge, out=lines.append), 0)
        report = json.loads(lines[0])
        self.assertEqual([(e["reason"], e["packet_id"]) for e in report["events"]],
                         [("LATE_BELOW_BOUNDARY", "R2G-050")])
        self.assertFalse(os.path.exists(self.cp_path))  # plan wrote nothing
        lines.clear()
        self.assertEqual(main(["init", "--high-water", "R2G-058", "--seed-db", seed], environ=env,
                              bridge_root=self.bridge, out=lines.append), 0)
        self.assertIn("57 seeded packet identities", lines[0])
        lines.clear()
        self.assertEqual(main(["plan", "--db", later], environ=env, bridge_root=self.bridge, out=lines.append), 0)
        self.assertEqual(json.loads(lines[0])["events"][0]["reason"], "LATE_BELOW_BOUNDARY")
