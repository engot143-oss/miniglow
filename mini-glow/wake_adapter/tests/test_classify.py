"""Criteria 7 (classification on poller-made databases) and 9 (D1 reproduced on a synthetic database)."""
import dataclasses
import json
import os

from wake_adapter import checkpoint, events, produce
from wake_adapter.classify import classify
from wake_adapter.classify import utcnow

from .support import NOW, TempTree, make_open_db, pfile, seeded


class ClassifyTests(TempTree):
    def run_adapter(self, names, high_water="R2G-058"):
        return produce(names, base=self.base, bridge_root=self.bridge,
                       checkpoint=seeded(high_water), stop_check=self.no_stop)

    def test_backlog_at_or_below_high_water_gives_nothing(self):
        name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)], max_checks=2)
        result = self.run_adapter([name])
        self.assertEqual(result.events, ())
        self.assertEqual(result.waiting, ())

    def test_new_logged_above_high_water_gives_exactly_one_new(self):
        name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(59)]},
                       max_checks=2)
        result = self.run_adapter([name])
        self.assertEqual(len(result.events), 1)
        e = result.events[0]
        self.assertEqual((e.kind, e.route, e.packet_id, e.authority), ("NEW", "GLOW", "R2G-059", "NOTIFICATION_ONLY"))
        self.assertEqual(e.drive_file_id, "local:R2G-059_TEST.txt")
        self.assertEqual(e.packet["state"], "NEW_LOGGED")
        self.assertEqual(e.packet["check_number"], 1)
        self.assertEqual(e.source["db"], name)

    def test_new_logged_at_or_below_high_water_is_history(self):
        # The real shape of t4_20261007T034915Z: 001-057 BACKLOG, 058 NEW_LOGGED.
        name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 58)], schedule={1: [pfile(58)]},
                       max_checks=1)
        self.assertEqual(self.run_adapter([name]).events, ())

    def test_events_carry_no_packet_text(self):
        name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(59)]},
                       max_checks=1)
        dumped = json.dumps([e.to_dict() for e in self.run_adapter([name]).events])
        self.assertNotIn("SECRET-BODY", dumped)
        self.assertNotIn("END_OF_PACKET", dumped)
        self.assertNotIn('"text"', dumped)

    def test_needs_eric_row_escalates_to_eric(self):
        # Filename says R2G-059, header says R2G-060: bridge_poller logs NEEDS_ERIC.
        name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)],
                       schedule={1: [pfile(59, header="R2G-060")]}, max_checks=1)
        (e,) = self.run_adapter([name]).events
        self.assertEqual((e.kind, e.route, e.reason, e.packet_id), ("ESCALATE", "ERIC", "NEEDS_ERIC_ROW", "R2G-059"))

    def test_needs_eric_row_below_high_water_still_escalates(self):
        name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 5)],
                       schedule={1: [pfile(5, header="R2G-006")]}, max_checks=1)
        (e,) = self.run_adapter([name]).events
        self.assertEqual((e.kind, e.reason, e.packet_id), ("ESCALATE", "NEEDS_ERIC_ROW", "R2G-005"))

    def test_error_run_escalates(self):
        name = self.db("t4_a.sqlite", files=[pfile(1)], max_checks=3, fail_on_listing=2)
        (e,) = self.run_adapter([name]).events
        self.assertEqual((e.kind, e.route, e.reason, e.source["run_id"]), ("ESCALATE", "ERIC", "RUN_ERROR", 1))

    def test_stop_run_escalates(self):
        name = self.db("t4_a.sqlite", files=[pfile(1)], max_checks=3, stop_at=1)
        (e,) = self.run_adapter([name]).events
        self.assertEqual((e.kind, e.reason), ("ESCALATE", "RUN_STOP"))

    def test_unhealthy_run_escalates_health_and_suspect_listings(self):
        files = [pfile(n) for n in range(1, 4)]
        name = self.db("t4_a.sqlite", files=files, remove={1: [f["id"] for f in files]}, max_checks=2)
        reasons = sorted(e.reason for e in self.run_adapter([name]).events)
        self.assertEqual(reasons, ["RUN_HEALTH_NEEDS_ERIC", "RUN_SUSPECT_LISTINGS"])

    def test_open_run_waits_and_delivers_nothing(self):
        make_open_db(os.path.join(self.base, "t4_open.sqlite"), n=70)
        result = self.run_adapter(["t4_open.sqlite"])
        self.assertEqual(result.events, ())
        self.assertEqual(result.waiting, ("t4_open.sqlite",))

    def test_event_ids_are_deterministic(self):
        name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 66)], schedule={1: [pfile(66)]},
                       max_checks=1)
        first = self.run_adapter([name])
        second = produce([name], base=self.base, bridge_root=self.bridge,
                         checkpoint=seeded("R2G-058"), stop_check=self.no_stop,
                         now=lambda: "2030-01-01T00:00:00+00:00")
        self.assertEqual([e.event_id for e in first.events], [e.event_id for e in second.events])
        self.assertNotEqual(first.events[0].produced_at, second.events[0].produced_at)

    def test_same_new_in_two_databases_is_one_event(self):
        a = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(59)]}, max_checks=1)
        b =self.db("t4_b.sqlite", files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(59)]}, max_checks=1)
        result = self.run_adapter([b, a])
        self.assertEqual([e.kind for e in result.events], ["NEW"])
        self.assertEqual(result.events[0].source["db"], "t4_a.sqlite")  # earliest database wins

    def test_events_are_immutable(self):
        name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(59)]},
                       max_checks=1)
        (e,) = self.run_adapter([name]).events
        with self.assertRaises(dataclasses.FrozenInstanceError):
            e.kind = "ESCALATE"
        with self.assertRaises(TypeError):
            e.packet["state"] = "BACKLOG"
        with self.assertRaises(ValueError):
            events.WakeEvent("x", "NEW", "ERIC", None, None, None, {}, None, None, NOW)  # wrong route
        with self.assertRaises(ValueError):
            events.WakeEvent("x", "NEW", "GLOW", None, None, None, {}, None, None, NOW, authority="AUTHORISED")

    def test_no_snapshots_give_no_events(self):
        self.assertEqual(classify([], checkpoint.empty("R2G-001", NOW), utcnow()), ((), ()))


class D1Tests(TempTree):
    """Eric's D1: the current gap R2G-059..R2G-075 (17 packets) as ONE summarised event to Eric."""

    def run_adapter(self, names):
        return produce(names, base=self.base, bridge_root=self.bridge,
                       checkpoint=seeded("R2G-058"), stop_check=self.no_stop)

    def test_d1_gap_is_one_offline_gap_event(self):
        name = self.db("t4_catchup.sqlite", files=[pfile(n) for n in range(1, 76)], max_checks=0)
        result = self.run_adapter([name])
        self.assertEqual(len(result.events), 1)
        (e,) = result.events
        self.assertEqual((e.kind, e.route, e.authority), ("OFFLINE_GAP", "ERIC", "NOTIFICATION_ONLY"))
        self.assertEqual((e.gap["first"], e.gap["last"], e.gap["count"]), ("R2G-059", "R2G-075", 17))
        self.assertEqual(e.gap["missing_numbers"], ())
        self.assertEqual(len(e.gap["members"]), 17)
        self.assertIsNone(e.packet_id)
        self.assertFalse(any(x.kind == "NEW" for x in result.events))

    def test_d1_with_real_history_shape(self):
        # Like the real databases: the last run saw 058 arrive; a later run finds 059-075 already there.
        old = self.db("t4_20261007T034915Z.sqlite", files=[pfile(n) for n in range(1, 58)],
                      schedule={1: [pfile(58)]}, max_checks=1)
        new = self.db("t4_20261008T000000Z.sqlite", files=[pfile(n) for n in range(1, 76)], max_checks=0)
        (e,) = self.run_adapter([old, new]).events
        self.assertEqual((e.kind, e.gap["first"], e.gap["last"], e.gap["count"]),
                         ("OFFLINE_GAP", "R2G-059", "R2G-075", 17))
        self.assertEqual(e.gap["dbs"], (new,))

    def test_gap_reports_missing_numbers(self):
        files = [pfile(n) for n in range(1, 76) if n != 70]
        name = self.db("t4_catchup.sqlite", files=files, max_checks=0)
        (e,) = self.run_adapter([name]).events
        self.assertEqual((e.gap["count"], e.gap["missing_numbers"]), (16, ("R2G-070",)))

    def test_packet_logged_new_elsewhere_is_not_in_the_gap(self):
        a = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(59)]}, max_checks=1)
        b = self.db("t4_b.sqlite", files=[pfile(n) for n in range(1, 62)], max_checks=0)
        kinds = {e.kind: e for e in self.run_adapter([a, b]).events}
        self.assertEqual(kinds["NEW"].packet_id, "R2G-059")
        self.assertEqual((kinds["OFFLINE_GAP"].gap["first"], kinds["OFFLINE_GAP"].gap["count"]), ("R2G-060", 2))
