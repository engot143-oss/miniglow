"""Criteria 6 (checkpoint fails closed) and 8 (deduplication and at-least-once delivery)."""
import json
import os

from wake_adapter import checkpoint, hand_over, produce
from wake_adapter.paths import Refused, Stopped
from wake_adapter.transport import Receipt, batch_id

from .support import NOW, RecordingTransport, TempTree, fingerprint, key, pfile


class CheckpointFileTests(TempTree):
    def write_raw(self, data):
        with open(self.cp_path, "w", encoding="utf-8") as handle:
            handle.write(data if isinstance(data, str) else json.dumps(data))

    def good(self):
        return checkpoint.empty("R2G-058", NOW)

    def test_init_creates_and_refuses_twice(self):
        data = self.init_checkpoint()
        self.assertEqual((data["high_water"], data["revision"], data["confirmed"]), ("R2G-058", 0, {}))
        self.assertEqual(checkpoint.load(self.cp_path), data)
        with self.assertRaises(Refused):
            self.init_checkpoint()
        self.assertEqual(sorted(os.listdir(self.base)), ["wake_adapter_checkpoint.json"])

    def test_bad_high_water_refused(self):
        for bad in ("R2G-58", "G2R-058", "", "R2G-0580", None):
            with self.assertRaises(Refused):
                checkpoint.init(self.cp_path, bad, checkpoint.make_seed([key(1)], ["t4_seed.sqlite"]), NOW)
        self.assertFalse(os.path.exists(self.cp_path))

    def test_missing_checkpoint_refused(self):
        with self.assertRaises(Refused) as caught:
            produce(["t4_a.sqlite"], base=self.base, bridge_root=self.bridge, stop_check=self.no_stop)
        self.assertIn("checkpoint missing", str(caught.exception))

    def test_corrupt_or_unexpected_content_refused(self):
        version_bool = dict(self.good(), version=True)
        cases = ["{not json", "[]", json.dumps(dict(self.good(), extra=1)), json.dumps(dict(self.good(), version=1)), json.dumps(dict(self.good(), version=3)),
                 json.dumps(version_bool), json.dumps(dict(self.good(), format="other")),
                 json.dumps(dict(self.good(), revision=-1)), json.dumps(dict(self.good(), high_water="R2G-5")),
                 json.dumps(dict(self.good(), gap_reported=["nonsense"])),
                 json.dumps(dict(self.good(), gap_reported=[key(59), key(59)])),
                 json.dumps(dict(self.good(), confirmed={"abc": {}})),
                 json.dumps(dict(self.good(), confirmed={"a" * 64: {"kind": "NEW", "keys": [], "confirmed_at": NOW,
                                                                     "transport": "t", "db": None, "more": 1}}))]
        for text in cases:
            self.write_raw(text)
            with self.assertRaises(Refused, msg=text[:60]):
                checkpoint.load(self.cp_path)

    def test_linked_or_not_plain_checkpoint_refused(self):
        self.init_checkpoint()
        os.link(self.cp_path, os.path.join(self.tmp, "second_name.json"))
        with self.assertRaises(Refused) as caught:
            checkpoint.load(self.cp_path)
        self.assertIn("linked", str(caught.exception))
        os.remove(os.path.join(self.tmp, "second_name.json"))
        os.remove(self.cp_path)
        os.makedirs(self.cp_path)
        with self.assertRaises(Refused):
            checkpoint.load(self.cp_path)

    def test_leftover_temporary_file_refused(self):
        self.init_checkpoint()
        name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(59)]}, max_checks=1)
        loaded = checkpoint.load(self.cp_path)
        result = produce([name], base=self.base, bridge_root=self.bridge, stop_check=self.no_stop)
        receipt = hand_over(RecordingTransport(), result.events, self.no_stop)
        with open(self.cp_path + ".tmp", "w") as handle:
            handle.write("left over")
        before = fingerprint(self.cp_path)
        with self.assertRaises(Refused):
            checkpoint.commit(self.cp_path, loaded, result.events, receipt, self.no_stop, NOW)
        self.assertEqual(fingerprint(self.cp_path), before)


class AtLeastOnceTests(TempTree):
    def setUp(self):
        super().setUp()
        self.init_checkpoint("R2G-058")

    def produce(self, names):
        return produce(names, base=self.base, bridge_root=self.bridge, stop_check=self.no_stop)

    def deliver_and_commit(self, events, transport):
        loaded = checkpoint.load(self.cp_path)
        receipt = hand_over(transport, events, self.no_stop)
        return checkpoint.commit(self.cp_path, loaded, events, receipt, self.no_stop, NOW)

    def three_new(self):
        return self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)],
                       schedule={1: [pfile(59)], 2: [pfile(60)], 3: [pfile(61)]}, max_checks=3)

    def test_without_receipt_events_come_back(self):
        name = self.three_new()
        first = [e.event_id for e in self.produce([name]).events]
        second = [e.event_id for e in self.produce([name]).events]
        self.assertEqual(len(first), 3)
        self.assertEqual(first, second)

    def test_full_confirmation_then_nothing_comes_back(self):
        name = self.three_new()
        cp = self.deliver_and_commit(self.produce([name]).events, RecordingTransport())
        self.assertEqual((cp["revision"], len(cp["confirmed"])), (1, 3))
        self.assertEqual(self.produce([name]).events, ())

    def test_partial_confirmation_only_the_rest_come_back(self):
        name = self.three_new()
        events = self.produce([name]).events
        self.deliver_and_commit(events, RecordingTransport(confirm=lambda e: e.packet_id == "R2G-059"))
        self.assertEqual([e.packet_id for e in self.produce([name]).events], ["R2G-060", "R2G-061"])

    def test_transport_failure_leaves_checkpoint_and_events(self):
        name = self.three_new()
        events = self.produce([name]).events
        before = fingerprint(self.cp_path)
        with self.assertRaises(ConnectionError):
            self.deliver_and_commit(events, RecordingTransport(raise_error=True))
        self.assertEqual(fingerprint(self.cp_path), before)
        self.assertEqual(len(self.produce([name]).events), 3)

    def test_nothing_confirmed_writes_nothing(self):
        name = self.three_new()
        before = fingerprint(self.cp_path)
        self.deliver_and_commit(self.produce([name]).events, RecordingTransport(confirm=lambda e: False))
        self.assertEqual(fingerprint(self.cp_path), before)

    def test_confirmed_packet_does_not_return_from_a_fresh_database(self):
        a = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(59)]}, max_checks=1)
        self.deliver_and_commit(self.produce([a]).events, RecordingTransport())
        # Next T4 run: fresh database, 059 is now BACKLOG, 060 arrives during the window.
        b = self.db("t4_b.sqlite", files=[pfile(n) for n in range(1, 60)], schedule={1: [pfile(60)]}, max_checks=1)
        events = self.produce([a, b]).events
        self.assertEqual([(e.kind, e.packet_id) for e in events], [("NEW", "R2G-060")])

    def test_confirmed_gap_is_not_reported_again_and_high_water_stays(self):
        a = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 76)], max_checks=0)
        cp = self.deliver_and_commit(self.produce([a]).events, RecordingTransport())
        self.assertEqual(len(cp["gap_reported"]), 17)
        self.assertEqual(cp["high_water"], "R2G-058")
        self.assertEqual(self.produce([a]).events, ())
        b = self.db("t4_b.sqlite", files=[pfile(n) for n in range(1, 81)], max_checks=0)
        (e,) = self.produce([a, b]).events
        self.assertEqual((e.kind, e.gap["first"], e.gap["last"], e.gap["count"]), ("OFFLINE_GAP", "R2G-076", "R2G-080", 5))

    def test_confirmed_escalation_does_not_return(self):
        a = self.db("t4_a.sqlite", files=[pfile(1)], max_checks=3, stop_at=1)
        self.assertEqual(len(self.produce([a]).events), 1)
        self.deliver_and_commit(self.produce([a]).events, RecordingTransport())
        self.assertEqual(self.produce([a]).events, ())

    def test_bad_receipts_refused_and_checkpoint_unchanged(self):
        name = self.three_new()
        events = self.produce([name]).events
        ids = tuple(e.event_id for e in events)
        good = batch_id(events)
        bad = [
            Receipt("t", good, ids + ("f" * 64,), (), NOW),  # unknown id
            Receipt("t", "0" * 64, ids, (), NOW),  # wrong batch
            Receipt("t", good, (ids[0], ids[0]), (), NOW),  # duplicate
            Receipt("t", good, (ids[0],), ((ids[0], "x"),), NOW),  # both confirmed and failed
            Receipt("", good, ids, (), NOW),  # no transport name
            Receipt("t", good, list(ids), (), NOW),  # not a tuple
        ]
        loaded = checkpoint.load(self.cp_path)
        before = fingerprint(self.cp_path)
        for receipt in bad:
            with self.assertRaises(Refused):
                checkpoint.commit(self.cp_path, loaded, events, receipt, self.no_stop, NOW)
        self.assertEqual(fingerprint(self.cp_path), before)

    def test_revision_conflict_refused(self):
        name = self.three_new()
        events = self.produce([name]).events
        first, second = checkpoint.load(self.cp_path), checkpoint.load(self.cp_path)
        receipt = hand_over(RecordingTransport(), events, self.no_stop)
        checkpoint.commit(self.cp_path, first, events, receipt, self.no_stop, NOW)
        with self.assertRaises(Refused) as caught:
            checkpoint.commit(self.cp_path, second, events, receipt, self.no_stop, NOW)
        self.assertIn("changed since", str(caught.exception))

    def test_commit_refused_under_stop(self):
        name = self.three_new()
        events = self.produce([name]).events
        loaded = checkpoint.load(self.cp_path)
        receipt = hand_over(RecordingTransport(), events, self.no_stop)
        before = fingerprint(self.cp_path)
        with self.assertRaises(Stopped):
            checkpoint.commit(self.cp_path, loaded, events, receipt, lambda: ["STOP"], NOW)
        self.assertEqual(fingerprint(self.cp_path), before)
        self.assertEqual(len(self.produce([name]).events), 3)  # redelivered once STOP clears
