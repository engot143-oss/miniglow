"""Glow's special review: high_water is the initialisation boundary and never advances.

A confirmed higher-numbered packet must never make an unconfirmed lower-numbered packet disappear from
later OFFLINE_GAP detection. Sequence number is ordering/anomaly evidence; confirmed packet identity is
delivery/dedup evidence.
"""
from wake_adapter import checkpoint, hand_over, produce

from .support import NOW, RecordingTransport, TempTree, key, pfile


class HighWaterRegressionTests(TempTree):
    def setUp(self):
        super().setUp()
        self.init_checkpoint("R2G-058")

    def produce(self, names):
        return produce(names, base=self.base, bridge_root=self.bridge, stop_check=self.no_stop)

    def confirm_all(self, events):
        loaded = checkpoint.load(self.cp_path)
        receipt = hand_over(RecordingTransport(), events, self.no_stop)
        return checkpoint.commit(self.cp_path, loaded, events, receipt, self.no_stop, NOW)

    def test_confirmed_080_does_not_hide_later_079(self):
        # Run A: 001-078 present at startup (059-078 are a gap), R2G-080 arrives during the window. 079 missed.
        a = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 79)], schedule={1: [pfile(80)]}, max_checks=1)
        first = self.produce([a]).events
        self.assertEqual(sorted((e.kind, e.packet_id or e.gap["first"]) for e in first),
                         [("NEW", "R2G-080"), ("OFFLINE_GAP", "R2G-059")])
        cp = self.confirm_all(first)
        self.assertEqual(cp["high_water"], "R2G-058")  # the boundary did not move to 080
        self.assertIn(key(80), {k for e in cp["confirmed"].values() for k in e["keys"]})
        # Run B: R2G-079 is now found, already present at startup (BACKLOG).
        b = self.db("t4_b.sqlite", files=[pfile(n) for n in range(1, 81)], max_checks=0)
        later = self.produce([a, b]).events
        self.assertEqual(len(later), 1)
        (gap,) = later
        self.assertEqual((gap.kind, gap.route, gap.authority), ("OFFLINE_GAP", "ERIC", "NOTIFICATION_ONLY"))
        self.assertEqual((gap.gap["first"], gap.gap["last"], gap.gap["count"]), ("R2G-079", "R2G-079", 1))
        self.assertEqual(gap.gap["members"], (key(79),))
        self.assertEqual(self.produce([b]).events, later)  # same answer without run A in the call

    def test_079_stays_reportable_until_its_own_gap_is_confirmed(self):
        a = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 79)], schedule={1: [pfile(80)]}, max_checks=1)
        self.confirm_all(self.produce([a]).events)
        b = self.db("t4_b.sqlite", files=[pfile(n) for n in range(1, 81)], max_checks=0)
        (gap,) = self.produce([b]).events
        for _ in range(2):  # not confirmed: it comes back (at-least-once)
            loaded = checkpoint.load(self.cp_path)
            receipt = hand_over(RecordingTransport(confirm=lambda e: False), (gap,), self.no_stop)
            checkpoint.commit(self.cp_path, loaded, (gap,), receipt, self.no_stop, NOW)
            self.assertEqual([e.event_id for e in self.produce([b]).events], [gap.event_id])
        self.confirm_all((gap,))
        self.assertEqual(self.produce([b]).events, ())
        self.assertEqual(checkpoint.load(self.cp_path)["high_water"], "R2G-058")

    def test_only_the_new_080_confirmed_still_reports_079_with_the_rest(self):
        a = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(80)]}, max_checks=1)
        self.confirm_all(self.produce([a]).events)  # only NEW 080 exists here
        b = self.db("t4_b.sqlite", files=[pfile(n) for n in range(1, 81)], max_checks=0)
        (gap,) = self.produce([b]).events
        self.assertEqual((gap.gap["first"], gap.gap["last"], gap.gap["count"]), ("R2G-059", "R2G-079", 21))
        self.assertIn(key(79), gap.gap["members"])
        self.assertNotIn(key(80), gap.gap["members"])
