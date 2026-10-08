"""The transport boundary: route check, receipt validation, and a failing transport (criterion 8 support)."""
from wake_adapter import checkpoint, hand_over, produce, validate_receipt
from wake_adapter.paths import Refused
from wake_adapter.transport import Receipt, batch_id

from .support import NOW, RecordingTransport, TempTree, pfile, seeded


class TransportContractTests(TempTree):
    def setUp(self):
        super().setUp()
        # One NEW (route GLOW) and one ESCALATE from a STOP-ended run would need two databases; use both.
        a = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(59)]}, max_checks=1)
        b = self.db("t4_b.sqlite", files=[pfile(1)], max_checks=2, stop_at=1)
        self.events = produce([a, b], base=self.base, bridge_root=self.bridge,
                              checkpoint=seeded("R2G-058"), stop_check=self.no_stop).events

    def test_two_routes_present(self):
        self.assertEqual(sorted(e.route for e in self.events), ["ERIC", "GLOW"])

    def test_transport_must_serve_every_route(self):
        glow_only = RecordingTransport(routes=("GLOW",))
        with self.assertRaises(Refused):
            hand_over(glow_only, self.events, self.no_stop)
        self.assertEqual(glow_only.delivered, [])
        glow_events = tuple(e for e in self.events if e.route == "GLOW")
        self.assertEqual(len(hand_over(glow_only, glow_events, self.no_stop).confirmed), 1)

    def test_receipt_for_exact_batch(self):
        receipt = hand_over(RecordingTransport(), self.events, self.no_stop)
        self.assertEqual(receipt.batch_id, batch_id(self.events))
        self.assertEqual(validate_receipt(self.events, receipt), {e.event_id for e in self.events})
        with self.assertRaises(Refused):  # same receipt, different batch
            validate_receipt(self.events[:1], receipt)

    def test_failed_entries_validated(self):
        ids = [e.event_id for e in self.events]
        good = batch_id(self.events)
        with self.assertRaises(Refused):
            validate_receipt(self.events, Receipt("t", good, (), (("f" * 64, "x"),), NOW))  # unknown failed id
        with self.assertRaises(Refused):
            validate_receipt(self.events, Receipt("t", good, (), ((ids[0],),), NOW))  # malformed pair
        with self.assertRaises(Refused):
            validate_receipt(self.events, {"confirmed": ids})  # not a Receipt
        with self.assertRaises(Refused):
            validate_receipt(self.events + self.events[:1], Receipt("t", good, (), (), NOW))  # batch repeats an event

    def test_events_handed_over_unchanged(self):
        transport = RecordingTransport()
        hand_over(transport, self.events, self.no_stop)
        self.assertEqual(transport.delivered, [tuple(self.events)])
        self.assertEqual([e.to_dict() for e in transport.delivered[0]], [e.to_dict() for e in self.events])

    def test_raising_transport_confirms_nothing(self):
        with self.assertRaises(ConnectionError):
            hand_over(RecordingTransport(raise_error=True), self.events, self.no_stop)
