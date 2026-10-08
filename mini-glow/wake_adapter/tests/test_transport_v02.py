"""Wake Transport v0.2: local outbox delivery, explicit acknowledgment, retries, STOP gates and the audit chain."""
import io
import json
import os

from wake_adapter import audit, checkpoint, events, outbox, paths
from wake_adapter.__main__ import main
from wake_adapter.paths import Refused, Stopped

from .support import NOW, TempTree, fingerprint, pfile, tree


class TransportCase(TempTree):
    def setUp(self):
        super().setUp()
        self.init_checkpoint("R2G-058")
        self.box = os.path.join(self.base, "outbox")
        self.log = os.path.join(self.base, "wake_transport_audit.jsonl")

    def cli(self, *argv, answer="YES", text=None):
        lines = []
        code = main(list(argv), environ={"LOCALAPPDATA": self.local, "USERNAME": "eric"}, bridge_root=self.bridge,
                    out=lines.append, ask=lambda prompt: answer, stdin=io.StringIO(text or ""))
        return code, "\n".join(lines)

    def gap_db(self, name="t4_gap.sqlite"):
        return self.db(name, files=[pfile(n) for n in range(1, 76)], max_checks=0)  # D1 shape: 059-075 gap

    def new_db(self, name="t4_new.sqlite"):
        return self.db(name, files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(59)]}, max_checks=1)

    def pending(self, route=None):
        return [r for r in outbox.records(self.box, route) if r["status"] != "ACKED"]

    def cp(self):
        return checkpoint.load(self.cp_path)


class DeliveryTests(TransportCase):
    def test_delivery_writes_one_pending_record_per_event_and_confirms_nothing(self):
        db = self.gap_db()
        before = fingerprint(self.cp_path)
        code, text = self.cli("deliver", "--db", db)
        self.assertEqual(code, 0, text)
        (rec,) = self.pending()
        self.assertEqual((rec["route"], rec["status"], rec["attempt"]), ("ERIC", "PENDING", 1))
        self.assertRegex(rec["code"], r"^[0-9a-f]{8}$")
        self.assertEqual(rec["event"].kind, "OFFLINE_GAP")
        self.assertEqual(rec["event"].gap["count"], 17)
        self.assertEqual(fingerprint(self.cp_path), before)  # delivery is not acknowledgment
        self.assertIn("Nothing was sent off this PC", text)

    def test_only_outbox_and_audit_log_are_written(self):
        db = self.gap_db()
        f = pfile(1)
        with open(os.path.join(self.bridge, "Ray-to-Glow", f["name"]), "w", encoding="utf-8") as handle:
            handle.write(f["text"])
        before = tree(self.tmp)
        self.cli("deliver", "--db", db)
        after = tree(self.tmp)
        changed = sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))
        prefix = os.path.join("Local", "MiniGlow")
        self.assertTrue(changed)
        for p in changed:
            self.assertTrue(p.startswith(os.path.join(prefix, "outbox") + os.sep) or
                            p == os.path.join(prefix, "wake_transport_audit.jsonl"), p)

    def test_audit_records_code_hash_never_the_code(self):
        db = self.gap_db()
        self.cli("deliver", "--db", db)
        (rec,) = self.pending()
        with open(self.log, encoding="utf-8") as handle:
            raw = handle.read()
        self.assertNotIn(rec["code"], raw)
        (entry,) = audit.read(self.log)
        self.assertEqual((entry["action"], entry["code_sha256"]), ("DELIVERED", audit.code_hash(rec["code"])))

    def test_routes_go_to_their_own_folders(self):
        a, b = self.new_db(), self.gap_db()
        self.cli("deliver", "--db", a, "--db", b)
        self.assertEqual([r["event"].kind for r in self.pending("GLOW")], ["NEW"])
        self.assertEqual([r["event"].kind for r in self.pending("ERIC")], ["OFFLINE_GAP"])

    def test_redelivery_uses_a_new_code_and_the_old_code_is_rejected(self):
        db = self.gap_db()
        self.cli("deliver", "--db", db)
        (first,) = self.pending()
        self.cli("deliver", "--db", db)
        (second,) = self.pending()
        self.assertEqual((second["attempt"], second["event"].event_id), (2, first["event"].event_id))
        self.assertNotEqual(second["code"], first["code"])
        code, text = self.cli("ack", first["event"].event_id, first["code"])
        self.assertEqual(code, 2)
        self.assertIn("does not match", text)
        self.assertEqual(self.cp()["revision"], 0)

    def test_stuck_after_three_attempts_escalates_once_to_eric(self):
        db = self.new_db()  # a GLOW event that Glow never acknowledges
        for _ in range(3):
            self.cli("deliver", "--db", db)
        self.assertEqual(self.pending("GLOW")[0]["attempt"], 3)
        code, text = self.cli("deliver", "--db", db)
        self.assertIn("STUCK after 3 attempts", text)
        self.assertEqual(self.pending("GLOW")[0]["status"], "STUCK")
        (esc,) = self.pending("ERIC")
        self.assertEqual((esc["event"].reason, esc["event"].source["stuck_event_id"]),
                         ("STUCK_DELIVERY", self.pending("GLOW")[0]["event"].event_id))
        self.cli("deliver", "--db", db)  # no second escalation, no redelivery of the stuck event
        self.assertEqual(len(self.pending("ERIC")), 1)
        self.assertEqual(self.pending("GLOW")[0]["attempt"], 3)
        self.assertEqual(self.pending("ERIC")[0]["attempt"], 2)  # the escalation itself is retried

    def test_stuck_event_can_still_be_acknowledged(self):
        db = self.new_db()
        for _ in range(4):
            self.cli("deliver", "--db", db)
        (rec,) = self.pending("GLOW")
        code, text = self.cli("ack-glow", text="ACK %s %s" % (rec["event"].event_id, rec["code"]))
        self.assertEqual(code, 0, text)
        self.assertIn(rec["event"].event_id, self.cp()["confirmed"])

    def test_stop_prevents_any_delivery_write(self):
        db = self.gap_db()
        with open(os.path.join(self.bridge, "STOP"), "w") as handle:
            handle.write("")
        code, text = self.cli("deliver", "--db", db)
        self.assertEqual(code, 2)
        self.assertTrue(text.startswith("STOPPED"))
        self.assertFalse(os.path.exists(self.box))
        self.assertFalse(os.path.exists(self.log))

    def test_transport_gate_three_writes_nothing(self):
        db = self.gap_db()
        from wake_adapter import produce
        events_ = produce([db], base=self.base, bridge_root=self.bridge, stop_check=self.no_stop).events
        t = outbox.LocalOutboxTransport(self.box, self.log, lambda: ["STOP"], lambda: NOW)
        receipt = t.deliver(events_)
        self.assertEqual((receipt.confirmed, t.delivered), ((), []))
        self.assertFalse(os.path.exists(self.box))

    def test_pending_delivery_is_retried_even_without_its_database(self):
        db = self.gap_db()
        self.cli("deliver", "--db", db)
        other = self.db("t4_other.sqlite", files=[pfile(n) for n in range(1, 59)])
        self.cli("deliver", "--db", other)
        (rec,) = self.pending()
        self.assertEqual(rec["attempt"], 2)


class AcknowledgmentTests(TransportCase):
    def deliver_gap(self):
        db = self.gap_db()
        self.cli("deliver", "--db", db)
        (rec,) = self.pending()
        return db, rec

    def test_eric_ack_advances_the_checkpoint_for_that_event_only(self):
        db, rec = self.deliver_gap()
        code, text = self.cli("ack", rec["event"].event_id, rec["code"])
        self.assertEqual(code, 0, text)
        cp = self.cp()
        self.assertEqual((cp["revision"], list(cp["confirmed"])), (1, [rec["event"].event_id]))
        self.assertEqual(len(cp["gap_reported"]), 17)
        self.assertEqual(self.pending(), [])
        self.assertEqual(self.cli("deliver", "--db", db)[0], 0)
        self.assertEqual(self.pending(), [])  # nothing comes back
        entries = audit.read(self.log)
        self.assertEqual([e["action"] for e in entries], ["DELIVERED", "ACKED"])
        self.assertEqual((entries[1]["revision_before"], entries[1]["revision_after"], entries[1]["actor"]),
                         (0, 1, "eric (eric)"))

    def test_without_typed_yes_nothing_changes(self):
        _, rec = self.deliver_gap()
        before = fingerprint(self.cp_path)
        for answer in ("", "yes", "Y", "YES please"):
            code, text = self.cli("ack", rec["event"].event_id, rec["code"], answer=answer)
            self.assertEqual(code, 2)
        self.assertEqual(fingerprint(self.cp_path), before)

    def test_wrong_code_is_rejected_and_logged(self):
        _, rec = self.deliver_gap()
        wrong = "0" * 8 if rec["code"] != "0" * 8 else "1" * 8
        code, _ = self.cli("ack", rec["event"].event_id, wrong)
        self.assertEqual(code, 2)
        self.assertEqual(self.cp()["revision"], 0)
        self.assertEqual(audit.read(self.log)[-1]["action"], "REJECTED")
        for bad in ("short", "ZZZZZZZZ", ""):
            self.assertEqual(self.cli("ack", rec["event"].event_id, bad)[0], 2)

    def test_acknowledgments_are_bound_to_their_route(self):
        a, b = self.new_db(), self.gap_db()
        self.cli("deliver", "--db", a, "--db", b)
        glow, eric = self.pending("GLOW")[0], self.pending("ERIC")[0]
        self.assertEqual(self.cli("ack", glow["event"].event_id, glow["code"])[0], 2)  # Eric cannot ack Glow's
        code, text = self.cli("ack-glow", text="ACK %s %s" % (eric["event"].event_id, eric["code"]))
        self.assertEqual(code, 2)  # Glow cannot ack Eric's
        self.assertEqual(self.cp()["revision"], 0)
        code, text = self.cli("ack-glow", text="Glow says:\nACK %s %s\nthanks" % (glow["event"].event_id,
                                                                                 glow["code"]))
        self.assertEqual(code, 0, text)
        self.assertEqual(audit.read(self.log)[-1]["actor"], "glow (entered by eric)")

    def test_glow_reply_must_hold_exactly_one_ack(self):
        for text in ("", "ACK nothing", "ACK %s %s\nACK %s %s" % ("a" * 64, "b" * 8, "c" * 64, "d" * 8)):
            with self.assertRaises(Refused):
                outbox.parse_glow_ack(text)
        self.assertEqual(outbox.parse_glow_ack("  ACK %s %s  " % ("a" * 64, "b" * 8)), ("a" * 64, "b" * 8))

    def test_stop_blocks_acknowledgment(self):
        _, rec = self.deliver_gap()
        with open(os.path.join(self.base, "MINIRAY_STOP"), "w") as handle:
            handle.write("")
        log_before = fingerprint(self.log)
        code, text = self.cli("ack", rec["event"].event_id, rec["code"])
        self.assertEqual(code, 2)
        self.assertTrue(text.startswith("STOPPED"))
        self.assertEqual((self.cp()["revision"], fingerprint(self.log)), (0, log_before))

    def test_acknowledging_twice_is_refused(self):
        _, rec = self.deliver_gap()
        self.assertEqual(self.cli("ack", rec["event"].event_id, rec["code"])[0], 0)
        code, text = self.cli("ack", rec["event"].event_id, rec["code"])
        self.assertEqual(code, 2)
        self.assertEqual(self.cp()["revision"], 1)

    def test_event_confirmed_elsewhere_is_marked_without_a_second_commit(self):
        db, rec = self.deliver_gap()
        from wake_adapter import hand_over, produce
        from .support import RecordingTransport
        e = rec["event"]
        loaded = self.cp()
        receipt = hand_over(RecordingTransport(), (e,), self.no_stop)
        checkpoint.commit(self.cp_path, loaded, (e,), receipt, self.no_stop, NOW)
        code, text = self.cli("ack", e.event_id, rec["code"])
        self.assertEqual(code, 0, text)
        self.assertEqual(self.cp()["revision"], 1)
        self.assertEqual(audit.read(self.log)[-1]["action"], "ALREADY_CONFIRMED")


class TamperTests(TransportCase):
    def deliver_gap(self):
        self.cli("deliver", "--db", self.gap_db())
        (rec,) = self.pending()
        return rec, outbox.record_path(self.box, "ERIC", rec["event"].event_id)

    def edit(self, path, change):
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        change(data)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

    def test_edited_event_content_is_refused(self):
        changes = [lambda d: d["event"]["gap"].__setitem__("count", 3),
                   lambda d: d["event"]["gap"]["members"].pop(),
                   lambda d: d["event"].__setitem__("route", "GLOW"),
                   lambda d: d["event"].__setitem__("authority", "AUTHORISED"),
                   lambda d: d.__setitem__("route", "GLOW"),
                   lambda d: d.__setitem__("attempt", 9),
                   lambda d: d.__setitem__("extra", 1)]
        for change in changes:
            rec, path = self.deliver_gap()
            self.edit(path, change)
            with self.assertRaises(Refused):
                outbox.load_record(path)
            self.assertEqual(self.cli("ack", rec["event"].event_id, rec["code"])[0], 2)
            os.remove(path)
        self.assertEqual(self.cp()["revision"], 0)

    def test_linked_record_is_refused(self):
        rec, path = self.deliver_gap()
        os.link(path, os.path.join(self.tmp, "second_name.json"))
        with self.assertRaises(Refused):
            outbox.load_record(path)

    def test_from_dict_refuses_a_forged_event_id(self):
        rec, _ = self.deliver_gap()
        d = rec["event"].to_dict()
        d["event_id"] = "f" * 64
        with self.assertRaises(ValueError):
            events.from_dict(d)
        self.assertEqual(events.from_dict(rec["event"].to_dict()), rec["event"])


class AuditChainTests(TransportCase):
    def make_log(self):
        db = self.gap_db()
        self.cli("deliver", "--db", db)
        self.cli("deliver", "--db", db)
        (rec,) = self.pending()
        self.cli("ack", rec["event"].event_id, rec["code"])
        return audit.read(self.log)

    def test_chain_is_valid_and_verifiable(self):
        entries = self.make_log()
        self.assertEqual([e["action"] for e in entries], ["DELIVERED", "DELIVERED", "ACKED"])
        self.assertEqual(entries[0]["prev"], audit.GENESIS)
        self.assertEqual(entries[1]["prev"], entries[0]["hash"])
        code, text = self.cli("audit-verify")
        self.assertEqual((code, text), (0, "AUDIT OK: 3 entries\n"
                                           "RECONCILIATION OK: audit log, checkpoint and outbox agree"))

    def rewrite(self, transform):
        with open(self.log, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        with open(self.log, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(transform(lines)) + "\n")

    def test_any_edit_breaks_the_chain(self):
        self.make_log()
        self.rewrite(lambda lines: [lines[0].replace('"attempt":1', '"attempt":2')] + lines[1:])
        code, text = self.cli("audit-verify")
        self.assertEqual(code, 2)
        self.assertIn("BROKEN", text)

    def test_removed_or_reordered_lines_break_the_chain(self):
        self.make_log()
        with open(self.log, encoding="utf-8") as handle:
            original = handle.read()
        for transform in (lambda lines: lines[1:], lambda lines: [lines[1], lines[0], lines[2]],
                          lambda lines: lines[:1] + lines[2:]):
            self.rewrite(transform)
            self.assertFalse(audit.verify(self.log)[0])
            with open(self.log, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(original)
            self.assertTrue(audit.verify(self.log)[0])

    def test_a_broken_chain_blocks_further_writes(self):
        self.make_log()
        self.rewrite(lambda lines: lines[1:])
        box_before = tree(self.box)
        fresh = self.db("t4_fresh.sqlite", files=[pfile(n) for n in range(1, 76)], schedule={1: [pfile(80)]},
                        max_checks=1)  # R2G-080 is a genuinely new event (059-075 were gap-reported)
        code, text = self.cli("deliver", "--db", fresh)
        self.assertEqual(code, 2)
        self.assertIn("audit chain broken", text)
        self.assertEqual(tree(self.box), box_before)  # no unaudited record was written


class InboxTests(TransportCase):
    def test_inbox_is_read_only_and_shows_codes(self):
        db = self.gap_db()
        self.cli("deliver", "--db", db)
        (rec,) = self.pending()
        before = tree(self.tmp)
        code, text = self.cli("inbox")
        self.assertEqual(code, 0)
        self.assertIn(rec["code"], text)
        self.assertIn("OFFLINE_GAP R2G-059..R2G-075 count 17", text)
        self.assertEqual(tree(self.tmp), before)
        self.assertIn("0 delivery(ies)", self.cli("inbox", "--route", "GLOW")[1])


class Interrupted(Exception):
    """Simulates the process dying at a chosen point."""


class InterruptionTests(TransportCase):
    """F1/F3: an interruption never confirms anything wrongly, audit-verify finds the trace, and it can be repaired."""

    def verify(self):
        return self.cli("audit-verify")

    def test_delivery_interrupted_before_its_audit_entry(self):
        from unittest import mock
        db = self.gap_db()
        real = audit.append

        def die_on_delivered(path, action, time, **fields):
            if action == "DELIVERED":
                raise Interrupted()
            return real(path, action, time, **fields)
        cp_before = fingerprint(self.cp_path)
        with mock.patch("wake_adapter.audit.append", die_on_delivered):
            with self.assertRaises(Interrupted):
                self.cli("deliver", "--db", db)
        (rec,) = self.pending()
        self.assertEqual((rec["status"], rec["attempt"]), ("PENDING", 1))
        self.assertEqual(fingerprint(self.cp_path), cp_before)  # nothing confirmed
        code, text = self.verify()
        self.assertEqual(code, 2)
        self.assertIn("without its DELIVERED audit entry", text)
        self.cli("deliver", "--db", db)  # repair: redelivery is audited
        (rec,) = self.pending()
        self.assertEqual(rec["attempt"], 2)
        self.assertEqual(self.verify()[0], 0)
        self.assertEqual(self.cli("ack", rec["event"].event_id, rec["code"])[0], 0)
        self.assertEqual(self.verify()[0], 0)

    def test_acknowledgment_interrupted_after_the_commit(self):
        from unittest import mock
        db = self.gap_db()
        self.cli("deliver", "--db", db)
        (rec,) = self.pending()
        real = outbox._write

        def die_when_marking_acked(path, r):
            if r["status"] == "ACKED":
                raise Interrupted()
            return real(path, r)
        with mock.patch("wake_adapter.outbox._write", die_when_marking_acked):
            with self.assertRaises(Interrupted):
                self.cli("ack", rec["event"].event_id, rec["code"])
        self.assertEqual(self.cp()["revision"], 1)  # the commit happened once
        self.assertEqual(self.pending()[0]["status"], "PENDING")
        self.assertIn("already confirmed in the checkpoint", self.cli("inbox")[1])
        self.cli("deliver", "--db", db)  # a confirmed event is never delivered again
        self.assertEqual(self.pending()[0]["attempt"], 1)
        code, text = self.verify()
        self.assertEqual(code, 2)
        self.assertIn("without an ACKED audit entry", text)
        self.assertEqual(self.cli("ack", rec["event"].event_id, rec["code"])[0], 0)  # repair
        self.assertEqual(self.cp()["revision"], 1)  # no second commit
        self.assertEqual(audit.read(self.log)[-1]["action"], "ALREADY_CONFIRMED")
        self.assertEqual(self.verify()[0], 0)

    def test_acknowledgment_interrupted_before_its_audit_entry(self):
        from unittest import mock
        db = self.gap_db()
        self.cli("deliver", "--db", db)
        (rec,) = self.pending()
        real = audit.append

        def die_on_acked(path, action, time, **fields):
            if action == "ACKED":
                raise Interrupted()
            return real(path, action, time, **fields)
        with mock.patch("wake_adapter.audit.append", die_on_acked):
            with self.assertRaises(Interrupted):
                self.cli("ack", rec["event"].event_id, rec["code"])
        self.assertEqual(outbox.records(self.box)[0]["status"], "ACKED")
        self.assertEqual(self.verify()[0], 2)
        self.assertEqual(self.cli("ack", rec["event"].event_id, rec["code"])[0], 0)  # repair allowed once
        self.assertEqual((self.cp()["revision"], self.verify()[0]), (1, 0))
        self.assertEqual(self.cli("ack", rec["event"].event_id, rec["code"])[0], 2)  # then refused again

    def test_acknowledgment_interrupted_during_the_checkpoint_write(self):
        from unittest import mock
        db = self.gap_db()
        self.cli("deliver", "--db", db)
        (rec,) = self.pending()
        cp_before = fingerprint(self.cp_path)
        with mock.patch("wake_adapter.checkpoint.os.replace", side_effect=Interrupted()):
            with self.assertRaises(Interrupted):
                self.cli("ack", rec["event"].event_id, rec["code"])
        self.assertEqual(fingerprint(self.cp_path), cp_before)
        self.assertFalse(os.path.exists(self.cp_path + ".tmp"))  # our temporary file was cleaned up
        self.assertEqual(self.pending()[0]["status"], "PENDING")
        self.assertEqual(self.verify()[0], 0)  # consistent: nothing was confirmed
        self.assertEqual(self.cli("ack", rec["event"].event_id, rec["code"])[0], 0)
        self.assertEqual(self.cp()["revision"], 1)

    def test_leftover_temporary_outbox_record_is_refused(self):
        db = self.gap_db()
        self.cli("deliver", "--db", db)
        (rec,) = self.pending()
        path = outbox.record_path(self.box, "ERIC", rec["event"].event_id)
        with open(path + ".tmp", "w") as handle:
            handle.write("left over")
        before = fingerprint(path)
        code, text = self.cli("deliver", "--db", db)
        self.assertEqual(code, 2)
        self.assertIn("leftover temporary outbox record", text)
        self.assertEqual(fingerprint(path), before)
        with open(path + ".tmp") as handle:
            self.assertEqual(handle.read(), "left over")  # never overwritten or removed


class NoCascadeTests(TransportCase):
    """F2: a STUCK_DELIVERY escalation that itself gets stuck never produces another escalation."""

    def test_stuck_escalation_does_not_cascade(self):
        db = self.new_db()
        for _ in range(4):
            self.cli("deliver", "--db", db)  # GLOW event: attempts 1-3, then STUCK + escalation attempt 1
        for _ in range(2):
            self.cli("deliver", "--db", db)  # escalation attempts 2-3
        code, text = self.cli("deliver", "--db", db)  # escalation exceeds its attempts
        self.assertEqual(code, 0, text)
        (esc,) = outbox.records(self.box, "ERIC")
        self.assertEqual((esc["status"], esc["attempt"], esc["event"].reason), ("STUCK", 3, "STUCK_DELIVERY"))
        for _ in range(3):
            self.cli("deliver", "--db", db)
        self.assertEqual(len(outbox.records(self.box, "ERIC")), 1)  # no escalation of the escalation
        self.assertEqual([r["status"] for r in outbox.records(self.box)], ["STUCK", "STUCK"])
        self.assertEqual([e["action"] for e in audit.read(self.log)].count("STUCK"), 2)
        self.assertIn("STUCK", self.cli("inbox", "--route", "ERIC")[1])  # still visible to Eric
        self.assertEqual(self.cli("ack", esc["event"].event_id, esc["code"])[0], 0)  # and still acknowledgeable
        self.assertEqual(self.cli("audit-verify")[0], 0)
