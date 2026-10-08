"""Criterion 10: STOP gates #1 and #2 (and #3 on the adapter side of the transport boundary)."""
import os
from types import SimpleNamespace

from mini_ray.context import Context

from wake_adapter import checkpoint, hand_over, produce, stop
from wake_adapter.__main__ import main
from wake_adapter.paths import Stopped

from .support import NOW, RecordingTransport, TempTree, pfile


def touch(path):
    with open(path, "w") as handle:
        handle.write("")


class StopTests(TempTree):
    def setUp(self):
        super().setUp()
        self.init_checkpoint()
        self.name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(59)]},
                            max_checks=1)

    def produce(self, names=None, **kw):
        return produce(names or [self.name], base=self.base, bridge_root=self.bridge, **kw)

    def test_baseline_without_stop_produces_the_event(self):
        self.assertEqual(len(self.produce().events), 1)

    def test_each_stop_name_in_bridge_root_stops(self):
        for name in ("STOP", "STOP.txt", "stop", "Stop_now"):
            path = os.path.join(self.bridge, name)
            touch(path)
            with self.assertRaises(Stopped, msg=name):
                self.produce()
            os.remove(path)

    def test_each_miniray_stop_name_in_miniglow_stops(self):
        for name in ("MINIRAY_STOP", "MINIRAY_STOP_x", "miniray_stop.txt"):
            path = os.path.join(self.base, name)
            touch(path)
            with self.assertRaises(Stopped, msg=name):
                self.produce()
            os.remove(path)

    def test_unreachable_bridge_root_stops(self):
        with self.assertRaises(Stopped) as caught:
            produce([self.name], base=self.base, bridge_root=os.path.join(self.tmp, "no-such-bridge"))
        self.assertIn("unreachable", caught.exception.found[0])

    def test_gate_one_comes_before_checkpoint_and_database(self):
        touch(os.path.join(self.bridge, "STOP"))
        os.remove(self.cp_path)
        with self.assertRaises(Stopped):  # not "checkpoint missing", not "database not found"
            self.produce(["t4_does_not_exist.sqlite"])

    def test_gate_two_stops_after_snapshot(self):
        calls = iter([[], ["STOP appeared during the snapshot"]])
        with self.assertRaises(Stopped) as caught:
            self.produce(stop_check=lambda: next(calls))
        self.assertEqual(caught.exception.found, ["STOP appeared during the snapshot"])

    def test_stop_inside_ray_to_glow_is_not_the_stop_signal(self):
        touch(os.path.join(self.bridge, "Ray-to-Glow", "STOP"))
        self.assertEqual(len(self.produce().events), 1)

    def test_same_answer_as_mini_ray(self):
        scenarios = [(), ("bridge", "STOP"), ("bridge", "STOP.txt"), ("bridge", "stop"), ("base", "MINIRAY_STOP"),
                     ("base", "MINIRAY_STOP_x"), ("base", "STOP"), ("bridge", "MINIRAY_STOP"),
                     ("r2g", "STOP"), ("bridge", "NOT_STOP")]
        for scenario in scenarios:
            made = None
            if scenario:
                folder = {"bridge": self.bridge, "base": self.base,
                          "r2g": os.path.join(self.bridge, "Ray-to-Glow")}[scenario[0]]
                made = os.path.join(folder, scenario[1])
                touch(made)
            ours = stop.stop_present(self.bridge, self.base)
            theirs = Context.stop_present(SimpleNamespace(bridge_root=self.bridge, base=self.base))
            self.assertEqual(ours, theirs, scenario)
            if made:
                os.remove(made)
        missing = os.path.join(self.tmp, "gone")
        self.assertEqual(stop.stop_present(missing, self.base),
                         Context.stop_present(SimpleNamespace(bridge_root=missing, base=self.base)))

    def test_gate_three_on_hand_over(self):
        events = self.produce().events
        transport = RecordingTransport()
        touch(os.path.join(self.bridge, "STOP"))
        with self.assertRaises(Stopped):
            hand_over(transport, events, lambda: stop.stop_present(self.bridge, self.base))
        self.assertEqual(transport.delivered, [])

    def test_commit_refused_under_stop(self):
        events = self.produce().events
        loaded = checkpoint.load(self.cp_path)
        receipt = hand_over(RecordingTransport(), events, self.no_stop)
        touch(os.path.join(self.base, "MINIRAY_STOP"))
        with self.assertRaises(Stopped):
            checkpoint.commit(self.cp_path, loaded, events, receipt,
                              lambda: stop.stop_present(self.bridge, self.base), NOW)
        self.assertEqual(checkpoint.load(self.cp_path)["revision"], 0)

    def test_command_line_reports_stop(self):
        touch(os.path.join(self.bridge, "STOP"))
        lines = []
        code = main(["plan", "--db", self.name], environ={"LOCALAPPDATA": self.local}, bridge_root=self.bridge,
                    out=lines.append)
        self.assertEqual(code, 2)
        self.assertTrue(lines[0].startswith("STOPPED:"))
        os.remove(self.cp_path)
        code = main(["init", "--high-water", "R2G-058", "--seed-db", self.name], environ={"LOCALAPPDATA": self.local},
                    bridge_root=self.bridge, out=lines.append)
        self.assertEqual(code, 2)
        self.assertTrue(lines[-1].startswith("STOPPED:"))
        self.assertFalse(os.path.exists(self.cp_path))
