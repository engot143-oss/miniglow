"""Ray loop: send once, check every minute up to five times, stop at the first matching reply."""
import io
import os

from wake_adapter import audit, ray_loop
from wake_adapter.__main__ import main

from .support import TempTree, tree


class RayLoopCase(TempTree):
    def setUp(self):
        super().setUp()
        self.init_checkpoint("R2G-058")
        self.inbox = os.path.join(self.bridge, "Glow-to-Ray")
        self.r2g = os.path.join(self.bridge, "Ray-to-Glow")
        os.makedirs(self.inbox)
        with open(os.path.join(self.r2g, "R2G-075_OLD.txt"), "w") as handle:
            handle.write("old packet, mentions C2R-002 but was there before")
        with open(os.path.join(self.inbox, "C2R-001_EARLIER.txt"), "w") as handle:
            handle.write("earlier request")
        self.sleeps = []
        self.ray_at = {}  # check number -> (file name, text) that "Ray" writes during that minute

    def fake_sleep(self, seconds):
        self.sleeps.append(seconds)
        n = len(self.sleeps)
        if n in self.ray_at:
            name, text = self.ray_at[n]
            with open(os.path.join(self.r2g, name), "w", encoding="utf-8") as handle:
                handle.write(text)

    def run_loop(self, message="Hello Ray, bridge loop test."):
        lines = []
        code = main(["ray-loop", "--message", message], environ={"LOCALAPPDATA": self.local, "USERNAME": "eric"},
                    bridge_root=self.bridge, out=lines.append, ask=lambda p: "", stdin=io.StringIO(""),
                    sleep=self.fake_sleep)
        return code, "\n".join(lines)


class RayLoopTests(RayLoopCase):
    def test_sends_the_next_c2r_packet(self):
        self.run_loop()
        self.assertIn("C2R-002_CLAUDE_to_RAY_BRIDGE_LOOP.txt", os.listdir(self.inbox))
        with open(os.path.join(self.inbox, "C2R-002_CLAUDE_to_RAY_BRIDGE_LOOP.txt"), encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("PACKET_ID: C2R-002", text)
        self.assertIn("Hello Ray, bridge loop test.", text)
        self.assertTrue(text.rstrip().endswith("END_OF_PACKET"))

    def test_stops_immediately_when_the_reply_arrives(self):
        self.ray_at[2] = ("R2G-076_RAY_to_CLAUDE.txt", "PACKET_ID: R2G-076\nREPLY_TO: C2R-002\nEND_OF_PACKET")
        code, text = self.run_loop()
        self.assertEqual(code, 0, text)
        self.assertEqual(self.sleeps, [60, 60])  # two one-minute waits, then stop
        self.assertIn("REPLY: Ray answered C2R-002 in R2G-076_RAY_to_CLAUDE.txt (check 2)", text)

    def test_reports_no_reply_after_five_checks(self):
        code, text = self.run_loop()
        self.assertEqual(code, 3)
        self.assertEqual(self.sleeps, [60] * 5)
        self.assertIn("NO REPLY from Ray after 5 checks (about 5 minutes)", text)
        self.assertEqual(text.count("no reply yet"), 5)

    def test_old_files_never_count_as_the_reply(self):
        code, text = self.run_loop()
        self.assertNotIn("R2G-075_OLD.txt", text)
        self.assertEqual(code, 3)

    def test_unrelated_new_ray_file_does_not_stop_the_loop(self):
        self.ray_at[1] = ("R2G-076_RAY_ABOUT_SOMETHING_ELSE.txt", "PACKET_ID: R2G-076\nabout other work")
        self.ray_at[4] = ("R2G-077_RAY_REPLY.txt", "Re C2R-002: received.")
        code, text = self.run_loop()
        self.assertIn("R2G-076_RAY_ABOUT_SOMETHING_ELSE.txt -> OTHER", text)
        self.assertIn("(check 4)", text)
        self.assertEqual((code, len(self.sleeps)), (0, 4))

    def test_unreadable_google_doc_is_reported_unverified(self):
        self.ray_at[3] = ("R2G-076_RAY_to_GLOW.gdoc", '{"doc_id": "x"}')
        code, text = self.run_loop()
        self.assertIn("POSSIBLE REPLY: new Ray file R2G-076_RAY_to_GLOW.gdoc (check 3)", text)
        self.assertEqual((code, len(self.sleeps)), (3, 3))

    def test_the_same_message_is_never_sent_twice(self):
        self.run_loop("Same text")
        before = sorted(os.listdir(self.inbox))
        code, text = self.run_loop("Same text")
        self.assertEqual(code, 2)
        self.assertIn("already sent as C2R-002; not sending a duplicate", text)
        self.assertEqual(sorted(os.listdir(self.inbox)), before)
        self.run_loop("A different message")
        self.assertIn("C2R-003_CLAUDE_to_RAY_BRIDGE_LOOP.txt", os.listdir(self.inbox))

    def test_stop_prevents_sending(self):
        with open(os.path.join(self.bridge, "STOP"), "w") as handle:
            handle.write("")
        before = tree(self.bridge)
        code, text = self.run_loop()
        self.assertEqual(code, 2)
        self.assertEqual(tree(self.bridge), before)
        self.assertEqual(self.sleeps, [])

    def test_stop_during_the_wait_ends_the_loop(self):
        def sleep_then_stop(seconds):
            self.sleeps.append(seconds)
            if len(self.sleeps) == 2:
                with open(os.path.join(self.bridge, "STOP"), "w") as handle:
                    handle.write("")
        lines = []
        code = main(["ray-loop", "--message", "x"], environ={"LOCALAPPDATA": self.local}, bridge_root=self.bridge,
                    out=lines.append, sleep=sleep_then_stop)
        self.assertEqual(code, 3)
        self.assertIn("check 2: STOP present, stopping", "\n".join(lines))

    def test_ray_to_glow_is_only_read(self):
        before = tree(self.r2g)
        self.run_loop()
        self.assertEqual(tree(self.r2g), before)
        self.assertEqual(audit.read(os.path.join(self.base, "wake_transport_audit.jsonl"))[-1]["kind"], "RAY_MESSAGE")
