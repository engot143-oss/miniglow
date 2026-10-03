"""End-to-end: drives the real command line in separate processes, so each command
is a fresh 'restart' with nothing carried in memory."""

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = str(Path(self.tmp.name) / "data")

    def mg(self, *args, expect=0):
        r = subprocess.run([sys.executable, "-m", "mini_glow", "--home", self.home, *args],
                           cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(r.returncode, expect, f"{args}\nSTDOUT:{r.stdout}\nSTDERR:{r.stderr}")
        return r.stdout + r.stderr

    def eric_allows(self, category, target):
        out = self.mg("policy", "propose", category, target, "--source", "e2e test")
        pid = re.search(r"#(\d+)", out).group(1)
        self.mg("proposal", "approve", pid, "--by", "eric")

    def setup_allowed(self):
        self.mg("init")
        self.eric_allows("read_file", "C:/Users/Eric/practice_files")
        self.eric_allows("write_file", "C:/Users/Eric/practice_files/out")

    def test_manual_handoff_workflow(self):
        self.setup_allowed()
        out = self.mg("add", str(EXAMPLES / "task_from_glow.md"))
        self.assertIn("queued", out)
        self.mg("start")
        self.assertIn("ALLOW", self.mg("authorize", "MG-T-0001", "read_file", "C:/Users/Eric/practice_files/a.txt"))
        self.mg("note", "MG-T-0001", "Opened practice folder")
        out = self.mg("block", "MG-T-0001", "Which naming style?", "--tried", "checked the folder")
        self.assertIn("HELP REQUEST", out)
        self.assertIn("No automatic connection", out)
        self.mg("resume", "MG-T-0001", "Use YYYY-MM-DD_name")
        self.mg("submit", "MG-T-0001", "Checklist drafted", expect=2)        # no evidence yet
        self.mg("evidence", "MG-T-0001", "--text", "checklist.txt created, 6 steps")
        out = self.mg("submit", "MG-T-0001", "Checklist drafted")
        self.assertIn("RETURN PACKET", out)
        self.assertIn("read_file: C:/Users/Eric/practice_files", out)
        self.assertTrue((Path(self.home) / "handoffs" / "outbox" / "MG-T-0001-return.md").exists())
        self.mg("accept", "MG-T-0001", "--by", "glow", "--comment", "good")
        self.assertIn("OK", self.mg("verify"))

    def test_default_deny_then_clarify(self):
        self.mg("init")
        out = self.mg("add", str(EXAMPLES / "task_from_glow.md"))
        self.assertIn("needs_clarification", out)
        self.mg("start", "MG-T-0001", expect=2)

    def test_unknown_action_pauses(self):
        self.setup_allowed()
        self.assertIn("unknown action category", self.mg("add", str(EXAMPLES / "task_unknown_action.md")))
        self.mg("clarify", "MG-T-0001", "--by", "glow", "--actions", "read_file: C:/Users/Eric/practice_files")
        self.assertIn("queued", self.mg("list"))

    def test_buy_send_cannot_be_activated_by_approval(self):
        self.setup_allowed()
        self.eric_allows("draft_text", "local-draft")
        self.mg("add", str(EXAMPLES / "task_needs_approval.md"))
        self.mg("decide", "MG-T-0001", "--by", "glow", "--decision", "approve", expect=2)
        self.mg("decide", "MG-T-0001", "--by", "eric", "--decision", "approve")
        self.mg("clarify", "MG-T-0001", "--by", "eric")
        self.assertIn("needs_clarification", self.mg("list"))
        self.mg("start", "MG-T-0001", expect=2)
        self.mg("policy", "propose", "send_message", "team", "--source", "test", expect=2)

    def test_authorize_exit_codes(self):
        self.setup_allowed()
        self.mg("add", str(EXAMPLES / "task_from_glow.md"))
        self.mg("start")
        self.mg("authorize", "MG-T-0001", "read_file", "C:/Users/Eric/practice_files")                  # 0 allow
        self.mg("authorize", "MG-T-0001", "read_file", "C:/Users/Eric/Documents", expect=4)             # deny
        self.mg("authorize", "MG-T-0001", "send_message", "team", expect=4)                             # deny
        self.mg("authorize", "MG-T-0001", "organize_files", "x", expect=5)                              # pause

    def test_guardrail_exit_code_and_no_leak(self):
        self.mg("init")
        bad = Path(self.tmp.name) / "bad.md"
        bad.write_text("GOAL: do it\nYOUR JOB: log in with password: topsecret1\n")
        out = self.mg("add", str(bad), expect=3)
        self.assertIn("GUARDRAIL", out)
        self.assertNotIn("topsecret1", out)
        self.assertIn("(no tasks)", self.mg("list"))

    def test_recover_backup_restore_and_exports(self):
        self.setup_allowed()
        self.mg("add", str(EXAMPLES / "task_from_glow.md"))
        self.mg("start")
        self.assertIn("in_progress", self.mg("recover"))
        self.mg("backup")
        snap = self.mg("snapshots").strip().splitlines()[-1]
        self.mg("cancel", "MG-T-0001", "--by", "eric")
        self.mg("restore", snap)
        self.assertIn("in_progress", self.mg("list"))
        self.assertIn("Archive written", self.mg("backup", "--zip"))
        self.assertIn("Wrote", self.mg("export-log"))
        self.assertTrue((Path(self.home) / "exports" / "events.jsonl").exists())
        self.assertIn("OK", self.mg("verify"))

    def test_memory_tiers_via_cli(self):
        self.mg("init")
        out = self.mg("memory", "propose", "project_context", "Practice folder has 12 files",
                      "--source", "MG-T-0001 evidence", "--scope", "mini-glow")
        pid = re.search(r"#(\d+)", out).group(1)
        self.assertNotIn("12 files", self.mg("memory", "show", "project_context"))
        self.mg("proposal", "approve", pid, "--by", "glow", expect=2)           # scope not approved yet
        self.mg("scope", "allow", "mini-glow", "--by", "glow", expect=2)         # Eric only
        self.mg("scope", "allow", "mini-glow", "--by", "eric")
        self.mg("proposal", "approve", pid, "--by", "glow")
        self.assertIn("12 files", self.mg("memory", "show", "project_context"))
        out = self.mg("memory", "propose", "identity", "Changed identity text", "--source", "worker idea")
        pid2 = re.search(r"#(\d+)", out).group(1)
        self.mg("proposal", "approve", pid2, "--by", "glow", expect=2)           # Eric only
        self.mg("proposal", "approve", pid2, "--by", "eric")
        self.assertIn("OK", self.mg("verify"))


if __name__ == "__main__":
    unittest.main()
