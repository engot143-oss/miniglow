"""Mini Ray v0.1 tests: every deny rule, STOP, timeout, output cap, evidence and each task.

Temporary folders only. The fixture Git repository lives in a temporary folder; nothing touches
the real Bridge, the real MiniGlow folder, or the network.
"""
import hashlib
import io
import json
import os
import pathlib
import py_compile
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from mini_ray import cli, runner
from mini_ray.__main__ import launch_ok
from mini_ray.context import BRANCH, Context, Refused, default_git, is_inside, validate_git
from mini_ray.evidence import Evidence
from mini_ray.runner import OUTPUT_CAP, Command, reduced_env
from mini_ray.tasks import (CATALOG, BridgeInventory, PollerBoundedRun, RunTests, blob_sha1, db_facts, dirty_lines,
                            tree_mismatches)

GIT = shutil.which("git")


def packet(pid):
    return ("PACKET_ID: %s\nFROM: RAY\nTO: GLOW\nREPLY_TO: G2R-001\nSTATUS: RESPONSE\nMESSAGE:\nx\n"
            "END_OF_PACKET\n" % pid)


class Fixture:
    """Temporary MiniGlow folder, Bridge and Git repository."""

    def __init__(self, case):
        tmp = tempfile.TemporaryDirectory()
        case.addCleanup(tmp.cleanup)
        self.tmp = os.path.realpath(tmp.name)
        self.base = os.path.join(self.tmp, "MiniGlow")
        os.makedirs(self.base)
        self.bridge = os.path.join(self.tmp, "Bridge")
        os.makedirs(os.path.join(self.bridge, "Ray-to-Glow"))
        os.makedirs(os.path.join(self.bridge, "Glow-to-Ray"))
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        self.git("init", "-q")
        self.git("checkout", "-q", "-b", BRANCH)
        with open(os.path.join(self.repo, "a.txt"), "w") as handle:
            handle.write("a\n")
        self.git("add", "a.txt")
        self.git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "t")
        self.head = self.git("rev-parse", "HEAD").strip()
        self.ctx = Context(base=self.base, bridge_root=self.bridge, repo=self.repo, mini_glow=self.repo,
                           python=sys.executable, git=GIT)

    def git(self, *args):
        env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        return subprocess.run([GIT, "-c", "safe.directory=" + self.repo, "-c", "commit.gpgsign=false",
                               "-C", self.repo] + list(args), capture_output=True, text=True, check=True,
                              env=env).stdout

    def add_packet(self, name, text):
        path = os.path.join(self.bridge, "Ray-to-Glow", name)
        with open(path, "w", encoding="ascii", newline="\n") as handle:
            handle.write(text)
        return path

    def main(self, argv, answer="YES"):
        out = []
        code = cli.main(argv, ctx=self.ctx, confirm=lambda prompt: answer, admin=lambda: False,
                        out=lambda *a: out.append(" ".join(str(x) for x in a)))
        return code, "\n".join(out)

    def evidence_files(self):
        folder = os.path.join(self.base, "evidence")
        return sorted(os.listdir(folder)) if os.path.isdir(folder) else []

    def read_evidence(self):
        """The evidence file of the most recent run (the audit log keeps run order)."""
        with open(os.path.join(self.base, "miniray_audit.jsonl"), encoding="ascii") as handle:
            last = json.loads(handle.readlines()[-1])["evidence"]
        with open(os.path.join(self.base, "evidence", last), encoding="ascii") as handle:
            return handle.read()


@unittest.skipIf(GIT is None, "git not available")
class DenyModelTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture(self)

    def test_only_python_and_git_may_run(self):
        ctx = self.f.ctx
        ctx.check_program([sys.executable, "-c", "pass"])
        ctx.check_program([GIT, "status"])
        for argv in ([], ["cmd.exe", "/c", "dir"], ["powershell", "-c", "x"], ["/bin/sh", "-c", "x"],
                     [os.path.join(self.f.tmp, "python.exe")], [sys.executable, "a\x00b"]):
            with self.assertRaises(Refused, msg=argv):
                ctx.check_program(argv)

    def test_disallowed_program_in_a_step_fails_closed_with_evidence(self):
        ev = Evidence(self.f.ctx, "x", {})
        step = Command("bad", ["powershell", "-c", "Get-ChildItem"], self.f.repo, 5)

        class FakeTask:
            def verdict(self, ev, results):
                return "PASS"

        with mock.patch.object(cli, "preflight_steps", return_value=[]):
            verdict = cli.execute(self.f.ctx, FakeTask(), [step], ev, self.f.head)
        self.assertEqual(verdict, "FAIL")
        self.assertIn(("deny model", False), [(n, ok) for n, ok, _ in ev.checks])

    def test_writes_only_inside_miniglow_and_never_in_keys(self):
        ctx = self.f.ctx
        ctx.check_write(os.path.join(self.f.base, "evidence", "x.txt"))
        for path in (os.path.join(self.f.tmp, "x.txt"), os.path.join(self.f.bridge, "x.txt"),
                     os.path.join(self.f.base, "keys", "k.json"), os.path.join(self.f.base, "..", "x.txt")):
            with self.assertRaises(Refused, msg=path):
                ctx.check_write(path)

    def test_unknown_task_is_refused(self):
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            self.f.main(["run", "powershell", "--expect-head", self.f.head])
        self.assertEqual(self.f.evidence_files(), [])

    def test_bad_or_extra_parameters_are_refused_before_anything_runs(self):
        bad = [
            ["run", "bridge_inventory", "--expect-head", self.f.head, "--packet", "..\\..\\secret.txt"],
            ["run", "bridge_inventory", "--expect-head", self.f.head, "--packet", "R2G-001_a/b.txt"],
            ["run", "bridge_inventory", "--expect-head", self.f.head, "--packet", "R2G-001_x.txt.exe"],
            ["run", "bridge_inventory", "--expect-head", self.f.head, "--packet", "R2G-001_x.txt",
             "--expect-sha256", "ABC"],
            ["run", "db_report", "--expect-head", self.f.head, "--db", "..\\f.sqlite"],
            ["run", "db_report", "--expect-head", self.f.head, "--db", "missing.sqlite"],
            ["run", "repo_status", "--expect-head", self.f.head, "--packet", "R2G-001_x.txt"],
            ["run", "repo_status", "--expect-head", "48a6214"],
            ["run", "repo_status", "--expect-head", "x" * 40],
        ]
        for argv in bad:
            code, out = self.f.main(argv)
            self.assertEqual(code, 2, argv)
            self.assertIn("REFUSED", out, argv)
        self.assertEqual(self.f.evidence_files(), [])

    def test_administrator_is_refused(self):
        out = []
        code = cli.main(["run", "repo_status", "--expect-head", self.f.head], ctx=self.f.ctx,
                        confirm=lambda p: "YES", admin=lambda: True, out=out.append)
        self.assertEqual(code, 2)
        self.assertIn("Administrator", out[0])

    def test_without_yes_nothing_runs(self):
        for answer in ("", "yes", "Y", "YES please", "no"):
            code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head], answer=answer)
            self.assertEqual(code, 2)
            self.assertIn("nothing was run", out)
        self.assertEqual(self.f.evidence_files(), [])

    def test_child_environment_is_reduced(self):
        with mock.patch.dict(os.environ, {"BRIDGE_POLLER_KEY_FILE": "secret", "SOME_TOKEN": "t"}):
            env = reduced_env()
            result = Command("env", [sys.executable, "-c", "import os;print(sorted(os.environ))"],
                             self.f.repo, 30).run(self.f.ctx)
        self.assertNotIn("SOME_TOKEN", env)
        self.assertNotIn("BRIDGE_POLLER_KEY_FILE", result["stdout"])
        self.assertNotIn("SOME_TOKEN", result["stdout"])


@unittest.skipIf(GIT is None, "git not available")
class RunControlTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture(self)

    def test_bridge_stop_or_local_stop_refuses_start(self):
        for stop in (os.path.join(self.f.bridge, "STOP"), os.path.join(self.f.base, "MINIRAY_STOP")):
            open(stop, "w").close()
            code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
            self.assertEqual(code, 2)
            self.assertIn("STOP present", out)
            os.remove(stop)
        self.assertEqual(self.f.evidence_files(), [])

    def test_stop_between_steps_aborts_with_evidence(self):
        stop = os.path.join(self.f.base, "MINIRAY_STOP")
        real_run = Command.run

        def run_then_stop(step, ctx):
            result = real_run(step, ctx)
            open(stop, "w").close()
            return result

        with mock.patch.object(Command, "run", run_then_stop):
            code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
        self.assertEqual(code, 1)
        self.assertIn("VERDICT: ABORTED", out)
        self.assertIn("VERDICT: ABORTED", self.f.read_evidence())

    def test_timeout_kills_the_step_and_fails(self):
        step = Command("slow", [sys.executable, "-c", "import time; time.sleep(30)"], self.f.repo, 1)
        result = step.run(self.f.ctx)
        self.assertTrue(result["timed_out"])
        self.assertIsNone(result["exit"])
        self.assertLess(result["seconds"], 15)

        class FakeTask:
            def verdict(self, ev, results):
                return "PASS"

        ev = Evidence(self.f.ctx, "x", {})
        with mock.patch.object(cli, "preflight_steps", return_value=[]):
            self.assertEqual(cli.execute(self.f.ctx, FakeTask(), [step], ev, self.f.head), "FAIL")

    def test_output_is_capped(self):
        step = Command("loud", [sys.executable, "-c", "print('x' * 200000)"], self.f.repo, 30)
        result = step.run(self.f.ctx)
        self.assertTrue(result["stdout_truncated"])
        self.assertEqual(len(result["stdout"]), OUTPUT_CAP)

    def test_ctrl_c_aborts_with_evidence(self):
        with mock.patch.object(Command, "run", side_effect=KeyboardInterrupt):
            code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
        self.assertEqual(code, 1)
        self.assertIn("VERDICT: ABORTED", out)

    def test_plan_runs_nothing(self):
        with mock.patch.object(Command, "run", side_effect=AssertionError("ran")):
            for task in sorted(CATALOG):
                argv = ["plan", task]
                if task == "bridge_inventory":
                    argv += ["--packet", "R2G-001_x.txt"]
                if task == "db_report":
                    open(os.path.join(self.f.base, "f.sqlite"), "w").close()
                    argv += ["--db", "f.sqlite"]
                code, out = self.f.main(argv)
                self.assertEqual(code, 0, task)
                self.assertIn("PLAN ONLY", out)
        self.assertEqual(self.f.evidence_files(), [])


@unittest.skipIf(GIT is None, "git not available")
class EvidenceAndPreflightTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture(self)

    def test_repo_status_pass_writes_hashed_evidence_and_audit_line(self):
        code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
        self.assertEqual(code, 0, out)
        self.assertIn("VERDICT: PASS", out)
        text = self.f.read_evidence()
        body, footer = text.rsplit("SHA256: ", 1)
        self.assertEqual(hashlib.sha256(body.encode("ascii")).hexdigest(), footer.strip())
        self.assertIn("PASS HEAD is the approved commit", text)
        with open(os.path.join(self.f.base, "miniray_audit.jsonl"), encoding="ascii") as handle:
            lines = [json.loads(line) for line in handle]
        self.assertEqual(len(lines), 1)
        self.assertEqual((lines[0]["task"], lines[0]["verdict"]), ("repo_status", "PASS"))
        self.assertEqual(lines[0]["sha256"], hashlib.sha256(text.encode("ascii")).hexdigest())

    def test_audit_log_is_appended_not_rewritten(self):
        for _ in range(2):
            self.f.main(["run", "repo_status", "--expect-head", self.f.head])
        with open(os.path.join(self.f.base, "miniray_audit.jsonl"), encoding="ascii") as handle:
            self.assertEqual(len(handle.readlines()), 2)

    def test_wrong_head_or_dirty_tree_fails(self):
        code, out = self.f.main(["run", "repo_status", "--expect-head", "0" * 40])
        self.assertEqual(code, 1)
        self.assertIn("FAIL HEAD is the approved commit", self.f.read_evidence())
        with open(os.path.join(self.f.repo, "new.txt"), "w") as handle:
            handle.write("x")
        code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
        self.assertEqual(code, 1)
        self.assertIn("FAIL working tree clean", self.f.read_evidence())

    def test_evidence_is_ascii_even_with_unicode_output(self):
        ev = Evidence(self.f.ctx, "x", {})
        ev.add_step({"kind": "command", "label": "u", "argv": ["p"], "cwd": "c", "exit": 0, "timed_out": False,
                     "seconds": 0.1, "stdout": "café ✓", "stderr": "", "stdout_truncated": False,
                     "stderr_truncated": False})
        path = ev.finish("PASS")
        with open(path, "rb") as handle:
            handle.read().decode("ascii")


@unittest.skipIf(GIT is None, "git not available")
class TaskTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture(self)

    def test_bridge_inventory(self):
        p = self.f.add_packet("R2G-001_RAY_to_GLOW_X.txt", packet("R2G-001"))
        self.f.add_packet("R2G-002_RAY_to_GLOW_Y.txt", packet("R2G-002"))
        self.f.add_packet("MSG-002_RAY_to_GLOW_ARIP.txt", "m")
        with open(p, "rb") as handle:
            sha = hashlib.sha256(handle.read()).hexdigest()
        code, out = self.f.main(["run", "bridge_inventory", "--expect-head", self.f.head,
                                 "--packet", "R2G-001_RAY_to_GLOW_X.txt", "--expect-sha256", sha])
        self.assertEqual(code, 0, out)
        text = self.f.read_evidence()
        self.assertIn("r2g_count: 2", text)
        self.assertIn("other_names: ['MSG-002_RAY_to_GLOW_ARIP.txt']", text)
        self.assertIn("packet_sha256: " + sha, text)
        code, out = self.f.main(["run", "bridge_inventory", "--expect-head", self.f.head,
                                 "--packet", "R2G-001_RAY_to_GLOW_X.txt", "--expect-sha256", "0" * 64])
        self.assertEqual(code, 1)
        self.assertIn("FAIL packet SHA-256 matches", self.f.read_evidence())

    def test_bridge_inventory_reports_stop_gdoc_as_stop_like_name(self):
        self.f.add_packet("R2G-001_X.txt", packet("R2G-001"))
        facts = BridgeInventory.look(self.f.ctx, self.f.ctx.packet_path("R2G-001_X.txt"))
        open(os.path.join(self.f.bridge, "STOP.gdoc"), "w").close()
        facts2 = BridgeInventory.look(self.f.ctx, self.f.ctx.packet_path("R2G-001_X.txt"))
        self.assertEqual((facts["stop_names"], facts2["stop_names"]), ([], ["STOP.gdoc"]))
        ev = Evidence(self.f.ctx, "t3", {})
        self.assertEqual(BridgeInventory(self.f.ctx, {}).verdict(ev, [{"facts": facts2}]), "FAIL")
        code, out = self.f.main(["run", "bridge_inventory", "--expect-head", self.f.head, "--packet", "R2G-001_X.txt"])
        self.assertEqual(code, 2)  # Mini Ray itself also treats STOP.gdoc as STOP and does not start
        self.assertIn("STOP present", out)

    def test_run_tests_verdict(self):
        ok = {"label": "s", "exit": 0, "stdout": "", "stderr": "....\nRan 4 tests in 0.1s\n\nOK\n"}
        bad = {"label": "s", "exit": 1, "stdout": "", "stderr": "Ran 4 tests\n\nFAILED (errors=1)\n"}
        warn = dict(ok, stderr=ok["stderr"] + "ResourceWarning: unclosed file\n")
        for results, expected in (([ok, ok], "PASS"), ([ok, bad], "FAIL"), ([warn, ok], "FAIL")):
            ev = Evidence(self.f.ctx, "run_tests", {})
            self.assertEqual(RunTests(self.f.ctx, {}).verdict(ev, results), expected)

    def test_run_tests_uses_only_python_with_fixed_suites(self):
        steps = RunTests(self.f.ctx, {}).steps()
        for step in steps:
            self.f.ctx.check_program(step.argv)
            self.assertEqual(step.argv[:6], [sys.executable, "-X", "dev", "-W", "error::ResourceWarning", "-m"])

    def test_poller_bounded_run_command_and_verdict(self):
        task = PollerBoundedRun(self.f.ctx, {})
        steps = task.steps()
        argv = steps[0].argv
        self.assertEqual(argv[1:3], ["-m", "bridge_poller.poller"])
        self.assertEqual(argv[argv.index("--max-checks") + 1], "10")
        self.assertEqual(argv[argv.index("--interval") + 1], "60")
        self.assertTrue(is_inside(argv[argv.index("--db") + 1], self.f.base))
        self.assertFalse(os.path.exists(task.db))
        facts = {"last_run": (1, "s", "e", 10, 1, "WINDOW_DONE", 0, "OK"), "NEEDS_ERIC": 0}
        good = {"exit": 0, "stdout": "run=1 end_reason=WINDOW_DONE checks_done=10 new_count=1 "
                                     "suspect_listings=0 health=OK\n"}
        stop = {"exit": 0, "stdout": "run=1 end_reason=STOP checks_done=3 new_count=0 suspect_listings=0 health=OK\n"}
        err = {"exit": 3, "stdout": "ERROR: Bridge root folder disappeared\n"}
        for run, expected in ((good, "PASS"), (stop, "NEEDS_ERIC"), (err, "FAIL")):
            ev = Evidence(self.f.ctx, "t4", {})
            self.assertEqual(task.verdict(ev, [run, {"facts": facts}]), expected)

    def test_db_report_reads_a_poller_database(self):
        from bridge_poller.store import Store
        path = os.path.join(self.f.base, "f3.sqlite")
        store = Store(path)
        run_id = store.start_run("t0")
        store.insert_packet("R2G-001", "id1", "c", None, 0, "BACKLOG")
        store.end_run(run_id, "t1", 10, 0, "WINDOW_DONE", 0, "OK")
        store.close()
        facts = db_facts(path)
        self.assertEqual((facts["runs"], facts["BACKLOG"], facts["NEEDS_ERIC"]), (1, 1, 0))
        code, out = self.f.main(["run", "db_report", "--expect-head", self.f.head, "--db", "f3.sqlite"])
        self.assertEqual(code, 0, out)
        with self.assertRaises(sqlite3.OperationalError):  # the report connection is read-only
            uri = pathlib.Path(path).resolve().as_uri() + "?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            try:
                conn.execute("INSERT INTO runs (started_at) VALUES ('x')")
            finally:
                conn.close()


class FakeTask:
    def verdict(self, ev, results):
        return "PASS"


def proc_alive(pid):
    """True while a process exists and is not a zombie (Linux /proc; elsewhere os.kill)."""
    stat = "/proc/%d/stat" % pid
    if os.path.exists("/proc"):
        try:
            with open(stat) as handle:
                return handle.read().rsplit(")", 1)[1].split()[0] != "Z"
        except OSError:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


@unittest.skipIf(GIT is None, "git not available")
class HardeningTests(unittest.TestCase):
    """Fixes from the independent review of the v0.1 draft."""

    def setUp(self):
        self.f = Fixture(self)

    # ---- review 1: repository git config must not make git run code
    @unittest.skipIf(os.name == "nt", "the hook positive control uses a POSIX shell script")
    def test_fsmonitor_hook_never_runs(self):
        marker = os.path.join(self.f.tmp, "hook_ran")
        hook = os.path.join(self.f.tmp, "hook.sh")
        with open(hook, "w") as handle:
            handle.write("#!/bin/sh\ntouch '%s'\n" % marker)
        os.chmod(hook, 0o755)
        self.f.git("config", "core.fsmonitor", hook)
        self.f.git("status")  # positive control: plain git runs the hook
        self.assertTrue(os.path.exists(marker), "positive control: the hook should run under plain git")
        os.remove(marker)
        code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
        self.assertEqual(code, 1)
        self.assertIn("repository git config not allowed: core.fsmonitor", self.f.read_evidence())
        self.assertFalse(os.path.exists(marker))
        # second layer: even if the config check were skipped, Mini Ray's git flags switch the hook off
        from mini_ray.tasks import git
        git(self.f.ctx, "status", "status", "--porcelain=v1").run(self.f.ctx)
        self.assertFalse(os.path.exists(marker))

    def test_risky_git_config_sections_are_refused_before_git_runs(self):
        for key, value in (("status.showUntrackedFiles", "no"), ("core.hooksPath", "h"), ("core.trustctime", "false"),
                           ("core.checkStat", "minimal"),
                           ("filter.x.clean", "evil"), ("include.path", "other"), ("alias.st", "!evil")):
            self.f.git("config", key, value)
            with mock.patch.object(Command, "run", side_effect=AssertionError("git ran")):
                code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
            self.assertEqual(code, 1, key)
            self.assertIn("repository git config not allowed", self.f.read_evidence(), key)
            self.f.git("config", "--unset", key)

    # ---- review 2: a clean tree cannot be faked
    def test_excluded_untracked_file_fails(self):
        with open(os.path.join(self.f.repo, ".git", "info", "exclude"), "a") as handle:
            handle.write("hidden.py\n")
        with open(os.path.join(self.f.repo, "hidden.py"), "w") as handle:
            handle.write("x = 1\n")
        self.assertEqual(self.f.git("status", "--porcelain"), "")  # plain status hides it
        code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
        self.assertEqual(code, 1)
        self.assertIn("FAIL working tree clean (untracked and ignored files included) - !! hidden.py",
                      self.f.read_evidence())

    def test_assume_unchanged_file_fails(self):
        self.f.git("update-index", "--assume-unchanged", "a.txt")
        with open(os.path.join(self.f.repo, "a.txt"), "w") as handle:
            handle.write("changed\n")
        self.assertEqual(self.f.git("status", "--porcelain"), "")  # plain status hides it
        code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
        self.assertEqual(code, 1)
        self.assertIn("FAIL no assume-unchanged or skip-worktree files - h a.txt", self.f.read_evidence())

    def test_pycache_folders_are_the_only_allowed_ignored_entries(self):
        self.assertEqual(dirty_lines("!! __pycache__/\n!! mini_ray/tests/__pycache__/\n"), [])
        self.assertEqual(dirty_lines("!! x.pyc\n?? new.py\n!! __pycache__x/\n"),
                         ["!! x.pyc", "?? new.py", "!! __pycache__x/"])
        with open(os.path.join(self.f.repo, ".gitignore"), "w") as handle:
            handle.write("__pycache__/\n")
        self.f.git("add", ".gitignore")
        self.f.git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "i")
        head = self.f.git("rev-parse", "HEAD").strip()
        os.makedirs(os.path.join(self.f.repo, "__pycache__"))
        open(os.path.join(self.f.repo, "__pycache__", "m.cpython-99.pyc"), "w").close()
        code, out = self.f.main(["run", "repo_status", "--expect-head", head])
        self.assertEqual(code, 0, self.f.read_evidence())

    # ---- review 3: planted compiled code is never read by children
    def test_planted_pyc_is_never_run(self):
        folder = os.path.join(self.f.tmp, "pkg")
        os.makedirs(folder)
        with open(os.path.join(folder, "mod.py"), "w") as handle:
            handle.write("print('source')\n")
        planted = os.path.join(self.f.tmp, "planted.py")
        with open(planted, "w") as handle:
            handle.write("print('planted')\n")
        cfile = os.path.join(folder, "__pycache__", "mod.%s.pyc" % sys.implementation.cache_tag)
        py_compile.compile(planted, cfile=cfile, doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        control = subprocess.run([sys.executable, "-c", "import mod"], cwd=folder, env=env,
                                 capture_output=True, text=True)
        self.assertEqual(control.stdout.strip(), "planted", "positive control: plain Python runs the planted file")
        result = Command("import", [sys.executable, "-c", "import mod"], folder, 30).run(self.f.ctx)
        self.assertEqual(result["stdout"].strip(), "source")
        self.assertEqual(os.listdir(self.f.ctx.child_pycache), [])

    def test_child_pycache_must_be_empty(self):
        self.f.ctx.prepare_child_pycache()
        open(os.path.join(self.f.ctx.child_pycache, "x.pyc"), "w").close()
        with self.assertRaises(Refused):
            Command("p", [sys.executable, "-c", "pass"], self.f.repo, 30).run(self.f.ctx)

    def test_launch_needs_pycache_prefix_inside_miniglow(self):
        local = os.path.join(self.f.tmp, "Local")
        env = {"LOCALAPPDATA": local}
        self.assertFalse(launch_ok(None, env))
        self.assertFalse(launch_ok(os.path.join(self.f.tmp, "elsewhere"), env))
        self.assertFalse(launch_ok(os.path.join(local, "MiniGlow", "pycache"), {"LOCALAPPDATA": "rel"}))
        self.assertTrue(launch_ok(os.path.join(local, "MiniGlow", "pycache"), env))
        child_env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        child_env.update(LOCALAPPDATA=local, PYTHONDONTWRITEBYTECODE="1")
        mini_glow = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        proc = subprocess.run([sys.executable, "-m", "mini_ray", "plan", "repo_status"], cwd=mini_glow,
                              env=child_env, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("REFUSED: start Mini Ray with -X pycache_prefix", proc.stdout)

    # ---- review 4: git is a fixed .exe, never one from the repository or the current folder
    def test_git_program_location_rules(self):
        cwd = os.path.join(self.f.tmp, "cwd")
        other = os.path.join(self.f.tmp, "Program Files", "Git", "cmd")
        os.makedirs(cwd)
        os.makedirs(other)
        for name, folder in (("git.bat", cwd), ("git.exe", cwd), ("git.exe", self.f.repo), ("git.cmd", other)):
            path = os.path.join(folder, name)
            open(path, "w").close()
            with self.assertRaises(Refused, msg=path):
                validate_git(path, self.f.repo, cwd, windows=True)
        good = os.path.join(other, "git.exe")
        open(good, "w").close()
        self.assertEqual(validate_git(good, self.f.repo, cwd, windows=True), good)
        for bad in (None, "git.exe", os.path.join(other, "missing.exe")):
            with self.assertRaises(Refused):
                validate_git(bad, self.f.repo, cwd, windows=True)
        self.assertEqual(default_git(self.f.repo, cwd, windows=True,
                                     candidates=(os.path.join(cwd, "none.exe"), good)), good)
        with self.assertRaises(Refused):
            default_git(self.f.repo, cwd, windows=True, candidates=(os.path.join(cwd, "git.exe"),))

    # ---- review 5: deadline and STOP end the whole process tree
    @unittest.skipIf(os.name == "nt", "process-group check; Windows uses a job object (checked at M1)")
    def test_timeout_kills_grandchildren(self):
        pidfile = os.path.join(self.f.tmp, "grandchild.pid")
        grandchild = os.path.join(self.f.tmp, "grandchild.py")
        with open(grandchild, "w") as handle:
            handle.write("import os, sys, time\nopen(sys.argv[1], 'w').write(str(os.getpid()))\ntime.sleep(60)\n")
        code = ("import subprocess, sys, time\n"
                "subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])\n"
                "time.sleep(60)\n")
        result = Command("tree", [sys.executable, "-c", code, grandchild, pidfile], self.f.repo, 3).run(self.f.ctx)
        self.assertTrue(result["timed_out"])
        self.assertLess(result["seconds"], 20)
        with open(pidfile) as handle:
            pid = int(handle.read())
        for _ in range(50):
            if not proc_alive(pid):
                break
            time.sleep(0.1)
        self.assertFalse(proc_alive(pid))

    def test_job_object_layout(self):
        if ctypes_pointer_size() == 8:
            self.assertEqual(ctypes_sizeof(runner._ExtendedLimit), 144)

    def test_stop_during_a_step_ends_it_and_aborts(self):
        step = Command("slow", [sys.executable, "-c", "import time; time.sleep(30)"], self.f.repo, 60)
        timer = threading.Timer(1.0, lambda: open(os.path.join(self.f.base, "MINIRAY_STOP"), "w").close())
        timer.start()
        self.addCleanup(timer.cancel)
        ev = Evidence(self.f.ctx, "x", {})
        with mock.patch.object(cli, "preflight_steps", return_value=[]):
            verdict = cli.execute(self.f.ctx, FakeTask(), [step], ev, self.f.head)
        self.assertEqual(verdict, "ABORTED")
        self.assertTrue(ev.steps[0]["stopped"])
        self.assertLess(ev.steps[0]["seconds"], 15)

    def test_stop_grace_lets_a_stop_aware_program_end_itself(self):
        step = Command("polite", [sys.executable, "-c", "import time; time.sleep(2.5)"], self.f.repo, 60,
                       stop_grace=20)
        timer = threading.Timer(0.5, lambda: open(os.path.join(self.f.bridge, "STOP"), "w").close())
        timer.start()
        self.addCleanup(timer.cancel)
        result = step.run(self.f.ctx)
        self.assertEqual((result["stopped"], result["exit"]), (False, 0))

    def test_stop_names_and_unreachable_bridge_refuse_start(self):
        for name in ("STOP.txt", "stop", "Stop.gdoc"):
            path = os.path.join(self.f.bridge, name)
            open(path, "w").close()
            code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
            self.assertEqual(code, 2, name)
            self.assertIn("STOP present", out)
            os.remove(path)
        os.makedirs(os.path.join(self.f.bridge, "STOP"))
        self.assertEqual(self.f.main(["run", "repo_status", "--expect-head", self.f.head])[0], 2)
        os.rmdir(os.path.join(self.f.bridge, "STOP"))
        os.rename(self.f.bridge, self.f.bridge + "_gone")
        code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
        self.assertEqual(code, 2)
        self.assertIn("Bridge root unreachable", out)
        self.assertEqual(self.f.evidence_files(), [])

    # ---- re-review N1: content is compared with HEAD byte for byte (file times are not trusted)
    def test_changed_file_with_restored_times_fails(self):
        path = os.path.join(self.f.repo, "a.txt")
        st = os.stat(path)
        tree = self.f.git("ls-tree", "-r", "--full-tree", "HEAD", "--", ".")
        self.assertEqual(tree_mismatches(self.f.repo, tree), (1, []))
        with open(path, "w") as handle:
            handle.write("b\n")  # same size
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.assertEqual(tree_mismatches(self.f.repo, tree), (1, ["changed a.txt"]))
        with open(path, "wb") as handle:
            handle.write(b"a\r\n")  # a CRLF checkout of the same content is fine
        self.assertEqual(tree_mismatches(self.f.repo, tree), (1, []))
        os.remove(path)
        self.assertEqual(tree_mismatches(self.f.repo, tree), (1, ["missing a.txt"]))
        self.assertEqual(tree_mismatches(self.f.repo, "120000 blob %s\tlink" % ("0" * 40))[1], ["120000 link", "no files listed"])
        self.assertEqual(tree_mismatches(self.f.repo, "")[1], ["no files listed"])
        committed = "a\n".replace("\n", os.linesep).encode("ascii")  # the fixture wrote a.txt in text mode
        self.assertEqual(blob_sha1(committed), tree.split()[2])

    def test_preflight_fails_when_content_differs_even_if_git_status_is_clean(self):
        real = __import__("mini_ray.tasks", fromlist=["tree_mismatches"])
        with mock.patch.object(real, "tree_mismatches", return_value=(1, ["changed a.txt"])):
            code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
        self.assertEqual(code, 1)
        self.assertIn("FAIL every committed code file matches HEAD byte for byte - 1 files; changed a.txt",
                      self.f.read_evidence())
        code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
        self.assertEqual(code, 0)
        self.assertIn("PASS every committed code file matches HEAD byte for byte - 1 files", self.f.read_evidence())

    # ---- re-review N2: a short unreachable blip or a STOP that clears does not end a step
    def test_short_bridge_blip_does_not_stop_a_step(self):
        calls = {"n": 0}
        real = self.f.ctx.stop_present

        def blip():
            calls["n"] += 1
            return ["Bridge root unreachable: x"] if calls["n"] in (1, 2) else real()

        with mock.patch.object(self.f.ctx, "stop_present", blip):
            result = Command("p", [sys.executable, "-c", "import time; time.sleep(4)"], self.f.repo, 60).run(self.f.ctx)
        self.assertEqual((result["stopped"], result["exit"]), (False, 0))

        with mock.patch.object(self.f.ctx, "stop_present", lambda: ["Bridge root unreachable: x"]):
            result = Command("p", [sys.executable, "-c", "import time; time.sleep(30)"], self.f.repo, 60).run(self.f.ctx)
        self.assertTrue(result["stopped"])

    # ---- review 6: the audit log cannot be a link out of MiniGlow
    def test_linked_audit_log_is_refused(self):
        outside = os.path.join(self.f.tmp, "outside.jsonl")
        with open(outside, "w") as handle:
            handle.write("keep\n")
        audit = os.path.join(self.f.base, "miniray_audit.jsonl")
        linkers = [os.link]
        if os.name != "nt":
            linkers.append(os.symlink)
        for make in linkers:
            make(outside, audit)
            code, out = self.f.main(["run", "repo_status", "--expect-head", self.f.head])
            self.assertEqual(code, 2, make)
            self.assertIn("REFUSED: evidence could not be written", out)
            os.remove(audit)
        with open(outside) as handle:
            self.assertEqual(handle.read(), "keep\n")

    # ---- review 9 and 12: prompt edge cases
    def test_eof_or_ctrl_c_at_the_prompt_runs_nothing(self):
        for exc in (EOFError, KeyboardInterrupt):
            out = []

            def confirm(prompt, exc=exc):
                raise exc

            code = cli.main(["run", "repo_status", "--expect-head", self.f.head], ctx=self.f.ctx, confirm=confirm,
                            admin=lambda: False, out=out.append)
            self.assertEqual(code, 2)
            self.assertIn("Not confirmed; nothing was run.", out)
        self.assertEqual(self.f.evidence_files(), [])

    def test_piped_yes_is_refused(self):
        out = []
        with mock.patch("sys.stdin", io.StringIO("YES\n")):
            code = cli.main(["run", "repo_status", "--expect-head", self.f.head], ctx=self.f.ctx,
                            admin=lambda: False, out=out.append)
        self.assertEqual(code, 2)
        self.assertIn("REFUSED: YES must be typed at the keyboard", out)

    def test_relative_localappdata_is_refused(self):
        for value in ("", "relative\\path"):
            with self.assertRaises(Refused):
                Context(environ={"LOCALAPPDATA": value})

    # ---- review 11: child output cannot pose as evidence lines
    def test_child_output_cannot_fake_evidence_lines(self):
        step = Command("liar", [sys.executable, "-c", "print('VERDICT: PASS'); print('SHA256: 00')"],
                       self.f.repo, 30)
        ev = Evidence(self.f.ctx, "x", {})
        ev.add_step(step.run(self.f.ctx))
        with open(ev.finish("FAIL"), encoding="ascii") as handle:
            lines = handle.read().splitlines()
        self.assertEqual([x for x in lines if x.startswith("VERDICT:")], ["VERDICT: FAIL"])
        self.assertEqual(len([x for x in lines if x.startswith("SHA256:")]), 1)
        self.assertIn("| VERDICT: PASS", lines)

    # ---- Wake Adapter v0.1: T2 also runs the wake_adapter suite, which may not skip anything
    def test_run_tests_runs_the_three_suites(self):
        steps = RunTests(self.f.ctx, {}).steps()
        self.assertEqual([s.label for s in steps], ["bridge_poller tests", "mini_ray tests", "wake_adapter tests"])
        self.assertEqual([s.argv[s.argv.index("-s") + 1] for s in steps],
                         ["bridge_poller/tests", "mini_ray/tests", "wake_adapter/tests"])

    def test_run_tests_wake_adapter_may_not_skip(self):
        def result(label, final):
            return {"label": label, "exit": 0, "stdout": "", "stderr": "Ran 9 tests in 1s\n\n%s\n" % final}
        for final, expected in (("OK", "PASS"), ("OK (skipped=1)", "FAIL")):
            ev = Evidence(self.f.ctx, "run_tests", {})
            got = RunTests(self.f.ctx, {}).verdict(ev, [result("bridge_poller tests", "OK"),
                                                        result("mini_ray tests", "OK"),
                                                        result("wake_adapter tests", final)])
            self.assertEqual(got, expected, final)

    # ---- review 12: skipped tests are limited
    def test_run_tests_skip_limits(self):
        def result(label, final):
            return {"label": label, "exit": 0, "stdout": "", "stderr": "Ran 9 tests in 1s\n\n%s\n" % final}
        cases = ((["OK (skipped=1)", "OK"], "PASS"), (["OK (skipped=2)", "OK"], "FAIL"),
                 (["OK", "OK (skipped=2)"], "PASS"), (["OK", "OK (skipped=3)"], "FAIL"))
        for (a, b), expected in cases:
            ev = Evidence(self.f.ctx, "run_tests", {})
            got = RunTests(self.f.ctx, {}).verdict(ev, [result("bridge_poller tests", a), result("mini_ray tests", b)])
            self.assertEqual(got, expected, (a, b))

    # ---- M8 (Windows): child output with CRLF line ends must still pass the verdict checks
    def test_crlf_child_output_is_normalised_for_verdicts(self):
        summary = "run=1 end_reason=WINDOW_DONE checks_done=10 new_count=1 suspect_listings=0 health=OK"
        code = "import sys; sys.stdout.buffer.write(%r)" % (summary + "\r\n").encode("ascii")
        result = Command("crlf", [sys.executable, "-c", code], self.f.repo, 30).run(self.f.ctx)
        self.assertNotIn("\r", result["stdout"])
        facts = {"last_run": (1, "s", "e", 10, 1, "WINDOW_DONE", 0, "OK"), "NEEDS_ERIC": 0}
        ev = Evidence(self.f.ctx, "t4", {})
        self.assertEqual(PollerBoundedRun(self.f.ctx, {}).verdict(ev, [result, {"facts": facts}]), "PASS")
        tests_out = "import sys; sys.stderr.buffer.write(b'Ran 9 tests in 1s\\r\\n\\r\\nOK\\r\\n')"
        r1 = Command("bridge_poller tests", [sys.executable, "-c", tests_out], self.f.repo, 30).run(self.f.ctx)
        r2 = Command("mini_ray tests", [sys.executable, "-c", tests_out], self.f.repo, 30).run(self.f.ctx)
        ev = Evidence(self.f.ctx, "run_tests", {})
        self.assertEqual(RunTests(self.f.ctx, {}).verdict(ev, [r1, r2]), "PASS")

    def test_child_environment_hardening(self):
        env = reduced_env(self.f.ctx)
        self.assertNotIn("GIT_CONFIG_NOSYSTEM", env)  # Git for Windows keeps its admin-only system config
        for key, value in (("GIT_CONFIG_GLOBAL", os.devnull),
                           ("GIT_OPTIONAL_LOCKS", "0"), ("PYTHONDONTWRITEBYTECODE", "1"),
                           ("PYTHONPYCACHEPREFIX", self.f.ctx.child_pycache)):
            self.assertEqual(env[key], value)


def ctypes_pointer_size():
    import ctypes
    return ctypes.sizeof(ctypes.c_void_p)


def ctypes_sizeof(cls):
    import ctypes
    return ctypes.sizeof(cls)


if __name__ == "__main__":
    unittest.main()
