"""Criteria 4 (imports / no network) and 12 (writes contained), plus the command line end to end."""
import ast
import json
import os
import socket

import wake_adapter
from wake_adapter import checkpoint, hand_over, produce, stop
from wake_adapter.__main__ import main

from .support import NOW, RecordingTransport, TempTree, pfile, tree

PACKAGE = os.path.dirname(os.path.abspath(wake_adapter.__file__))
ALLOWED = {"argparse", "dataclasses", "datetime", "hashlib", "json", "os", "pathlib", "re", "secrets", "sqlite3", "stat", "sys",
           "types", "typing"}
FORBIDDEN = {"socket", "urllib", "http", "ssl", "subprocess", "ctypes", "bridge_poller", "mini_ray", "requests",
             "asyncio", "smtplib", "ftplib", "multiprocessing", "shutil", "tempfile"}


def package_imports():
    found = {}
    for name in sorted(os.listdir(PACKAGE)):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(PACKAGE, name), encoding="utf-8") as handle:
            module = ast.parse(handle.read(), name)
        for node in ast.walk(module):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.setdefault(alias.name.split(".")[0], set()).add(name)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                found.setdefault(node.module.split(".")[0], set()).add(name)
            elif isinstance(node, ast.Call) and getattr(node.func, "id", None) in ("__import__", "eval", "exec"):
                found.setdefault("<dynamic:%s>" % node.func.id, set()).add(name)
    return found


class ImportTests(TempTree):
    def test_only_allowlisted_standard_library_imports(self):
        found = package_imports()
        self.assertEqual(set(found) - ALLOWED, set(), found)
        self.assertEqual(set(found) & FORBIDDEN, set())

    def test_full_flow_with_network_disabled(self):
        def refuse(*args, **kwargs):
            raise AssertionError("network use attempted")
        original = socket.socket
        socket.socket = refuse
        try:
            self.init_checkpoint()
            name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 76)], schedule={1: [pfile(76)]},
                           max_checks=1)
            result = produce([name], base=self.base, bridge_root=self.bridge)
            loaded = checkpoint.load(self.cp_path)
            receipt = hand_over(RecordingTransport(), result.events, self.no_stop)
            checkpoint.commit(self.cp_path, loaded, result.events, receipt, self.no_stop, NOW)
        finally:
            socket.socket = original
        self.assertEqual(sorted(e.kind for e in result.events), ["NEW", "OFFLINE_GAP"])


class ContainedWriteTests(TempTree):
    def test_only_the_checkpoint_is_written(self):
        name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 76)], schedule={1: [pfile(76)]}, max_checks=1)
        for n in (1, 2, 75):  # the Bridge holds real files too
            f = pfile(n)
            with open(os.path.join(self.bridge, "Ray-to-Glow", f["name"]), "w", encoding="utf-8") as handle:
                handle.write(f["text"])
        before = tree(self.tmp)
        self.init_checkpoint()
        result = produce([name], base=self.base, bridge_root=self.bridge)
        loaded = checkpoint.load(self.cp_path)
        receipt = hand_over(RecordingTransport(), result.events,
                            lambda: stop.stop_present(self.bridge, self.base))
        checkpoint.commit(self.cp_path, loaded, result.events, receipt,
                          lambda: stop.stop_present(self.bridge, self.base), NOW)
        after = tree(self.tmp)
        changed = {p for p in set(before) | set(after) if before.get(p) != after.get(p)}
        self.assertEqual(changed, {os.path.join("Local", "MiniGlow", "wake_adapter_checkpoint.json")})


class CommandLineTests(TempTree):
    def cli(self, *argv):
        lines = []
        code = main(list(argv), environ={"LOCALAPPDATA": self.local}, bridge_root=self.bridge, out=lines.append)
        return code, "\n".join(lines)

    def test_plan_with_assumed_high_water_writes_nothing(self):
        name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 76)], max_checks=0)
        before = tree(self.tmp)
        code, text = self.cli("plan", "--db", name, "--assume-high-water", "R2G-058", "--seed-db", name)
        self.assertEqual(code, 0, text)
        report = json.loads(text)
        self.assertEqual((report["dry_run"], report["event_count"]), (True, 1))
        self.assertEqual(report["events"][0]["gap"]["count"], 17)
        self.assertEqual(tree(self.tmp), before)

    def test_plan_needs_a_checkpoint_or_an_assumed_high_water(self):
        name = self.db("t4_a.sqlite", files=[pfile(1)])
        code, text = self.cli("plan", "--db", name)
        self.assertEqual(code, 2)
        self.assertIn("checkpoint missing", text)

    def test_init_then_plan(self):
        name = self.db("t4_a.sqlite", files=[pfile(n) for n in range(1, 59)], schedule={1: [pfile(59)]}, max_checks=1)
        self.assertEqual(self.cli("init", "--high-water", "R2G-058", "--seed-db", name)[0], 0)
        self.assertEqual(self.cli("init", "--high-water", "R2G-058", "--seed-db", name)[0], 2)  # never overwritten
        code, text = self.cli("plan", "--db", name)
        self.assertEqual(code, 0, text)
        self.assertEqual(json.loads(text)["events"][0]["packet_id"], "R2G-059")

    def test_refusals(self):
        self.assertEqual(self.cli("plan", "--db", "../t4_a.sqlite", "--assume-high-water", "R2G-058")[0], 2)
        self.assertEqual(self.cli("plan", "--db", "t4_none.sqlite", "--assume-high-water", "R2G-058")[0], 2)
        self.assertEqual(self.cli("plan", "--db", "t4_none.sqlite", "--assume-high-water", "58")[0], 2)
        lines = []
        code = main(["plan", "--db", "x.sqlite"], environ={}, bridge_root=self.bridge, out=lines.append)
        self.assertEqual(code, 2)
        self.assertIn("LOCALAPPDATA", lines[0])
