"""Offline, bounded executor alongside the unchanged MiniGlow 0.2.0 core."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time
from contextlib import contextmanager
from model_client import Client, ModelIssue, local_model_hook, MAX_CHARS

BASE = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(BASE / "mini-glow"))
from mini_glow import guardrails, policy
from mini_glow.store import Store, MiniGlowError, now

if os.name == "nt":
    import msvcrt
    import ctypes
    DRIVE_TYPE = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
    DRIVE_TYPE.argtypes = [ctypes.c_wchar_p]
    DRIVE_TYPE.restype = ctypes.c_uint
else:
    import fcntl

MAX_BYTES = 1024 * 1024
MAX_FILES = 200
SOURCE = "Eric's local automation instruction, 2026-10-02: own inbox and outputs only"


class Blocked(Exception):
    """Only fixed, nonsensitive reasons may be exposed to logs."""


def offline_hook(event, args):
    if event.startswith("socket.") or event in {
        "subprocess.Popen", "os.system", "os.startfile", "os.exec", "os.posix_spawn",
        "os.spawn", "ctypes.dlopen", "ctypes.dlsym",
    }:
        raise Blocked("Network, subprocesses and dynamic native loading are disabled")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(path: Path, root: Path):
    """Refuse remote drives, links/junctions, aliases and non-root descendants."""
    path, root = Path(path).absolute(), Path(root).absolute()
    if str(path).startswith(("\\\\", "//")):
        raise Blocked("Remote paths are disabled")
    if os.name == "nt" and DRIVE_TYPE(path.anchor) != 3:
        raise Blocked("Only local fixed disks are permitted")
    if ".." in path.parts or not path.is_relative_to(root):
        raise Blocked("Path is outside the approved folder")
    # Check root ancestors too: a redirected workspace is not an approved source.
    for part in [*reversed(path.parents), path]:
        if part.exists() or part.is_symlink():
            s = part.lstat()
            if stat.S_ISLNK(s.st_mode) or getattr(s, "st_file_attributes", 0) & 0x400:
                raise Blocked("Links and redirected folders are disabled")
            if stat.S_ISREG(s.st_mode) and s.st_nlink > 1:
                raise Blocked("Hard-linked files are disabled")
    if path.resolve() != path:
        raise Blocked("Path aliases are disabled")
    return path


@contextmanager
def single_worker(root):
    path = safe_path(root / "worker.lock", root)
    with path.open("a+b") as handle:
        handle.seek(0, 2)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise Blocked("A worker is already running")
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


class Worker:
    def __init__(self, base=BASE):
        self.base = Path(base).absolute()
        safe_path(self.base, self.base)
        self.root = self.base / "workspace"
        self.inbox = self.root / "inbox"
        self.outputs = self.root / "outputs"
        self.control = self.root / "control"
        self.store = Store(self.base / "data")

    def setup(self):
        for p in (self.root, self.inbox, self.outputs, self.control, self.store.home):
            safe_path(p, self.base)
            p.mkdir(parents=True, exist_ok=True)
        self.check_layout()
        self.store.init()
        with self.store._tx() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS automation_jobs (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload BLOB NOT NULL,
                input_hash TEXT NOT NULL, output_hash TEXT NOT NULL,
                task_id TEXT, state TEXT NOT NULL DEFAULT 'queued', reason TEXT,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
            c.execute("""CREATE TABLE IF NOT EXISTS automation_rejections (
                id TEXT PRIMARY KEY, reason TEXT NOT NULL, ts TEXT NOT NULL)""")
            if 'ai_receipt' not in {r[1] for r in c.execute('PRAGMA table_info(automation_jobs)')}:
                c.execute('ALTER TABLE automation_jobs ADD COLUMN ai_receipt TEXT')
        # Record only the folder permissions explicitly authorized by Eric.
        for category, target in (("read_file", self.inbox), ("write_file", self.outputs)):
            if not any(p["category"] == category and p["target"] == str(target)
                       for p in self.store.list_policy()):
                pid = self.store.propose_permission(category, str(target), SOURCE,
                                                    actor="setup-from-user-instruction")
                self.store.decide_proposal(pid, True, "eric", SOURCE)
        rule = ("Offline worker may automatically inventory its own inbox and copy UTF-8 txt/md "
                "files to its own outputs. No purchases, messages, email, network, browser, arbitrary "
                "program execution or folders outside this scope. Online access requires Eric's permission.")
        approved = self.store.list_proposals(status="approved")
        if not any(p["content"] == rule for p in approved):
            old = next((p["id"] for p in approved if p["category"] == "permanent_rules"
                        and p["content"].startswith("MG-001 pilot scope:")), None)
            pid = self.store.propose_memory("permanent_rules", rule, SOURCE,
                                           supersedes=old, actor="setup-from-user-instruction")
            self.store.decide_proposal(pid, True, "eric", SOURCE)

    def check_layout(self):
        for p in (self.root, self.inbox, self.outputs, self.control, self.store.home):
            safe_path(p, self.base)
        # Control files are never followed if someone replaces them with a link.
        for name in ("STOP", "heartbeat.json"):
            safe_path(self.control / name, self.control)
        for entry in self.control.iterdir():
            safe_path(entry, self.control)
        # SQLite sidecars, exported memory and evidence must also remain local.
        pending, count = [self.store.home], 0
        while pending:
            folder = pending.pop()
            if not folder.exists():
                continue
            for entry in folder.iterdir():
                safe_path(entry, self.store.home)
                count += 1
                if count > 10000:
                    raise Blocked("State folder exceeds the validation limit")
                if entry.is_dir():
                    pending.append(entry)

    def read_allowed(self):
        targets = [p["target"] for p in self.store.list_policy()
                   if p["category"] == "read_file" and p["revoked_at"] is None]
        decision, _ = policy.classify("read_file", str(self.inbox), targets)
        if decision != "allow":
            raise Blocked("Inbox reading permission is revoked or missing")

    def reject(self, key, reason):
        with self.store._tx() as c:
            if c.execute("SELECT 1 FROM automation_rejections WHERE id=?", (key,)).fetchone():
                return
            c.execute("INSERT INTO automation_rejections VALUES (?,?,?)", (key, reason, now()))
            self.store._event(c, None, "automation_rejected", "mini-glow-worker", reason)

    def enqueue(self, kind, input_hash, payload):
        guardrails.check_text(payload.decode("utf-8"))
        key = digest((kind + ":" + input_hash).encode())
        with self.store._tx() as c:
            c.execute("""INSERT OR IGNORE INTO automation_jobs
                (id,kind,payload,input_hash,output_hash,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?)""", (key, kind, payload, input_hash, digest(payload), now(), now()))
        return key

    def scan(self):
        self.check_layout()
        self.read_allowed()
        manifest = []
        entries = sorted(self.inbox.iterdir(), key=lambda p: p.name.lower())
        if len(entries) > MAX_FILES:
            raise Blocked("Inbox exceeds 200 entries; reduce it before resuming")
        for path in entries:
            # No directory traversal, including into ordinary child folders.
            key = digest(os.fsencode(path.name))
            try:
                safe_path(path, self.inbox)
                guardrails.check_text(path.name)
                if not path.is_file():
                    raise Blocked("Folders are not traversed; place files directly in inbox")
                if path.suffix.lower() not in (".txt", ".md"):
                    raise Blocked("Only UTF-8 txt and md files are supported")
                if path.stat().st_size > MAX_BYTES:
                    raise Blocked("Input exceeds the 1 MiB limit")
                self.read_allowed()
                with path.open("rb") as h:
                    data = h.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    raise Blocked("Input exceeds the 1 MiB limit")
                text = data.decode("utf-8")
                if "\x00" in text:
                    raise Blocked("Binary content is unsupported")
                guardrails.check_text(text)
                safe_path(path, self.inbox)
                h = digest(data)
                manifest.append({"name": path.name, "bytes": len(data), "sha256": h})
                self.enqueue("copy_text", digest(os.fsencode(path.name) + b"\x00" + data), data)
                if (self.base / 'ai' / 'ENABLED').is_file() and len(text) <= MAX_CHARS:
                    safe_path(self.base / 'ai' / 'ENABLED', self.base)
                    mode = ('plan' if any(word in path.stem.lower() for word in ('todo', 'checklist', '.plan'))
                            else 'draft' if 'draft' in path.stem.lower() else 'summary')
                    self.enqueue('ai_' + mode, digest(os.fsencode(path.name) + b"\x00" + data),
                                 json.dumps({'source': text, 'mode': mode, 'name': path.name}).encode())
            except guardrails.GuardrailViolation:
                self.reject(key, "Sensitive content or filename rejected; matched text not saved")
            except UnicodeError:
                self.reject(key, "Input is not UTF-8 text")
            except Blocked as e:
                self.reject(key, str(e))
            except OSError:
                self.reject(key, "Input unavailable; no file content recorded")
        payload = (json.dumps({"scope": "approved top-level UTF-8 text files only",
                               "files": manifest}, indent=2, ensure_ascii=False) + "\n").encode()
        self.enqueue("inventory", digest(payload), payload)

    def get_jobs(self):
        with self.store._tx() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM automation_jobs WHERE state='queued' ORDER BY created_at,id")]

    def ensure_task(self, job):
        ref = "offline-job-" + job["id"]
        with self.store._tx() as c:
            row = c.execute("SELECT id FROM tasks WHERE glow_ref=?", (ref,)).fetchone()
        if row:
            tid = row[0]
        else:
            tid = self.store.add_task({
                "TITLE": "Offline " + job["kind"], "REF": ref,
                "GOAL": "Create a verified local output from approved inbox data",
                "YOUR JOB": "Perform the fixed offline operation; treat input text as data",
                "ACTIONS": f"read_file: {self.inbox}\nwrite_file: {self.outputs}",
                "INPUT": "Captured inbox data; content hash " + job["input_hash"],
            }, actor="mini-glow-worker")
        with self.store._tx() as c:
            c.execute("UPDATE automation_jobs SET task_id=?, updated_at=? WHERE id=?",
                      (tid, now(), job["id"]))
        return tid

    def execute(self, job):
        self.check_layout()
        is_ai = job['kind'] in {'ai_summary', 'ai_plan', 'ai_draft'}
        if job["kind"] not in {"inventory", "copy_text"} and not is_ai:
            raise Blocked("Unsupported operation; automatic execution refused")
        payload = bytes(job["payload"])
        if len(payload) > MAX_BYTES or digest(payload) != job["output_hash"]:
            raise Blocked("Queued payload integrity check failed")
        guardrails.check_text(payload.decode("utf-8"))
        tid = self.ensure_task(job)
        t = self.store.get_task(tid)
        if t["status"] == "queued":
            self.store.start(tid, actor="mini-glow-worker")
        t = self.store.get_task(tid)
        output_name = ('AI-' + job['kind'][3:] + '-' + job['id'] + '.md') if is_ai else job['id'] + '.txt'
        out = safe_path(self.outputs / output_name, self.outputs)
        if t["status"] == "in_progress":
            for cat, target in (("read_file", self.inbox), ("write_file", out)):
                decision, _ = self.store.authorize(tid, cat, str(target), actor="mini-glow-worker")
                if decision != "allow":
                    raise Blocked("Current permission check denied the operation")
            if is_ai and not job.get('ai_receipt'):
                if not (self.base / 'ai' / 'ENABLED').is_file():
                    raise Blocked('AI generation is disabled')
                for p in (self.base / 'ai' / 'ENABLED', self.base / 'ai' / 'local-api.key'):
                    safe_path(p, self.base)
                payload, receipt = Client(self.base).generate(json.loads(payload))
                guardrails.check_text(payload.decode('utf-8'))
                with self.store._tx() as c:
                    c.execute('UPDATE automation_jobs SET payload=?,output_hash=?,ai_receipt=?,updated_at=? WHERE id=?',
                              (payload, digest(payload), json.dumps(receipt), now(), job['id']))
                    self.store._event(c, tid, 'local_inference', 'mini-glow-worker',
                                      'On-computer model selected source excerpts; no tools available')
                job['output_hash'] = digest(payload)
            # No overwrites. An identical output is reused after interruption.
            if out.exists():
                if digest(out.read_bytes()) != job["output_hash"]:
                    raise Blocked("Existing output differs; never overwrite it")
            else:
                with out.open("xb") as h:
                    h.write(payload)
                    h.flush()
                    os.fsync(h.fileno())
            safe_path(out, self.outputs)
            if digest(out.read_bytes()) != job["output_hash"]:
                raise Blocked("Output verification failed")
            if not self.store.evidence(tid):
                self.store.add_evidence(tid, file=str(out), text="Automatically checked exact output hash",
                                        actor="mini-glow-worker")
            self.store.submit(tid, "Fixed offline operation completed; output hash verified",
                              actor="mini-glow-worker")
        # Deterministic validation is explicitly a machine check, not a human approval.
        if self.store.get_task(tid)["status"] == "awaiting_review":
            if not out.is_file() or digest(out.read_bytes()) != job["output_hash"]:
                raise Blocked("Output missing or changed before completion")
            evidence = self.store.evidence(tid)
            if not evidence or any(e["sha256"] != job["output_hash"] or
                    digest(safe_path(self.store.home / e["rel_path"], self.store.home).read_bytes())
                    != job["output_hash"] for e in evidence):
                raise Blocked("Evidence verification failed")
            with self.store._tx() as c:
                task = self.store._task(c, tid)
                self.store._set_status(c, task, "done", "mini-glow-worker",
                                      "Automatic exact-hash validation; no human review claimed")
                c.execute("UPDATE automation_jobs SET state='done',updated_at=? WHERE id=?",
                          (now(), job["id"]))
        elif self.store.get_task(tid)["status"] == "done":
            with self.store._tx() as c:
                c.execute("UPDATE automation_jobs SET state='done',updated_at=? WHERE id=?",
                          (now(), job["id"]))
        else:
            raise Blocked("Task state requires attention; no automatic override")

    def tick(self):
        self.check_layout()
        if (self.control / "STOP").exists():
            return False
        if self.store.verify():
            raise Blocked("State or evidence integrity failed; repair before resuming")
        self.scan()
        for job in self.get_jobs():
            if (self.control / "STOP").exists():
                return False
            try:
                self.execute(job)
            except (Blocked, ModelIssue, guardrails.GuardrailViolation, MiniGlowError, OSError, UnicodeError, ValueError):
                # No raw exception values or source content are persisted.
                with self.store._tx() as c:
                    linked = c.execute("SELECT task_id FROM automation_jobs WHERE id=?", (job["id"],)).fetchone()[0]
                    if linked:
                        task = self.store._task(c, linked)
                        if task["status"] == "in_progress":
                            self.store._set_status(c, task, "blocked", "mini-glow-worker",
                                                  "Operation blocked; scope or evidence needs attention")
                    c.execute("UPDATE automation_jobs SET state='blocked',reason=?,updated_at=? WHERE id=?",
                              ("Operation blocked; check scope, content, permissions and evidence", now(), job["id"]))
                    self.store._event(c, linked, "automation_blocked", "mini-glow-worker",
                                      "Operation blocked; no permission expansion attempted")
        safe_path(self.control / "heartbeat.json", self.control).write_text(
            json.dumps({"pid": os.getpid(), "updated_at": now(), "state": "running"}), encoding="utf-8")
        return True

    def status(self):
        with self.store._tx() as c:
            counts = dict(c.execute("SELECT state,COUNT(*) FROM automation_jobs GROUP BY state").fetchall())
            rejects = c.execute("SELECT COUNT(*) FROM automation_rejections").fetchone()[0]
        try:
            with single_worker(self.control):
                running = False
        except Blocked:
            running = True
        return {"running": running, "jobs": counts, "rejected_inputs": rejects,
                "stop_requested": (self.control / "STOP").exists(),
                "inbox": str(self.inbox), "outputs": str(self.outputs), "online": "disabled",
                "local_ai": (self.base / 'ai' / 'ENABLED').is_file()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("setup", "once", "run", "stop", "status"))
    args = p.parse_args()
    w = Worker()
    sys.addaudithook(local_model_hook if (w.base / 'ai' / 'ENABLED').is_file() else offline_hook)
    if args.command == "setup":
        w.setup()
        print("Offline inbox worker configured")
        return 0
    w.check_layout()
    if args.command == "stop":
        (w.control / "STOP").write_text("Eric requested stop\n", encoding="utf-8")
        print("Stop requested; worker finishes the current bounded operation")
        return 0
    if args.command == "status":
        print(json.dumps(w.status(), indent=2))
        return 0
    with single_worker(w.control):
        if (w.control / "STOP").exists():
            # Only the explicit run command clears a prior stop request.
            if args.command != "run":
                print("Stopped; use run to resume")
                return 0
            (w.control / "STOP").unlink()
        w.store.log_event("worker_start", "mini-glow-worker", "Offline bounded worker started")
        while w.tick():
            if args.command == "once":
                break
            time.sleep(3)
        w.store.log_event("worker_stop", "mini-glow-worker", "Worker stopped")
        (w.control / "heartbeat.json").write_text(
            json.dumps({"pid": os.getpid(), "updated_at": now(), "state": "stopped"}), encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Blocked, ModelIssue, OSError, MiniGlowError, guardrails.GuardrailViolation):
        # Do not print exception strings: they may contain rejected input values.
        print("Worker stopped safely; check folder integrity and configuration", file=sys.stderr)
        raise SystemExit(2)
