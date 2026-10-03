"""Persistent storage for Mini Glow (Layers 2 and 3). Version 0.2.

ONE SQLite database is the single source of truth. Every change to a task, evidence record,
proposal or policy is written together with its audit event in ONE transaction, so there is
no gap between "the change happened" and "the log says so". The events table is append-only
(triggers refuse UPDATE and DELETE).

Readable files are EXPORTS generated from the database, never edited by hand:
  <home>/memory/*.md          export-memory  (regenerated automatically after approved changes)
  <home>/exports/events.jsonl export-log     (on demand)

Other folders: evidence/ (copied files, SHA-256 recorded in the database), handoffs/, backups/.
There are no timers and no in-memory state between commands, so state survives restarts.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from . import guardrails, packets, policy

APP_VERSION = "0.2.0"
SCHEMA_VERSION = 2

TRANSITIONS = {
    "needs_clarification": {"queued", "cancelled"},
    "queued": {"in_progress", "needs_clarification", "cancelled"},
    "in_progress": {"blocked", "awaiting_review", "failed", "cancelled"},
    "blocked": {"in_progress", "failed", "cancelled"},
    "awaiting_review": {"done", "in_progress", "cancelled"},
    "failed": {"queued"},
    "done": set(),
    "cancelled": set(),
}

# Memory tiers.
ORDINARY_CATEGORIES = ("project_context", "task_context")      # Glow may approve, inside Eric's approved scope
ERIC_ONLY_CATEGORIES = ("identity", "permanent_rules")         # Eric approves
MEMORY_CATEGORIES = ORDINARY_CATEGORIES + ERIC_ONLY_CATEGORIES
MEMORY_FILES = MEMORY_CATEGORIES + ("permissions", "upgrade_history")

SEED_SOURCE = "Eric's instruction, 2026-10-02 (seed)"
SEEDS = [
    ("identity", "Mini Glow is a worker agent acting as Glow's arms on Eric's Windows PC. Glow coordinates and reviews. Eric is the final authority."),
    ("permanent_rules", "Buying anything and sending any message require Eric's explicit approval. Both are unavailable in the MG-001 pilot even after approval."),
    ("permanent_rules", "Never handle credentials, patient records, or unrelated sensitive data."),
    ("permanent_rules", "Relevant low- and medium-sensitivity information is allowed within designated sources."),
    ("permanent_rules", "MG-001 pilot scope: no browser control, no unattended execution, no automatic contact with Glow. Eric relays messages by hand."),
]


class MiniGlowError(Exception):
    pass


def now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def default_home() -> Path:
    env = os.environ.get("MINI_GLOW_HOME")
    return Path(env) if env else Path.cwd() / "mini_glow_data"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


DDL = [
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    """CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY, seq INTEGER NOT NULL, title TEXT NOT NULL,
        status TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 5,
        glow_ref TEXT, goal TEXT, your_job TEXT, context TEXT, input TEXT,
        rules TEXT, output_format TEXT, done_when TEXT, next_stop TEXT,
        flagged INTEGER NOT NULL DEFAULT 0,
        flag_decision TEXT, flag_decided_by TEXT, flag_decided_at TEXT,
        result_summary TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS task_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES tasks(id),
        category TEXT NOT NULL, target TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, ts TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
        task_id TEXT, kind TEXT NOT NULL, actor TEXT NOT NULL, detail TEXT NOT NULL)""",
    """CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
        BEGIN SELECT RAISE(ABORT, 'events are append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
        BEGIN SELECT RAISE(ABORT, 'events are append-only'); END""",
    """CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL REFERENCES tasks(id), ts TEXT NOT NULL,
        text TEXT, rel_path TEXT, sha256 TEXT)""",
    """CREATE TABLE IF NOT EXISTS proposals (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
        kind TEXT NOT NULL,                 -- memory | permission
        category TEXT NOT NULL,             -- memory category, or action category for permissions
        target TEXT,                        -- permissions only
        scope TEXT, task_id TEXT,
        content TEXT NOT NULL, source TEXT NOT NULL,
        proposed_by TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
        decided_by TEXT, decided_at TEXT, reason TEXT,
        supersedes INTEGER, superseded_by INTEGER)""",
    """CREATE TABLE IF NOT EXISTS policy_allow (
        id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL, target TEXT NOT NULL,
        approved_by TEXT NOT NULL, source TEXT NOT NULL, proposal_id INTEGER, ts TEXT NOT NULL, revoked_at TEXT, revoked_by TEXT)""",
    """CREATE TABLE IF NOT EXISTS scopes (
        name TEXT PRIMARY KEY, approved_by TEXT NOT NULL, ts TEXT NOT NULL, revoked_at TEXT)""",
]


class Store:
    def __init__(self, home: Path | str | None = None):
        self.home = Path(home) if home else default_home()
        self.db_path = self.home / "mini_glow.db"

    # ------------------------------------------------------------------ plumbing
    @contextmanager
    def _tx(self):
        self.home.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def _require_init(self):
        if not self.db_path.exists():
            raise MiniGlowError(f"No Mini Glow data found at {self.home}. Run: init")

    @staticmethod
    def _event(c, task_id, kind, actor, detail):
        c.execute("INSERT INTO events (ts, task_id, kind, actor, detail) VALUES (?,?,?,?,?)",
                  (now(), task_id, kind, actor, detail))

    def log_event(self, kind: str, actor: str, detail: str, task_id: str | None = None) -> None:
        """For callers outside the store (e.g. backup). One transaction, one event."""
        self._require_init()
        with self._tx() as c:
            self._event(c, task_id, kind, actor, detail)

    @staticmethod
    def _task(c, task_id: str) -> dict:
        row = c.execute("SELECT * FROM tasks WHERE id=?", (str(task_id).upper(),)).fetchone()
        if not row:
            raise MiniGlowError(f"No such task: {task_id}")
        return dict(row)

    @staticmethod
    def _actions(c, task_id: str) -> list[dict]:
        return [dict(r) for r in c.execute(
            "SELECT category, target FROM task_actions WHERE task_id=? AND active=1 ORDER BY id", (task_id,))]

    @staticmethod
    def _allowed_targets(c, category: str) -> list[str]:
        return [r[0] for r in c.execute(
            "SELECT target FROM policy_allow WHERE category=? AND revoked_at IS NULL", (category,))]

    def _evaluate(self, c, actions: list[dict]) -> list[tuple[str, str, str, str]]:
        out = []
        for a in actions:
            d, why = policy.classify(a["category"], a["target"], self._allowed_targets(c, a["category"].lower()))
            out.append((a["category"], a["target"], d, why))
        return out

    @staticmethod
    def _summarize(decs) -> str:
        if not decs:
            return "No ACTIONS declared. Ask Glow to list what this task needs."
        return "; ".join(f"{cat}:{tgt or '-'} -> {d} ({why})" for cat, tgt, d, why in decs if d != "allow") or "all actions allowed"

    def _set_status(self, c, t: dict, new: str, actor: str, detail: str, summary: str | None = None):
        if new not in TRANSITIONS[t["status"]]:
            allowed = ", ".join(sorted(TRANSITIONS[t["status"]])) or "none"
            raise MiniGlowError(f"{t['id']} is '{t['status']}'; cannot move to '{new}'. Allowed: {allowed}")
        if summary is not None:
            c.execute("UPDATE tasks SET status=?, updated_at=?, result_summary=? WHERE id=?", (new, now(), summary, t["id"]))
        else:
            c.execute("UPDATE tasks SET status=?, updated_at=? WHERE id=?", (new, now(), t["id"]))
        self._event(c, t["id"], "status", actor, f"{t['status']} -> {new}. {detail}".strip())

    # ------------------------------------------------------------------ setup
    def init(self) -> bool:
        created = not self.db_path.exists()
        for sub in ("memory", "evidence", "exports", "handoffs/inbox", "handoffs/outbox", "backups"):
            (self.home / sub).mkdir(parents=True, exist_ok=True)
        with self._tx() as c:
            for ddl in DDL:
                c.execute(ddl)
            c.execute("INSERT OR IGNORE INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
            c.execute("INSERT OR IGNORE INTO meta VALUES ('task_seq', '0')")
            if created:
                for cat, text in SEEDS:
                    c.execute(
                        """INSERT INTO proposals (ts, kind, category, scope, content, source, proposed_by,
                           status, decided_by, decided_at, reason) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (now(), "memory", cat, "general", text, SEED_SOURCE, "seed", "approved", "eric", now(), "seed"))
                self._event(c, None, "init", "system", f"Initialized Mini Glow {APP_VERSION} (schema {SCHEMA_VERSION}) with {len(SEEDS)} seed entries")
        self.export_memory()
        return created

    # ------------------------------------------------------------------ tasks
    def add_task(self, fields: dict, actor: str = "eric") -> str:
        self._require_init()
        guardrails.check_text(*[v for v in fields.values() if isinstance(v, str)])
        actions = [{"category": c_, "target": t_} for c_, t_ in packets.parse_actions(fields.get("ACTIONS", ""))]
        flag = guardrails.needs_approval(fields.get("GOAL", ""), fields.get("YOUR JOB", ""), fields.get("INPUT", ""))
        with self._tx() as c:
            seq = int(c.execute("SELECT value FROM meta WHERE key='task_seq'").fetchone()[0]) + 1
            c.execute("UPDATE meta SET value=? WHERE key='task_seq'", (str(seq),))
            tid = f"MG-T-{seq:04d}"
            decs = self._evaluate(c, actions)
            ok = bool(decs) and all(d[2] == "allow" for d in decs)
            status = "queued" if ok else "needs_clarification"
            ts = now()
            c.execute(
                """INSERT INTO tasks (id, seq, title, status, priority, glow_ref, goal, your_job, context, input,
                   rules, output_format, done_when, next_stop, flagged, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (tid, seq, fields["TITLE"], status, int(fields.get("PRIORITY", 5)), fields.get("REF"),
                 fields.get("GOAL"), fields.get("YOUR JOB"), fields.get("CONTEXT"), fields.get("INPUT"),
                 fields.get("RULES"), fields.get("OUTPUT FORMAT"), fields.get("DONE WHEN"),
                 fields.get("NEXT STOP"), 1 if flag else 0, ts, ts))
            for a in actions:
                c.execute("INSERT INTO task_actions (task_id, category, target, ts) VALUES (?,?,?,?)",
                          (tid, a["category"], a["target"], ts))
            self._event(c, tid, "created", actor, f"Task received: {fields['TITLE']} (status {status})")
            if not ok:
                self._event(c, tid, "pause", "mini-glow", "Needs clarification before it can queue: " + self._summarize(decs))
            if flag:
                self._event(c, tid, "flag", "mini-glow",
                            "Wording suggests buying/sending/publishing. Flag only: it grants nothing. Eric must record a decision before start.")
        return tid

    def get_task(self, task_id: str) -> dict:
        self._require_init()
        with self._tx() as c:
            return self._task(c, task_id)

    def task_actions(self, task_id: str) -> list[dict]:
        with self._tx() as c:
            return self._actions(c, self._task(c, task_id)["id"])

    def list_tasks(self, status: str | None = None) -> list[dict]:
        self._require_init()
        with self._tx() as c:
            if status:
                rows = c.execute("SELECT * FROM tasks WHERE status=? ORDER BY priority, seq", (status,)).fetchall()
            else:
                rows = c.execute("SELECT * FROM tasks ORDER BY seq").fetchall()
        return [dict(r) for r in rows]

    def decide_flag(self, task_id: str, by: str, decision: str) -> None:
        """Record Eric's decision on a flagged task. This records a decision only. It never enables an action."""
        if by.lower() != "eric":
            raise MiniGlowError("Only Eric can record a decision on a flagged task (use --by eric).")
        if decision not in ("approve", "decline"):
            raise MiniGlowError("decision must be approve or decline")
        with self._tx() as c:
            t = self._task(c, task_id)
            if not t["flagged"]:
                raise MiniGlowError(f"{t['id']} is not flagged.")
            if t["flag_decision"]:
                raise MiniGlowError(f"{t['id']} already has a recorded decision: {t['flag_decision']}.")
            if t["status"] not in ("queued", "needs_clarification"):
                raise MiniGlowError(f"{t['id']} is '{t['status']}'; decisions are recorded before work starts.")
            c.execute("UPDATE tasks SET flag_decision=?, flag_decided_by='eric', flag_decided_at=?, updated_at=? WHERE id=?",
                      ("approved" if decision == "approve" else "declined", now(), now(), t["id"]))
            self._event(c, t["id"], "flag_decision", "eric",
                        f"Eric {decision}d the flagged wording. This does NOT enable buy/send or any action; actions still need Eric's allowed targets.")
            if decision == "decline":
                self._set_status(c, t, "cancelled", "eric", "Declined by Eric")

    def clarify(self, task_id: str, by: str, actions_text: str | None = None) -> dict:
        """Glow or Eric supplies/changes ACTIONS (or just re-checks after policy changes)."""
        by = by.lower()
        if by not in ("glow", "eric"):
            raise MiniGlowError("Clarification must be recorded as glow or eric.")
        if actions_text:
            guardrails.check_text(actions_text)
        with self._tx() as c:
            t = self._task(c, task_id)
            if t["status"] != "needs_clarification":
                raise MiniGlowError(f"{t['id']} is '{t['status']}', not needs_clarification.")
            if actions_text:
                old = self._actions(c, t["id"])
                c.execute("UPDATE task_actions SET active=0 WHERE task_id=?", (t["id"],))
                new = [{"category": a, "target": b} for a, b in packets.parse_actions(actions_text)]
                for a in new:
                    c.execute("INSERT INTO task_actions (task_id, category, target, ts) VALUES (?,?,?,?)",
                              (t["id"], a["category"], a["target"], now()))
                self._event(c, t["id"], "actions_changed", by,
                            f"Actions replaced. Before: {[(a['category'], a['target']) for a in old]} After: {[(a['category'], a['target']) for a in new]}")
            decs = self._evaluate(c, self._actions(c, t["id"]))
            if decs and all(d[2] == "allow" for d in decs):
                self._set_status(c, t, "queued", by, "Clarified; all actions allowed")
            else:
                self._event(c, t["id"], "pause", "mini-glow", "Still needs clarification: " + self._summarize(decs))
            return self._task(c, t["id"])

    def start(self, task_id: str | None = None, actor: str = "mini-glow") -> dict:
        error, started = None, None
        with self._tx() as c:
            if task_id:
                cands = [self._task(c, task_id)]
            else:
                cands = [dict(r) for r in c.execute("SELECT * FROM tasks WHERE status='queued' ORDER BY priority, seq")]
            for t in cands:
                if t["status"] != "queued":
                    error = f"{t['id']} is '{t['status']}'; only queued tasks can start."
                    break
                if t["flagged"] and t["flag_decision"] != "approved":
                    if task_id:
                        error = f"{t['id']} is flagged (buy/send/publish wording). Eric must record a decision: decide {t['id']} --by eric --decision approve"
                        break
                    continue
                decs = self._evaluate(c, self._actions(c, t["id"]))
                if not decs or any(d[2] != "allow" for d in decs):
                    self._set_status(c, t, "needs_clarification", "mini-glow", "Policy check at start: " + self._summarize(decs))
                    if task_id:
                        error = f"{t['id']} paused for clarification: " + self._summarize(decs)
                        break
                    continue
                self._set_status(c, t, "in_progress", actor, "Started")
                started = t["id"]
                break
            if started is None and error is None:
                error = "No startable tasks in the queue."
        if error:
            raise MiniGlowError(error)
        return self.get_task(started)

    def authorize(self, task_id: str, category: str, target: str, actor: str = "mini-glow") -> tuple[str, str]:
        """Gate for ONE action on an in-progress task. Returns (allow|deny|pause, reason) and audits it.
        In MG-001 nothing is executed; a later execution layer must call this first."""
        with self._tx() as c:
            t = self._task(c, task_id)
            if t["status"] != "in_progress":
                raise MiniGlowError(f"{t['id']} is '{t['status']}'; actions can only be authorized for in_progress tasks.")
            cat = (category or "").strip().lower()
            # 1. Policy first: unavailable categories and non-allowed targets are denied no matter what the task says;
            #    unknown categories and missing targets pause.
            decision, reason = policy.classify(category, target, self._allowed_targets(c, cat))
            # 2. Even if policy allows it, the action must be one the task declared.
            if decision == "allow":
                norm = policy.normalize_target(target)
                declared = [a for a in self._actions(c, t["id"])
                            if a["category"].lower() == cat and policy.normalize_target(a["target"]) is not None
                            and policy.covers(policy.normalize_target(a["target"]), norm)]
                if not declared:
                    decision, reason = "pause", "allowed by Eric's list, but not declared on this task. Ask Glow to add it (clarify)"
            self._event(c, t["id"], "authorize", actor, f"{decision.upper()}: {category}:{target} - {reason}")
        return decision, reason

    def block(self, task_id: str, question: str, tried: str, actor: str = "mini-glow") -> dict:
        guardrails.check_text(question, tried)
        with self._tx() as c:
            t = self._task(c, task_id)
            self._set_status(c, t, "blocked", actor, f"Asked Glow: {question}")
            if tried:
                self._event(c, t["id"], "note", actor, f"Tried before blocking: {tried}")
            return self._task(c, t["id"])

    def resume(self, task_id: str, guidance: str, actor: str = "mini-glow") -> dict:
        guardrails.check_text(guidance)
        with self._tx() as c:
            t = self._task(c, task_id)
            self._set_status(c, t, "in_progress", actor, "Resumed")
            self._event(c, t["id"], "guidance", actor, f"Guidance from Glow/Eric: {guidance}")
            return self._task(c, t["id"])

    def submit(self, task_id: str, summary: str, actor: str = "mini-glow") -> dict:
        guardrails.check_text(summary)
        with self._tx() as c:
            t = self._task(c, task_id)
            if t["status"] != "in_progress":
                raise MiniGlowError(f"{t['id']} is '{t['status']}'; only in_progress tasks can be submitted.")
            if not c.execute("SELECT 1 FROM evidence WHERE task_id=?", (t["id"],)).fetchone():
                raise MiniGlowError("Cannot submit without evidence. Add some first (evidence command).")
            self._set_status(c, t, "awaiting_review", actor, "Submitted for Glow's review", summary=summary)
            return self._task(c, t["id"])

    def accept(self, task_id: str, by: str, comment: str = "") -> dict:
        by = by.lower()
        if by not in ("glow", "eric"):
            raise MiniGlowError("Review must be recorded as glow or eric.")
        with self._tx() as c:
            t = self._task(c, task_id)
            self._set_status(c, t, "done", by, f"Accepted. {comment}")
            return self._task(c, t["id"])

    def rework(self, task_id: str, by: str, comment: str) -> dict:
        by = by.lower()
        if by not in ("glow", "eric"):
            raise MiniGlowError("Review must be recorded as glow or eric.")
        guardrails.check_text(comment)
        with self._tx() as c:
            t = self._task(c, task_id)
            self._set_status(c, t, "in_progress", by, "Sent back for rework")
            self._event(c, t["id"], "guidance", by, f"Rework requested: {comment}")
            return self._task(c, t["id"])

    def fail(self, task_id: str, reason: str, actor: str = "mini-glow") -> dict:
        guardrails.check_text(reason)
        with self._tx() as c:
            t = self._task(c, task_id)
            self._set_status(c, t, "failed", actor, reason, summary=f"FAILED: {reason}")
            return self._task(c, t["id"])

    def cancel(self, task_id: str, by: str, reason: str = "") -> dict:
        with self._tx() as c:
            t = self._task(c, task_id)
            self._set_status(c, t, "cancelled", by.lower(), reason)
            return self._task(c, t["id"])

    def retry(self, task_id: str, by: str = "eric") -> dict:
        with self._tx() as c:
            t = self._task(c, task_id)
            self._set_status(c, t, "queued", by.lower(), "Re-queued after failure")
            return self._task(c, t["id"])

    # ------------------------------------------------------------------ notes and evidence
    def add_note(self, task_id: str, text: str, kind: str = "note", actor: str = "mini-glow") -> None:
        guardrails.check_text(text)
        if kind not in ("note", "assumption"):
            raise MiniGlowError("kind must be note or assumption")
        with self._tx() as c:
            t = self._task(c, task_id)
            self._event(c, t["id"], kind, actor, text)

    def add_evidence(self, task_id: str, text: str | None = None, file: str | None = None,
                     actor: str = "mini-glow") -> str:
        if not text and not file:
            raise MiniGlowError("Provide evidence text and/or a file.")
        if text:
            guardrails.check_text(text)
        copied: Path | None = None
        rel = digest = None
        try:
            with self._tx() as c:
                t = self._task(c, task_id)
                if t["status"] != "in_progress":
                    raise MiniGlowError(f"{t['id']} is '{t['status']}'; evidence is added while a task is in_progress.")
                if file:
                    src = Path(file)
                    if not src.is_file():
                        raise MiniGlowError(f"Evidence file not found: {file}")
                    digest = sha256_file(src)
                    dest_dir = self.home / "evidence" / t["id"]
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    dest = dest_dir / src.name
                    if dest.exists():
                        dest = dest_dir / f"{digest[:8]}_{src.name}"
                    shutil.copy2(src, dest)
                    copied = dest
                    rel = dest.relative_to(self.home).as_posix()
                c.execute("INSERT INTO evidence (task_id, ts, text, rel_path, sha256) VALUES (?,?,?,?,?)",
                          (t["id"], now(), text, rel, digest))
                detail = " | ".join(x for x in (text, f"file={rel} sha256={digest}" if rel else None) if x)
                self._event(c, t["id"], "evidence", actor, detail)
        except BaseException:
            if copied and copied.exists():
                copied.unlink()  # database change rolled back, so remove the orphan copy
            raise
        return detail

    def evidence(self, task_id: str) -> list[dict]:
        with self._tx() as c:
            t = self._task(c, task_id)
            return [dict(r) for r in c.execute("SELECT * FROM evidence WHERE task_id=? ORDER BY id", (t["id"],))]

    def events(self, task_id: str | None = None) -> list[dict]:
        self._require_init()
        with self._tx() as c:
            if task_id:
                rows = c.execute("SELECT * FROM events WHERE task_id=? ORDER BY id", (task_id.upper(),)).fetchall()
            else:
                rows = c.execute("SELECT * FROM events ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ reviewed memory and permissions
    def propose_memory(self, category: str, content: str, source: str, scope: str | None = None,
                       task_id: str | None = None, supersedes: int | None = None, actor: str = "mini-glow") -> int:
        self._require_init()
        if category not in MEMORY_CATEGORIES:
            raise MiniGlowError("category must be one of: " + ", ".join(MEMORY_CATEGORIES))
        if not (source or "").strip():
            raise MiniGlowError("A source is required (where this came from: task, document, review, person).")
        if category in ORDINARY_CATEGORIES and not (scope or "").strip():
            raise MiniGlowError(f"{category} needs a --scope (the project or area it belongs to).")
        guardrails.check_text(content, source)
        with self._tx() as c:
            if supersedes is not None:
                old = c.execute("SELECT * FROM proposals WHERE id=? AND kind='memory' AND status='approved'", (supersedes,)).fetchone()
                if not old:
                    raise MiniGlowError(f"#{supersedes} is not an approved memory entry, so it cannot be superseded.")
            tid = self._task(c, task_id)["id"] if task_id else None
            cur = c.execute(
                """INSERT INTO proposals (ts, kind, category, scope, task_id, content, source, proposed_by, supersedes)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (now(), "memory", category, scope, tid, content, source, actor, supersedes))
            pid = cur.lastrowid
            self._event(c, tid, "proposal", actor, f"Candidate #{pid} ({category}) awaiting review; source: {source}")
        return pid

    def propose_permission(self, category: str, target: str, source: str, actor: str = "mini-glow") -> int:
        self._require_init()
        cat = (category or "").lower()
        if cat in policy.UNAVAILABLE:
            raise MiniGlowError(f"'{cat}' is not available in this pilot, so no permission can be proposed for it.")
        if cat not in policy.AVAILABLE:
            raise MiniGlowError("category must be one of: " + ", ".join(sorted(policy.AVAILABLE)))
        if policy.normalize_target(target) is None:
            raise MiniGlowError("target is empty or contains '..'")
        if not (source or "").strip():
            raise MiniGlowError("A source is required.")
        guardrails.check_text(target, source)
        with self._tx() as c:
            cur = c.execute(
                """INSERT INTO proposals (ts, kind, category, target, content, source, proposed_by)
                   VALUES (?,?,?,?,?,?,?)""",
                (now(), "permission", cat, target, f"Allow {cat} on {target}", source, actor))
            pid = cur.lastrowid
            self._event(c, None, "proposal", actor, f"Permission candidate #{pid}: allow {cat} on {target}")
        return pid

    def list_proposals(self, status: str | None = "pending") -> list[dict]:
        self._require_init()
        with self._tx() as c:
            if status:
                rows = c.execute("SELECT * FROM proposals WHERE status=? ORDER BY id", (status,)).fetchall()
            else:
                rows = c.execute("SELECT * FROM proposals ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def decide_proposal(self, pid: int, approve: bool, by: str, reason: str = "") -> None:
        by = by.lower()
        if by not in ("glow", "eric"):
            raise MiniGlowError("Decisions must be recorded as glow or eric.")
        guardrails.check_text(reason)
        with self._tx() as c:
            p = c.execute("SELECT * FROM proposals WHERE id=?", (pid,)).fetchone()
            if not p:
                raise MiniGlowError(f"No such proposal: {pid}")
            p = dict(p)
            if p["status"] != "pending":
                raise MiniGlowError(f"Proposal #{pid} is already {p['status']}.")
            if approve and by != "eric":
                if p["kind"] == "permission":
                    raise MiniGlowError("Permissions and access can only be approved by Eric.")
                if p["category"] in ERIC_ONLY_CATEGORIES:
                    raise MiniGlowError(f"{p['category']} can only be approved by Eric.")
                ok = c.execute("SELECT 1 FROM scopes WHERE name=? AND revoked_at IS NULL", ((p["scope"] or "").lower(),)).fetchone()
                if not ok:
                    raise MiniGlowError(f"Scope '{p['scope']}' has not been approved by Eric. Glow can approve only inside an approved scope.")
            c.execute("UPDATE proposals SET status=?, decided_by=?, decided_at=?, reason=? WHERE id=?",
                      ("approved" if approve else "rejected", by, now(), reason, pid))
            if approve and p["kind"] == "permission":
                c.execute("""INSERT INTO policy_allow (category, target, approved_by, source, proposal_id, ts)
                             VALUES (?,?,?,?,?,?)""", (p["category"], p["target"], by, p["source"], pid, now()))
            if approve and p["kind"] == "memory" and p["supersedes"]:
                c.execute("UPDATE proposals SET superseded_by=? WHERE id=?", (pid, p["supersedes"]))
            self._event(c, p["task_id"], "decision", by,
                        f"Proposal #{pid} ({p['kind']}/{p['category']}) {'approved' if approve else 'rejected'}. {reason}".strip())
        self.export_memory()

    def allow_scope(self, name: str, by: str) -> None:
        if by.lower() != "eric":
            raise MiniGlowError("Only Eric can approve a scope.")
        n = (name or "").strip().lower()
        if not n:
            raise MiniGlowError("scope name is empty")
        with self._tx() as c:
            c.execute("INSERT INTO scopes (name, approved_by, ts) VALUES (?, 'eric', ?) "
                      "ON CONFLICT(name) DO UPDATE SET revoked_at=NULL, approved_by='eric', ts=excluded.ts", (n, now()))
            self._event(c, None, "scope", "eric", f"Scope '{n}' approved for Glow's ordinary-context approvals")
        self.export_memory()

    def revoke_scope(self, name: str, by: str) -> None:
        if by.lower() != "eric":
            raise MiniGlowError("Only Eric can revoke a scope.")
        with self._tx() as c:
            c.execute("UPDATE scopes SET revoked_at=? WHERE name=? AND revoked_at IS NULL", (now(), name.strip().lower()))
            self._event(c, None, "scope", "eric", f"Scope '{name}' revoked")
        self.export_memory()

    def revoke_policy(self, policy_id: int, by: str) -> None:
        if by.lower() != "eric":
            raise MiniGlowError("Only Eric can revoke access.")
        with self._tx() as c:
            r = c.execute("SELECT * FROM policy_allow WHERE id=?", (policy_id,)).fetchone()
            if not r or r["revoked_at"]:
                raise MiniGlowError(f"No active permission #{policy_id}.")
            c.execute("UPDATE policy_allow SET revoked_at=?, revoked_by='eric' WHERE id=?", (now(), policy_id))
            self._event(c, None, "policy", "eric", f"Permission #{policy_id} revoked ({r['category']} on {r['target']})")
        self.export_memory()

    def list_policy(self) -> list[dict]:
        with self._tx() as c:
            return [dict(r) for r in c.execute("SELECT * FROM policy_allow ORDER BY id")]

    def list_scopes(self) -> list[dict]:
        with self._tx() as c:
            return [dict(r) for r in c.execute("SELECT * FROM scopes ORDER BY name")]

    # ------------------------------------------------------------------ exports (generated from the database)
    def render_memory(self, name: str) -> str:
        if name not in MEMORY_FILES:
            raise MiniGlowError("No such memory file: " + name)
        head = "<!-- Generated from the database. Do not edit by hand; use proposals. -->\n"
        with self._tx() as c:
            if name in MEMORY_CATEGORIES:
                lines = [head, f"# {name.replace('_', ' ').title()}\n"]
                rows = c.execute("SELECT * FROM proposals WHERE kind='memory' AND category=? AND status='approved' ORDER BY id", (name,)).fetchall()
                for r in rows:
                    sup = f" SUPERSEDED by #{r['superseded_by']}." if r["superseded_by"] else ""
                    scope = f", scope {r['scope']}" if r["scope"] else ""
                    task = f", task {r['task_id']}" if r["task_id"] else ""
                    prior = f" Replaces #{r['supersedes']}." if r["supersedes"] else ""
                    lines.append(f"- #{r['id']} [{r['decided_at'][:10]}, approved by {r['decided_by']}{scope}{task}, source: {r['source']}] {r['content']}{prior}{sup}")
                if not rows:
                    lines.append("(no approved entries)")
            elif name == "permissions":
                lines = [head, "# Permissions (Eric's allowed targets)\n",
                         "Default is deny. Unavailable in the pilot even with approval: " + ", ".join(sorted(policy.UNAVAILABLE)) + ".\n"]
                rows = c.execute("SELECT * FROM policy_allow ORDER BY id").fetchall()
                for r in rows:
                    state = f"REVOKED {r['revoked_at'][:10]}" if r["revoked_at"] else "active"
                    lines.append(f"- #{r['id']} {r['category']} on {r['target']} ({state}; approved by {r['approved_by']} {r['ts'][:10]}; source: {r['source']})")
                if not rows:
                    lines.append("(no targets allowed yet)")
                lines += ["", "## Approved scopes for Glow's ordinary-context approvals"]
                srows = c.execute("SELECT * FROM scopes ORDER BY name").fetchall()
                for r in srows:
                    lines.append(f"- {r['name']} ({'revoked' if r['revoked_at'] else 'active'}, approved by {r['approved_by']} {r['ts'][:10]})")
                if not srows:
                    lines.append("(none)")
            else:
                lines = [head, "# Upgrade history\n", f"- {APP_VERSION}: single-transaction audit, action policy, reviewed memory tiers (MG-001 pilot).\n",
                         "## Reviewed changes"]
                rows = c.execute("SELECT * FROM proposals WHERE status!='pending' ORDER BY id").fetchall()
                for r in rows:
                    lines.append(f"- {r['decided_at'][:10]} #{r['id']} {r['kind']}/{r['category']} {r['status']} by {r['decided_by']} (proposed by {r['proposed_by']}; source: {r['source']})")
        return "\n".join(lines) + "\n"

    def export_memory(self) -> None:
        mem = self.home / "memory"
        mem.mkdir(parents=True, exist_ok=True)
        for name in MEMORY_FILES:
            (mem / f"{name}.md").write_text(self.render_memory(name), encoding="utf-8")

    def read_memory(self, name: str) -> str:
        return self.render_memory(name)

    def export_events_jsonl(self, out: str | Path | None = None) -> Path:
        dest = Path(out) if out else self.home / "exports" / "events.jsonl"
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            for e in self.events():
                f.write(json.dumps({"id": e["id"], "ts": e["ts"], "task": e["task_id"], "kind": e["kind"],
                                    "actor": e["actor"], "detail": e["detail"]}) + "\n")
        os.replace(tmp, dest)
        return dest

    # ------------------------------------------------------------------ recovery and verification
    def recovery_report(self) -> dict:
        """Describe unfinished work after a restart. Changes no task state."""
        self._require_init()
        with self._tx() as c:
            def rows(sql, *a):
                return [dict(r) for r in c.execute(sql, a)]
            rep = {
                "unfinished": rows("SELECT * FROM tasks WHERE status IN ('in_progress','blocked','awaiting_review') ORDER BY seq"),
                "needs_clarification": rows("SELECT * FROM tasks WHERE status='needs_clarification' ORDER BY seq"),
                "queued": rows("SELECT * FROM tasks WHERE status='queued' ORDER BY priority, seq"),
                "pending_proposals": rows("SELECT * FROM proposals WHERE status='pending' ORDER BY id"),
            }
            self._event(c, None, "recovery_check", "mini-glow",
                        f"{len(rep['unfinished'])} unfinished, {len(rep['needs_clarification'])} awaiting clarification, "
                        f"{len(rep['queued'])} queued, {len(rep['pending_proposals'])} pending proposals")
        return rep

    def verify(self) -> list[str]:
        self._require_init()
        problems = []
        with self._tx() as c:
            res = c.execute("PRAGMA integrity_check").fetchone()[0]
            if res != "ok":
                problems.append(f"SQLite integrity_check: {res}")
            triggers = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
            for t in ("events_no_update", "events_no_delete"):
                if t not in triggers:
                    problems.append(f"Audit protection missing: trigger {t}")
            for r in c.execute("SELECT id, status FROM tasks"):
                if r["status"] not in TRANSITIONS:
                    problems.append(f"{r['id']} has unknown status '{r['status']}'")
            seq = int(c.execute("SELECT value FROM meta WHERE key='task_seq'").fetchone()[0])
            top = c.execute("SELECT COALESCE(MAX(seq),0) FROM tasks").fetchone()[0]
            if top > seq:
                problems.append("Task counter is behind the highest task number")
            ev = [dict(r) for r in c.execute("SELECT * FROM evidence WHERE rel_path IS NOT NULL")]
            for t in c.execute("SELECT id FROM tasks WHERE status='queued' AND flagged=1 AND flag_decision='declined'"):
                problems.append(f"{t['id']} is queued although Eric declined it")
        for e in ev:
            p = self.home / e["rel_path"]
            if not p.exists():
                problems.append(f"Evidence file missing: {e['rel_path']}")
            elif sha256_file(p) != e["sha256"]:
                problems.append(f"Evidence file changed since it was recorded: {e['rel_path']}")
        for name in MEMORY_FILES:
            p = self.home / "memory" / f"{name}.md"
            if not p.exists() or p.read_text(encoding="utf-8") != self.render_memory(name):
                problems.append(f"memory/{name}.md is missing or out of date. Run: export-memory")
        return problems
