"""The fixed task catalog. Adding a task means a reviewed, tested, committed code change."""
import hashlib
import os
import pathlib
import re
import sqlite3
from datetime import datetime, timezone

from .context import BRANCH, Refused
from .runner import Command, Inspect

WARN_RE = re.compile(r"ResourceWarning:|Exception ignored")
SUMMARY_RE = re.compile(r"^run=\d+ end_reason=(\w+) checks_done=(\d+) new_count=(\d+) "
                        r"suspect_listings=(\d+) health=(\w+)$", re.M)
SHA_RE = re.compile(r"^[0-9a-f]{64}\Z")
MAX_READ = 5 * 1024 * 1024


# Command-line settings outrank the repository's own config: no fsmonitor hook, no untracked cache,
# no user-level ignore file. The repository config itself is checked first (git_config_facts).
GIT_SAFE = ["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.excludesFile="]
GIT_SECTIONS = {"core", "remote", "branch", "user"}
GIT_CORE_KEYS = {"repositoryformatversion", "filemode", "bare", "logallrefupdates", "symlinks", "ignorecase",
                 "autocrlf", "safecrlf", "eol", "longpaths", "precomposeunicode", "quotepath"}
SECTION_RE = re.compile(r'^\[\s*([A-Za-z0-9.-]+)(\s+"[^"]*")?\s*\]\s*([#;].*)?$')
KEY_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)\s*(=.*)?$")


def git(ctx, label, *args):
    return Command(label, [ctx.git] + GIT_SAFE + ["-c", "safe.directory=" + ctx.repo, "-C", ctx.repo] + list(args),
                   ctx.repo, 30)


def git_config_facts(ctx):
    """Read .git/config in Python before any git command. Anything that can make git run other code
    (fsmonitor, filters, hooksPath, includes, aliases, pagers, ...) is refused: only a short list of
    sections and core keys is allowed."""
    gitdir = os.path.join(ctx.repo, ".git")
    if os.path.islink(gitdir) or not os.path.isdir(gitdir):
        raise Refused("the repository's .git must be a plain folder")
    for name in ("config.worktree", "commondir"):
        if os.path.exists(os.path.join(gitdir, name)):
            raise Refused("git setup not allowed: .git/" + name)
    with open(os.path.join(gitdir, "config"), "rb") as handle:
        data = handle.read(MAX_READ)
    problems, section, entries = [], None, 0
    for raw in data.decode("utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        m = SECTION_RE.match(line)
        if m:
            section = m.group(1).lower().split(".")[0]
            if section not in GIT_SECTIONS:
                problems.append("section [%s]" % m.group(1))
            continue
        k = KEY_RE.match(line)
        if not k or section is None or line.endswith("\\"):
            problems.append("unreadable line")
            continue
        entries += 1
        if section == "core" and k.group(1).lower() not in GIT_CORE_KEYS:
            problems.append("core." + k.group(1))
    if problems:
        raise Refused("repository git config not allowed: " + ", ".join(sorted(set(problems))))
    return {"git_config": "allowed (%d entries)" % entries}


# ---------------------------------------------------------------- preflight (every task)

def preflight_steps(ctx):
    return [Inspect("git config", git_config_facts, "repository .git/config holds only allowed settings"),
            git(ctx, "head", "rev-parse", "HEAD"),
            git(ctx, "status", "status", "--porcelain=v1", "--untracked-files=all", "--ignored=traditional"),
            git(ctx, "branch", "branch", "--show-current"),
            git(ctx, "index flags", "ls-files", "-v"),
            git(ctx, "tracked files", "ls-tree", "-r", "--full-tree", "HEAD", "--", code_folder(ctx))]


def code_folder(ctx):
    rel = os.path.relpath(ctx.mini_glow, ctx.repo).replace(os.sep, "/")
    return "." if rel == "." else rel


def blob_sha1(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def tree_mismatches(repo, ls_tree_out):
    """Compare every committed file under the code folder, byte by byte (as Git blob hashes), with the
    file on disk. Git's own status trusts file times; this does not. CRLF checkouts are accepted."""
    problems, count = [], 0
    for line in ls_tree_out.splitlines():
        m = re.match(r"^(\d{6}) (\w+) ([0-9a-f]{40})\t(.+)$", line)
        if not m:
            problems.append("unreadable ls-tree line")
            continue
        mode, kind, sha, rel = m.groups()
        if kind != "blob" or mode not in ("100644", "100755"):
            problems.append("%s %s" % (mode, rel))
            continue
        path = os.path.join(repo, *rel.split("/"))
        count += 1
        try:
            if os.path.islink(path):
                raise OSError("link")
            with open(path, "rb") as handle:
                data = handle.read(MAX_READ + 1)
        except OSError:
            problems.append("missing " + rel)
            continue
        if blob_sha1(data) != sha and blob_sha1(data.replace(b"\r\n", b"\n")) != sha:
            problems.append("changed " + rel)
    if count == 0:
        problems.append("no files listed")
    return count, problems


def dirty_lines(status_out):
    """Every status line counts, including ignored files; only Python's own __pycache__ folders are allowed
    (children never read them: PYTHONPYCACHEPREFIX points elsewhere)."""
    return [line for line in status_out.splitlines()
            if line.strip() and not re.match(r"^!! (.*/)?__pycache__/([^/]+\.pyc)?$", line)]


def preflight_checks(ev, results, expect_head, repo):
    config, head, status, branch, flags, tree = results
    commands = [head, status, branch, flags, tree]
    ok = ev.check("command steps exited 0", all(r["exit"] == 0 for r in commands))
    ok &= ev.check("command output complete", not any(r["stdout_truncated"] for r in commands))
    ok &= ev.check("HEAD is the approved commit", head["stdout"].strip() == expect_head, head["stdout"].strip())
    dirty = dirty_lines(status["stdout"])
    ok &= ev.check("working tree clean (untracked and ignored files included)", not dirty, "; ".join(dirty)[:300])
    hidden = [line for line in flags["stdout"].splitlines() if line and not line.startswith("H ")]
    ok &= ev.check("no assume-unchanged or skip-worktree files", not hidden, "; ".join(hidden)[:300])
    ok &= ev.check("branch is " + BRANCH, branch["stdout"].strip() == BRANCH, branch["stdout"].strip())
    count, problems = tree_mismatches(repo, tree["stdout"])
    ok &= ev.check("every committed code file matches HEAD byte for byte", not problems,
                   ("%d files; " % count) + "; ".join(problems)[:300])
    return ok


# ---------------------------------------------------------------- read-only helpers

def db_facts(path):
    uri = pathlib.Path(path).resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        states = dict(conn.execute("SELECT state, COUNT(*) FROM packets GROUP BY state").fetchall())
        runs = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        last = conn.execute("SELECT run_id, started_at, ended_at, checks_done, new_count, end_reason, "
                            "suspect_listings, health FROM runs ORDER BY run_id DESC LIMIT 1").fetchone()
        others = conn.execute("SELECT packet_id, state, check_number FROM packets WHERE state != 'BACKLOG' "
                              "ORDER BY packet_id LIMIT 50").fetchall()
    finally:
        conn.close()
    return {"db": os.path.basename(path), "runs": runs, "last_run": last,
            "BACKLOG": states.get("BACKLOG", 0), "NEW_LOGGED": states.get("NEW_LOGGED", 0),
            "NEEDS_ERIC": states.get("NEEDS_ERIC", 0), "not_backlog": others}


def db_checks(ev, facts):
    last = facts["last_run"]
    ok = ev.check("database has a run", bool(last))
    if not last:
        return False
    ok &= ev.check("last run ended", bool(last[2]), str(last[5]))
    ok &= ev.check("health OK", last[7] == "OK", str(last[7]))
    ok &= ev.check("no suspect listings", last[6] == 0, str(last[6]))
    ok &= ev.check("no NEEDS_ERIC rows", facts["NEEDS_ERIC"] == 0, str(facts["NEEDS_ERIC"]))
    return ok


# ---------------------------------------------------------------- tasks

class Task:
    params = ()  # names of the allowed parameters
    notes = ()  # shown with the plan

    def __init__(self, ctx, values):
        self.ctx, self.values = ctx, values

    def steps(self):
        raise NotImplementedError

    def verdict(self, ev, results):
        raise NotImplementedError


class RepoStatus(Task):
    """T1: repository state (the preflight already does all of it)."""
    name = "repo_status"

    def steps(self):
        return []

    def verdict(self, ev, results):
        return "PASS"


class RunTests(Task):
    """T2: both strict test suites."""
    name = "run_tests"
    # Known platform skips: bridge_poller has 1 test for the other OS; mini_ray has 2 POSIX-only tests
    # that Windows skips. More is a FAIL.
    MAX_SKIPS = {"bridge_poller tests": 1, "mini_ray tests": 2}
    notes = ("The test suites create and delete their own temporary folders (and small Git repositories) "
             "under TEMP. That is the one accepted write outside MiniGlow; nothing in the repository or "
             "the Bridge is written.",)

    def steps(self):
        py = [self.ctx.python, "-X", "dev", "-W", "error::ResourceWarning", "-m", "unittest", "discover"]
        mg = self.ctx.mini_glow
        return [Command("bridge_poller tests", py + ["-s", "bridge_poller/tests", "-t", "."], mg, 300),
                Command("mini_ray tests", py + ["-s", "mini_ray/tests", "-t", "."], mg, 300)]

    def verdict(self, ev, results):
        ok = True
        for r in results:
            text = r["stdout"] + "\n" + r["stderr"]
            ran = re.search(r"^Ran (\d+) tests?", text, re.M)
            final = re.search(r"^OK(?: \((.*)\))?$", text, re.M)
            skipped = int((re.search(r"skipped=(\d+)", final.group(1) or "") or [0, 0])[1]) if final else 0
            ok &= ev.check(r["label"] + " exit 0", r["exit"] == 0, str(r["exit"]))
            ok &= ev.check(r["label"] + " OK", final is not None and ran is not None and int(ran.group(1)) > 0,
                           ran.group(0) if ran else "no Ran line")
            ok &= ev.check(r["label"] + " skipped at most %d" % self.MAX_SKIPS.get(r["label"], 0),
                           skipped <= self.MAX_SKIPS.get(r["label"], 0), "skipped=%d" % skipped)
            ok &= ev.check(r["label"] + " no real warnings", not WARN_RE.search(text))
        return "PASS" if ok else "FAIL"


class BridgeInventory(Task):
    """T3: look at the synced Bridge; hash one named Ray packet. Reads only."""
    name = "bridge_inventory"
    params = ("packet", "expect_sha256")

    def steps(self):
        packet = self.ctx.packet_path(self.values.get("packet"))
        expect = self.values.get("expect_sha256")
        if expect is not None and not SHA_RE.match(expect):
            raise Refused("expect_sha256 must be 64 lowercase hex characters")
        return [Inspect("inventory", lambda ctx: self.look(ctx, packet),
                        "folders exist, R2G count, other names, STOP files, SHA-256 of " + os.path.basename(packet))]

    @staticmethod
    def look(ctx, packet):
        facts = {"root_exists": os.path.isdir(ctx.bridge_root), "r2g_exists": os.path.isdir(ctx.r2g),
                 "g2r_exists": os.path.isdir(ctx.g2r)}
        names = sorted(e.name for e in os.scandir(ctx.r2g) if e.is_file()) if facts["r2g_exists"] else []
        facts["r2g_count"] = sum(1 for n in names if re.match(r"^R2G-\d{3}_", n))
        facts["other_names"] = [n for n in names if not re.match(r"^R2G-\d{3}_", n)]
        root_files = [e.name for e in os.scandir(ctx.bridge_root) if e.is_file()] if facts["root_exists"] else []
        facts["stop_names"] = sorted(n for n in root_files if n.upper().startswith("STOP"))
        facts["packet"] = os.path.basename(packet)
        facts["packet_exists"] = os.path.isfile(packet)
        if facts["packet_exists"]:
            with open(packet, "rb") as handle:
                data = handle.read(MAX_READ + 1)
            facts["packet_size"] = len(data)
            facts["packet_sha256"] = hashlib.sha256(data).hexdigest()
        return facts

    def verdict(self, ev, results):
        f = results[0]["facts"]
        ok = ev.check("Bridge folders exist", f["root_exists"] and f["r2g_exists"] and f["g2r_exists"])
        ok &= ev.check("no STOP file", not f["stop_names"], ", ".join(f["stop_names"]))
        ok &= ev.check("packet exists", f["packet_exists"], f["packet"])
        expect = self.values.get("expect_sha256")
        if expect and f["packet_exists"]:
            ok &= ev.check("packet SHA-256 matches", f["packet_sha256"] == expect)
        return "PASS" if ok else "FAIL"


class PollerBoundedRun(Task):
    """T4: one bounded read-only poller run on the real Bridge, fresh database, then a read-only report."""
    name = "poller_bounded_run"

    def steps(self):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.db = self.ctx.db_path("t4_" + stamp + ".sqlite", must_exist=False)
        cmd = [self.ctx.python, "-m", "bridge_poller.poller", "--live", "--folder-path", self.ctx.r2g,
               "--root-path", self.ctx.bridge_root, "--db", self.db, "--max-checks", "10", "--interval", "60"]
        # The poller watches the Bridge STOP itself; it gets 75 s (> one 60 s interval) to end on its own.
        return [Command("bounded poller run", cmd, self.ctx.mini_glow, 15 * 60, stop_grace=75),
                Inspect("database report", lambda ctx: db_facts(self.db), "read-only report of " + self.db)]

    def verdict(self, ev, results):
        run, report = results
        m = SUMMARY_RE.search(run["stdout"])
        ok = ev.check("poller exit 0", run["exit"] == 0, str(run["exit"]))
        ok &= ev.check("summary line present", m is not None)
        if m:
            ev.check("new_count recorded", True, m.group(3))
            if m.group(1) == "STOP":
                ev.check("ended by STOP", False, "STOP file was present")
                return "NEEDS_ERIC"
            ok &= ev.check("WINDOW_DONE with 10 checks", m.group(1) == "WINDOW_DONE" and m.group(2) == "10",
                           "%s %s" % (m.group(1), m.group(2)))
        ok &= db_checks(ev, report["facts"])
        return "PASS" if ok else "FAIL"


class DbReport(Task):
    """T5: read-only report of one database in the MiniGlow folder."""
    name = "db_report"
    params = ("db",)

    def steps(self):
        path = self.ctx.db_path(self.values.get("db"), must_exist=True)
        return [Inspect("database report", lambda ctx: db_facts(path), "read-only report of " + path)]

    def verdict(self, ev, results):
        return "PASS" if db_checks(ev, results[0]["facts"]) else "FAIL"


CATALOG = {cls.name: cls for cls in (RepoStatus, RunTests, BridgeInventory, PollerBoundedRun, DbReport)}
