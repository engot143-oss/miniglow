"""Command line: plan or run one catalog task. Every run needs Eric's typed YES."""
import argparse
import hashlib
import os
import platform
import sys

from . import VERSION
from .context import HEAD_RE, Context, Refused, is_admin
from .evidence import Evidence, utc
from .tasks import CATALOG, preflight_checks, preflight_steps


def own_hashes(ctx):
    out = []
    for name in sorted(os.listdir(ctx.package)):
        if name.endswith(".py"):
            with open(os.path.join(ctx.package, name), "rb") as handle:
                out.append("%s=%s" % (name, hashlib.sha256(handle.read()).hexdigest()[:16]))
    return " ".join(out)


def parser():
    p = argparse.ArgumentParser(prog="mini_ray", description="Mini Ray v" + VERSION + ": fixed tasks only")
    sub = p.add_subparsers(dest="action", required=True)
    for action in ("plan", "run"):
        s = sub.add_parser(action)
        s.add_argument("task", choices=sorted(CATALOG))
        s.add_argument("--packet", help="bridge_inventory: R2G-nnn_NAME.txt in Ray-to-Glow")
        s.add_argument("--expect-sha256", help="bridge_inventory: expected SHA-256 of the packet")
        s.add_argument("--db", help="db_report: NAME.sqlite in the MiniGlow folder")
        if action == "run":
            s.add_argument("--expect-head", required=True, help="the approved commit (40 hex characters)")
    return p


def main(argv=None, ctx=None, confirm=input, admin=is_admin, out=print):
    args = parser().parse_args(argv)
    task_cls = CATALOG[args.task]
    given = {"packet": args.packet, "expect_sha256": args.expect_sha256, "db": args.db}
    extra = [k for k, v in given.items() if v is not None and k not in task_cls.params]
    try:
        if extra:
            raise Refused("parameter not allowed for %s: %s" % (args.task, ", ".join(extra)))
        if admin():
            raise Refused("Mini Ray does not run as Administrator")
        ctx = ctx or Context()
        task = task_cls(ctx, {k: given[k] for k in task_cls.params})
        steps = preflight_steps(ctx) + task.steps()
        if args.action == "run" and not HEAD_RE.match(args.expect_head or ""):
            raise Refused("--expect-head must be a full 40-character commit ID")
    except Refused as err:
        out("REFUSED: %s" % err)
        return 2
    out("Mini Ray v%s - task %s - plan:" % (VERSION, args.task))
    for i, step in enumerate(steps, 1):
        out("  %d. %s" % (i, step.describe()))
    for note in task.notes:
        out("  Note: " + note)
    if args.action == "plan":
        out("PLAN ONLY: nothing was run.")
        return 0
    stops = ctx.stop_present()
    if stops:
        out("REFUSED: STOP present: " + ", ".join(stops))
        return 2
    if confirm is input and not sys.stdin.isatty():
        out("REFUSED: YES must be typed at the keyboard")
        return 2
    try:
        answer = confirm("Type YES to run this task: ")
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer.strip() != "YES":
        out("Not confirmed; nothing was run.")
        return 2
    ev = Evidence(ctx, args.task, {k: v for k, v in given.items() if v is not None})
    for key, value in (("mini_ray_version", VERSION), ("confirmed_at", utc()), ("expect_head", args.expect_head),
                       ("python", platform.python_version() + " " + ctx.python), ("git", ctx.git),
                       ("mini_ray_files", own_hashes(ctx))):
        ev.note(key, value)
    verdict = execute(ctx, task, steps, ev, args.expect_head)
    try:
        path = ev.finish(verdict)
    except (Refused, OSError) as err:
        out("VERDICT: %s (but the evidence file or the audit line could not be written)" % verdict)
        out("REFUSED: evidence could not be written: %s" % err)
        return 2
    out("VERDICT: %s" % verdict)
    out("EVIDENCE: %s" % path)
    return 0 if verdict == "PASS" else 1


def execute(ctx, task, steps, ev, expect_head):
    """Run the steps in order; stop at the first problem. Always returns a verdict."""
    n_pre = len(preflight_steps(ctx))
    results = []
    try:
        for i, step in enumerate(steps):
            if ctx.stop_present():
                ev.check("no STOP before step %d" % (i + 1), False, ", ".join(ctx.stop_present()))
                return "ABORTED"
            result = step.run(ctx)
            ev.add_step(result)
            results.append(result)
            if result["kind"] == "command" and result["stopped"]:
                ev.check(step.label + " not stopped", False, "STOP appeared while it ran; it was ended")
                return "ABORTED"
            if result["kind"] == "command" and (result["timed_out"] or result["exit"] is None):
                ev.check(step.label + " finished in time", False, "timeout %d s" % step.timeout)
                return "FAIL"
            if i == n_pre - 1 and not preflight_checks(ev, results, expect_head, ctx.repo):
                return "FAIL"
        return task.verdict(ev, results[n_pre:])
    except Refused as err:
        ev.check("deny model", False, str(err))
        return "FAIL"
    except KeyboardInterrupt:
        ev.check("not interrupted", False, "Ctrl+C")
        return "ABORTED"
    except Exception as err:  # unexpected: fail closed, keep evidence
        ev.check("no unexpected error", False, err.__class__.__name__)
        return "FAIL"
