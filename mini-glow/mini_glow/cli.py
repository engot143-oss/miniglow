"""Command-line interface. Run with:  python -m mini_glow <command> ...

Data folder: --home PATH, or the MINI_GLOW_HOME environment variable,
or ./mini_glow_data in the current folder.

Exit codes: 0 ok | 2 error | 3 guardrail block | 4 authorize DENY | 5 authorize PAUSE
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, backup, packets, policy
from .guardrails import GuardrailViolation
from .store import MEMORY_CATEGORIES, MEMORY_FILES, MiniGlowError, Store


def _read_text_arg(file: str | None) -> str:
    if file and file != "-":
        return Path(file).read_text(encoding="utf-8")
    if sys.stdin.isatty():
        print("Paste the packet, then finish with Ctrl+Z then Enter (Windows) or Ctrl+D (Mac/Linux):")
    return sys.stdin.read()


def _row(t: dict) -> str:
    note = ""
    if t["flagged"] and not t["flag_decision"]:
        note = " [flagged: needs Eric's decision]"
    elif t["flag_decision"] == "declined":
        note = " [declined by Eric]"
    return f"{t['id']}  p{t['priority']}  {t['status']:<19} {t['title']}{note}"


def cmd_init(s, a):
    print(("Created" if s.init() else "Already set up:") + f" {s.home}")


def cmd_add(s, a):
    tid = s.add_task(packets.parse_packet(_read_text_arg(a.file)), actor="eric")
    t = s.get_task(tid)
    print(f"Received {tid}: {t['title']}  ->  {t['status']}")
    if t["status"] == "needs_clarification":
        print("  Paused. " + [e for e in s.events(tid) if e["kind"] == "pause"][-1]["detail"])
        print(f"  Glow or Eric can fix it with: clarify {tid} --by glow --actions \"read_file: <path>\"")
    if t["flagged"]:
        print(f"  Flagged (wording about buying/sending). Eric must record: decide {tid} --by eric --decision approve|decline")


def cmd_list(s, a):
    tasks = s.list_tasks(a.status)
    print("\n".join(_row(t) for t in tasks) if tasks else "(no tasks)")


def cmd_show(s, a):
    t = s.get_task(a.task)
    print(_row(t))
    for label, key in [("Glow ref", "glow_ref"), ("Goal", "goal"), ("Your job", "your_job"), ("Context", "context"),
                       ("Input", "input"), ("Rules", "rules"), ("Output format", "output_format"),
                       ("Done when", "done_when"), ("Summary", "result_summary")]:
        if t.get(key):
            print(f"\n{label}:\n{t[key]}")
    print("\nDeclared actions:")
    for x in s.task_actions(t["id"]) or []:
        print(f"  {x['category']}: {x['target'] or '(none)'}")
    print("\nHistory:")
    for e in s.events(t["id"]):
        print(f"  {e['ts'][:19]}  {e['actor']:<10} {e['kind']:<14} {e['detail']}")


def cmd_decide(s, a):
    s.decide_flag(a.task, a.by, a.decision)
    print(f"Eric's decision recorded: {a.decision}. (This enables no action. Buy/send stay unavailable.)")


def cmd_clarify(s, a):
    t = s.clarify(a.task, a.by, a.actions.replace(";", "\n") if a.actions else None)
    print(f"{t['id']} is now {t['status']}")
    if t["status"] == "needs_clarification":
        print("  " + [e for e in s.events(t["id"]) if e["kind"] == "pause"][-1]["detail"])


def cmd_start(s, a):
    t = s.start(a.task)
    print(f"Started {t['id']}: {t['title']}\n\nYOUR JOB:\n{t['your_job']}")


def cmd_authorize(s, a):
    decision, reason = s.authorize(a.task, a.category, a.target)
    print(f"{decision.upper()}: {reason}")
    return {"allow": 0, "deny": 4, "pause": 5}[decision]


def cmd_note(s, a):
    s.add_note(a.task, a.text, kind="assumption" if a.assumption else "note")
    print("Recorded.")


def cmd_evidence(s, a):
    print("Recorded: " + s.add_evidence(a.task, text=a.text, file=a.file))


def _save_packet(s, name, text):
    p = s.home / "handoffs" / "outbox" / name
    p.write_text(text, encoding="utf-8")
    return p


def _return_packet(s, t):
    return packets.render_return_packet(t, s.events(t["id"]), s.evidence(t["id"]), s.task_actions(t["id"]))


def cmd_block(s, a):
    t = s.block(a.task, a.question, a.tried or "")
    text = packets.render_help_request(t, a.question, a.tried or "", s.events(t["id"]))
    p = _save_packet(s, f"{t['id']}-help-request.md", text)
    print(text + f"--- saved to {p}\n--- Copy the packet above to Glow.")


def cmd_resume(s, a):
    print(f"Resumed {s.resume(a.task, a.guidance)['id']} with guidance recorded.")


def cmd_submit(s, a):
    t = s.submit(a.task, a.summary)
    text = _return_packet(s, t)
    p = _save_packet(s, f"{t['id']}-return.md", text)
    print(text + f"--- saved to {p}\n--- Copy the packet above to Glow for review.")


def cmd_packet(s, a):
    print(_return_packet(s, s.get_task(a.task)))


def cmd_accept(s, a):
    s.accept(a.task, a.by, a.comment or ""); print(f"{a.task.upper()} accepted by {a.by}.")


def cmd_rework(s, a):
    s.rework(a.task, a.by, a.comment); print(f"{a.task.upper()} sent back for rework.")


def cmd_fail(s, a):
    s.fail(a.task, a.reason); print(f"{a.task.upper()} marked failed.")


def cmd_cancel(s, a):
    s.cancel(a.task, a.by, a.reason or ""); print(f"{a.task.upper()} cancelled.")


def cmd_retry(s, a):
    s.retry(a.task, a.by); print(f"{a.task.upper()} back in the queue.")


def cmd_log(s, a):
    evs = s.events(a.task)
    for e in (evs[-a.last:] if a.last else evs):
        print(f"{e['ts'][:19]}  {e['task_id'] or '-':<9} {e['actor']:<10} {e['kind']:<14} {e['detail']}")


def cmd_export_log(s, a):
    print("Wrote " + str(s.export_events_jsonl(a.out)))


def cmd_export_memory(s, a):
    s.export_memory(); print("Memory files regenerated from the database.")


def cmd_recover(s, a):
    r = s.recovery_report()
    for title, key in [("Unfinished work (state unchanged)", "unfinished"), ("Waiting for clarification", "needs_clarification"), ("Queued", "queued")]:
        print(title + ":")
        for t in r[key]:
            print("  " + _row(t))
        if not r[key]:
            print("  (none)")
    print(f"Pending proposals: {len(r['pending_proposals'])}")


def cmd_verify(s, a):
    problems = s.verify()
    if problems:
        print("PROBLEMS FOUND:")
        for p in problems:
            print("  - " + p)
        return 1
    print("OK: integrity, audit protection, evidence hashes and memory exports are consistent.")


def cmd_backup(s, a):
    print(("Archive written: " + str(backup.archive(s, a.out))) if a.zip else ("Snapshot written: " + str(backup.snapshot(s))))


def cmd_snapshots(s, a):
    for p in backup.list_snapshots(s):
        print(p)


def cmd_restore(s, a):
    print(f"Restored. Previous state saved as {backup.restore(s, Path(a.snapshot)).name}")


def cmd_memory(s, a):
    if a.action == "show":
        print(s.read_memory(a.name))
    elif a.action == "propose":
        pid = s.propose_memory(a.category, a.text, a.source, scope=a.scope, task_id=a.task, supersedes=a.supersedes)
        print(f"Candidate #{pid} recorded. It is not memory until reviewed.")


def cmd_policy(s, a):
    if a.action == "propose":
        print(f"Permission candidate #{s.propose_permission(a.category, a.target, a.source)} recorded. Eric must approve it.")
    elif a.action == "list":
        for r in s.list_policy():
            print(f"#{r['id']} {r['category']} on {r['target']} ({'revoked' if r['revoked_at'] else 'active'})")
        if not s.list_policy():
            print("(no targets allowed; default is deny)")
    elif a.action == "revoke":
        s.revoke_policy(a.id, a.by); print(f"Permission #{a.id} revoked.")
    elif a.action == "categories":
        for k, v in policy.AVAILABLE.items():
            print(f"available    {k:<16} {v}")
        for k, v in policy.UNAVAILABLE.items():
            print(f"UNAVAILABLE  {k:<16} {v}")


def cmd_scope(s, a):
    if a.action == "allow":
        s.allow_scope(a.name, a.by); print(f"Scope '{a.name}' approved by Eric.")
    elif a.action == "revoke":
        s.revoke_scope(a.name, a.by); print(f"Scope '{a.name}' revoked.")
    else:
        for r in s.list_scopes():
            print(f"{r['name']} ({'revoked' if r['revoked_at'] else 'active'})")


def cmd_proposals(s, a):
    for p in s.list_proposals("pending"):
        extra = f" target={p['target']}" if p["target"] else (f" scope={p['scope']}" if p["scope"] else "")
        print(f"#{p['id']} {p['kind']}/{p['category']}{extra} by {p['proposed_by']}: {p['content']}  [source: {p['source']}]")
    if not s.list_proposals("pending"):
        print("(no pending candidates)")


def cmd_proposal(s, a):
    s.decide_proposal(a.id, a.action == "approve", a.by, a.reason or "")
    print(f"Candidate #{a.id} {a.action}d by {a.by}.")


def build_parser():
    p = argparse.ArgumentParser(prog="mini_glow", description="Mini Glow MG-001 pilot: task queue and manual handoff.")
    p.add_argument("--home", help="data folder (default: $MINI_GLOW_HOME or ./mini_glow_data)")
    p.add_argument("--version", action="version", version=f"mini_glow {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_); sp.set_defaults(fn=fn); return sp

    add("init", cmd_init, "create the data folder and database")
    sp = add("add", cmd_add, "receive a task from a Glow handoff packet"); sp.add_argument("file", nargs="?")
    sp = add("list", cmd_list, "list tasks"); sp.add_argument("--status")
    sp = add("show", cmd_show, "show a task, its actions and history"); sp.add_argument("task")
    sp = add("decide", cmd_decide, "Eric records a decision on a flagged task (enables nothing)")
    sp.add_argument("task"); sp.add_argument("--by", required=True); sp.add_argument("--decision", required=True, choices=["approve", "decline"])
    sp = add("clarify", cmd_clarify, "Glow/Eric supplies ACTIONS or re-checks a paused task")
    sp.add_argument("task"); sp.add_argument("--by", required=True); sp.add_argument("--actions", help='e.g. "read_file: C:/x; write_file: C:/y" (use ; or newlines)')
    sp = add("start", cmd_start, "start a task (next startable if none given)"); sp.add_argument("task", nargs="?")
    sp = add("authorize", cmd_authorize, "gate one action: prints ALLOW/DENY/PAUSE (nothing is executed)")
    sp.add_argument("task"); sp.add_argument("category"); sp.add_argument("target")
    sp = add("note", cmd_note, "record progress"); sp.add_argument("task"); sp.add_argument("text"); sp.add_argument("--assumption", action="store_true")
    sp = add("evidence", cmd_evidence, "attach evidence text and/or a file"); sp.add_argument("task"); sp.add_argument("--text"); sp.add_argument("--file")
    sp = add("block", cmd_block, "ask Glow for help; prints a help-request packet"); sp.add_argument("task"); sp.add_argument("question"); sp.add_argument("--tried")
    sp = add("resume", cmd_resume, "resume a blocked task with guidance"); sp.add_argument("task"); sp.add_argument("guidance")
    sp = add("submit", cmd_submit, "submit for review; prints a return packet"); sp.add_argument("task"); sp.add_argument("summary")
    sp = add("packet", cmd_packet, "re-print the return packet"); sp.add_argument("task")
    sp = add("accept", cmd_accept, "record acceptance"); sp.add_argument("task"); sp.add_argument("--by", required=True); sp.add_argument("--comment")
    sp = add("rework", cmd_rework, "send back for rework"); sp.add_argument("task"); sp.add_argument("--by", required=True); sp.add_argument("comment")
    sp = add("fail", cmd_fail, "mark failed"); sp.add_argument("task"); sp.add_argument("reason")
    sp = add("cancel", cmd_cancel, "cancel"); sp.add_argument("task"); sp.add_argument("--by", required=True); sp.add_argument("--reason")
    sp = add("retry", cmd_retry, "re-queue a failed task"); sp.add_argument("task"); sp.add_argument("--by", default="eric")
    sp = add("log", cmd_log, "show the audit log"); sp.add_argument("--task"); sp.add_argument("--last", type=int, default=0)
    sp = add("export-log", cmd_export_log, "export the audit log as JSONL"); sp.add_argument("--out")
    add("export-memory", cmd_export_memory, "regenerate memory/*.md from the database")
    add("recover", cmd_recover, "after a restart: list unfinished work (changes nothing)")
    add("verify", cmd_verify, "check integrity, audit protection, evidence hashes, memory exports")
    sp = add("backup", cmd_backup, "snapshot, or --zip for a full archive"); sp.add_argument("--zip", action="store_true"); sp.add_argument("--out")
    add("snapshots", cmd_snapshots, "list snapshots")
    sp = add("restore", cmd_restore, "restore from a snapshot"); sp.add_argument("snapshot")

    mem = sub.add_parser("memory", help="reviewed project memory (candidates until approved)"); mem.set_defaults(fn=cmd_memory)
    ms = mem.add_subparsers(dest="action", required=True)
    m = ms.add_parser("show"); m.add_argument("name", choices=list(MEMORY_FILES))
    m = ms.add_parser("propose"); m.add_argument("category", choices=MEMORY_CATEGORIES); m.add_argument("text")
    m.add_argument("--source", required=True); m.add_argument("--scope"); m.add_argument("--task"); m.add_argument("--supersedes", type=int)

    pol = sub.add_parser("policy", help="allowed targets per action category (Eric approves)"); pol.set_defaults(fn=cmd_policy)
    ps = pol.add_subparsers(dest="action", required=True)
    m = ps.add_parser("propose"); m.add_argument("category"); m.add_argument("target"); m.add_argument("--source", required=True)
    ps.add_parser("list"); ps.add_parser("categories")
    m = ps.add_parser("revoke"); m.add_argument("id", type=int); m.add_argument("--by", required=True)

    sc = sub.add_parser("scope", help="scopes in which Glow may approve ordinary context (Eric sets)"); sc.set_defaults(fn=cmd_scope)
    ss = sc.add_subparsers(dest="action", required=True)
    for act in ("allow", "revoke"):
        m = ss.add_parser(act); m.add_argument("name"); m.add_argument("--by", required=True)
    ss.add_parser("list")

    add("proposals", cmd_proposals, "list pending candidates (memory and permission)")
    pr = sub.add_parser("proposal", help="approve or reject a candidate"); pr.set_defaults(fn=cmd_proposal)
    pr.add_argument("action", choices=["approve", "reject"]); pr.add_argument("id", type=int); pr.add_argument("--by", required=True); pr.add_argument("--reason")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    store = Store(args.home)
    try:
        return args.fn(store, args) or 0
    except GuardrailViolation as e:
        print(f"GUARDRAIL: {e}", file=sys.stderr)
        return 3
    except (MiniGlowError, packets.PacketError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
