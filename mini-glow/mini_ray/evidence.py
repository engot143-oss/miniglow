"""Evidence file (one per run, plain ASCII, SHA-256 footer) and the append-only audit log."""
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ascii(text):
    return str(text).encode("ascii", errors="backslashreplace").decode("ascii")


class Evidence:
    def __init__(self, ctx, task, params):
        self.ctx, self.task, self.params = ctx, task, params
        self.started = utc()
        self.run_id = ("MR-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
                       + "-" + task)
        self.header, self.steps, self.checks = [], [], []
        self.verdict = None

    def note(self, key, value):
        self.header.append((key, value))

    def add_step(self, result):
        self.steps.append(result)

    def check(self, name, ok, detail=""):
        self.checks.append((name, bool(ok), detail))
        return bool(ok)

    def render(self):
        lines = ["MINI RAY EVIDENCE", "run_id: " + self.run_id, "task: " + self.task,
                 "params: " + json.dumps(self.params, sort_keys=True), "started: " + self.started,
                 "ended: " + self.ended]
        lines += ["%s: %s" % (k, v) for k, v in self.header]
        for i, s in enumerate(self.steps, 1):
            lines.append("--- step %d: %s (%s, %.1f s)" % (i, s["label"], s["kind"], s["seconds"]))
            if s["kind"] == "command":
                lines.append("argv: " + json.dumps(s["argv"]))
                lines.append("cwd: " + s["cwd"])
                lines.append("exit: %s  timed_out: %s  stopped: %s" % (s["exit"], s["timed_out"], s.get("stopped", False)))
                # child output lines start with "| " so they can never pose as evidence lines
                lines.append("stdout%s:" % (" (TRUNCATED)" if s["stdout_truncated"] else ""))
                lines += ["| " + x for x in s["stdout"].splitlines()] or ["(empty)"]
                lines.append("stderr%s:" % (" (TRUNCATED)" if s["stderr_truncated"] else ""))
                lines += ["| " + x for x in s["stderr"].splitlines()] or ["(empty)"]
            else:
                for k in sorted(s["facts"]):
                    lines.append("%s: %s" % (k, s["facts"][k]))
        lines.append("--- checks")
        for name, ok, detail in self.checks:
            lines.append("%s %s%s" % ("PASS" if ok else "FAIL", name, (" - " + detail) if detail else ""))
        lines.append("VERDICT: " + self.verdict)
        body = _ascii("\n".join(lines) + "\n")
        return body + "SHA256: " + hashlib.sha256(body.encode("ascii")).hexdigest() + "\n"

    def finish(self, verdict):
        """Write the evidence file and one audit line. Returns the evidence path."""
        self.verdict, self.ended = verdict, utc()
        text = self.render()
        os.makedirs(self.ctx.check_write(self.ctx.evidence_dir), exist_ok=True)
        path = self.ctx.check_write(os.path.join(self.ctx.evidence_dir, self.run_id + ".txt"))
        with open(path, "x", encoding="ascii", newline="\n") as handle:
            handle.write(text)
        line = {"run_id": self.run_id, "task": self.task, "started": self.started, "ended": self.ended,
                "verdict": verdict, "evidence": os.path.basename(path),
                "sha256": hashlib.sha256(text.encode("ascii")).hexdigest()}
        with open(self.ctx.check_append(self.ctx.audit_log), "a", encoding="ascii", newline="\n") as handle:
            handle.write(json.dumps(line, sort_keys=True) + "\n")
        return path
