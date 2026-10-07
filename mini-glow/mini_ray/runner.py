"""Runs one allowed program with an argument list: no shell, fixed folder, reduced environment, deadline,
STOP watch, whole-process-tree kill, capped output."""
import ctypes
import os
import signal
import subprocess
import time

from .context import Refused

OUTPUT_CAP = 64 * 1024
POLL_SECONDS = 1.0
UNREACHABLE_POLLS = 5  # a short Google Drive hiccup is not a STOP; 5 polls in a row is
ENV_KEEP = ("PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "TEMP", "TMP", "LOCALAPPDATA",
            "USERPROFILE", "HOME", "HOMEDRIVE", "HOMEPATH")


def reduced_env(ctx=None, environ=None):
    environ = os.environ if environ is None else environ
    env = {k: environ[k] for k in ENV_KEEP if k in environ}
    env.update({
        "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1",
        # git: no user config, no prompts, no pager, no optional index writes
        # (the system config of Git for Windows lives in Program Files, writable only by an administrator,
        # and holds core.autocrlf, so it is kept; the per-user config is not read)
        "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat",
    })
    if ctx is not None:
        env["PYTHONPYCACHEPREFIX"] = ctx.child_pycache  # planted __pycache__ files are never read
    return env


def _cap(data):
    text = (data or b"").decode("utf-8", errors="replace")
    if len(text) > OUTPUT_CAP:
        return text[:OUTPUT_CAP], True
    return text, False


# ---------------------------------------------------------------- Windows job object (kills the whole tree)

class _BasicLimit(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32)]


class _IoCounters(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                               "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _ExtendedLimit(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimit), ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


KILL_ON_JOB_CLOSE = 0x2000
EXTENDED_LIMIT_CLASS = 9


class _Tree:
    """The started process and everything it starts."""

    def __init__(self, proc):
        self.proc, self.job = proc, None
        if os.name == "nt":
            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateJobObjectW.restype = ctypes.c_void_p
            k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
            k32.SetInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
            k32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            k32.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint]
            k32.CloseHandle.argtypes = [ctypes.c_void_p]
            self.k32 = k32
            job = k32.CreateJobObjectW(None, None)
            info = _ExtendedLimit()
            info.BasicLimitInformation.LimitFlags = KILL_ON_JOB_CLOSE
            ok = bool(job) and k32.SetInformationJobObject(job, EXTENDED_LIMIT_CLASS, ctypes.byref(info),
                                                           ctypes.sizeof(info))
            ok = ok and k32.AssignProcessToJobObject(job, int(proc._handle))
            if not ok:
                proc.kill()
                proc.wait()
                if job:
                    k32.CloseHandle(job)
                raise Refused("could not put the process in a job object (cannot guarantee a full stop)")
            self.job = job

    def kill(self):
        if os.name == "nt":
            if self.job:
                self.k32.TerminateJobObject(self.job, 1)
            try:
                self.proc.kill()
            except OSError:
                pass
        else:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

    def close(self):
        """Nothing the step started may outlive it."""
        self.kill()
        if os.name == "nt" and self.job:
            self.k32.CloseHandle(self.job)
            self.job = None


class Command:
    kind = "command"

    def __init__(self, label, argv, cwd, timeout, stop_grace=0):
        self.label, self.argv, self.cwd, self.timeout = label, list(argv), cwd, timeout
        self.stop_grace = stop_grace  # seconds a program that watches STOP itself gets to end on its own

    def describe(self):
        return "%s: %s  (folder %s, timeout %d s)" % (self.label, " ".join(self.argv), self.cwd, self.timeout)

    def run(self, ctx):
        ctx.check_program(self.argv)
        if not os.path.isdir(self.cwd):
            raise Refused("working folder missing: " + self.cwd)
        ctx.prepare_child_pycache()
        start = time.monotonic()
        deadline = start + self.timeout
        extra = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else \
            {"start_new_session": True}
        proc = subprocess.Popen(self.argv, cwd=self.cwd, env=reduced_env(ctx), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, **extra)
        tree = _Tree(proc)
        timed_out = stopped = False
        stop_seen, misses = None, 0
        out = err = b""
        try:
            while True:
                try:
                    out, err = proc.communicate(timeout=max(0.0, min(POLL_SECONDS, deadline - time.monotonic())))
                    break
                except subprocess.TimeoutExpired:
                    pass
                now = time.monotonic()
                if now >= deadline:
                    timed_out = True
                else:
                    stops = ctx.stop_present()
                    real = [x for x in stops if not x.startswith("Bridge root unreachable")]
                    misses = misses + 1 if len(stops) > len(real) else 0
                    if real or misses >= UNREACHABLE_POLLS:
                        stop_seen = stop_seen or now
                        stopped = now - stop_seen >= self.stop_grace
                    else:
                        stop_seen = None  # STOP cleared: the grace period starts over next time
                if timed_out or stopped:
                    tree.kill()
                    try:
                        out, err = proc.communicate(timeout=10)
                    except subprocess.TimeoutExpired as exc:
                        out, err = exc.stdout or b"", (exc.stderr or b"") + b"\n[mini_ray: output pipes stayed open]"
                    break
        except BaseException:
            tree.kill()
            raise
        finally:
            tree.close()
            if proc.poll() is None:
                proc.kill()
            for pipe in (proc.stdout, proc.stderr):
                if pipe:
                    pipe.close()
            proc.wait()
        stdout, cut_out = _cap(out)
        stderr, cut_err = _cap(err)
        return {"kind": "command", "label": self.label, "argv": self.argv, "cwd": self.cwd,
                "exit": None if timed_out else proc.returncode, "timed_out": timed_out, "stopped": stopped,
                "seconds": round(time.monotonic() - start, 1),
                "stdout": stdout, "stderr": stderr, "stdout_truncated": cut_out, "stderr_truncated": cut_err}


class Inspect:
    """A read-only look implemented in Python (no program is started)."""
    kind = "inspect"

    def __init__(self, label, func, text):
        self.label, self.func, self.text = label, func, text

    def describe(self):
        return "%s: %s (read-only, in Python)" % (self.label, self.text)

    def run(self, ctx):
        start = time.monotonic()
        facts = self.func(ctx)
        return {"kind": "inspect", "label": self.label, "facts": facts,
                "seconds": round(time.monotonic() - start, 1)}
