"""Fixed locations and the checks that keep Mini Ray inside them."""
import ctypes
import os
import re
import shutil
import sys

BRIDGE_ROOT = r"H:\My Drive\Glow-Ray-Bridge"
BRANCH = "verified-local-miniglow"
PACKET_RE = re.compile(r"^R2G-\d{3}_[A-Za-z0-9_.-]{1,150}\.txt\Z")
DB_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}\.sqlite\Z")
HEAD_RE = re.compile(r"^[0-9a-f]{40}\Z")
# Git for Windows is taken only from these fixed places, never from PATH or the current folder
# (a git.bat or git.exe planted in the working folder must never be the program that runs).
WINDOWS_GIT = (r"C:\Program Files\Git\cmd\git.exe", r"C:\Program Files\Git\bin\git.exe")


class Refused(Exception):
    """A rule of the deny model was hit; nothing (more) is run."""


def is_inside(path, folder):
    path, folder = os.path.normcase(os.path.realpath(path)), os.path.normcase(os.path.realpath(folder))
    try:
        return os.path.commonpath([path, folder]) == folder
    except ValueError:
        return False


def is_admin():
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return True  # cannot tell: treat as admin and refuse (fail closed)
    return os.geteuid() == 0


def validate_git(path, repo, cwd, windows):
    """The git program must be a real file outside the repository and the current folder (.exe on Windows)."""
    if not path or not os.path.isabs(path) or not os.path.isfile(path):
        raise Refused("git was not found at a fixed absolute path")
    if windows and not path.lower().endswith(".exe"):
        raise Refused("git must be git.exe: " + path)
    for folder in (repo, cwd):
        if folder and is_inside(path, folder):
            raise Refused("git inside the repository or the current folder is refused: " + path)
    return path


def default_git(repo, cwd, windows=None, candidates=WINDOWS_GIT):
    windows = (os.name == "nt") if windows is None else windows
    if windows:
        found = [c for c in candidates if os.path.isfile(c)]
        path = found[0] if found else None
    else:
        path = shutil.which("git", path=os.defpath + os.pathsep + "/usr/local/bin")
    return validate_git(path, repo, cwd, windows)


class Context:
    """Everything Mini Ray may touch. Tests build one with temporary folders."""

    def __init__(self, base=None, bridge_root=BRIDGE_ROOT, repo=None, mini_glow=None, python=None, git=None,
                 environ=None):
        environ = os.environ if environ is None else environ
        if base is None:
            local = (environ.get("LOCALAPPDATA") or "").strip()
            if not local or not os.path.isabs(local):
                raise Refused("LOCALAPPDATA is not set to an absolute folder")
            base = os.path.join(local, "MiniGlow")
        self.base = os.path.realpath(base)
        self.evidence_dir = os.path.join(self.base, "evidence")
        self.audit_log = os.path.join(self.base, "miniray_audit.jsonl")
        self.local_stop = os.path.join(self.base, "MINIRAY_STOP")
        self.keys_dir = os.path.join(self.base, "keys")
        self.child_pycache = os.path.join(self.base, "child_pycache")
        self.bridge_root = bridge_root
        self.r2g = os.path.join(bridge_root, "Ray-to-Glow")
        self.g2r = os.path.join(bridge_root, "Glow-to-Ray")
        package = os.path.dirname(os.path.abspath(__file__))
        self.package = package
        self.mini_glow = mini_glow or os.path.dirname(package)
        self.repo = repo or os.path.dirname(os.path.dirname(package))
        self.python = python or sys.executable
        if is_inside(self.python, self.repo):
            raise Refused("python inside the repository is refused: " + self.python)
        self.git = validate_git(git, self.repo, os.getcwd(), os.name == "nt") if git else \
            default_git(self.repo, os.getcwd())
        self.allowed_programs = {os.path.normcase(os.path.realpath(self.python)),
                                 os.path.normcase(os.path.realpath(self.git))}

    # ---- deny-model checks -------------------------------------------------
    def check_program(self, argv):
        if not argv or os.path.normcase(os.path.realpath(argv[0])) not in self.allowed_programs:
            raise Refused("program not allowed: %r" % (argv[0] if argv else None))
        for arg in argv:
            if not isinstance(arg, str) or "\x00" in arg:
                raise Refused("bad argument")

    def check_write(self, path):
        """Mini Ray may only write inside the MiniGlow folder, never in keys."""
        if not is_inside(path, self.base):
            raise Refused("write outside MiniGlow refused: " + path)
        if is_inside(path, self.keys_dir):
            raise Refused("the keys folder is off limits")
        return path

    def check_append(self, path):
        """An existing file that Mini Ray appends to must be a plain file with one name (no link out of MiniGlow)."""
        self.check_write(path)
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return path
        if os.path.islink(path) or not os.path.isfile(path) or st.st_nlink != 1:
            raise Refused("file is linked or not a plain file: " + path)
        return path

    def prepare_child_pycache(self):
        """Children read compiled code only from this empty folder, so a planted __pycache__ file never runs."""
        path = self.check_write(self.child_pycache)
        if os.path.islink(path):
            raise Refused("child_pycache is a link")
        os.makedirs(path, exist_ok=True)
        if os.listdir(path):
            raise Refused("child_pycache is not empty: " + path)
        return path

    def stop_present(self):
        """Any STOP* name in the Bridge root, an unreachable Bridge root, or MINIRAY_STOP* in MiniGlow."""
        found = []
        try:
            names = os.listdir(self.bridge_root)
        except OSError:
            return ["Bridge root unreachable: " + self.bridge_root]
        found += [os.path.join(self.bridge_root, n) for n in sorted(names) if n.upper().startswith("STOP")]
        try:
            local = os.listdir(self.base)
        except OSError:
            local = []
        found += [os.path.join(self.base, n) for n in sorted(local) if n.upper().startswith("MINIRAY_STOP")]
        return found

    def packet_path(self, name):
        if not isinstance(name, str) or not PACKET_RE.match(name):
            raise Refused("packet name must look like R2G-nnn_NAME.txt")
        return os.path.join(self.r2g, name)

    def db_path(self, name, must_exist):
        if not isinstance(name, str) or not DB_RE.match(name):
            raise Refused("database name must look like NAME.sqlite (letters, digits, _ and -)")
        path = os.path.join(self.base, name)
        if must_exist and not os.path.isfile(path):
            raise Refused("database not found: " + name)
        if not must_exist and os.path.exists(path):
            raise Refused("database already exists: " + name)
        return self.check_write(path)
