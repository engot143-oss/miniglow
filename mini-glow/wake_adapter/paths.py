"""Fixed places the adapter may read, and the one file it may write. Standard library only."""
import os
import re

BRIDGE_ROOT = r"H:\My Drive\Glow-Ray-Bridge"
DB_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}\.sqlite\Z")
CHECKPOINT_NAME = "wake_adapter_checkpoint.json"


class Refused(Exception):
    """A safety rule was hit; nothing (more) is done."""


class Stopped(Refused):
    """A STOP signal is present (or the Bridge root is unreachable); nothing leaves the adapter."""

    def __init__(self, found):
        self.found = list(found)
        super().__init__("STOP present: " + ", ".join(self.found))


def is_inside(path, folder):
    """True if path is folder itself or anywhere below it (after resolving links)."""
    path, folder = os.path.normcase(os.path.realpath(path)), os.path.normcase(os.path.realpath(folder))
    try:
        return os.path.commonpath([path, folder]) == folder
    except ValueError:  # different drives on Windows
        return False


def miniglow_base(environ=None):
    environ = os.environ if environ is None else environ
    local = (environ.get("LOCALAPPDATA") or "").strip()
    if not local or not os.path.isabs(local):
        raise Refused("LOCALAPPDATA is not set to an absolute folder")
    return os.path.realpath(os.path.join(local, "MiniGlow"))


def _outside_bridge(path, bridge_root):
    if is_inside(path, bridge_root):
        raise Refused("path inside the Bridge refused: " + path)
    return path


def db_path(base, name, bridge_root):
    """A bridge_poller database in the MiniGlow folder, named NAME.sqlite. It must already exist."""
    if not isinstance(name, str) or not DB_RE.match(name):
        raise Refused("database name must look like NAME.sqlite (letters, digits, _ and -)")
    path = _outside_bridge(os.path.join(base, name), bridge_root)
    if os.path.islink(path) or not os.path.isfile(path):
        raise Refused("database not found or not a plain file: " + name)
    return path


def checkpoint_path(base, bridge_root):
    """The adapter's only persistent write: one JSON file directly in the MiniGlow folder."""
    if not os.path.isdir(base):
        raise Refused("MiniGlow folder not found: " + base)
    return _outside_bridge(os.path.join(base, CHECKPOINT_NAME), bridge_root)
