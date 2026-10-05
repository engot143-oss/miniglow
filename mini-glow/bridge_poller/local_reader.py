"""Read-only reader for a LOCAL folder copy of the Bridge (Step 1, candidate 2).

Only lists folders, opens files for reading, and checks whether STOP exists.
It never writes, renames, moves, or deletes anything. Any path or read problem
raises ReaderError, which ends the run as ERROR (fail-closed).
"""
import os
from datetime import datetime, timezone

from .drive_reader import DriveReader

STOP_NAME = "STOP"
MAX_BYTES = 5 * 1024 * 1024  # a packet larger than this is treated as a read problem


class ReaderError(RuntimeError):
    """A configured path or file could not be read safely."""


def _real_dir(path, label):
    if not path:
        raise ReaderError(label + " path is not configured")
    real = os.path.realpath(path)
    if not os.path.isdir(real):
        raise ReaderError(label + " path is missing or not a folder: " + path)
    return real


def is_inside(path, folder):
    """True if path is folder itself or anywhere below it (after resolving links)."""
    path, folder = os.path.realpath(path), os.path.realpath(folder)
    try:
        return os.path.commonpath([os.path.normcase(path), os.path.normcase(folder)]) == os.path.normcase(folder)
    except ValueError:  # different drives on Windows
        return False


class LocalFolderReader(DriveReader):
    def __init__(self, folder_path, root_path):
        self.folder_path = _real_dir(folder_path, "Ray-to-Glow")
        self.root_path = _real_dir(root_path, "Bridge root")
        if self.folder_path == self.root_path or not is_inside(self.folder_path, self.root_path):
            raise ReaderError("Ray-to-Glow folder must be a subfolder of the Bridge root")

    def _check(self, given, expected, label):
        if os.path.realpath(given or "") != expected:
            raise ReaderError(label + " path requested by the poller does not match the configured path")

    def list_folder(self, folder_id):
        self._check(folder_id, self.folder_path, "Ray-to-Glow")
        try:
            entries = list(os.scandir(self.folder_path))
        except OSError as err:
            raise ReaderError("cannot list Ray-to-Glow folder: %s" % err)
        listing = []
        for entry in entries:
            try:
                if entry.is_symlink() or not entry.is_file():
                    continue  # only plain files are packets
                st = entry.stat()
            except OSError as err:
                raise ReaderError("cannot inspect %s: %s" % (entry.name, err))
            created = getattr(st, "st_birthtime", st.st_ctime)
            listing.append({
                "id": "local:" + entry.name,
                "name": entry.name,
                "createdTime": datetime.fromtimestamp(created, timezone.utc).isoformat(timespec="seconds"),
            })
        return listing

    def read_text(self, file_id):
        if not file_id.startswith("local:"):
            raise ReaderError("unexpected file id: " + file_id)
        name = file_id[len("local:"):]
        if os.path.basename(name) != name or name in ("", ".", ".."):
            raise ReaderError("unsafe file name: " + name)
        path = os.path.join(self.folder_path, name)
        try:
            with open(path, "rb") as handle:  # read-only, binary
                data = handle.read(MAX_BYTES + 1)
        except OSError as err:
            raise ReaderError("cannot read %s: %s" % (name, err))
        if len(data) > MAX_BYTES:
            raise ReaderError("file too large to be a packet: " + name)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return ""  # partly synced or not text: treated as incomplete and re-checked next cycle

    def stop_present(self, root_folder_id):
        self._check(root_folder_id, self.root_path, "Bridge root")
        if not os.path.isdir(self.root_path):
            raise ReaderError("Bridge root folder disappeared")
        return os.path.isfile(os.path.join(self.root_path, STOP_NAME))
