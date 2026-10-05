"""Read-only Drive access for the poller.

By design this interface has exactly three read functions and NO write function.
RealDrive is a blocked placeholder until Eric approves a narrow read method.
FakeDrive reads a scenario in memory and needs no credentials.
"""
import json


class BlockedError(RuntimeError):
    """Raised when a part of the plan is waiting on a decision (NEEDS_ERIC)."""


class DriveReader:
    def list_folder(self, folder_id):
        """Return a list of {'id', 'name', 'createdTime'}."""
        raise NotImplementedError

    def read_text(self, file_id):
        """Return the text of one file."""
        raise NotImplementedError

    def stop_present(self, root_folder_id):
        """True if a file named STOP exists in the bridge root folder."""
        raise NotImplementedError


class RealDrive(DriveReader):
    def __init__(self):
        raise BlockedError(
            "Live Drive read is not available: the narrow read-only method "
            "(synced read-only copy or folder-scoped read grant) has not been set up. "
            "Report to Glow as NEEDS_ERIC."
        )


class FakeDrive(DriveReader):
    """In-memory Drive for tests. 'advance(n)' applies changes scheduled for check n."""

    def __init__(self, files=None, schedule=None, text_updates=None, remove=None, stop_at=None):
        self.files = {f["id"]: dict(f) for f in (files or [])}
        self.schedule = {int(k): v for k, v in (schedule or {}).items()}
        self.text_updates = {int(k): v for k, v in (text_updates or {}).items()}
        self.remove = {int(k): v for k, v in (remove or {}).items()}
        self.stop_at = stop_at
        self.stop = stop_at == 0
        self.calls = []
        self.folder_ids = []  # ids the poller asked for (lets tests check configuration)
        self.root_ids = []

    @classmethod
    def from_json(cls, path):
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return cls(
            files=data.get("files"),
            schedule=data.get("schedule"),
            text_updates=data.get("text_updates"),
            remove=data.get("remove"),
            stop_at=data.get("stop_at"),
        )

    def advance(self, check_number):
        for f in self.schedule.get(check_number, []):
            self.files[f["id"]] = dict(f)
        for file_id, text in self.text_updates.get(check_number, {}).items():
            self.files[file_id]["text"] = text
        for file_id in self.remove.get(check_number, []):
            self.files.pop(file_id, None)
        if self.stop_at is not None and check_number >= self.stop_at:
            self.stop = True

    def list_folder(self, folder_id):
        self.calls.append("list_folder")
        self.folder_ids.append(folder_id)
        return [
            {"id": f["id"], "name": f["name"], "createdTime": f["createdTime"]}
            for f in self.files.values()
        ]

    def read_text(self, file_id):
        self.calls.append("read_text")
        return self.files[file_id]["text"]

    def stop_present(self, root_folder_id):
        self.calls.append("stop_present")
        self.root_ids.append(root_folder_id)
        return self.stop
