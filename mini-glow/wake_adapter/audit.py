"""Append-only, hash-chained audit log for the v0.2 transport (one JSON object per line).

Each entry carries the SHA-256 of the previous entry ("prev") and its own hash over its canonical JSON without
the "hash" field, so editing, removing or reordering any line breaks the chain. Delivery codes are never logged,
only their SHA-256.
"""
import hashlib
import json
import os
import stat

from .paths import Refused

GENESIS = "0" * 64
ACTIONS = frozenset({"DELIVERED", "STUCK", "ACKED", "REJECTED", "ALREADY_CONFIRMED",
                     "LINK_SENT", "LINK_RECEIVED", "LINK_REJECTED", "LINK_DUPLICATE"})
MAX_BYTES = 16 * 1024 * 1024


def _hash(entry):
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _plain_or_missing(path):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise Refused("audit log is linked or not a plain file: " + path)
    return True


def read(path):
    """All entries, after checking the whole chain. Raises Refused on any break."""
    if not _plain_or_missing(path):
        return []
    with open(path, "rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise Refused("audit log too large")
    entries, prev = [], GENESIS
    for n, line in enumerate(data.decode("utf-8").splitlines(), 1):
        try:
            entry = json.loads(line)
        except ValueError:
            raise Refused("audit log line %d is not JSON" % n)
        if not isinstance(entry, dict) or entry.get("seq") != n or entry.get("prev") != prev or \
                entry.get("action") not in ACTIONS or entry.get("hash") != _hash(entry):
            raise Refused("audit chain broken at line %d" % n)
        entries.append(entry)
        prev = entry["hash"]
    return entries


def verify(path):
    """(ok, entry_count, problem)."""
    try:
        return True, len(read(path)), None
    except Refused as err:
        return False, None, str(err)


def code_hash(code):
    return hashlib.sha256(code.encode("ascii")).hexdigest()


def append(path, action, time, **fields):
    """Add one entry after verifying the existing chain. Returns the entry."""
    if action not in ACTIONS:
        raise Refused("unknown audit action: %s" % action)
    entries = read(path)
    entry = {"seq": len(entries) + 1, "time": time, "action": action}
    entry.update(fields)
    entry["prev"] = entries[-1]["hash"] if entries else GENESIS
    entry["hash"] = _hash(entry)
    with open(path, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return entry
