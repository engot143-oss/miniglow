"""Backups and recovery (Layer 3).

- snapshot(): consistent copy of the database using SQLite's backup API
- archive(): zip with a database snapshot, generated memory files, an events.jsonl export,
  handoff packets and evidence files
- restore(): replace the live database from a snapshot (a safety snapshot is taken first)
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

from .store import MiniGlowError, Store, sha256_file


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-%f")


def snapshot(store: Store, label: str = "manual") -> Path:
    store._require_init()
    dest = store.home / "backups" / f"mg-{_stamp()}-{label}.db"
    dest.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(store.db_path, timeout=15)
    try:
        dst = sqlite3.connect(dest)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    store.log_event("backup", "mini-glow", f"Snapshot {dest.name} sha256={sha256_file(dest)[:16]}")
    return dest


def archive(store: Store, out_dir: Path | None = None) -> Path:
    snap = snapshot(store, "archive")
    out_dir = Path(out_dir) if out_dir else store.home / "backups"
    out_dir.mkdir(parents=True, exist_ok=True)
    zpath = out_dir / f"mini-glow-data-{_stamp()}.zip"
    with tempfile.TemporaryDirectory() as td:
        jsonl = store.export_events_jsonl(Path(td) / "events.jsonl")
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(snap, "mini_glow.db")
            z.write(jsonl, "exports/events.jsonl")
            for folder in ("memory", "handoffs", "evidence"):
                base = store.home / folder
                if base.exists():
                    for p in sorted(base.rglob("*")):
                        if p.is_file():
                            z.write(p, p.relative_to(store.home).as_posix())
    snap.unlink()
    return zpath


def list_snapshots(store: Store) -> list[Path]:
    return sorted((store.home / "backups").glob("mg-*.db"))


def restore(store: Store, snapshot_path: Path) -> Path:
    snapshot_path = Path(snapshot_path)
    if not snapshot_path.is_file():
        raise MiniGlowError(f"Snapshot not found: {snapshot_path}")
    try:
        probe = sqlite3.connect(snapshot_path)
        try:
            ok = probe.execute("PRAGMA integrity_check").fetchone()[0]
            has_tasks = probe.execute("SELECT name FROM sqlite_master WHERE name='tasks'").fetchone()
            has_events = probe.execute("SELECT name FROM sqlite_master WHERE name='events'").fetchone()
        finally:
            probe.close()
    except sqlite3.DatabaseError:
        raise MiniGlowError("That file is not a healthy Mini Glow snapshot; nothing was changed.")
    if ok != "ok" or not has_tasks or not has_events:
        raise MiniGlowError("That file is not a healthy Mini Glow snapshot; nothing was changed.")
    safety = snapshot(store, "pre-restore")
    tmp = store.db_path.with_suffix(".restore.tmp")
    shutil.copy2(snapshot_path, tmp)
    for suffix in ("-wal", "-shm"):
        side = Path(str(store.db_path) + suffix)
        if side.exists():
            side.unlink()
    os.replace(tmp, store.db_path)
    store.log_event("restore", "mini-glow", f"Restored from {snapshot_path.name}; safety copy {safety.name}")
    store.export_memory()
    return safety
