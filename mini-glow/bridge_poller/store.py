"""SQLite state for the dry-run poller. Local file only; nothing here touches Drive."""
import sqlite3

MISS_LIMIT = 2  # consecutive missing listings before a row becomes NEEDS_ERIC
SUSPECT_LIMIT = 2  # consecutive suspect (empty) listings before the RUN health becomes NEEDS_ERIC

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    packet_id          TEXT PRIMARY KEY,
    drive_file_id      TEXT UNIQUE NOT NULL,
    drive_created_time TEXT NOT NULL,
    detected_at        TEXT,
    check_number       INTEGER NOT NULL,
    state              TEXT NOT NULL CHECK (state IN ('BACKLOG', 'NEW_LOGGED', 'NEEDS_ERIC')),
    missing_count      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS runs (
    run_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    baseline_at  TEXT,
    ended_at     TEXT,
    checks_done  INTEGER,
    new_count    INTEGER,
    end_reason   TEXT CHECK (end_reason IN ('WINDOW_DONE', 'STOP', 'ERROR')),
    suspect_listings INTEGER NOT NULL DEFAULT 0,
    health       TEXT NOT NULL DEFAULT 'OK'
);
"""

# Columns added after the first draft; older databases get them on open.
_MIGRATIONS = (
    ("packets", "missing_count", "INTEGER NOT NULL DEFAULT 0"),
    ("runs", "suspect_listings", "INTEGER NOT NULL DEFAULT 0"),
    ("runs", "health", "TEXT NOT NULL DEFAULT 'OK'"),
)


class Store:
    def __init__(self, path=":memory:"):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        for table, column, decl in _MIGRATIONS:
            columns = [r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})")]
            if column not in columns:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        self.conn.commit()

    def close(self):
        self.conn.close()

    def has_packet(self, packet_id):
        row = self.conn.execute("SELECT 1 FROM packets WHERE packet_id = ?", (packet_id,)).fetchone()
        return row is not None

    def has_file(self, drive_file_id):
        row = self.conn.execute("SELECT 1 FROM packets WHERE drive_file_id = ?", (drive_file_id,)).fetchone()
        return row is not None

    def insert_packet(self, packet_id, drive_file_id, created_time, detected_at, check_number, state):
        self.conn.execute(
            "INSERT INTO packets (packet_id, drive_file_id, drive_created_time, detected_at, check_number, state) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (packet_id, drive_file_id, created_time, detected_at, check_number, state),
        )
        self.conn.commit()

    def record_listing(self, listed_file_ids, count_misses=True):
        """Update sighting counters from one folder listing. Returns how many rows became NEEDS_ERIC.

        A listed file resets its missing_count to 0. An unlisted file adds 1 (only when
        count_misses is True). The second consecutive miss (MISS_LIMIT) sets NEEDS_ERIC.
        NEEDS_ERIC rows are never changed here, so a flag is not cleared automatically.
        """
        rows = self.conn.execute(
            "SELECT packet_id, drive_file_id, missing_count FROM packets WHERE state IN ('BACKLOG', 'NEW_LOGGED')"
        ).fetchall()
        flagged = 0
        for r in rows:
            if r["drive_file_id"] in listed_file_ids:
                if r["missing_count"]:
                    self.conn.execute("UPDATE packets SET missing_count = 0 WHERE packet_id = ?", (r["packet_id"],))
            elif count_misses:
                misses = r["missing_count"] + 1
                if misses >= MISS_LIMIT:
                    self.conn.execute(
                        "UPDATE packets SET missing_count = ?, state = 'NEEDS_ERIC' WHERE packet_id = ?",
                        (misses, r["packet_id"]),
                    )
                    flagged += 1
                else:
                    self.conn.execute(
                        "UPDATE packets SET missing_count = ? WHERE packet_id = ?", (misses, r["packet_id"])
                    )
        self.conn.commit()
        return flagged

    def packet_count(self):
        return self.conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]

    def all_packets(self):
        rows = self.conn.execute("SELECT * FROM packets ORDER BY packet_id").fetchall()
        return [dict(r) for r in rows]

    def start_run(self, started_at):
        cur = self.conn.execute("INSERT INTO runs (started_at) VALUES (?)", (started_at,))
        self.conn.commit()
        return cur.lastrowid

    def set_baseline(self, run_id, baseline_at):
        self.conn.execute("UPDATE runs SET baseline_at = ? WHERE run_id = ?", (baseline_at, run_id))
        self.conn.commit()

    def end_run(self, run_id, ended_at, checks_done, new_count, end_reason, suspect_listings=0, health="OK"):
        self.conn.execute(
            "UPDATE runs SET ended_at = ?, checks_done = ?, new_count = ?, end_reason = ?, "
            "suspect_listings = ?, health = ? WHERE run_id = ?",
            (ended_at, checks_done, new_count, end_reason, suspect_listings, health, run_id),
        )
        self.conn.commit()

    def last_run(self):
        row = self.conn.execute("SELECT * FROM runs ORDER BY run_id DESC LIMIT 1").fetchone()
        return dict(row) if row else None
