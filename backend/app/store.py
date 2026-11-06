"""SQLite storage for scans and findings."""
import json
import sqlite3
import time
from pathlib import Path

from .schema import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY, name TEXT, source TEXT, status TEXT, created REAL,
  duration REAL, files_scanned INTEGER, files_skipped INTEGER, error TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT, scan_id TEXT, data TEXT, PRIMARY KEY (scan_id, id)
);
CREATE TABLE IF NOT EXISTS files (
  scan_id TEXT, path TEXT, content TEXT, PRIMARY KEY (scan_id, path)
);
"""


class Store:
    def __init__(self, path: str | Path):
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def create_scan(self, scan_id: str, name: str, source: str) -> None:
        self.db.execute("INSERT INTO scans (id, name, source, status, created) VALUES (?, ?, ?, ?, ?)",
                        (scan_id, name, source, "running", time.time()))
        self.db.commit()

    def finish_scan(self, scan_id: str, findings: list[Finding], files: dict[str, str],
                    duration: float, skipped: int) -> None:
        self.db.executemany("INSERT OR REPLACE INTO findings VALUES (?, ?, ?)",
                            [(f.id, scan_id, f.model_dump_json()) for f in findings])
        self.db.executemany("INSERT OR REPLACE INTO files VALUES (?, ?, ?)",
                            [(scan_id, p, c) for p, c in files.items()])
        self.db.execute("UPDATE scans SET status='done', duration=?, files_scanned=?, files_skipped=? "
                        "WHERE id=?", (duration, len(files), skipped, scan_id))
        self.db.commit()

    def fail_scan(self, scan_id: str, error: str) -> None:
        self.db.execute("UPDATE scans SET status='failed', error=? WHERE id=?", (error, scan_id))
        self.db.commit()

    def scan(self, scan_id: str) -> dict | None:
        row = self.db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def scans(self) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM scans ORDER BY created DESC")]

    def findings(self, scan_id: str) -> list[Finding]:
        rows = self.db.execute("SELECT data FROM findings WHERE scan_id=? ORDER BY id", (scan_id,))
        return [Finding.model_validate_json(r["data"]) for r in rows]

    def finding(self, scan_id: str, finding_id: str) -> Finding | None:
        row = self.db.execute("SELECT data FROM findings WHERE scan_id=? AND id=?",
                              (scan_id, finding_id)).fetchone()
        return Finding.model_validate_json(row["data"]) if row else None

    def set_status(self, scan_id: str, finding_id: str, status: str) -> Finding | None:
        f = self.finding(scan_id, finding_id)
        if f is None:
            return None
        f = f.model_copy(update={"status": status})
        self.db.execute("UPDATE findings SET data=? WHERE scan_id=? AND id=?",
                        (f.model_dump_json(), scan_id, finding_id))
        self.db.commit()
        return f

    def file(self, scan_id: str, path: str) -> str | None:
        row = self.db.execute("SELECT content FROM files WHERE scan_id=? AND path=?",
                              (scan_id, path)).fetchone()
        return row["content"] if row else None


def dumps(findings: list[Finding]) -> str:
    return json.dumps([f.model_dump() for f in findings], indent=2)
