"""SQLite persistence layer for audit records."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator, Optional

DB_PATH = os.environ.get("BIDI_DB_PATH", "/data/audit.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    REAL    NOT NULL,
    filename      TEXT,
    text_length   INTEGER NOT NULL,
    risk_level    TEXT    NOT NULL,
    max_depth     INTEGER NOT NULL,
    error_count   INTEGER NOT NULL,
    control_count INTEGER NOT NULL,
      -- raw input is retained so it can be reviewed later
    raw_text      TEXT    NOT NULL,
    result_json   TEXT    NOT NULL,
      -- optional source/mapping metadata (e.g. unified-diff locations);
      -- kept out of result_json so verify compares the raw parse result
    meta_json     TEXT
);
CREATE INDEX IF NOT EXISTS idx_audits_risk     ON audits(risk_level);
CREATE INDEX IF NOT EXISTS idx_audits_filename ON audits(filename);
CREATE INDEX IF NOT EXISTS idx_audits_created  ON audits(created_at);
"""

# Columns added after the initial release (name -> column DDL).
_ADDED_COLUMNS = {
    "meta_json": "TEXT",
}


def init_db(db_path: Optional[str] = None) -> None:
    path = db_path or DB_PATH
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.executescript(_SCHEMA)
        existing = {row[1] for row in conn.execute("PRAGMA table_info(audits)")}
        for name, ddl in _ADDED_COLUMNS.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE audits ADD COLUMN {name} {ddl}")
        conn.commit()


@contextmanager
def connect(db_path: Optional[str] = None) -> Iterator[sqlite3.Connection]:
    path = db_path or DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def insert_audit(
    *,
    filename: Optional[str],
    text: str,
    result: dict,
    meta: Optional[dict] = None,
) -> int:
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO audits (created_at, filename, text_length, risk_level,
                                max_depth, error_count, control_count,
                                raw_text, result_json, meta_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(),
                filename,
                result["length"],
                result["risk_level"],
                result["max_depth"],
                result["error_count"],
                result["stats"]["total_control_chars"],
                text,
                json.dumps(result, ensure_ascii=False),
                json.dumps(meta, ensure_ascii=False) if meta is not None else None,
            ),
        )
        return int(cur.lastrowid)


def _row_to_summary(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "filename": row["filename"],
        "text_length": row["text_length"],
        "risk_level": row["risk_level"],
        "max_depth": row["max_depth"],
        "error_count": row["error_count"],
        "control_count": row["control_count"],
    }


def query_audits(
    *,
    risk_level: Optional[str] = None,
    filename: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    clauses: list[str] = []
    params: list = []
    if risk_level:
        clauses.append("risk_level = ?")
        params.append(risk_level)
    if filename:
        # case-insensitive substring match on file name
        clauses.append("filename LIKE ?")
        params.append(f"%{filename}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (
        "SELECT * FROM audits " + where +
        " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    )
    params.extend([limit, offset])
    with connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_summary(r) for r in rows]


def count_audits(
    *, risk_level: Optional[str] = None, filename: Optional[str] = None
) -> int:
    clauses: list[str] = []
    params: list = []
    if risk_level:
        clauses.append("risk_level = ?")
        params.append(risk_level)
    if filename:
        clauses.append("filename LIKE ?")
        params.append(f"%{filename}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with connect() as conn:
        row = conn.execute(f"SELECT COUNT(*) AS c FROM audits {where}", params).fetchone()
    return int(row["c"])


def get_audit(audit_id: int) -> Optional[dict]:
    with connect() as conn:
        row = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    if row is None:
        return None
    detail = _row_to_summary(row)
    detail["raw_text"] = row["raw_text"]
    detail["result"] = json.loads(row["result_json"])
    if row["meta_json"]:
        detail["meta"] = json.loads(row["meta_json"])
    return detail
