"""
database.py - ChronosLog SQLite Data Access Layer
Provides connection management and a clean query execution interface.
"""

import sqlite3
import os
import logging

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("CHRONOS_DB_PATH", "chronoslog.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def init_db() -> None:
    if not os.path.exists(SCHEMA_PATH):
        raise FileNotFoundError(f"schema.sql not found at {SCHEMA_PATH}")

    # Always run the schema — every statement uses CREATE TABLE IF NOT EXISTS
    # and INSERT OR IGNORE, so this is safe on both new and existing databases.
    # This ensures new tables added to schema.sql are created without wiping data.
    is_new = not os.path.exists(DB_PATH)
    logger.info("%s. Applying schema.sql...", "New database detected" if is_new else "Existing database found")

    with open(SCHEMA_PATH, "r") as fh:
        sql = fh.read()

    conn = get_connection()
    try:
        conn.executescript(sql)
        conn.commit()
        logger.info("Database schema applied successfully → %s", DB_PATH)
    except sqlite3.Error as exc:
        logger.error("Database initialisation failed: %s", exc)
        raise
    finally:
        conn.close()

def fetchall(sql: str, params: tuple = ()) -> list[dict]:
    conn = get_connection()
    try:
        cursor = conn.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def fetchone(sql: str, params: tuple = ()) -> dict | None:
    conn = get_connection()
    try:
        cursor = conn.execute(sql, params)
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def execute(sql: str, params: tuple = ()) -> int:
    conn = get_connection()
    try:
        cursor = conn.execute(sql, params)
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()

def execute_script(sql: str) -> None:
    conn = get_connection()
    try:
        conn.executescript(sql)
        conn.commit()
    finally:
        conn.close()