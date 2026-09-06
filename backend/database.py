import sqlite3
from datetime import datetime
from pathlib import Path


# Always store the database in the project root
BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE = BASE_DIR / "promptguard.db"


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_prompt TEXT NOT NULL,
            masked_prompt TEXT NOT NULL,
            privacy_score INTEGER NOT NULL,
            security_score INTEGER NOT NULL,
            overall_score INTEGER NOT NULL,
            overall_level TEXT NOT NULL,
            injection_detected INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_scan(
    original_prompt,
    masked_prompt,
    risk,
    injection_detected
):

    connection = get_connection()

    connection.execute(
        """
        INSERT INTO scans (
            original_prompt,
            masked_prompt,
            privacy_score,
            security_score,
            overall_score,
            overall_level,
            injection_detected,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            original_prompt,
            masked_prompt,
            risk["privacy_score"],
            risk["security_score"],
            risk["overall_score"],
            risk["overall_level"],
            int(injection_detected),
            datetime.now().isoformat()
        )
    )

    connection.commit()
    connection.close()


def get_scans():

    connection = get_connection()

    scans = connection.execute(
        """
        SELECT *
        FROM scans
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return scans