"""Database schema and constraint tests."""

import sqlite3

import pytest

from config import Config
from core.database import get_db
from core.models import init_db


@pytest.fixture()
def temp_database(tmp_path, monkeypatch):
    database_path = tmp_path / "test.db"
    monkeypatch.setattr(Config, "DATABASE", str(database_path))
    init_db()
    return database_path


def _insert_assessment(connection) -> int:
    cursor = connection.execute(
        "INSERT INTO assessments (scan_type, target) VALUES (?, ?)",
        ("network", "10.0.0.5"),
    )
    return cursor.lastrowid


def _insert_finding(connection, assessment_id: int, fingerprint: str) -> None:
    connection.execute(
        """
        INSERT INTO findings (
            assessment_id, finding_type, title, risk_level, confidence,
            fingerprint
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            assessment_id,
            "misconfiguration",
            "Test finding",
            "Low",
            "high",
            fingerprint,
        ),
    )


def test_init_db_creates_all_tables(temp_database):
    with get_db() as connection:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()

    table_names = {row["name"] for row in rows}
    assert {
        "assessments",
        "assets",
        "findings",
        "cve_records",
        "finding_cves",
    } <= table_names


def test_foreign_key_enforcement(temp_database):
    with pytest.raises(sqlite3.IntegrityError):
        with get_db() as connection:
            _insert_finding(connection, 999999, "orphan-finding")


def test_unique_assessment_fingerprint(temp_database):
    with get_db() as connection:
        assessment_id = _insert_assessment(connection)
        _insert_finding(connection, assessment_id, "duplicate-fingerprint")

    with pytest.raises(sqlite3.IntegrityError):
        with get_db() as connection:
            _insert_finding(connection, assessment_id, "duplicate-fingerprint")


def test_finding_check_constraints(temp_database):
    with pytest.raises(sqlite3.IntegrityError):
        with get_db() as connection:
            assessment_id = _insert_assessment(connection)
            connection.execute(
                """
                INSERT INTO findings (
                    assessment_id, finding_type, title, risk_level,
                    confidence, fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id,
                    "made_up_type",
                    "Invalid finding",
                    "Severe",
                    "certain",
                    "bad-enum-finding",
                ),
            )
