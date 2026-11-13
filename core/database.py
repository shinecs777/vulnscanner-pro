"""Low-level SQLite connection management."""

import sqlite3
from contextlib import contextmanager
from typing import Iterator

from config import Config


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection with foreign keys enabled.

    Commits on success, rolls back on any exception, and always closes.
    Schema definition intentionally lives in core.models.
    """
    connection = sqlite3.connect(Config.DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
