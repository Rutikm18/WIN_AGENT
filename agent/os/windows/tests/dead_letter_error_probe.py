"""Read-only support probe for distinct durable-outbox rejection errors.

This tool never selects or decrypts ``protected_payload``.  Run it elevated
when ProgramData ACLs intentionally deny standard-user access.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("database", type=Path)
    args = parser.parse_args()
    uri = args.database.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5)
    try:
        rows = connection.execute(
            """
            SELECT section, last_status, last_error, COUNT(*)
            FROM outbox WHERE state='dead'
            GROUP BY section, last_status, last_error
            ORDER BY COUNT(*) DESC
            """
        ).fetchall()
    finally:
        connection.close()
    print(json.dumps([
        {
            "section": section,
            "status": status,
            "error": str(error or "")[:512],
            "count": count,
        }
        for section, status, error, count in rows
    ], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
