"""Reputation rows from older databases gain a country column."""

import sqlite3
import tempfile
import unittest

from requestguard.store import Store


class StoreTest(unittest.TestCase):
    def test_old_reputation_table_gains_country(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/old.db"
            conn = sqlite3.connect(path)
            conn.execute(
                """
                CREATE TABLE reputation (
                    ip TEXT PRIMARY KEY,
                    score INTEGER NOT NULL,
                    checked_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    detail TEXT NOT NULL
                )
                """
            )
            conn.execute("INSERT INTO reputation VALUES ('8.8.8.8', 10, 1, 9999999999, '')")
            conn.commit()
            conn.close()
            store = Store(path)
            try:
                row = store.get_reputation("8.8.8.8", 2)
            finally:
                store.close()
            assert row is not None
            self.assertEqual(row.score, 10)
            self.assertEqual(row.country, "")


if __name__ == "__main__":
    unittest.main()
