import sqlite3
from pathlib import Path
from contextlib import closing


class SQLiteTransactionTracker:

    def __init__(self, database_path=None):

        if database_path is None:
            project_root = Path(__file__).resolve().parent.parent
            database_path = project_root / "data" / "agentguard.db"

        self.database_path = Path(database_path)

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self._initialize_database()

    def _connect(self):
        return sqlite3.connect(self.database_path)

    def _initialize_database(self):

        with closing(self._connect()) as connection:
            with connection:
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS processed_transactions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        transaction_id TEXT NOT NULL UNIQUE,
                        processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

    def _validate_transaction_id(self, transaction_id):

        if not isinstance(transaction_id, str) or not transaction_id.strip():
            raise ValueError("Transaction ID must be non-empty text")

        return transaction_id.strip()

    def is_duplicate(self, transaction_id):

        transaction_id = self._validate_transaction_id(transaction_id)

        with closing(self._connect()) as connection:
            result = connection.execute(
                """
                SELECT 1
                FROM processed_transactions
                WHERE transaction_id = ?
                """,
                (transaction_id,)
            ).fetchone()

        return result is not None

    def mark_processed(self, transaction_id):

        transaction_id = self._validate_transaction_id(transaction_id)

        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO processed_transactions
                    (transaction_id)
                    VALUES (?)
                    """,
                    (transaction_id,)
                )