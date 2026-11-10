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

                connection.execute("""
                    CREATE TABLE IF NOT EXISTS pending_approvals (
                        approval_id TEXT PRIMARY KEY,
                        transaction_id TEXT NOT NULL,
                        transaction_json TEXT NOT NULL,
                        fingerprint TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'PENDING'
                            CHECK (
                                status IN (
                                    'PENDING',
                                    'APPROVED',
                                    'CONSUMED',
                                    'EXPIRED'
                                )
                            ),
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        approved_at INTEGER,
                        consumed_at INTEGER
                    )
                """)

                connection.execute("""
                    CREATE INDEX IF NOT EXISTS
                    idx_pending_approvals_transaction
                    ON pending_approvals(transaction_id)
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

    def create_pending_approval(
        self,
        approval_id,
        transaction_id,
        transaction_json,
        fingerprint,
        created_at,
        expires_at
    ):

        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    INSERT INTO pending_approvals (
                        approval_id,
                        transaction_id,
                        transaction_json,
                        fingerprint,
                        created_at,
                        expires_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval_id,
                        transaction_id,
                        transaction_json,
                        fingerprint,
                        created_at,
                        expires_at
                    )
                )
    def get_transaction_history(self, limit=50):

        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("Limit must be an integer between 1 and 200")

        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT id, transaction_id, processed_at
                FROM processed_transactions
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

        return [
            {
                "id": row[0],
                "transaction_id": row[1],
                "processed_at": row[2]
            }
            for row in rows
        ]
    def get_approval(self, approval_id):

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT *
                FROM pending_approvals
                WHERE approval_id = ?
                """,
                (approval_id,)
            ).fetchone()

        if row is None:
            return None

        columns = [
            "approval_id",
            "transaction_id",
            "transaction_json",
            "fingerprint",
            "status",
            "created_at",
            "expires_at",
            "approved_at",
            "consumed_at"
        ]

        return dict(zip(columns, row))

    def approve_pending_approval(self, approval_id, current_time):

        with closing(self._connect()) as connection:
            with connection:

                result = connection.execute(
                    """
                    UPDATE pending_approvals
                    SET status = 'APPROVED',
                        approved_at = ?
                    WHERE approval_id = ?
                      AND status = 'PENDING'
                      AND expires_at > ?
                    """,
                    (current_time, approval_id, current_time)
                )

                if result.rowcount == 1:
                    return True

                connection.execute(
                    """
                    UPDATE pending_approvals
                    SET status = 'EXPIRED'
                    WHERE approval_id = ?
                      AND status = 'PENDING'
                      AND expires_at <= ?
                    """,
                    (approval_id, current_time)
                )

                return False

    def consume_approved_approval(self, approval_id, current_time):

        with closing(self._connect()) as connection:
            with connection:

                result = connection.execute(
                    """
                    UPDATE pending_approvals
                    SET status = 'CONSUMED',
                        consumed_at = ?
                    WHERE approval_id = ?
                      AND status = 'APPROVED'
                      AND expires_at > ?
                    """,
                    (current_time, approval_id, current_time)
                )

                if result.rowcount == 1:
                    return True

                connection.execute(
                    """
                    UPDATE pending_approvals
                    SET status = 'EXPIRED'
                    WHERE approval_id = ?
                      AND status = 'APPROVED'
                      AND expires_at <= ?
                    """,
                    (approval_id, current_time)
                )

                return False
    def get_approvals(self, status=None, limit=50):

        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("Limit must be an integer between 1 and 200")

        valid_statuses = {
            "PENDING",
            "APPROVED",
            "CONSUMED",
            "EXPIRED"
        }

        if status is not None:
            if not isinstance(status, str):
                raise ValueError("Invalid approval status")

            status = status.strip().upper()

            if status not in valid_statuses:
                raise ValueError("Invalid approval status")

        query = """
            SELECT
                approval_id,
                transaction_id,
                status,
                created_at,
                expires_at,
                approved_at,
                consumed_at
            FROM pending_approvals
        """

        parameters = []

        if status is not None:
            query += " WHERE status = ?"
            parameters.append(status)

        query += " ORDER BY created_at DESC LIMIT ?"
        parameters.append(limit)

        with closing(self._connect()) as connection:
            rows = connection.execute(
                query,
                parameters
            ).fetchall()

        columns = [
            "approval_id",
            "transaction_id",
            "status",
            "created_at",
            "expires_at",
            "approved_at",
            "consumed_at"
        ]

        return [
            dict(zip(columns, row))
            for row in rows
        ]