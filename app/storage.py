import sqlite3
import json
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
                    CREATE TABLE IF NOT EXISTS inspected_transactions (
                        transaction_id TEXT PRIMARY KEY,
                        inspected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

                # PERSONAL USER ACCOUNTS
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                        password_hash TEXT NOT NULL,
                        password_salt TEXT NOT NULL,
                        approval_key_hash TEXT,
                        email_verified INTEGER NOT NULL DEFAULT 0,
                        created_at INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL
                    )
                """)

                # DEVELOPER API KEYS
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS developer_api_keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        name TEXT NOT NULL,
                        key_hash TEXT NOT NULL UNIQUE,
                        key_prefix TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        last_used_at INTEGER,
                        revoked_at INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                """)

                connection.execute("""
                    CREATE INDEX IF NOT EXISTS
                    idx_developer_api_keys_user
                    ON developer_api_keys(user_id)
                """)

                # DEVELOPER API ANALYTICS EVENTS
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS developer_api_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        api_key_id INTEGER NOT NULL,
                        event_type TEXT NOT NULL CHECK (
                            event_type IN (
                                'INSPECTION',
                                'RATE_LIMIT'
                            )
                        ),
                        gateway_status TEXT CHECK (
                            gateway_status IS NULL OR gateway_status IN (
                                'PERMITTED',
                                'APPROVAL_REQUIRED',
                                'REJECTED'
                            )
                        ),
                        risk_score INTEGER CHECK (
                            risk_score IS NULL OR
                            (risk_score >= 0 AND risk_score <= 100)
                        ),
                        duplicate_inspection INTEGER NOT NULL DEFAULT 0
                            CHECK (duplicate_inspection IN (0, 1)),
                        http_status INTEGER NOT NULL,
                        created_at INTEGER NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(id),
                        FOREIGN KEY (api_key_id)
                            REFERENCES developer_api_keys(id)
                    )
                """)

                connection.execute("""
                    CREATE INDEX IF NOT EXISTS
                    idx_developer_api_events_user_time
                    ON developer_api_events(user_id, created_at DESC)
                """)

                connection.execute("""
                    CREATE INDEX IF NOT EXISTS
                    idx_developer_api_events_key_time
                    ON developer_api_events(api_key_id, created_at DESC)
                """)

                connection.execute("""
                    CREATE INDEX IF NOT EXISTS
                    idx_developer_api_events_type
                    ON developer_api_events(user_id, event_type, gateway_status)
                """)

                # USER AUTHENTICATION SESSIONS
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        token_hash TEXT NOT NULL UNIQUE,
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        revoked_at INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                """)

                connection.execute("""
                    CREATE INDEX IF NOT EXISTS
                    idx_user_sessions_user
                    ON user_sessions(user_id)
                """)

                connection.execute("""
                    CREATE INDEX IF NOT EXISTS
                    idx_user_sessions_expiry
                    ON user_sessions(expires_at)
                """)

                # EMAIL VERIFICATION AND APPROVAL KEY RECOVERY TOKENS
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS account_tokens (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        token_hash TEXT NOT NULL UNIQUE,
                        purpose TEXT NOT NULL CHECK (
                            purpose IN (
                                'EMAIL_VERIFICATION',
                                'APPROVAL_KEY_RECOVERY',
                                'PASSWORD_RESET'
                            )
                        ),
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        used_at INTEGER,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                """)

                # Migrate existing databases to support password reset tokens.
                token_schema = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='account_tokens'"
                ).fetchone()

                if token_schema and 'PASSWORD_RESET' not in token_schema[0]:
                    connection.execute("""
                        CREATE TABLE account_tokens_new (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER NOT NULL,
                            token_hash TEXT NOT NULL UNIQUE,
                            purpose TEXT NOT NULL CHECK (
                                purpose IN (
                                    'EMAIL_VERIFICATION',
                                    'APPROVAL_KEY_RECOVERY',
                                    'PASSWORD_RESET'
                                )
                            ),
                            created_at INTEGER NOT NULL,
                            expires_at INTEGER NOT NULL,
                            used_at INTEGER,
                            FOREIGN KEY (user_id) REFERENCES users(id)
                        )
                    """)

                    connection.execute("""
                        INSERT INTO account_tokens_new (
                            id, user_id, token_hash, purpose,
                            created_at, expires_at, used_at
                        )
                        SELECT
                            id, user_id, token_hash, purpose,
                            created_at, expires_at, used_at
                        FROM account_tokens
                    """)

                    connection.execute("DROP TABLE account_tokens")
                    connection.execute(
                        "ALTER TABLE account_tokens_new RENAME TO account_tokens"
                    )
                connection.execute("""
                    CREATE INDEX IF NOT EXISTS
                    idx_account_tokens_user_purpose
                    ON account_tokens(user_id, purpose)
                """)

                connection.execute("""
                    CREATE INDEX IF NOT EXISTS
                    idx_account_tokens_expiry
                    ON account_tokens(expires_at)
                """)

                # Add ownership to existing approvals without deleting records.
                approval_columns = {
                    row[1] for row in connection.execute(
                        "PRAGMA table_info(pending_approvals)"
                    ).fetchall()
                }

                if "owner_user_id" not in approval_columns:
                    connection.execute("""
                        ALTER TABLE pending_approvals
                        ADD COLUMN owner_user_id INTEGER
                        REFERENCES users(id)
                    """)

                connection.execute("""
                    CREATE INDEX IF NOT EXISTS
                    idx_pending_approvals_transaction
                    ON pending_approvals(transaction_id)
                """)

                connection.execute("""
                    CREATE INDEX IF NOT EXISTS
                    idx_pending_approvals_owner
                    ON pending_approvals(owner_user_id)
                """)


                # PERSISTENT NEAR WALLET BEHAVIOUR INVESTIGATION HISTORY
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS wallet_behavior_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        account_id TEXT NOT NULL,
                        network TEXT NOT NULL CHECK (
                            network IN ('mainnet', 'testnet')
                        ),
                        risk_score INTEGER NOT NULL CHECK (
                            risk_score >= 0 AND risk_score <= 100
                        ),
                        risk_level TEXT NOT NULL CHECK (
                            risk_level IN ('LOW', 'MEDIUM', 'HIGH')
                        ),
                        transaction_count INTEGER NOT NULL,
                        created_at INTEGER NOT NULL,
                        report_json TEXT NOT NULL
                    )
                """)

                # Safely add ownership to existing wallet history records.
                wallet_history_columns = {
                    row[1] for row in connection.execute(
                        "PRAGMA table_info(wallet_behavior_history)"
                    ).fetchall()
                }

                if "owner_user_id" not in wallet_history_columns:
                    connection.execute("""
                        ALTER TABLE wallet_behavior_history
                        ADD COLUMN owner_user_id INTEGER
                        REFERENCES users(id)
                    """)

                connection.execute("""
                    CREATE INDEX IF NOT EXISTS
                    idx_wallet_behavior_history_owner
                    ON wallet_behavior_history(
                        owner_user_id, account_id, network, created_at DESC
                    )
                """)
                connection.execute("""
                    CREATE INDEX IF NOT EXISTS
                    idx_wallet_behavior_history_account
                    ON wallet_behavior_history(
                        account_id, network, created_at DESC
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

    def claim_processed(self, transaction_id):
        """Atomically claim a transaction ID for simulated processing."""

        transaction_id = self._validate_transaction_id(transaction_id)

        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO processed_transactions
                    (transaction_id)
                    VALUES (?)
                    """,
                    (transaction_id,)
                )

        return cursor.rowcount == 1

    def register_inspection(self, transaction_id):

        transaction_id = self._validate_transaction_id(transaction_id)

        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO inspected_transactions
                    (transaction_id)
                    VALUES (?)
                    """,
                    (transaction_id,)
                )

        return cursor.rowcount == 1

    def is_inspected(self, transaction_id):

        transaction_id = self._validate_transaction_id(transaction_id)

        with closing(self._connect()) as connection:
            result = connection.execute(
                """
                SELECT 1
                FROM inspected_transactions
                WHERE transaction_id = ?
                """,
                (transaction_id,)
            ).fetchone()

        return result is not None

    def create_pending_approval(
        self,
        approval_id,
        transaction_id,
        transaction_json,
        fingerprint,
        created_at,
        expires_at,
        owner_user_id=None
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
                        expires_at,
                        owner_user_id
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        approval_id,
                        transaction_id,
                        transaction_json,
                        fingerprint,
                        created_at,
                        expires_at,
                        owner_user_id
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
    def get_approval(self, approval_id, owner_user_id=None):

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT *
                FROM pending_approvals
                WHERE approval_id = ?
                  AND (? IS NULL OR owner_user_id = ?)
                """,
                (approval_id, owner_user_id, owner_user_id)
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
            "consumed_at",
            "owner_user_id"
        ]

        return dict(zip(columns, row))

    def approve_pending_approval(
        self, approval_id, current_time, owner_user_id=None
    ):

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
                      AND (? IS NULL OR owner_user_id = ?)
                    """,
                    (
                        current_time,
                        approval_id,
                        current_time,
                        owner_user_id,
                        owner_user_id
                    )
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
                      AND (? IS NULL OR owner_user_id = ?)
                    """,
                    (
                        approval_id,
                        current_time,
                        owner_user_id,
                        owner_user_id
                    )
                )

                return False

    def consume_approved_approval(
        self, approval_id, current_time, owner_user_id=None
    ):

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
                      AND (? IS NULL OR owner_user_id = ?)
                    """,
                    (
                        current_time,
                        approval_id,
                        current_time,
                        owner_user_id,
                        owner_user_id
                    )
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
                      AND (? IS NULL OR owner_user_id = ?)
                    """,
                    (
                        approval_id,
                        current_time,
                        owner_user_id,
                        owner_user_id
                    )
                )

                return False
    def get_approvals(
        self, status=None, limit=50, owner_user_id=None
    ):

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
        conditions = []

        if status is not None:
            conditions.append("status = ?")
            parameters.append(status)

        if owner_user_id is not None:
            if type(owner_user_id) is not int or owner_user_id <= 0:
                raise ValueError("Invalid owner user ID")
            conditions.append("owner_user_id = ?")
            parameters.append(owner_user_id)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

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
    # ==========================================
    # TRANSACTION ASSESSMENT HISTORY
    # ==========================================

    def _ensure_assessments_table(self, connection):

        connection.execute("""
            CREATE TABLE IF NOT EXISTS transaction_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT NOT NULL,
                network TEXT NOT NULL,
                amount REAL NOT NULL,
                recipient_address TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                decision TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                execution_status TEXT NOT NULL DEFAULT 'NOT_EXECUTED',
                assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_assessment_transaction
            ON transaction_assessments(transaction_id)
        """)

    def record_transaction_assessment(
        self,
        transaction,
        security_report,
        execution_status="NOT_EXECUTED"
    ):

        import json

        if not isinstance(transaction, dict):
            raise ValueError("Transaction must be a dictionary")

        if not isinstance(security_report, dict):
            raise ValueError("Security report must be a dictionary")

        transaction_id = self._validate_transaction_id(
            transaction.get("transaction_id")
        )

        network = transaction.get("network", "")

        if not isinstance(network, str) or not network.strip():
            raise ValueError("Valid network is required")

        amount = transaction.get("amount")

        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            raise ValueError("Valid transaction amount is required")

        risk_score = security_report.get("risk_score")
        decision = security_report.get("decision")
        reasons = security_report.get("reasons", [])

        if type(risk_score) is not int or not 0 <= risk_score <= 100:
            raise ValueError("Invalid risk score")

        if decision not in (
            "ALLOW",
            "BLOCK",
            "REQUIRE_CONFIRMATION"
        ):
            raise ValueError("Invalid security decision")

        if not isinstance(reasons, list):
            raise ValueError("Invalid security reasons")

        if execution_status not in (
            "NOT_EXECUTED",
            "AWAITING_CONFIRMATION",
            "APPROVAL_REQUIRED",
            "EXECUTED",
            "BLOCKED",
            "FAILED"
        ):
            raise ValueError("Invalid execution status")

        recipient = transaction.get("recipient_address", "")

        if not isinstance(recipient, str):
            raise ValueError("Invalid recipient address")

        with closing(self._connect()) as connection:
            with connection:

                self._ensure_assessments_table(connection)

                connection.execute("""
                    INSERT INTO transaction_assessments (
                        transaction_id,
                        network,
                        amount,
                        recipient_address,
                        risk_score,
                        decision,
                        reasons_json,
                        execution_status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    transaction_id,
                    network.strip().lower(),
                    amount,
                    recipient,
                    risk_score,
                    decision,
                    json.dumps(reasons),
                    execution_status
                ))

    def get_assessment_history(self, limit=50):

        import json

        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("Limit must be between 1 and 200")

        with closing(self._connect()) as connection:

            self._ensure_assessments_table(connection)

            rows = connection.execute("""
                SELECT
                    id,
                    transaction_id,
                    network,
                    amount,
                    recipient_address,
                    risk_score,
                    decision,
                    reasons_json,
                    execution_status,
                    assessed_at
                FROM transaction_assessments
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()

        columns = [
            "id",
            "transaction_id",
            "network",
            "amount",
            "recipient_address",
            "risk_score",
            "decision",
            "reasons_json",
            "execution_status",
            "assessed_at"
        ]

        history = []

        for row in rows:
            record = dict(zip(columns, row))
            record["reasons"] = json.loads(
                record.pop("reasons_json")
            )
            history.append(record)

        return history


    # ==========================================
    # PERSONAL USER ACCOUNT STORAGE
    # ==========================================

    def create_user(
        self,
        email,
        password_hash,
        password_salt,
        created_at
    ):
        import re

        if not isinstance(email, str):
            raise ValueError("Valid email address is required")

        email = email.strip().lower()

        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise ValueError("Invalid email address")

        if not isinstance(password_hash, str) or not password_hash:
            raise ValueError("Password hash is required")

        if not isinstance(password_salt, str) or not password_salt:
            raise ValueError("Password salt is required")

        if type(created_at) is not int or created_at <= 0:
            raise ValueError("Invalid account creation time")

        with closing(self._connect()) as connection:
            with connection:
                try:
                    cursor = connection.execute(
                        """
                        INSERT INTO users (
                            email,
                            password_hash,
                            password_salt,
                            created_at,
                            updated_at
                        )
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            email,
                            password_hash,
                            password_salt,
                            created_at,
                            created_at
                        )
                    )
                except sqlite3.IntegrityError:
                    raise ValueError("An account with this email already exists")

                return cursor.lastrowid

    def get_user_by_email(self, email):

        if not isinstance(email, str) or not email.strip():
            raise ValueError("Valid email address is required")

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    email,
                    password_hash,
                    password_salt,
                    approval_key_hash,
                    email_verified,
                    created_at,
                    updated_at
                FROM users
                WHERE email = ?
                """,
                (email.strip().lower(),)
            ).fetchone()

        if row is None:
            return None

        columns = [
            "id",
            "email",
            "password_hash",
            "password_salt",
            "approval_key_hash",
            "email_verified",
            "created_at",
            "updated_at"
        ]

        return dict(zip(columns, row))

    def get_user_by_id(self, user_id):

        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    email,
                    approval_key_hash,
                    email_verified,
                    created_at,
                    updated_at
                FROM users
                WHERE id = ?
                """,
                (user_id,)
            ).fetchone()

        if row is None:
            return None

        columns = [
            "id",
            "email",
            "approval_key_hash",
            "email_verified",
            "created_at",
            "updated_at"
        ]

        return dict(zip(columns, row))

    def update_user_password(
        self,
        user_id,
        password_hash,
        password_salt,
        updated_at
    ):

        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        if not isinstance(password_hash, str) or not password_hash:
            raise ValueError("Password hash is required")

        if not isinstance(password_salt, str) or not password_salt:
            raise ValueError("Password salt is required")

        with closing(self._connect()) as connection:
            with connection:
                result = connection.execute(
                    """
                    UPDATE users
                    SET password_hash = ?,
                        password_salt = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        password_hash,
                        password_salt,
                        updated_at,
                        user_id
                    )
                )

        return result.rowcount == 1

    def set_user_approval_key(
        self,
        user_id,
        approval_key_hash,
        updated_at
    ):

        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        if (
            not isinstance(approval_key_hash, str)
            or not approval_key_hash
        ):
            raise ValueError("Approval Key hash is required")

        with closing(self._connect()) as connection:
            with connection:
                result = connection.execute(
                    """
                    UPDATE users
                    SET approval_key_hash = ?,
                        updated_at = ?
                    WHERE id = ?
                      AND email_verified = 1
                    """,
                    (
                        approval_key_hash,
                        updated_at,
                        user_id
                    )
                )

        return result.rowcount == 1

    def verify_user_email(self, user_id, updated_at):

        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        with closing(self._connect()) as connection:
            with connection:
                result = connection.execute(
                    """
                    UPDATE users
                    SET email_verified = 1,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (updated_at, user_id)
                )

        return result.rowcount == 1


    # ==========================================
    # USER SESSION MANAGEMENT
    # ==========================================

    def create_user_session(
        self, user_id, token_hash, created_at, expires_at
    ):
        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        if not isinstance(token_hash, str) or not token_hash:
            raise ValueError("Session token hash is required")

        if type(created_at) is not int or type(expires_at) is not int:
            raise ValueError("Invalid session timestamps")

        if expires_at <= created_at:
            raise ValueError("Session expiry must be in the future")

        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    """
                    INSERT INTO user_sessions (
                        user_id, token_hash, created_at, expires_at
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (user_id, token_hash, created_at, expires_at)
                )

        return cursor.lastrowid

    def get_valid_user_session(self, token_hash, current_time):
        if not isinstance(token_hash, str) or not token_hash:
            raise ValueError("Session token hash is required")

        if type(current_time) is not int:
            raise ValueError("Invalid current timestamp")

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT
                    id, user_id, token_hash, created_at, expires_at
                FROM user_sessions
                WHERE token_hash = ?
                  AND revoked_at IS NULL
                  AND expires_at > ?
                """,
                (token_hash, current_time)
            ).fetchone()

        if row is None:
            return None

        columns = [
            "id", "user_id", "token_hash", "created_at", "expires_at"
        ]
        return dict(zip(columns, row))

    def revoke_user_session(self, token_hash, revoked_at):
        if not isinstance(token_hash, str) or not token_hash:
            raise ValueError("Session token hash is required")

        if type(revoked_at) is not int:
            raise ValueError("Invalid revocation timestamp")

        with closing(self._connect()) as connection:
            with connection:
                result = connection.execute(
                    """
                    UPDATE user_sessions
                    SET revoked_at = ?
                    WHERE token_hash = ?
                      AND revoked_at IS NULL
                    """,
                    (revoked_at, token_hash)
                )

        return result.rowcount == 1

    def revoke_all_user_sessions(self, user_id, revoked_at):
        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        if type(revoked_at) is not int:
            raise ValueError("Invalid revocation timestamp")

        with closing(self._connect()) as connection:
            with connection:
                result = connection.execute(
                    """
                    UPDATE user_sessions
                    SET revoked_at = ?
                    WHERE user_id = ?
                      AND revoked_at IS NULL
                    """,
                    (revoked_at, user_id)
                )

        return result.rowcount


    # ==========================================
    # EMAIL VERIFICATION AND RECOVERY TOKENS
    # ==========================================

    def create_account_token(
        self, user_id, token_hash, purpose, created_at, expires_at
    ):
        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        if not isinstance(token_hash, str) or not token_hash:
            raise ValueError("Token hash is required")

        allowed_purposes = {
            "EMAIL_VERIFICATION",
            "APPROVAL_KEY_RECOVERY",
            "PASSWORD_RESET"
        }

        if purpose not in allowed_purposes:
            raise ValueError("Invalid account token purpose")

        if type(created_at) is not int or type(expires_at) is not int:
            raise ValueError("Invalid token timestamps")

        if expires_at <= created_at:
            raise ValueError("Token expiry must be in the future")

        with closing(self._connect()) as connection:
            with connection:
                user = connection.execute(
                    "SELECT id FROM users WHERE id = ?",
                    (user_id,)
                ).fetchone()

                if user is None:
                    raise ValueError("User account not found")

                connection.execute(
                    """
                    UPDATE account_tokens
                    SET used_at = ?
                    WHERE user_id = ?
                      AND purpose = ?
                      AND used_at IS NULL
                    """,
                    (created_at, user_id, purpose)
                )

                cursor = connection.execute(
                    """
                    INSERT INTO account_tokens (
                        user_id,
                        token_hash,
                        purpose,
                        created_at,
                        expires_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        user_id,
                        token_hash,
                        purpose,
                        created_at,
                        expires_at
                    )
                )

        return cursor.lastrowid

    def get_valid_account_token(
        self, token_hash, purpose, current_time
    ):
        if not isinstance(token_hash, str) or not token_hash:
            raise ValueError("Token hash is required")

        if purpose not in {
            "EMAIL_VERIFICATION",
            "APPROVAL_KEY_RECOVERY",
            "PASSWORD_RESET"
        }:
            raise ValueError("Invalid account token purpose")

        if type(current_time) is not int:
            raise ValueError("Invalid current timestamp")

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    user_id,
                    token_hash,
                    purpose,
                    created_at,
                    expires_at
                FROM account_tokens
                WHERE token_hash = ?
                  AND purpose = ?
                  AND used_at IS NULL
                  AND expires_at > ?
                """,
                (token_hash, purpose, current_time)
            ).fetchone()

        if row is None:
            return None

        columns = [
            "id",
            "user_id",
            "token_hash",
            "purpose",
            "created_at",
            "expires_at"
        ]

        return dict(zip(columns, row))

    def consume_account_token(
        self, token_hash, purpose, current_time
    ):
        if not isinstance(token_hash, str) or not token_hash:
            raise ValueError("Token hash is required")

        if purpose not in {
            "EMAIL_VERIFICATION",
            "APPROVAL_KEY_RECOVERY",
            "PASSWORD_RESET"
        }:
            raise ValueError("Invalid account token purpose")

        if type(current_time) is not int:
            raise ValueError("Invalid current timestamp")

        with closing(self._connect()) as connection:
            with connection:
                result = connection.execute(
                    """
                    UPDATE account_tokens
                    SET used_at = ?
                    WHERE token_hash = ?
                      AND purpose = ?
                      AND used_at IS NULL
                      AND expires_at > ?
                    """,
                    (
                        current_time,
                        token_hash,
                        purpose,
                        current_time
                    )
                )

        return result.rowcount == 1


    def delete_unverified_user(self, user_id):
        """Delete an unverified account and its associated records."""

        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        with closing(self._connect()) as connection:
            with connection:
                user = connection.execute(
                    """
                    SELECT email_verified
                    FROM users
                    WHERE id = ?
                    """,
                    (user_id,)
                ).fetchone()

                if user is None or user[0] != 0:
                    return False

                connection.execute(
                    "DELETE FROM account_tokens WHERE user_id = ?",
                    (user_id,)
                )

                connection.execute(
                    "DELETE FROM user_sessions WHERE user_id = ?",
                    (user_id,)
                )

                connection.execute(
                    "DELETE FROM pending_approvals WHERE owner_user_id = ?",
                    (user_id,)
                )

                result = connection.execute(
                    """
                    DELETE FROM users
                    WHERE id = ? AND email_verified = 0
                    """,
                    (user_id,)
                )

        return result.rowcount == 1

    # ==========================================
    # ATOMIC EMAIL VERIFICATION
    # ==========================================

    def verify_email_with_token(self, token_hash, current_time):
        if not isinstance(token_hash, str) or not token_hash:
            raise ValueError("Verification token hash is required")

        if type(current_time) is not int or current_time <= 0:
            raise ValueError("Invalid verification timestamp")

        with closing(self._connect()) as connection:
            with connection:
                token = connection.execute(
                    """
                    SELECT id, user_id
                    FROM account_tokens
                    WHERE token_hash = ?
                      AND purpose = 'EMAIL_VERIFICATION'
                      AND used_at IS NULL
                      AND expires_at > ?
                    """,
                    (token_hash, current_time)
                ).fetchone()

                if token is None:
                    return False

                token_id, user_id = token

                updated = connection.execute(
                    """
                    UPDATE users
                    SET email_verified = 1,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (current_time, user_id)
                )

                if updated.rowcount != 1:
                    raise ValueError(
                        "Verification failed: user account not found"
                    )

                consumed = connection.execute(
                    """
                    UPDATE account_tokens
                    SET used_at = ?
                    WHERE id = ?
                      AND used_at IS NULL
                      AND expires_at > ?
                    """,
                    (current_time, token_id, current_time)
                )

                if consumed.rowcount != 1:
                    raise ValueError(
                        "Verification failed: token could not be consumed"
                    )

                return True

    # ==========================================
    # DEVELOPER API KEY MANAGEMENT
    # ==========================================

    def create_developer_api_key(
        self, user_id, name, key_hash, key_prefix, created_at
    ):
        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80:
            raise ValueError("API key name must contain 1 to 80 characters")

        if not isinstance(key_hash, str) or len(key_hash) != 64:
            raise ValueError("Invalid API key hash")

        if not isinstance(key_prefix, str) or not key_prefix.strip():
            raise ValueError("API key prefix is required")

        if type(created_at) is not int or created_at <= 0:
            raise ValueError("Invalid API key creation timestamp")

        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    """
                    INSERT INTO developer_api_keys (
                        user_id, name, key_hash, key_prefix, created_at
                    )
                    SELECT id, ?, ?, ?, ?
                    FROM users
                    WHERE id = ? AND email_verified = 1
                    """,
                    (
                        name.strip(),
                        key_hash,
                        key_prefix.strip(),
                        created_at,
                        user_id
                    )
                )

        if cursor.rowcount != 1:
            raise ValueError("Verified user account not found")

        return cursor.lastrowid

    def get_developer_api_key(self, key_hash):
        if not isinstance(key_hash, str) or len(key_hash) != 64:
            raise ValueError("Invalid API key hash")

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT
                    k.id,
                    k.user_id,
                    k.name,
                    k.key_hash,
                    k.key_prefix,
                    k.created_at,
                    k.last_used_at
                FROM developer_api_keys AS k
                JOIN users AS u ON u.id = k.user_id
                WHERE k.key_hash = ?
                  AND k.revoked_at IS NULL
                  AND u.email_verified = 1
                """,
                (key_hash,)
            ).fetchone()

        if row is None:
            return None

        columns = [
            "id", "user_id", "name", "key_hash",
            "key_prefix", "created_at", "last_used_at"
        ]
        return dict(zip(columns, row))

    def list_developer_api_keys(self, user_id):
        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT
                    id, name, key_prefix, created_at,
                    last_used_at, revoked_at
                FROM developer_api_keys
                WHERE user_id = ?
                ORDER BY created_at DESC, id DESC
                """,
                (user_id,)
            ).fetchall()

        columns = [
            "id", "name", "key_prefix",
            "created_at", "last_used_at", "revoked_at"
        ]
        return [dict(zip(columns, row)) for row in rows]

    def update_developer_api_key_usage(self, key_id, current_time):
        if type(key_id) is not int or key_id <= 0:
            raise ValueError("Invalid API key ID")

        if type(current_time) is not int or current_time <= 0:
            raise ValueError("Invalid usage timestamp")

        with closing(self._connect()) as connection:
            with connection:
                result = connection.execute(
                    """
                    UPDATE developer_api_keys
                    SET last_used_at = ?
                    WHERE id = ? AND revoked_at IS NULL
                    """,
                    (current_time, key_id)
                )

        return result.rowcount == 1

    def record_developer_api_event(
        self,
        user_id,
        api_key_id,
        event_type,
        http_status,
        created_at,
        gateway_status=None,
        risk_score=None,
        duplicate_inspection=False
    ):
        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        if type(api_key_id) is not int or api_key_id <= 0:
            raise ValueError("Invalid API key ID")

        if event_type not in ("INSPECTION", "RATE_LIMIT"):
            raise ValueError("Invalid analytics event type")

        if type(http_status) is not int or not 100 <= http_status <= 599:
            raise ValueError("Invalid HTTP status")

        if type(created_at) is not int or created_at <= 0:
            raise ValueError("Invalid event timestamp")

        if gateway_status is not None and gateway_status not in (
            "PERMITTED", "APPROVAL_REQUIRED", "REJECTED"
        ):
            raise ValueError("Invalid gateway status")

        if risk_score is not None:
            if type(risk_score) is not int or not 0 <= risk_score <= 100:
                raise ValueError("Invalid risk score")

        if type(duplicate_inspection) is not bool:
            raise ValueError("Duplicate inspection flag must be boolean")

        if event_type == "RATE_LIMIT" and gateway_status is not None:
            raise ValueError("Rate-limit events cannot have a gateway status")

        if event_type == "RATE_LIMIT" and risk_score is not None:
            raise ValueError("Rate-limit events cannot have a risk score")

        with closing(self._connect()) as connection:
            with connection:
                result = connection.execute(
                    """
                    INSERT INTO developer_api_events (
                        user_id, api_key_id, event_type,
                        gateway_status, risk_score,
                        duplicate_inspection, http_status, created_at
                    )
                    SELECT
                        k.user_id, k.id, ?, ?, ?, ?, ?, ?
                    FROM developer_api_keys AS k
                    JOIN users AS u ON u.id = k.user_id
                    WHERE k.id = ?
                      AND k.user_id = ?
                      AND u.email_verified = 1
                    """,
                    (
                        event_type,
                        gateway_status,
                        risk_score,
                        int(duplicate_inspection),
                        http_status,
                        created_at,
                        api_key_id,
                        user_id
                    )
                )

        if result.rowcount != 1:
            raise ValueError("Developer API key ownership could not be verified")

        return result.lastrowid

    def get_developer_api_analytics(
        self,
        user_id,
        limit=50,
        api_key_id=None
    ):
        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("Limit must be between 1 and 200")

        if api_key_id is not None:
            if type(api_key_id) is not int or api_key_id <= 0:
                raise ValueError("Invalid API key ID")

        with closing(self._connect()) as connection:
            ownership = ""
            parameters = [user_id]

            if api_key_id is not None:
                ownership = " AND api_key_id = ?"
                parameters.append(api_key_id)

            summary = connection.execute(
                """
                SELECT
                    COUNT(*) AS total_events,
                    SUM(CASE WHEN event_type = 'INSPECTION'
                        THEN 1 ELSE 0 END) AS total_inspections,
                    SUM(CASE WHEN event_type = 'RATE_LIMIT'
                        THEN 1 ELSE 0 END) AS rate_limit_events,
                    SUM(CASE WHEN gateway_status = 'PERMITTED'
                        THEN 1 ELSE 0 END) AS permitted,
                    SUM(CASE WHEN gateway_status = 'APPROVAL_REQUIRED'
                        THEN 1 ELSE 0 END) AS approval_required,
                    SUM(CASE WHEN gateway_status = 'REJECTED'
                        THEN 1 ELSE 0 END) AS rejected,
                    SUM(CASE WHEN duplicate_inspection = 1
                        THEN 1 ELSE 0 END) AS duplicate_inspections,
                    AVG(CASE WHEN event_type = 'INSPECTION'
                        THEN risk_score END) AS average_risk_score,
                    MAX(CASE WHEN event_type = 'INSPECTION'
                        THEN risk_score END) AS highest_risk_score
                FROM developer_api_events
                WHERE user_id = ?
                """ + ownership,
                parameters
            ).fetchone()

            events = connection.execute(
                """
                SELECT
                    e.id,
                    e.api_key_id,
                    k.name AS api_key_name,
                    e.event_type,
                    e.gateway_status,
                    e.risk_score,
                    e.duplicate_inspection,
                    e.http_status,
                    e.created_at
                FROM developer_api_events AS e
                JOIN developer_api_keys AS k ON k.id = e.api_key_id
                WHERE e.user_id = ?
                """ + ownership + """
                ORDER BY e.created_at DESC, e.id DESC
                LIMIT ?
                """,
                parameters + [limit]
            ).fetchall()

        summary_columns = [
            "total_events",
            "total_inspections",
            "rate_limit_events",
            "permitted",
            "approval_required",
            "rejected",
            "duplicate_inspections",
            "average_risk_score",
            "highest_risk_score"
        ]

        summary_data = dict(zip(summary_columns, summary))

        for key, value in summary_data.items():
            if key in ("average_risk_score",):
                summary_data[key] = round(value, 2) if value is not None else None
            elif value is None:
                summary_data[key] = 0

        event_columns = [
            "id", "api_key_id", "api_key_name",
            "event_type", "gateway_status", "risk_score",
            "duplicate_inspection", "http_status", "created_at"
        ]

        return {
            "summary": summary_data,
            "recent_events": [
                dict(zip(event_columns, row)) for row in events
            ]
        }

    def revoke_developer_api_key(self, user_id, key_id, revoked_at):
        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        if type(key_id) is not int or key_id <= 0:
            raise ValueError("Invalid API key ID")

        if type(revoked_at) is not int or revoked_at <= 0:
            raise ValueError("Invalid revocation timestamp")

        with closing(self._connect()) as connection:
            with connection:
                result = connection.execute(
                    """
                    UPDATE developer_api_keys
                    SET revoked_at = ?
                    WHERE id = ?
                      AND user_id = ?
                      AND revoked_at IS NULL
                    """,
                    (revoked_at, key_id, user_id)
                )

        return result.rowcount == 1


    # ==========================================
    # NEAR WALLET BEHAVIOUR INVESTIGATION HISTORY
    # ==========================================

    def _validate_wallet_history_owner_user_id(self, owner_user_id):
        if owner_user_id is None:
            return None

        if type(owner_user_id) is not int or owner_user_id <= 0:
            raise ValueError("Invalid wallet history owner ID")

        return owner_user_id

    def save_wallet_behavior_report(
        self, account_id, network, report, created_at=None,
        owner_user_id=None
    ):
        import time

        owner_user_id = self._validate_wallet_history_owner_user_id(
            owner_user_id
        )

        if not isinstance(account_id, str) or not account_id.strip():
            raise ValueError("Wallet account ID is required")

        account_id = account_id.strip().lower()

        if network not in ("mainnet", "testnet"):
            raise ValueError("Invalid NEAR network")

        if not isinstance(report, dict):
            raise ValueError("Investigation report must be an object")

        if report.get("analysis_type") != (
            "deterministic_wallet_behavior_analysis"
        ):
            raise ValueError("Unsupported wallet investigation report")

        if report.get("account_id") != account_id:
            raise ValueError("Report account does not match requested account")

        assessment = report.get("behavioural_assessment")
        if not isinstance(assessment, dict):
            raise ValueError("Invalid behavioural assessment")

        risk_score = assessment.get("risk_score")
        risk_level = assessment.get("risk_level")
        transaction_count = report.get("transaction_count")

        if type(risk_score) is not int or not 0 <= risk_score <= 100:
            raise ValueError("Invalid wallet behaviour risk score")

        if risk_level not in ("LOW", "MEDIUM", "HIGH"):
            raise ValueError("Invalid wallet behaviour risk level")

        if type(transaction_count) is not int or transaction_count < 1:
            raise ValueError("Invalid transaction count")

        if created_at is None:
            created_at = int(time.time())

        if type(created_at) is not int or created_at <= 0:
            raise ValueError("Invalid investigation timestamp")

        report_json = json.dumps(
            report, sort_keys=True, separators=(",", ":")
        )

        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    """
                    INSERT INTO wallet_behavior_history (
                        account_id, network, risk_score, risk_level,
                        transaction_count, created_at, report_json,
                        owner_user_id
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        account_id, network, risk_score, risk_level,
                        transaction_count, created_at, report_json,
                        owner_user_id
                    )
                )

        return cursor.lastrowid

    def get_wallet_behavior_history(
        self, account_id, network="mainnet", limit=20,
        owner_user_id=None
    ):
        owner_user_id = self._validate_wallet_history_owner_user_id(
            owner_user_id
        )

        if not isinstance(account_id, str) or not account_id.strip():
            raise ValueError("Wallet account ID is required")

        if network not in ("mainnet", "testnet"):
            raise ValueError("Invalid NEAR network")

        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("History limit must be between 1 and 100")

        query = """
            SELECT id, account_id, network, risk_score, risk_level,
                   transaction_count, created_at
            FROM wallet_behavior_history
            WHERE account_id = ? AND network = ?
        """
        parameters = [
            account_id.strip().lower(),
            network
        ]

        if owner_user_id is not None:
            query += " AND owner_user_id = ?"
            parameters.append(owner_user_id)

        query += """
            ORDER BY created_at DESC, id DESC
            LIMIT ?
        """
        parameters.append(limit)

        with closing(self._connect()) as connection:
            rows = connection.execute(
                query, tuple(parameters)
            ).fetchall()

        columns = (
            "id", "account_id", "network", "risk_score", "risk_level",
            "transaction_count", "created_at"
        )
        return [dict(zip(columns, row)) for row in rows]

    def get_wallet_behavior_report(
        self, report_id, owner_user_id=None
    ):
        owner_user_id = self._validate_wallet_history_owner_user_id(
            owner_user_id
        )

        if type(report_id) is not int or report_id <= 0:
            raise ValueError("Invalid investigation report ID")

        query = """
            SELECT id, account_id, network, risk_score, risk_level,
                   transaction_count, created_at, report_json
            FROM wallet_behavior_history
            WHERE id = ?
        """
        parameters = [report_id]

        if owner_user_id is not None:
            query += " AND owner_user_id = ?"
            parameters.append(owner_user_id)

        with closing(self._connect()) as connection:
            row = connection.execute(
                query, tuple(parameters)
            ).fetchone()

        if row is None:
            return None

        columns = (
            "id", "account_id", "network", "risk_score", "risk_level",
            "transaction_count", "created_at", "report_json"
        )
        result = dict(zip(columns, row))
        result["report"] = json.loads(result.pop("report_json"))
        return result
