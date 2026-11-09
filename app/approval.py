import hashlib
import json
import secrets
import time

from app.storage import SQLiteTransactionTracker


class ApprovalManager:

    def __init__(self, storage, approval_lifetime=300):

        if not isinstance(storage, SQLiteTransactionTracker):
            raise ValueError("Invalid approval storage")

        if (
            isinstance(approval_lifetime, bool)
            or not isinstance(approval_lifetime, int)
            or approval_lifetime <= 0
        ):
            raise ValueError("Approval lifetime must be positive")

        self.storage = storage
        self.approval_lifetime = approval_lifetime

    @staticmethod
    def fingerprint_transaction(transaction):

        if not isinstance(transaction, dict):
            raise ValueError("Transaction must be a dictionary")

        transaction_json = json.dumps(
            transaction,
            sort_keys=True,
            separators=(",", ":")
        )

        fingerprint = hashlib.sha256(
            transaction_json.encode("utf-8")
        ).hexdigest()

        return transaction_json, fingerprint

    def create_approval(self, transaction):

        if not isinstance(transaction, dict):
            raise ValueError("Transaction must be a dictionary")

        transaction_id = transaction.get("transaction_id")

        if not isinstance(transaction_id, str) or not transaction_id.strip():
            raise ValueError("Valid transaction ID is required")

        transaction_id = transaction_id.strip()

        transaction_json, fingerprint = (
            self.fingerprint_transaction(transaction)
        )

        approval_id = secrets.token_urlsafe(32)

        current_time = int(time.time())
        expires_at = current_time + self.approval_lifetime

        self.storage.create_pending_approval(
            approval_id=approval_id,
            transaction_id=transaction_id,
            transaction_json=transaction_json,
            fingerprint=fingerprint,
            created_at=current_time,
            expires_at=expires_at
        )

        return {
            "approval_id": approval_id,
            "transaction_id": transaction_id,
            "status": "PENDING",
            "expires_at": expires_at,
            "message": "Approval request created successfully."
        }

    def approve_transaction(self, approval_id, transaction):

        if not isinstance(approval_id, str) or not approval_id.strip():
            raise ValueError("Valid approval ID is required")

        if not isinstance(transaction, dict):
            raise ValueError("Transaction must be a dictionary")

        approval = self.storage.get_approval(approval_id)

        if approval is None:
            return {
                "approved": False,
                "message": "Approval request not found."
            }

        if approval["status"] != "PENDING":
            return {
                "approved": False,
                "message": "Approval request is no longer pending."
            }

        transaction_json, fingerprint = (
            self.fingerprint_transaction(transaction)
        )

        if (
            fingerprint != approval["fingerprint"]
            or transaction_json != approval["transaction_json"]
        ):
            return {
                "approved": False,
                "message": "Transaction was modified. Approval refused."
            }

        current_time = int(time.time())

        approved = self.storage.approve_pending_approval(
            approval_id,
            current_time
        )

        if not approved:
            return {
                "approved": False,
                "message": "Approval expired or could not be approved."
            }

        return {
            "approved": True,
            "message": "Transaction approved successfully."
        }

    def consume_approval(self, approval_id, transaction):

        if not isinstance(approval_id, str) or not approval_id.strip():
            raise ValueError("Valid approval ID is required")

        if not isinstance(transaction, dict):
            raise ValueError("Transaction must be a dictionary")

        approval = self.storage.get_approval(approval_id)

        if approval is None:
            return {
                "consumed": False,
                "message": "Approval request not found."
            }

        if approval["status"] != "APPROVED":
            return {
                "consumed": False,
                "message": "Approval is not available for use."
            }

        transaction_json, fingerprint = (
            self.fingerprint_transaction(transaction)
        )

        if (
            fingerprint != approval["fingerprint"]
            or transaction_json != approval["transaction_json"]
        ):
            return {
                "consumed": False,
                "message": "Transaction was modified. Execution refused."
            }

        current_time = int(time.time())

        consumed = self.storage.consume_approved_approval(
            approval_id,
            current_time
        )

        if not consumed:
            return {
                "consumed": False,
                "message": "Approval expired or has already been used."
            }

        return {
            "consumed": True,
            "message": "Approval successfully consumed."
        }
