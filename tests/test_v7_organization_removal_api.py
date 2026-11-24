import unittest
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient

from app import api
from app.auth import hash_password
from app.storage import SQLiteTransactionTracker


class TestV7OrganizationRemovalAPI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_dir.name) / "v7_removal.db"

        self.tracker = SQLiteTransactionTracker(database_path)
        api.tracker = self.tracker
        self.client = TestClient(api.app)

        now = int(time.time())
        password_hash, password_salt = hash_password("TestPassword123!")

        self.owner_id = self.tracker.create_user(
            "owner@example.com", password_hash, password_salt, now
        )
        self.admin_id = self.tracker.create_user(
            "admin@example.com", password_hash, password_salt, now
        )
        self.developer_id = self.tracker.create_user(
            "developer@example.com", password_hash, password_salt, now
        )
        self.security_id = self.tracker.create_user(
            "security@example.com", password_hash, password_salt, now
        )

        self.organization_id = self.tracker.create_organization(
            self.owner_id, "V7 Removal Test", now
        )

        self.tracker.add_organization_member(
            self.organization_id, self.owner_id,
            self.admin_id, "ADMINISTRATOR", now
        )
        self.tracker.add_organization_member(
            self.organization_id, self.owner_id,
            self.developer_id, "DEVELOPER", now
        )
        self.tracker.add_organization_member(
            self.organization_id, self.owner_id,
            self.security_id, "SECURITY_OFFICER", now
        )

    def tearDown(self):
        self.client.close()
        self.temp_dir.cleanup()

    def call_remove(self, actor_id, target_id, role):
        access = {
            "user": {"id": actor_id},
            "organization": {"role": role}
        }

        with patch.object(
            api, "require_organization_access", return_value=access
        ), patch.object(api, "require_csrf"):
            return self.client.delete(
                f"/organizations/{self.organization_id}/members/{target_id}"
            )

    def test_owner_can_remove_administrator(self):
        response = self.call_remove(
            self.owner_id, self.admin_id, "OWNER"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["membership"]["status"], "REMOVED"
        )

    def test_owner_can_remove_developer(self):
        response = self.call_remove(
            self.owner_id, self.developer_id, "OWNER"
        )

        self.assertEqual(response.status_code, 200)

    def test_administrator_can_remove_developer(self):
        response = self.call_remove(
            self.admin_id, self.developer_id, "ADMINISTRATOR"
        )

        self.assertEqual(response.status_code, 200)

    def test_administrator_cannot_remove_security_officer(self):
        response = self.call_remove(
            self.admin_id, self.security_id, "ADMINISTRATOR"
        )

        self.assertEqual(response.status_code, 403)

    def test_member_cannot_remove_themselves(self):
        response = self.call_remove(
            self.developer_id, self.developer_id, "DEVELOPER"
        )

        self.assertEqual(response.status_code, 403)

    def test_removal_preserves_personal_user_account(self):
        response = self.call_remove(
            self.owner_id, self.developer_id, "OWNER"
        )

        self.assertEqual(response.status_code, 200)

        user = self.tracker.get_user_by_id(self.developer_id)
        self.assertIsNotNone(user)

        access = self.tracker.get_organization_member_access(
            self.organization_id, self.developer_id
        )
        self.assertEqual(access["membership_status"], "REMOVED")


if __name__ == "__main__":
    unittest.main()
