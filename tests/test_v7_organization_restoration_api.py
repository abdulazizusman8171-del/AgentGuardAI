import unittest
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from fastapi import HTTPException

from app import api
from app.auth import hash_password
from app.storage import SQLiteTransactionTracker


class TestV7OrganizationRestorationAPI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database_path = Path(self.temp_dir.name) / "v7_restoration.db"

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
            self.owner_id, "V7 Restoration Test", now
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

    def suspend_target(self, target_id):
        self.tracker.suspend_organization_member(
            self.organization_id,
            self.owner_id,
            target_id,
            int(time.time())
        )

    def call_restore(self, actor_id, target_id, role):
        access = {
            "user": {"id": actor_id},
            "organization": {"role": role}
        }

        with patch.object(
            api, "require_organization_access", return_value=access
        ), patch.object(api, "require_csrf"):
            return self.client.post(
                f"/organizations/{self.organization_id}/members/"
                f"{target_id}/restore"
            )

    def test_owner_can_restore_administrator(self):
        self.suspend_target(self.admin_id)

        response = self.call_restore(
            self.owner_id, self.admin_id, "OWNER"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["membership"]["status"], "ACTIVE"
        )

    def test_owner_can_restore_security_officer(self):
        self.suspend_target(self.security_id)

        response = self.call_restore(
            self.owner_id, self.security_id, "OWNER"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["membership"]["status"], "ACTIVE"
        )

    def test_administrator_can_restore_developer(self):
        self.suspend_target(self.developer_id)

        response = self.call_restore(
            self.admin_id, self.developer_id, "ADMINISTRATOR"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["membership"]["status"], "ACTIVE"
        )

    def test_administrator_cannot_restore_security_officer(self):
        self.suspend_target(self.security_id)

        response = self.call_restore(
            self.admin_id, self.security_id, "ADMINISTRATOR"
        )

        self.assertEqual(response.status_code, 403)

    def test_member_cannot_restore_themselves(self):
        self.suspend_target(self.developer_id)

        response = self.call_restore(
            self.developer_id, self.developer_id, "DEVELOPER"
        )

        self.assertEqual(response.status_code, 403)

    def test_unauthenticated_request_is_rejected(self):
        with patch.object(
            api,
            "require_organization_access",
            side_effect=HTTPException(status_code=401)
        ):
            response = self.client.post(
                f"/organizations/{self.organization_id}/members/"
                f"{self.developer_id}/restore"
            )

        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
