import tempfile
import unittest
from pathlib import Path

from app.storage import SQLiteTransactionTracker


class TestSQLiteTransactionTracker(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "test.db"
        self.tracker = SQLiteTransactionTracker(self.database)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_new_transaction_is_not_duplicate(self):
        self.assertFalse(
            self.tracker.is_duplicate("transaction-001")
        )

    def test_processed_transaction_is_duplicate(self):
        self.tracker.mark_processed("transaction-002")

        self.assertTrue(
            self.tracker.is_duplicate("transaction-002")
        )

    def test_transaction_remains_duplicate_after_reopening(self):
        self.tracker.mark_processed("transaction-003")

        reopened_tracker = SQLiteTransactionTracker(self.database)

        self.assertTrue(
            reopened_tracker.is_duplicate("transaction-003")
        )

    def test_empty_transaction_id_is_rejected(self):
        with self.assertRaises(ValueError):
            self.tracker.mark_processed("")

    def test_non_string_transaction_id_is_rejected(self):
        with self.assertRaises(ValueError):
            self.tracker.mark_processed(123)

    def test_transaction_history(self):
        self.tracker.mark_processed("transaction-101")
        self.tracker.mark_processed("transaction-102")

        history = self.tracker.get_transaction_history()

        self.assertEqual(len(history), 2)
        self.assertEqual(
            history[0]["transaction_id"],
            "transaction-102"
        )

    def test_empty_transaction_history(self):
        history = self.tracker.get_transaction_history()

        self.assertEqual(history, [])

    def test_invalid_history_limit(self):
        with self.assertRaises(ValueError):
            self.tracker.get_transaction_history(limit=500)

    def test_invalid_approval_status(self):
        with self.assertRaises(ValueError):
            self.tracker.get_approvals(status="INVALID")

    def test_invalid_approval_limit(self):
        with self.assertRaises(ValueError):
            self.tracker.get_approvals(limit=500)

    # ==========================================
    # DEVELOPER API KEY TESTS
    # ==========================================

    def _create_verified_user(self, email):
        from app.auth import hash_password

        password_hash, password_salt = hash_password(
            "TestPassword123!"
        )
        user_id = self.tracker.create_user(
            email,
            password_hash,
            password_salt,
            1000
        )
        self.tracker.verify_user_email(user_id, 1001)
        return user_id

    def test_developer_api_key_creation_and_retrieval(self):
        user_id = self._create_verified_user("developer@example.com")
        key_hash = "a" * 64

        key_id = self.tracker.create_developer_api_key(
            user_id, "Test SDK", key_hash, "ag_live_test", 1002
        )

        self.assertGreater(key_id, 0)

        record = self.tracker.get_developer_api_key(key_hash)

        self.assertEqual(record["user_id"], user_id)
        self.assertEqual(record["name"], "Test SDK")
        self.assertEqual(record["key_hash"], key_hash)

    def test_unverified_user_cannot_create_api_key(self):
        from app.auth import hash_password

        password_hash, password_salt = hash_password(
            "TestPassword123!"
        )
        user_id = self.tracker.create_user(
            "unverified@example.com",
            password_hash,
            password_salt,
            1000
        )

        with self.assertRaises(ValueError):
            self.tracker.create_developer_api_key(
                user_id, "Test SDK", "b" * 64, "ag_live_test", 1002
            )

    def test_api_key_revocation_prevents_retrieval(self):
        user_id = self._create_verified_user("revoke@example.com")
        key_hash = "c" * 64

        key_id = self.tracker.create_developer_api_key(
            user_id, "Revocation Test", key_hash, "ag_live_test", 1002
        )

        self.assertTrue(
            self.tracker.revoke_developer_api_key(user_id, key_id, 1003)
        )
        self.assertIsNone(
            self.tracker.get_developer_api_key(key_hash)
        )

    def test_user_cannot_revoke_another_users_api_key(self):
        first_user = self._create_verified_user("first@example.com")
        second_user = self._create_verified_user("second@example.com")

        key_id = self.tracker.create_developer_api_key(
            first_user, "First Key", "d" * 64, "ag_live_test", 1002
        )

        self.assertFalse(
            self.tracker.revoke_developer_api_key(
                second_user, key_id, 1003
            )
        )
        self.assertIsNotNone(
            self.tracker.get_developer_api_key("d" * 64)
        )

    def test_api_key_usage_timestamp_updates(self):
        user_id = self._create_verified_user("usage@example.com")

        key_id = self.tracker.create_developer_api_key(
            user_id, "Usage Test", "e" * 64, "ag_live_test", 1002
        )

        self.assertTrue(
            self.tracker.update_developer_api_key_usage(key_id, 1005)
        )

        record = self.tracker.get_developer_api_key("e" * 64)
        self.assertEqual(record["last_used_at"], 1005)

    def test_api_key_list_does_not_expose_hash(self):
        user_id = self._create_verified_user("list@example.com")

        self.tracker.create_developer_api_key(
            user_id, "Listed Key", "f" * 64, "ag_live_test", 1002
        )

        records = self.tracker.list_developer_api_keys(user_id)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["name"], "Listed Key")
        self.assertNotIn("key_hash", records[0])


    # ==========================================
    # DEVELOPER ANALYTICS TESTS
    # ==========================================

    def _create_analytics_key(self, email, key_hash):
        user_id = self._create_verified_user(email)
        key_id = self.tracker.create_developer_api_key(
            user_id,
            "Analytics SDK",
            key_hash,
            "ag_live_test",
            1002
        )
        return user_id, key_id

    def test_record_and_retrieve_developer_inspection_analytics(self):
        user_id, key_id = self._create_analytics_key(
            "analytics@example.com", "1" * 64
        )

        self.tracker.record_developer_api_event(
            user_id=user_id,
            api_key_id=key_id,
            event_type="INSPECTION",
            gateway_status="PERMITTED",
            risk_score=15,
            http_status=200,
            created_at=1100
        )

        analytics = self.tracker.get_developer_api_analytics(user_id)

        self.assertEqual(analytics["summary"]["total_events"], 1)
        self.assertEqual(analytics["summary"]["total_inspections"], 1)
        self.assertEqual(analytics["summary"]["permitted"], 1)
        self.assertEqual(analytics["summary"]["rejected"], 0)
        self.assertEqual(analytics["summary"]["average_risk_score"], 15)
        self.assertEqual(len(analytics["recent_events"]), 1)
        self.assertEqual(
            analytics["recent_events"][0]["api_key_id"], key_id
        )

    def test_analytics_counts_outcomes_duplicates_and_rate_limits(self):
        user_id, key_id = self._create_analytics_key(
            "analytics-counts@example.com", "2" * 64
        )

        events = [
            ("PERMITTED", 10, False, 200, 1100),
            ("APPROVAL_REQUIRED", 45, False, 200, 1101),
            ("REJECTED", 100, True, 200, 1102),
        ]

        for status, risk, duplicate, http_status, timestamp in events:
            self.tracker.record_developer_api_event(
                user_id=user_id,
                api_key_id=key_id,
                event_type="INSPECTION",
                gateway_status=status,
                risk_score=risk,
                duplicate_inspection=duplicate,
                http_status=http_status,
                created_at=timestamp
            )

        self.tracker.record_developer_api_event(
            user_id=user_id,
            api_key_id=key_id,
            event_type="RATE_LIMIT",
            http_status=429,
            created_at=1103
        )

        summary = self.tracker.get_developer_api_analytics(
            user_id
        )["summary"]

        self.assertEqual(summary["total_events"], 4)
        self.assertEqual(summary["total_inspections"], 3)
        self.assertEqual(summary["rate_limit_events"], 1)
        self.assertEqual(summary["permitted"], 1)
        self.assertEqual(summary["approval_required"], 1)
        self.assertEqual(summary["rejected"], 1)
        self.assertEqual(summary["duplicate_inspections"], 1)
        self.assertEqual(summary["average_risk_score"], 51.67)
        self.assertEqual(summary["highest_risk_score"], 100)

    def test_developer_analytics_are_isolated_by_owner(self):
        first_user, first_key = self._create_analytics_key(
            "first-analytics@example.com", "3" * 64
        )
        second_user, second_key = self._create_analytics_key(
            "second-analytics@example.com", "4" * 64
        )

        self.tracker.record_developer_api_event(
            user_id=first_user,
            api_key_id=first_key,
            event_type="INSPECTION",
            gateway_status="PERMITTED",
            risk_score=5,
            http_status=200,
            created_at=1200
        )

        self.tracker.record_developer_api_event(
            user_id=second_user,
            api_key_id=second_key,
            event_type="INSPECTION",
            gateway_status="REJECTED",
            risk_score=90,
            http_status=200,
            created_at=1201
        )

        first_summary = self.tracker.get_developer_api_analytics(
            first_user
        )["summary"]

        self.assertEqual(first_summary["total_events"], 1)
        self.assertEqual(first_summary["permitted"], 1)
        self.assertEqual(first_summary["rejected"], 0)

    def test_developer_cannot_record_event_for_another_users_key(self):
        first_user, first_key = self._create_analytics_key(
            "owner-one@example.com", "5" * 64
        )
        second_user = self._create_verified_user(
            "owner-two@example.com"
        )

        with self.assertRaises(ValueError):
            self.tracker.record_developer_api_event(
                user_id=second_user,
                api_key_id=first_key,
                event_type="INSPECTION",
                gateway_status="PERMITTED",
                risk_score=5,
                http_status=200,
                created_at=1300
            )

        self.assertEqual(
            self.tracker.get_developer_api_analytics(
                first_user
            )["summary"]["total_events"],
            0
        )

    def test_empty_developer_analytics(self):
        user_id, _ = self._create_analytics_key(
            "empty-analytics@example.com", "6" * 64
        )

        analytics = self.tracker.get_developer_api_analytics(user_id)

        self.assertEqual(analytics["summary"]["total_events"], 0)
        self.assertEqual(analytics["summary"]["total_inspections"], 0)
        self.assertEqual(analytics["summary"]["rate_limit_events"], 0)
        self.assertEqual(analytics["summary"]["permitted"], 0)
        self.assertEqual(analytics["summary"]["rejected"], 0)
        self.assertIsNone(
            analytics["summary"]["average_risk_score"]
        )
        self.assertEqual(analytics["recent_events"], [])

    def test_developer_analytics_can_filter_by_api_key(self):
        user_id, first_key = self._create_analytics_key(
            "key-filter@example.com", "7" * 64
        )
        second_key = self.tracker.create_developer_api_key(
            user_id,
            "Second Analytics SDK",
            "8" * 64,
            "ag_live_test",
            1003
        )

        for key_id, timestamp in (
            (first_key, 1400),
            (second_key, 1401)
        ):
            self.tracker.record_developer_api_event(
                user_id=user_id,
                api_key_id=key_id,
                event_type="INSPECTION",
                gateway_status="PERMITTED",
                risk_score=20,
                http_status=200,
                created_at=timestamp
            )

        analytics = self.tracker.get_developer_api_analytics(
            user_id,
            api_key_id=first_key
        )

        self.assertEqual(analytics["summary"]["total_events"], 1)
        self.assertEqual(
            analytics["recent_events"][0]["api_key_id"],
            first_key
        )


if __name__ == "__main__":
    unittest.main()


class TestWalletBehaviorHistory(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "wallet_history.db"
        self.tracker = SQLiteTransactionTracker(self.database)

    def tearDown(self):
        self.temp_dir.cleanup()

    def make_report(self, account="alice.near", score=25,
                    level="MEDIUM", count=3):
        return {
            "analysis_type": "deterministic_wallet_behavior_analysis",
            "account_id": account,
            "network": "mainnet",
            "transaction_count": count,
            "behavioural_assessment": {
                "risk_score": score,
                "risk_level": level
            }
        }

    def test_save_and_retrieve_wallet_report(self):
        report = self.make_report()
        report_id = self.tracker.save_wallet_behavior_report(
            "alice.near", "mainnet", report, created_at=1000
        )

        record = self.tracker.get_wallet_behavior_report(report_id)

        self.assertIsNotNone(record)
        self.assertEqual(record["account_id"], "alice.near")
        self.assertEqual(record["network"], "mainnet")
        self.assertEqual(record["risk_score"], 25)
        self.assertEqual(record["report"], report)

    def test_history_returns_newest_first(self):
        first = self.tracker.save_wallet_behavior_report(
            "alice.near", "mainnet",
            self.make_report(score=10, level="LOW"),
            created_at=1000
        )
        second = self.tracker.save_wallet_behavior_report(
            "alice.near", "mainnet",
            self.make_report(score=70, level="HIGH"),
            created_at=2000
        )

        history = self.tracker.get_wallet_behavior_history(
            "alice.near", "mainnet"
        )

        self.assertEqual([item["id"] for item in history], [second, first])

    def test_history_is_isolated_by_wallet_and_network(self):
        self.tracker.save_wallet_behavior_report(
            "alice.near", "mainnet", self.make_report(), created_at=1000
        )
        self.tracker.save_wallet_behavior_report(
            "bob.near", "mainnet",
            self.make_report("bob.near"), created_at=1001
        )
        self.tracker.save_wallet_behavior_report(
            "alice.near", "testnet",
            self.make_report(), created_at=1002
        )

        history = self.tracker.get_wallet_behavior_history(
            "alice.near", "mainnet"
        )

        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["account_id"], "alice.near")
        self.assertEqual(history[0]["network"], "mainnet")

    def test_history_limit_is_respected(self):
        for timestamp in range(1, 4):
            self.tracker.save_wallet_behavior_report(
                "alice.near", "mainnet", self.make_report(),
                created_at=timestamp
            )

        history = self.tracker.get_wallet_behavior_history(
            "alice.near", "mainnet", limit=2
        )

        self.assertEqual(len(history), 2)

    def test_missing_report_returns_none(self):
        self.assertIsNone(
            self.tracker.get_wallet_behavior_report(999)
        )

    def test_invalid_report_id_is_rejected(self):
        for report_id in (0, -1, "1", True):
            with self.subTest(report_id=report_id):
                with self.assertRaises(ValueError):
                    self.tracker.get_wallet_behavior_report(report_id)

    def test_invalid_network_is_rejected(self):
        with self.assertRaises(ValueError):
            self.tracker.get_wallet_behavior_history(
                "alice.near", "invalid"
            )

    def test_invalid_history_limit_is_rejected(self):
        for limit in (0, 101, True):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    self.tracker.get_wallet_behavior_history(
                        "alice.near", "mainnet", limit
                    )

    def test_report_account_mismatch_is_rejected(self):
        with self.assertRaises(ValueError):
            self.tracker.save_wallet_behavior_report(
                "alice.near", "mainnet",
                self.make_report("bob.near")
            )

    def test_invalid_report_risk_score_is_rejected(self):
        for score in (-1, 101, True):
            with self.subTest(score=score):
                report = self.make_report(score=score)
                with self.assertRaises(ValueError):
                    self.tracker.save_wallet_behavior_report(
                        "alice.near", "mainnet", report
                    )

    def test_invalid_report_type_is_rejected(self):
        report = self.make_report()
        report["analysis_type"] = "unknown"

        with self.assertRaises(ValueError):
            self.tracker.save_wallet_behavior_report(
                "alice.near", "mainnet", report
            )
