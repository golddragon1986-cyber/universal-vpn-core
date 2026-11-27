"""Subscription metadata refreshes only while one of its nodes is enabled."""

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / "vendor" / "panel" / "panel"
sys.path.insert(0, str(source))

import subscription_automation as automation


class StopOnce:
    stopped = False

    def is_set(self):
        return self.stopped

    def wait(self, _seconds):
        self.stopped = True


class FakeQueue:
    def __init__(self):
        self.stop = StopOnce()
        self.jobs = []

    def submit(self, label, payload):
        self.jobs.append((label, payload))
        return len(self.jobs)


class SubscriptionInfoScheduleTests(unittest.TestCase):
    def db(self, enabled=True, updated=None):
        sub = {"name": "test", "automation": {"enabled": False}}
        if updated is not None:
            sub["usage_updated"] = updated
        return {"subscriptions": {"subscription-id": sub},
                "nodes": [{"subscription": "subscription-id", "proxy": {"name": "node"},
                           "balance": enabled}], "balance_overrides": {}}

    def run_watch(self, db):
        queue = FakeQueue()
        with patch.object(automation.manager, "read", return_value=db):
            automation.watch(queue)
        return queue.jobs

    def test_enabled_node_schedules_metadata_without_balance_automation(self):
        jobs = self.run_watch(self.db())
        self.assertEqual(len(jobs), 1)
        self.assertIn("action=subscription_info_refresh", jobs[0][1]["body"])
        self.assertIn("subscription=subscription-id", jobs[0][1]["body"])

    def test_disabled_or_recent_subscription_is_skipped(self):
        self.assertEqual(self.run_watch(self.db(enabled=False)), [])
        recent = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        self.assertEqual(self.run_watch(self.db(updated=recent)), [])

    def test_manual_override_controls_eligibility(self):
        db = self.db(enabled=True)
        db["balance_overrides"]["node"] = False
        self.assertFalse(automation.has_enabled_node(db, db["nodes"]))
        db["balance_overrides"]["node"] = True
        self.assertTrue(automation.has_enabled_node(db, db["nodes"]))


if __name__ == "__main__":
    unittest.main()
