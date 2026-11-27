"""Provider subscription limits stay separate from local VPN traffic counters."""

import sys
import copy
import unittest
from pathlib import Path
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / "vendor" / "panel" / "panel"
sys.path.insert(0, str(source))

import vpn_subscriptions as subscriptions
from ui_i18n import LANGUAGE


class SubscriptionUserinfoTests(unittest.TestCase):
    def setUp(self):
        self.language = LANGUAGE.set("ru")

    def tearDown(self):
        LANGUAGE.reset(self.language)

    def test_header_with_reordered_fields(self):
        values = subscriptions.parse_userinfo(
            "Total=10737418240; expire=1790000000; download=2147483648; upload=1024")
        self.assertEqual(values, {"total": 10737418240, "expire": 1790000000,
                                  "download": 2147483648, "upload": 1024})
        rendered = subscriptions.usage_html(values)
        self.assertIn("2 ГиБ", rendered)
        self.assertIn("10 ГиБ", rendered)
        self.assertIn("Осталось", rendered)
        self.assertIn("UTC", rendered)

    def test_unlimited_and_no_expiry(self):
        rendered = subscriptions.usage_html(
            subscriptions.parse_userinfo("upload=0; download=1; total=0; expire=0"))
        self.assertIn("без лимита", rendered)
        self.assertIn("Без срока", rendered)

    def test_malformed_and_unsafe_values(self):
        self.assertIsNone(subscriptions.parse_userinfo(None))
        self.assertIsNone(subscriptions.parse_userinfo("download=-1; total=evil"))
        self.assertEqual(subscriptions.parse_userinfo("download=5; total=1<script>"), {"download": 5})
        self.assertNotIn("<script>", subscriptions.usage_html({"download": 5, "total": "<script>"}))

    def test_fetch_uses_final_response_only(self):
        with patch.object(subscriptions, "subscription_target", return_value=(type("Target", (), {"hostname": "example.com"})(), 443, [])), \
                patch.object(subscriptions, "fetch_subscription_response", side_effect=[
                    (302, "https://example.com/next", b"", "total=1"),
                    (200, None, b"vless://example", "upload=2;download=3;total=10")]):
            body, usage = subscriptions.fetch("https://example.com/start", "standard")
        self.assertEqual(body, "vless://example")
        self.assertEqual(usage, {"upload": 2, "download": 3, "total": 10})

    def test_info_refresh_updates_only_subscription_metadata(self):
        db = {"nodes": [{"proxy": {"name": "vpn"}}],
              "subscriptions": {"id": {"name": "sample", "url": "https://example.com/token",
                                       "profile": "standard", "updated": "old"}}}
        writes = []
        with patch.object(subscriptions.manager, "read", side_effect=lambda: copy.deepcopy(db)), \
                patch.object(subscriptions.manager, "put", side_effect=lambda path, value: writes.append((path, value))), \
                patch.object(subscriptions, "fetch", return_value=("node data", {"total": 100, "download": 20})):
            subscriptions.refresh_info("id")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][0], subscriptions.manager.DB)
        self.assertEqual(writes[0][1]["nodes"], db["nodes"])
        self.assertEqual(writes[0][1]["subscriptions"]["id"]["updated"], "old")
        self.assertEqual(writes[0][1]["subscriptions"]["id"]["usage"], {"total": 100, "download": 20})


if __name__ == "__main__":
    unittest.main()
