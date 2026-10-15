import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from fetchers.urlhaus import fetch_urlhaus_recent
from main import parse_window_argument, run_pipeline


class TestURLhausWindow(unittest.TestCase):
    @patch("fetchers.urlhaus.requests.get")
    def test_filters_before_limit_using_utc_timestamp(self, get):
        # Unsorted feed: an old matching row must not consume the limited slot.
        get.return_value = Mock(status_code=200, text="\n".join([
            '# urlhaus recent',
            '1,2026-10-12 11:59:59,https://old.example/a,offline,2026-10-12 12:00:00,malware_download,clickfix,https://urlhaus.abuse.ch/url/1/',
            '2,2026-10-14 11:59:59,https://edge.example/b,online,2026-10-14 12:00:00,malware_download,clearfake,https://urlhaus.abuse.ch/url/2/',
            '6,2026-10-14 12:00:00,https://boundary.example/f,online,2026-10-14 12:00:00,malware_download,clickfix,https://urlhaus.abuse.ch/url/6/',
            '3,2026-10-15 11:59:59,https://inside.example/c,online,2026-10-15 12:00:00,malware_download,clickfix,https://urlhaus.abuse.ch/url/3/',
            '4,2026-10-15 12:00:01,https://future.example/d,online,2026-10-15 12:00:01,malware_download,clickfix,https://urlhaus.abuse.ch/url/4/',
            '5,not-a-date,https://unknown.example/e,online,2026-10-15 12:00:00,malware_download,clickfix,https://urlhaus.abuse.ch/url/5/',
        ]))
        with patch("fetchers.urlhaus.datetime", wraps=datetime) as clock:
            clock.now.return_value = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
            self.assertEqual([c["scan_id"] for c in fetch_urlhaus_recent(limit=2, time_window_minutes=1440)],
                             ["urlhaus_6", "urlhaus_3"])
            self.assertEqual([c["scan_id"] for c in fetch_urlhaus_recent(limit=5, time_window_minutes=4320)],
                             ["urlhaus_2", "urlhaus_6", "urlhaus_3"])
            self.assertEqual([c["scan_id"] for c in fetch_urlhaus_recent(limit=5, time_window_minutes=180)],
                             ["urlhaus_3"])

    def test_hours_and_legacy_minutes_cli_input(self):
        self.assertEqual(parse_window_argument("3h"), 180)
        self.assertEqual(parse_window_argument("6h"), 360)
        self.assertEqual(parse_window_argument("12h"), 720)
        self.assertEqual(parse_window_argument("24h"), 1440)
        self.assertEqual(parse_window_argument("360"), 360)
        for value in ("0", "-3h", "tomorrow", "3.5h"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_window_argument(value)

    @patch("main.fetch_urlhaus_recent", return_value=[])
    @patch("main.get_recent_candidates", return_value=[])
    @patch("main.load_database", return_value={})
    def test_pipeline_passes_same_window_to_both_feeds(self, load, scans, urlhaus):
        run_pipeline(time_window_minutes=180)
        scans.assert_called_once_with(time_window_minutes=180)
        urlhaus.assert_called_once_with(limit=150, time_window_minutes=180)


if __name__ == "__main__":
    unittest.main()
