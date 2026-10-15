import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.iocs import compact_scan, indicators_for_scan, merge_scan, valid_url
from main import analyze_candidate, update_domains_list
from scripts.migrate_iocs import migrate
from utils.csv_exporter import export_to_daily_csv


class TestIOCModel(unittest.TestCase):
    def test_missing_url_host_is_not_a_valid_indicator(self):
        for value in (None, "https://", "http://", "//example.org/path", "https://[bad"):
            self.assertFalse(valid_url(value))

    def test_clearfake_preserves_delivery_and_c2_not_landing_host(self):
        scan = {"scan_id": "s1", "domain": "compromised.example", "url": "https://compromised.example/",
                "source": "urlscan.io", "first_seen": "2026-09-25T12:00:00Z",
                "report_url": "https://urlscan.io/result/s1/", "is_clearfake": True,
                "live_c2_url": "https://idcool.codes", "delivery_url": "https://idcool.codes/api.php?s=abcd"}
        iocs = {}
        created = merge_scan(iocs, scan)
        self.assertEqual({i["type"] for i in created}, {"c2_host", "tds_delivery_url"})
        self.assertNotIn("compromised.example", [i["value"] for i in created])
        self.assertEqual(iocs["tds_delivery_url|https://idcool.codes/api.php?s=abcd"]["references"],
                         ["https://urlscan.io/result/s1/"])
        later = {**scan, "scan_id": "s2", "first_seen": "2026-09-26T12:00:00Z",
                 "report_url": "https://urlscan.io/result/s2/"}
        self.assertEqual(merge_scan(iocs, later), [])
        self.assertEqual(iocs["c2_host|idcool.codes"]["last_seen"], "2026-09-26T12:00:00Z")
        self.assertEqual(len(iocs["c2_host|idcool.codes"]["references"]), 2)

    def test_generic_lure_delivery_does_not_become_c2(self):
        scan = {"scan_id": "legacy", "source": "urlscan.io", "is_clearfake": True,
                "is_cfmd": True, "delivery_url": "https://connect.facebook.net/image.gif",
                "live_c2_url": "https://connect.facebook.net"}
        self.assertEqual(indicators_for_scan(scan), [])
        scan["delivery_url"] = "https://idcool.codes/api.php?s=abcd"
        self.assertEqual({(kind, value) for kind, value, _ in indicators_for_scan(scan)},
                         {("c2_host", "idcool.codes"), ("tds_delivery_url", scan["delivery_url"])})

    def test_urlhaus_listed_url_is_not_c2(self):
        scan = {"scan_id": "urlhaus_1", "domain": "github.com", "url": "https://github.com/x/tool.exe",
                "source": "abuse.ch (URLhaus)", "status": "offline", "first_seen": "2026-09-25 12:00:00"}
        self.assertEqual(indicators_for_scan(scan), [("malware_download_url", scan["url"], "urlhaus_listing")])
        self.assertEqual(compact_scan(scan)["status"], "offline")

    def test_legacy_extractions_are_not_assumed_payloads(self):
        scan = {"scan_id": "s1", "source": "urlscan.io", "extracted_b64_urls": ["https://site.example/image.png"]}
        self.assertEqual(indicators_for_scan(scan), [("extracted_url", "https://site.example/image.png", "legacy_extraction")])

    def test_benign_lure_without_url_does_not_become_ioc(self):
        candidate = {"scan_id": "s1", "domain": "benign.example", "url": "https://benign.example/",
                     "source": "urlscan.io", "dom_url": "fixture"}
        with patch("main.get_dom", return_value="Google Meet: microphone not working? See the audio issue guide."):
            result = analyze_candidate(candidate)
        self.assertIsNone(result)

    def test_legacy_migration_compacts_and_preserves_provenance(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "old.json"
            old.write_text(json.dumps({"s1": {"scan_id": "s1", "domain": "compromised.example",
                                               "source": "urlscan.io", "city": "London", "ip": "1.2.3.4",
                                               "first_seen": "2026-09-25T12:00:00Z",
                                               "report_url": "https://urlscan.io/result/s1/",
                                               "is_clearfake": True,
                                               "delivery_url": "https://idcool.codes/api.php?s=abc",
                                               "live_c2_url": "https://idcool.codes"}}))
            scans, iocs = migrate(old, root / "scans.json", root / "iocs.json")
            self.assertEqual(len(scans), 1)
            self.assertNotIn("city", scans["s1"])
            self.assertNotIn("ip", scans["s1"])
            self.assertEqual(iocs["c2_host|idcool.codes"]["references"], ["https://urlscan.io/result/s1/"])
            with self.assertRaises(FileExistsError):
                migrate(old, root / "scans.json", root / "iocs.json")

    def test_same_domain_new_scan_updates_existing_ioc(self):
        from main import run_pipeline
        import main
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scans.json").write_text(json.dumps({"old": {"scan_id": "old", "domain": "same.example"}}))
            sample = {"scan_id": "new", "domain": "same.example", "url": "https://same.example/",
                      "source": "urlscan.io", "first_seen": "2026-09-26T12:00:00Z",
                      "report_url": "https://urlscan.io/result/new/", "is_clearfake": True,
                      "delivery_url": "https://idcool.codes/api.php?s=abc", "live_c2_url": "https://idcool.codes"}
            with patch.object(main, "SCANS_FILE", str(root / "scans.json")), \
                 patch.object(main, "DATABASE_FILE", str(root / "iocs.json")), \
                 patch.object(main, "DOMAINS_FILE", str(root / "domains.txt")), \
                 patch.object(main, "REPORT_FILE", str(root / "report.md")), \
                 patch.object(main, "get_recent_candidates", return_value=[{"scan_id": "new", "domain": "same.example"}]), \
                 patch.object(main, "fetch_urlhaus_recent", return_value=[]), \
                 patch.object(main, "analyze_candidate", return_value=sample), \
                 patch.object(main, "register_techniques"), \
                 patch.object(main, "export_to_daily_csv"):
                run_pipeline()
            self.assertIn("new", json.loads((root / "scans.json").read_text()))
            self.assertIn("c2_host|idcool.codes", json.loads((root / "iocs.json").read_text()))

    def test_daily_export_does_not_append_to_legacy_header(self):
        with TemporaryDirectory() as directory:
            legacy = Path(directory) / "2026-09-26.csv"
            legacy.write_text("timestamp,domain,ip\nold,row,1.2.3.4\n")
            with patch("utils.csv_exporter.DAILY_DIR", directory), \
                 patch("utils.csv_exporter.datetime") as clock:
                from datetime import datetime, timezone
                clock.now.return_value = datetime(2026, 9, 26, tzinfo=timezone.utc)
                export_to_daily_csv([{"type": "c2_host", "value": "idcool.codes",
                                      "sources": ["urlscan.io"], "evidence": ["clearfake_loader"],
                                      "references": [], "first_seen": "2026-09-26T00:00:00Z"}])
            self.assertEqual(legacy.read_text(), "timestamp,domain,ip\nold,row,1.2.3.4\n")
            self.assertIn("c2_host", (Path(directory) / "2026-09-26-iocs.csv").read_text())

    def test_dns_feed_only_contains_c2_host(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path
        import main
        with TemporaryDirectory() as directory:
            with patch.object(main, "DOMAINS_FILE", str(Path(directory) / "domains.txt")):
                update_domains_list({"c2_host|idcool.codes": {"type": "c2_host", "value": "idcool.codes"},
                                     "malware_download_url|https://github.com/x": {"type": "malware_download_url", "value": "https://github.com/x"}})
                self.assertEqual((Path(directory) / "domains.txt").read_text(), "idcool.codes\n")


if __name__ == "__main__":
    unittest.main()
