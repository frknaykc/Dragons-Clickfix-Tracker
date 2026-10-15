# ClickFix / ClearFake IOC archive

A small, Git-backed research archive. The pipeline searches urlscan.io scans and the URLhaus recent feed, extracts concrete indicators from rendered DOM or feed listings, and keeps their observation history. It does **not** verify every downloaded file or promise that a URL is still online. No GeoIP enrichment, resolved-IP attribution, account system or hosted service is required.

## Outputs and their meaning

| File | Purpose |
| --- | --- |
| [`data/scans.json`](data/scans.json) | Scan-keyed observation archive: source, original URL, timestamp, detection context and report link. Landing hosts are context, not automatically malicious infrastructure. |
| [`data/iocs.json`](data/iocs.json) | Typed indicators keyed by `type|value`, with `first_seen`, `last_seen`, `evidence`, `sources` and `references`. Raw full URLs are retained for exact path matching. |
| [`data/daily/`](data/daily/) | Existing daily CSV archive remains intact. New scans create daily, defanged IOC exports; when today's older CSV has a different header, output goes to `YYYY-MM-DD-iocs.csv` rather than corrupting it. |
| [`data/domains.txt`](data/domains.txt) | DNS-level candidate list containing only `c2_host` indicators derived from the ClearFake `/api.php?s=...` loader. A DNS filter cannot isolate a malicious path on a shared host. Review before blocking; this is not an automatic verdict of current activity. |
| [`LATEST_REPORT.md`](LATEST_REPORT.md) | Most recently observed indicators, defanged, with source references. |
| [`data/detection_catalog.json`](data/detection_catalog.json) / [`DETECTION_CATALOG.md`](DETECTION_CATALOG.md) | Detection methods and lure patterns, **not** an IOC feed. |

Types: `tds_delivery_url` is a ClearFake loader URL; `c2_host` is its host (not a generic landing domain); `payload_url` is a command/stager extraction; `malware_download_url` is a URLhaus **listing** (not an independently verified payload); `extracted_url` is a decoded URL with insufficient evidence to call it a payload; `smart_contract` is an extracted blockchain address. A URLhaus `offline` status remains historical evidence, not a reason to delete it. DNS lookups never turn an IP into a malicious IP IOC.

Example key: `tds_delivery_url|https://idcool.codes/api.php?s=...`. The original scan UUID and urlscan.io/URLhaus report can be found in `data/scans.json` and each IOC's `references`. For path-level filtering, use the URL values in `data/iocs.json`, **not** `data/domains.txt`. Links in JSON are raw for machine use; report and CSV display is defanged.

## Run locally

Requires Python 3.11+.

```bash
python -m pip install -r requirements.txt
# Optional: put URLSCAN_API_KEY in .env or the environment for urlscan.io searches.
python main.py             # 24-hour window for both urlscan.io and URLhaus
python main.py 3h          # manual 3-hour window (also: 6h, 12h, 24h)
python main.py 360         # backwards-compatible: 360 minutes = 6 hours
python -m unittest discover -s tests -v
```

The URLhaus public CSV does not require an API key. Both sources now use the same requested UTC window; URLhaus records with missing, invalid, future or older `date_added` timestamps are skipped before the 150-result cap. This only affects future runs: older entries already in the archive are not deleted. GitHub Actions currently schedules a run every **20 minutes** (`.github/workflows/hunter.yml`), not three to five times daily; adjust the cron if that cadence is desired. No live scans or internet access are needed to inspect the archived JSON. The pipeline saves a scan only if it produces a concrete IOC; unsuccessful DOM fetches can be retried on the next run.

Historical scan-keyed `data/iocs.json` was migrated once to `data/scans.json` plus typed `data/iocs.json`; the original file remains in Git history. For an older checkout **before** migration run `python scripts/migrate_iocs.py` once. After adjusting classification rules, `python scripts/migrate_iocs.py --rebuild` regenerates the derived IOC JSON, DNS candidate list and latest report from the preserved scans without changing daily CSVs or catalog entries. Do not run the one-time migration on an already migrated archive.

**Caution:** These are third-party observations and heuristic extractions, not a validated maliciousness/availability benchmark. In particular, a URLhaus tag or a recovered URL does not prove the file contents, and a C2 host designation should be manually checked before deployment as a DNS blocklist. For defensive research and threat hunting only.
