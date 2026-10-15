# Guardian ML - Data Sources and Licenses

## Overview
This document catalogs all data sources used for training and evaluating the Guardian ML model, including their licenses, access methods, and snapshot dates. This ensures reproducibility and compliance.

## Malicious URL Sources

### 1. OpenPhish
- **URL**: https://openphish.com/feed.txt
- **Description**: Community-driven phishing intelligence feed updated every 12 hours
- **Format**: Plain text, one URL per line
- **License**: OpenPhish Community Feed - Free for non-commercial use
- **Attribution**: "Data provided by OpenPhish (https://openphish.com/)"
- **Snapshot Date**: [TO BE FILLED AT RUN TIME]
- **Typical Volume**: ~10,000-20,000 URLs per feed
- **Labels**: All URLs labeled as malicious (phishing)
- **Access Method**: Direct HTTP GET of feed.txt
- **Rate Limit**: Not specified; recommended max 1 request per 12 hours (feed update frequency)
- **No Page Fetching**: Only the URL list is downloaded; malicious pages are NEVER visited

### 2. PhishTank
- **URL**: https://data.phishtank.com/data/online-valid.csv
- **Description**: Collaborative phishing verification system
- **Format**: CSV with columns: phish_id, url, phish_detail_url, submission_time, verified, verification_time, online, target
- **License**: PhishTank Terms of Service - Free for research/non-commercial
- **Attribution**: "Data provided by PhishTank (https://www.phishtank.com/)"
- **Snapshot Date**: [TO BE FILLED AT RUN TIME]
- **Typical Volume**: ~50,000-100,000 online verified URLs
- **Labels**: Only `online=yes` and `verified=yes` URLs used; labeled malicious
- **Access Method**: Direct HTTP GET of CSV (requires free API key for automated access)
- **Rate Limit**: Respect API terms; recommended max 1 request per hour
- **No Page Fetching**: Only the URL list is downloaded; malicious pages are NEVER visited

### 3. URLhaus
- **URL**: https://urlhaus.abuse.ch/downloads/csv_online/
- **Description**: Malware URL exchange platform from abuse.ch
- **Format**: CSV with header comments; columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
- **License**: Creative Commons Attribution 4.0 International (CC BY 4.0)
- **Attribution**: "Data provided by URLhaus (https://urlhaus.abuse.ch/)"
- **Snapshot Date**: [TO BE FILLED AT RUN TIME]
- **Typical Volume**: ~50,000-80,000 online URLs
- **Labels**: Only `url_status=online` URLs used; labeled malicious
- **Access Method**: Direct HTTP GET of CSV
- **Rate Limit**: abuse.ch allows generous access; recommended max 1 request per hour
- **No Page Fetching**: Only the URL list is downloaded; malicious pages are NEVER visited

## Benign URL Sources

### 4. Tranco Top Sites
- **URL**: https://tranco-list.eu/top-1m.csv.zip
- **Description**: Research-oriented top sites ranking hardened against manipulation
- **Format**: ZIP containing CSV with columns: rank, domain
- **License**: Tranco License - Free for research purposes
- **Attribution**: "Data provided by Tranco (https://tranco-list.eu/)"
- **Snapshot Date**: [TO BE FILLED AT RUN TIME]
- **Typical Volume**: Top 100,000 domains (configurable)
- **Labels**: All labeled benign (0)
- **Processing**: Converted to `https://{domain}/` URLs; optionally crawled for common paths
- **Access Method**: Direct HTTP GET of ZIP file
- **Rate Limit**: Tranco updates daily; recommended max 1 request per day

## Data Processing Pipeline

### Deduplication Strategy
1. **URL-level deduplication**: Exact URL string matching across all sources
2. **Domain-level deduplication**: For train/test split, all URLs from same registrable domain go to same split
3. **Cross-source deduplication**: Same URL appearing in multiple feeds counted once

### Train/Test Splits

#### Domain-Disjoint Split (Primary)
- **Method**: Group by registrable domain (eTLD+1), split domains 80/20
- **Purpose**: Prevents domain leakage; models must generalize to unseen domains
- **Ratio**: 80% train / 20% test domains
- **Seed**: 42 (fixed for reproducibility)

#### Time-Based Split (Secondary)
- **Method**: Sort by `fetched_at` timestamp, split chronologically 80/20
- **Purpose**: Simulates real-world temporal deployment
- **Ratio**: 80% older / 20% newer
- **Use Case**: Evaluating model decay over time
- **Undated Records**: Records without `fetched_at` timestamp are excluded. Both classes must have dated records.

### Snapshot Versioning
Each ingestion run creates a versioned snapshot in `ml/data/snapshots/{YYYYMMDD_HHMMSS}/`:
- `urls.jsonl`: All records with source, label, fetch timestamp
- `metadata.json`: Source counts, SHA256 hash, timestamp

## Benign Crawling Policy (Optional Path Enrichment)

When `include_crawled_benign=True` (enabled by default in pipeline), the system crawls common benign paths on Tranco domains to create realistic benign URLs with paths.

### Crawling Rules:
1. **No Malicious URL Fetching**: Only Tranco domains (pre-verified benign) are crawled
2. **Rate Limiting**: 
   - Max 1 request per second per domain
   - Max 5 paths per domain (configurable)
   - Global timeout: 10 seconds per request
3. **Robots.txt Compliance**: 
   - robots.txt is fetched and parsed before crawling each domain
   - Disallowed paths are skipped
   - Crawl-delay directive is respected
4. **User-Agent**: `Guardian-ML/1.0 (+https://guardian.example.com/bot)`
5. **Paths Crawled**: `/`, `/about`, `/contact`, `/blog`, `/news`, `/products`, `/services`, `/login`, `/signup`, `/help`, `/support`, `/docs`, `/api`, `/developers`, `/privacy`, `/terms`
6. **Error Handling**: 
   - Non-2xx responses are logged but not retried
   - Timeouts and connection errors are logged
   - Failed domains are skipped, not retried

## License Compliance Checklist
- [ ] All sources permit research/non-commercial use
- [ ] Attribution included in model card and API responses
- [ ] No redistribution of raw feeds (only derived features/model)
- [ ] Snapshot dates recorded for reproducibility
- [ ] Commercial deployment requires separate license verification
- [ ] Malicious URLs never fetched (only URL metadata downloaded)
- [ ] Benign crawling respects robots.txt and rate limits
- [ ] No PII in training data (only URLs and metadata)

## Reproducibility
To reproduce exact dataset:
```bash
# Run ingestion with fixed seed
cd ml
python -m guardian_ml.components.data_ingestion --seed 42

# Or use pipeline
make train
```

The snapshot metadata.json contains SHA256 of urls.jsonl for integrity verification.