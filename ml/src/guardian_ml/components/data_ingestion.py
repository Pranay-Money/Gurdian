"""
Data Ingestion Component

Fetches malicious URLs from OpenPhish, PhishTank, URLhaus feeds
and benign URLs from Tranco top list. Implements domain-deduplication
and snapshot versioning.
"""
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urlparse

import pandas as pd
import requests

from guardian_ml.features import _tld_extract
from guardian_ml.exception import DataIngestionException
from guardian_ml.logger import logger


@dataclass
class DataIngestionConfig:
    """Configuration for data ingestion paths and sources."""
    raw_data_dir: Path = None
    processed_data_dir: Path = None
    snapshot_dir: Path = None
    malicious_sources: Dict[str, str] = None
    benign_sources: Dict[str, str] = None

    def __post_init__(self):
        from guardian_ml.paths import get_raw_data_dir, get_processed_data_dir, get_snapshot_dir
        
        if self.raw_data_dir is None:
            self.raw_data_dir = get_raw_data_dir()
        if self.processed_data_dir is None:
            self.processed_data_dir = get_processed_data_dir()
        if self.snapshot_dir is None:
            self.snapshot_dir = get_snapshot_dir()
        
        if self.malicious_sources is None:
            self.malicious_sources = {
                "openphish": "https://openphish.com/feed.txt",
                "phishtank": "https://data.phishtank.com/data/online-valid.csv",
                "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_online/",
            }
        if self.benign_sources is None:
            self.benign_sources = {
                "tranco": "https://tranco-list.eu/top-1m.csv.zip",
            }

        # Create directories
        self.raw_data_dir.mkdir(parents=True, exist_ok=True)
        self.processed_data_dir.mkdir(parents=True, exist_ok=True)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)


class DataIngestion:
    """
    Handles fetching, deduplication, and snapshotting of URL datasets.
    
    Key principles:
    - Deduplicate by URL and by registrable domain
    - Never leak same domain across train/test splits
    - Snapshot with timestamps for reproducibility
    - Store source attribution for each URL
    """

    def __init__(self, config: Optional[DataIngestionConfig] = None):
        self.config = config or DataIngestionConfig()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Guardian-ML/1.0"})

    def _get_registrable_domain(self, url: str) -> str:
        """Extract registrable domain (e.g., example.co.uk -> example.co.uk)."""
        extracted = _tld_extract(url)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()
        return ""

    def _fetch_openphish(self) -> List[Dict]:
        """Fetch URLs from OpenPhish feed."""
        logger.info("Fetching OpenPhish feed...")
        try:
            response = self.session.get(self.config.malicious_sources["openphish"], timeout=30)
            response.raise_for_status()
            urls = [line.strip() for line in response.text.splitlines() if line.strip()]
            return [{"url": u, "source": "openphish", "label": 1, "fetched_at": datetime.now(timezone.utc).isoformat()} for u in urls]
        except Exception as e:
            logger.warning(f"Failed to fetch OpenPhish: {e}")
            return []

    def _fetch_phishtank(self) -> List[Dict]:
        """Fetch URLs from PhishTank CSV."""
        logger.info("Fetching PhishTank feed...")
        try:
            response = self.session.get(self.config.malicious_sources["phishtank"], timeout=60)
            response.raise_for_status()
            from io import StringIO
            df = pd.read_csv(StringIO(response.text))
            # PhishTank columns: phish_id, url, phish_detail_url, submission_time, verified, verification_time, online, target
            urls = df[df["online"] == "yes"]["url"].tolist()
            return [{"url": u, "source": "phishtank", "label": 1, "fetched_at": datetime.now(timezone.utc).isoformat()} for u in urls]
        except Exception as e:
            logger.warning(f"Failed to fetch PhishTank: {e}")
            return []

    def _fetch_urlhaus(self) -> List[Dict]:
        """Fetch URLs from URLhaus CSV."""
        logger.info("Fetching URLhaus feed...")
        try:
            response = self.session.get(self.config.malicious_sources["urlhaus"], timeout=60)
            response.raise_for_status()
            from io import StringIO
            # URLhaus CSV has header lines starting with #
            lines = response.text.splitlines()
            data_lines = [l for l in lines if not l.startswith("#")]
            df = pd.read_csv(StringIO("\n".join(data_lines)))
            # Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
            urls = df[df["url_status"] == "online"]["url"].tolist()
            return [{"url": u, "source": "urlhaus", "label": 1, "fetched_at": datetime.now(timezone.utc).isoformat()} for u in urls]
        except Exception as e:
            logger.warning(f"Failed to fetch URLhaus: {e}")
            return []

    def _fetch_tranco(self, limit: int = 100000) -> List[Dict]:
        """Fetch top domains from Tranco list."""
        logger.info(f"Fetching Tranco top {limit} domains...")
        try:
            response = self.session.get(self.config.benign_sources["tranco"], timeout=60)
            response.raise_for_status()
            import zipfile
            from io import BytesIO
            with zipfile.ZipFile(BytesIO(response.content)) as z:
                csv_name = z.namelist()[0]
                with z.open(csv_name) as f:
                    df = pd.read_csv(f, header=None, names=["rank", "domain"])
            domains = df.head(limit)["domain"].tolist()
            # Convert to URLs with https
            urls = [f"https://{d}" for d in domains]
            return [{"url": u, "source": "tranco", "label": 0, "fetched_at": datetime.now(timezone.utc).isoformat()} for u in urls]
        except Exception as e:
            logger.warning(f"Failed to fetch Tranco: {e}")
            return []

    def _crawl_benign_paths(self, domains: List[str], max_paths_per_domain: int = 5) -> List[Dict]:
        """
        Crawl common benign paths for top domains to get full URLs.
        This is optional and can be skipped for speed.
        """
        logger.info(f"Crawling benign paths for {len(domains)} domains...")
        common_paths = [
            "/", "/about", "/contact", "/blog", "/news", "/products",
            "/services", "/login", "/signup", "/help", "/support",
            "/docs", "/api", "/developers", "/privacy", "/terms"
        ]
        results = []
        for domain in domains[:1000]:  # Limit to top 1000 for speed
            for path in common_paths[:max_paths_per_domain]:
                url = f"https://{domain}{path}"
                results.append({"url": url, "source": "tranco_crawled", "label": 0, "fetched_at": datetime.now(timezone.utc).isoformat()})
        return results

    def fetch_all(self, include_crawled: bool = False, tranco_limit: int = 100000) -> Tuple[List[Dict], Dict]:
        """
        Fetch all sources and return combined records with metadata.
        
        Returns:
            Tuple of (records, metadata_dict)
        """
        logger.info("Starting data ingestion from all sources...")
        all_records = []
        source_counts = {}

        # Fetch malicious sources
        for name, func in [
            ("openphish", self._fetch_openphish),
            ("phishtank", self._fetch_phishtank),
            ("urlhaus", self._fetch_urlhaus),
        ]:
            records = func()
            all_records.extend(records)
            source_counts[name] = len(records)
            logger.info(f"Fetched {len(records)} URLs from {name}")

        # Fetch benign sources
        tranco_records = self._fetch_tranco(tranco_limit)
        all_records.extend(tranco_records)
        source_counts["tranco"] = len(tranco_records)
        logger.info(f"Fetched {len(tranco_records)} URLs from Tranco")

        # Optionally crawl benign paths
        if include_crawled:
            tranco_domains = [urlparse(r["url"]).netloc for r in tranco_records]
            crawled = self._crawl_benign_paths(tranco_domains)
            all_records.extend(crawled)
            source_counts["tranco_crawled"] = len(crawled)
            logger.info(f"Crawled {len(crawled)} additional benign URLs")

        # Deduplicate by URL
        seen_urls: Set[str] = set()
        deduped_records = []
        for rec in all_records:
            url = rec["url"]
            if url not in seen_urls:
                seen_urls.add(url)
                deduped_records.append(rec)

        logger.info(f"After URL deduplication: {len(deduped_records)} records")

        return deduped_records, source_counts

    def create_snapshot(self, records: List[Dict], source_counts: Dict) -> Path:
        """
        Create a versioned snapshot of the dataset.
        
        Snapshot includes:
        - JSONL file with all records
        - Metadata JSON with source counts, timestamp, hash
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        snapshot_dir = self.config.snapshot_dir / timestamp
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        # Write JSONL
        jsonl_path = snapshot_dir / "urls.jsonl"
        with open(jsonl_path, "w") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")

        # Compute content hash for integrity
        content_hash = hashlib.sha256()
        with open(jsonl_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                content_hash.update(chunk)

        # Write metadata
        metadata = {
            "timestamp": timestamp,
            "total_records": len(records),
            "source_counts": source_counts,
            "sha256": content_hash.hexdigest(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        metadata_path = snapshot_dir / "metadata.json"
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info(f"Created snapshot at {snapshot_dir}")
        logger.info(f"  Total records: {len(records)}")
        logger.info(f"  SHA256: {content_hash.hexdigest()[:16]}...")

        return snapshot_dir

    def load_latest_snapshot(self) -> Tuple[List[Dict], Dict]:
        """Load the most recent snapshot."""
        snapshots = sorted(self.config.snapshot_dir.glob("*"))
        if not snapshots:
            raise DataIngestionException("No snapshots found", sys)
        latest = snapshots[-1]
        logger.info(f"Loading latest snapshot: {latest.name}")
        
        records = []
        with open(latest / "urls.jsonl") as f:
            for line in f:
                records.append(json.loads(line))
        
        with open(latest / "metadata.json") as f:
            metadata = json.load(f)
        
        return records, metadata

    def split_by_domain(self, records: List[Dict], test_ratio: float = 0.2, seed: int = 42) -> Tuple[List[Dict], List[Dict]]:
        """
        Split records by registrable domain to prevent leakage.
        
        All URLs from the same registrable domain go to the same split.
        """
        import random
        random.seed(seed)
        
        # Group by registrable domain
        domain_to_records: Dict[str, List[Dict]] = {}
        for rec in records:
            domain = self._get_registrable_domain(rec["url"])
            if domain:
                domain_to_records.setdefault(domain, []).append(rec)
        
        domains = list(domain_to_records.keys())
        random.shuffle(domains)
        
        split_idx = int(len(domains) * (1 - test_ratio))
        train_domains = set(domains[:split_idx])
        test_domains = set(domains[split_idx:])
        
        train_records = []
        test_records = []
        for domain, recs in domain_to_records.items():
            if domain in train_domains:
                train_records.extend(recs)
            else:
                test_records.extend(recs)
        
        logger.info(f"Domain-disjoint split: {len(train_records)} train, {len(test_records)} test")
        logger.info(f"  Train domains: {len(train_domains)}, Test domains: {len(test_domains)}")
        
        return train_records, test_records

    def split_by_time(self, records: List[Dict], test_ratio: float = 0.2) -> Tuple[List[Dict], List[Dict]]:
        """
        Split records by fetch timestamp (time-based split).
        
        Older records -> train, newer records -> test.
        This simulates real-world deployment where model sees older data first.
        
        Records without timestamps are excluded from the split.
        Both classes (malicious/benign) must have dated records for a valid split.
        """
        # Filter records with valid timestamps
        dated_records = [r for r in records if r.get("fetched_at")]
        undated_count = len(records) - len(dated_records)
        
        if undated_count > 0:
            logger.warning(f"Excluding {undated_count} records without timestamps from time-based split")
        
        if not dated_records:
            raise ValueError("No records with timestamps available for time-based split")
        
        # Check both classes have dated records
        dated_labels = [r["label"] for r in dated_records]
        if len(set(dated_labels)) < 2:
            raise ValueError("Time-based split requires both classes to have dated records")
        
        # Sort by fetched_at
        sorted_records = sorted(dated_records, key=lambda r: r["fetched_at"])
        
        split_idx = int(len(sorted_records) * (1 - test_ratio))
        train_records = sorted_records[:split_idx]
        test_records = sorted_records[split_idx:]
        
        # Log class distribution in each split
        train_malicious = sum(1 for r in train_records if r["label"] == 1)
        test_malicious = sum(1 for r in test_records if r["label"] == 1)
        
        logger.info(f"Time-based split: {len(train_records)} train, {len(test_records)} test")
        logger.info(f"  Train: {train_malicious} malicious, {len(train_records)-train_malicious} benign")
        logger.info(f"  Test: {test_malicious} malicious, {len(test_records)-test_malicious} benign")
        
        return train_records, test_records

    def run(self, create_snapshot: bool = True, include_crawled: bool = False) -> Tuple[List[Dict], List[Dict], Dict]:
        """
        Run full ingestion pipeline.
        
        Returns:
            (train_records, test_records, metadata)
        """
        records, source_counts = self.fetch_all(include_crawled=include_crawled)
        
        if create_snapshot:
            snapshot_dir = self.create_snapshot(records, source_counts)
            metadata = {"snapshot_dir": str(snapshot_dir), "source_counts": source_counts}
        else:
            metadata = {"source_counts": source_counts}
        
        # Default to domain-disjoint split for training
        train_records, test_records = self.split_by_domain(records)
        
        return train_records, test_records, metadata


if __name__ == "__main__":
    ingestion = DataIngestion()
    train, test, meta = ingestion.run(create_snapshot=True)
    print(f"Train: {len(train)}, Test: {len(test)}")