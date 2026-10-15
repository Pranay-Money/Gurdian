"""
Tests for data ingestion component.
"""
import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from guardian_ml.components.data_ingestion import DataIngestion, DataIngestionConfig


class TestDataIngestion:
    """Test data ingestion functionality."""

    def test_get_registrable_domain(self):
        """Test registrable domain extraction."""
        ingestion = DataIngestion()

        assert ingestion._get_registrable_domain("https://www.google.com/search") == "google.com"
        assert ingestion._get_registrable_domain("https://sub.domain.co.uk/path") == "domain.co.uk"
        assert ingestion._get_registrable_domain("http://192.168.1.1/") == ""
        assert ingestion._get_registrable_domain("https://example.com") == "example.com"

    def test_config_defaults(self):
        """Test default configuration."""
        config = DataIngestionConfig()

        assert "openphish" in config.malicious_sources
        assert "phishtank" in config.malicious_sources
        assert "urlhaus" in config.malicious_sources
        assert "tranco" in config.benign_sources

    def test_deduplication_by_url(self):
        """Test URL deduplication."""
        # This would need mock data - skip for now
        pass

    def test_split_by_domain(self):
        """Test domain-disjoint split."""
        ingestion = DataIngestion()

        records = [
            {"url": "https://google.com/a", "label": 0, "source": "test"},
            {"url": "https://google.com/b", "label": 0, "source": "test"},
            {"url": "https://github.com/a", "label": 0, "source": "test"},
            {"url": "https://evil.tk/a", "label": 1, "source": "test"},
            {"url": "https://evil.tk/b", "label": 1, "source": "test"},
            {"url": "https://phish.ml/a", "label": 1, "source": "test"},
        ]

        train, test = ingestion.split_by_domain(records, test_ratio=0.5, seed=42)

        # All URLs from same domain should be in same split
        train_domains = set(ingestion._get_registrable_domain(r["url"]) for r in train)
        test_domains = set(ingestion._get_registrable_domain(r["url"]) for r in test)

        assert train_domains.isdisjoint(test_domains)
        assert len(train) + len(test) == len(records)

    def test_split_by_time(self):
        """Test time-based split."""
        ingestion = DataIngestion()

        records = [
            {"url": f"https://example{i}.com", "label": 0, "source": "test", "fetched_at": f"2024-01-{i:02d}T00:00:00"}
            for i in range(1, 11)
        ]
        # Add malicious records with timestamps
        records += [
            {"url": f"http://malicious{i}.tk", "label": 1, "source": "test", "fetched_at": f"2024-01-{i:02d}T00:00:00"}
            for i in range(1, 11)
        ]

        train, test = ingestion.split_by_time(records, test_ratio=0.2)

        # Train should have older records
        assert len(train) == 16
        assert len(test) == 4
        assert train[0]["fetched_at"] < test[0]["fetched_at"]


class TestSnapshotCreation:
    """Test snapshot creation and loading."""

    def test_create_and_load_snapshot(self, tmp_path):
        """Test creating and loading a snapshot."""
        config = DataIngestionConfig()
        config.snapshot_dir = tmp_path / "snapshots"

        ingestion = DataIngestion(config)

        records = [
            {"url": "https://example.com", "label": 0, "source": "test", "fetched_at": "2024-01-01T00:00:00"},
            {"url": "http://evil.tk", "label": 1, "source": "test", "fetched_at": "2024-01-01T00:00:00"},
        ]
        source_counts = {"test": 2}

        snapshot_dir = ingestion.create_snapshot(records, source_counts)

        assert snapshot_dir.exists()
        assert (snapshot_dir / "urls.jsonl").exists()
        assert (snapshot_dir / "metadata.json").exists()

        # Load and verify
        loaded_records, metadata = ingestion.load_latest_snapshot()
        assert len(loaded_records) == 2
        assert metadata["total_records"] == 2
        assert "sha256" in metadata


if __name__ == "__main__":
    pytest.main([__file__, "-v"])