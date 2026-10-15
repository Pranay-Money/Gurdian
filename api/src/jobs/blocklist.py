"""
Blocklist Job - Generates and updates the blocklist for extension sync.

Sources:
- Intel adapter MALICIOUS verdicts
- User-reported URLs (reviewed/confirmed)
- Feedback-confirmed false negatives
- High-confidence ML predictions

Output: Delta format for extension sync
"""
import hashlib
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any

from sqlalchemy import select, and_, or_, func

# Add project paths
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from src.db.session import get_session_context
from src.db.models import (
    BlocklistEntry, UrlIntel, IntelVerdict, ReportedUrl, 
    Feedback, Case, VerdictType, Url
)
from guardian_ml.logger import logger


@dataclass
class BlocklistConfig:
    """Configuration for blocklist generation."""
    # Sources
    use_intel_malicious: bool = True
    use_reported_confirmed: bool = True
    use_feedback_confirmed: bool = True
    use_high_confidence_ml: bool = True
    ml_confidence_threshold: float = 0.95
    
    # Processing
    max_age_days: int = 30
    min_sources_for_entry: int = 1  # Require at least N sources
    deduplicate_by_domain: bool = True
    
    # Output
    output_dir: Path = Path("api/blocklist")
    version_key: str = "blocklist:version"
    
    # Schedule
    schedule_cron: str = "*/5 * * * *"  # Every 5 minutes
    sync_interval_seconds: int = 300
    
    def __post_init__(self):
        self.output_dir = Path(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)


@dataclass
class BlocklistEntryData:
    """Data for a blocklist entry."""
    domain: str
    domain_hash: str
    reason: str
    source: str
    expires_at: datetime
    confidence: float


class BlocklistJob:
    """
    Generates blocklist from multiple sources and outputs delta format.
    
    Merge strategy:
    1. Collect domains with MALICIOUS verdict from any source
    2. Deduplicate by registrable domain
    3. Assign reason: most severe source
    4. Set expiry: max 30 days from detection
    4. Output compact delta for extension
    """
    
    SEVERITY_ORDER = {
        "phishing": 5,
        "malware": 5,
        "scam": 4,
        "suspicious": 3,
        "intel_malicious": 3,
        "reported": 2,
        "feedback_fn": 2,
        "ml_high_confidence": 1,
    }
    
    def __init__(self, config: Optional[BlocklistConfig] = None):
        self.config = config or BlocklistConfig()
    
    def _get_registrable_domain(self, url: str) -> str:
        """Extract registrable domain from URL."""
        import tldextract
        extracted = tldextract.extract(url)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()
        return ""
    
    def _domain_hash(self, domain: str) -> str:
        """Compute 16-char domain hash."""
        return hashlib.sha256(domain.encode()).hexdigest()[:16]
    
    def _collect_from_intel(self, since: datetime) -> List[BlocklistEntryData]:
        """Collect malicious domains from intel adapters."""
        entries = []
        
        with get_session_context() as session:
            stmt = select(UrlIntel).where(
                and_(
                    UrlIntel.verdict == IntelVerdict.MALICIOUS,
                    UrlIntel.checked_at >= since,
                    UrlIntel.expires_at > datetime.now(timezone.utc),
                )
            ).join(Url, UrlIntel.url_id == Url.id)
            
            results = session.execute(stmt).all()
            
            for url_intel in results:
                # Need to get the URL
                url_stmt = select(Url).where(Url.id == url_intel.url_id)
                url = session.execute(url_stmt).scalar_one_or_none()
                
                if url:
                    domain = self._get_registrable_domain(url.url)
                    if domain:
                        entries.append(BlocklistEntryData(
                            domain=domain,
                            domain_hash=self._domain_hash(domain),
                            reason=url_intel.source.value,
                            source=f"intel_{url_intel.source.value}",
                            expires_at=url_intel.expires_at,
                            confidence=url_intel.confidence / 100.0,
                        ))
        
        logger.info(f"Collected {len(entries)} entries from intel")
        return entries
    
    def _collect_from_reports(self, since: datetime) -> List[BlocklistEntryData]:
        """Collect confirmed malicious from user reports."""
        entries = []
        
        with get_session_context() as session:
            stmt = select(ReportedUrl).where(
                and_(
                    ReportedUrl.status.in_(["confirmed", "blocked"]),
                    ReportedUrl.reviewed_at >= since,
                )
            )
            
            reports = session.execute(stmt).scalars().all()
            
            for report in reports:
                domain = self._get_registrable_domain(report.url)
                if domain:
                    expires = datetime.now(timezone.utc) + timedelta(days=self.config.max_age_days)
                    entries.append(BlocklistEntryData(
                        domain=domain,
                        domain_hash=self._domain_hash(domain),
                        reason="reported",
                        source="user_report",
                        expires_at=expires,
                        confidence=0.9,
                    ))
        
        logger.info(f"Collected {len(entries)} entries from reports")
        return entries
    
    def _collect_from_feedback(self, since: datetime) -> List[BlocklistEntryData]:
        """Collect domains from confirmed false negatives."""
        entries = []
        
        with get_session_context() as session:
            stmt = select(Feedback, Case).join(Case, Feedback.case_id == Case.id).where(
                and_(
                    Feedback.verdict == VerdictType.FALSE_NEGATIVE,
                    Feedback.created_at >= since,
                    Case.store_raw_text == True,  # Only consented
                )
            )
            
            results = session.execute(stmt).all()
            
            for feedback, case in results:
                for url_data in case.urls:
                    domain = self._get_registrable_domain(url_data["url"])
                    if domain:
                        expires = datetime.now(timezone.utc) + timedelta(days=self.config.max_age_days)
                        entries.append(BlocklistEntryData(
                            domain=domain,
                            domain_hash=self._domain_hash(domain),
                            reason="feedback_fn",
                            source="feedback_false_negative",
                            expires_at=expires,
                            confidence=0.85,
                        ))
        
        logger.info(f"Collected {len(entries)} entries from feedback")
        return entries
    
    def _collect_from_ml(self, since: datetime) -> List[BlocklistEntryData]:
        """Collect high-confidence ML predictions (placeholder for now)."""
        # This would require storing ML predictions in DB
        # For now, return empty - would be implemented when ML results are persisted
        return []
    
    def _merge_entries(self, all_entries: List[BlocklistEntryData]) -> Dict[str, BlocklistEntryData]:
        """Merge entries by domain, keeping highest severity."""
        merged = {}
        
        for entry in all_entries:
            if entry.domain not in merged:
                merged[entry.domain] = entry
            else:
                existing = merged[entry.domain]
                # Keep entry with higher severity
                existing_severity = self.SEVERITY_ORDER.get(existing.reason, 0)
                new_severity = self.SEVERITY_ORDER.get(entry.reason, 0)
                
                if new_severity > existing_severity:
                    merged[entry.domain] = entry
                elif new_severity == existing_severity:
                    # Keep longer expiry
                    if entry.expires_at > existing.expires_at:
                        merged[entry.domain] = entry
        
        return merged
    
    def _get_current_version(self) -> int:
        """Get current blocklist version from Redis or file."""
        version_file = self.config.output_dir / "version.txt"
        if version_file.exists():
            try:
                return int(version_file.read_text().strip())
            except Exception:
                pass
        return 0
    
    def _save_version(self, version: int) -> None:
        """Save blocklist version."""
        version_file = self.config.output_dir / "version.txt"
        version_file.write_text(str(version))
    
    def _load_current_blocklist(self) -> Dict[str, BlocklistEntryData]:
        """Load current blocklist from database."""
        current = {}
        
        with get_session_context() as session:
            stmt = select(BlocklistEntry).where(BlocklistEntry.expires_at > datetime.now(timezone.utc))
            entries = session.execute(stmt).scalars().all()
            
            for entry in entries:
                current[entry.domain] = BlocklistEntryData(
                    domain=entry.domain,
                    domain_hash=entry.domain_hash,
                    reason=entry.reason,
                    source=entry.source,
                    expires_at=entry.expires_at,
                    confidence=1.0,
                )
        
        return current
    
    def _save_blocklist(self, entries: Dict[str, BlocklistEntryData]) -> None:
        """Save blocklist to database."""
        with get_session_context() as session:
            # Delete expired entries
            session.execute(
                BlocklistEntry.__table__.delete().where(
                    BlocklistEntry.expires_at <= datetime.now(timezone.utc)
                )
            )
            
            # Upsert current entries
            for entry_data in entries.values():
                # Check if exists
                stmt = select(BlocklistEntry).where(BlocklistEntry.domain == entry_data.domain)
                existing = session.execute(stmt).scalar_one_or_none()
                
                if existing:
                    existing.reason = entry_data.reason
                    existing.source = entry_data.source
                    existing.expires_at = entry_data.expires_at
                    existing.updated_at = datetime.now(timezone.utc)
                else:
                    new_entry = BlocklistEntry(
                        domain=entry_data.domain,
                        domain_hash=entry_data.domain_hash,
                        reason=entry_data.reason,
                        source=entry_data.source,
                        expires_at=entry_data.expires_at,
                    )
                    session.add(new_entry)
            
            session.commit()
    
    def _generate_delta(
        self, 
        current: Dict[str, BlocklistEntryData], 
        previous: Dict[str, BlocklistEntryData]
    ) -> Tuple[List[Dict], List[str]]:
        """Generate delta between current and previous blocklist."""
        current_domains = set(current.keys())
        previous_domains = set(previous.keys())
        
        additions = []
        for domain in current_domains - previous_domains:
            entry = current[domain]
            additions.append({
                "h": entry.domain_hash,
                "r": entry.reason,
                "exp": entry.expires_at.isoformat(),
            })
        
        removals = [self._domain_hash(d) for d in previous_domains - current_domains]
        
        return additions, removals
    
    def run(self) -> Dict[str, Any]:
        """Run blocklist generation job."""
        logger.info("Running blocklist generation job...")
        
        since = datetime.now(timezone.utc) - timedelta(days=self.config.max_age_days)
        
        # Load previous blocklist for delta
        previous_blocklist = self._load_current_blocklist()
        previous_version = self._get_current_version()
        
        # Collect from all sources
        all_entries = []
        
        if self.config.use_intel_malicious:
            all_entries.extend(self._collect_from_intel(since))
        
        if self.config.use_reported_confirmed:
            all_entries.extend(self._collect_from_reports(since))
        
        if self.config.use_feedback_confirmed:
            all_entries.extend(self._collect_from_feedback(since))
        
        if self.config.use_high_confidence_ml:
            all_entries.extend(self._collect_from_ml(since))
        
        # Merge and deduplicate
        merged = self._merge_entries(all_entries)
        
        # Filter expired
        now = datetime.now(timezone.utc)
        merged = {d: e for d, e in merged.items() if e.expires_at > now}
        
        # Save to database
        self._save_blocklist(merged)
        
        # Generate delta
        additions, removals = self._generate_delta(merged, previous_blocklist)
        
        # Increment version
        new_version = previous_version + 1 if (additions or removals) else previous_version
        self._save_version(new_version)
        
        # Save delta file for extension
        delta = {
            "version": new_version,
            "timestamp": now.isoformat(),
            "additions": additions,
            "removals": removals,
        }
        
        delta_file = self.config.output_dir / f"delta_v{new_version}.json"
        import json
        with open(delta_file, "w") as f:
            json.dump(delta, f)
        
        # Also save latest symlink
        latest_file = self.config.output_dir / "delta_latest.json"
        with open(latest_file, "w") as f:
            json.dump(delta, f)
        
        logger.info(f"Blocklist generated: v{new_version}, +{len(additions)} -{len(removals)}")
        
        return {
            "version": new_version,
            "timestamp": now.isoformat(),
            "total_entries": len(merged),
            "additions": len(additions),
            "removals": len(removals),
            "delta_file": str(delta_file),
        }


def run_blocklist_job(config: Optional[BlocklistConfig] = None) -> Dict[str, Any]:
    """Convenience function to run blocklist job."""
    job = BlocklistJob(config)
    return job.run()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Run blocklist generation")
    parser.add_argument("--max-age", type=int, default=30, help="Max age in days")
    args = parser.parse_args()
    
    config = BlocklistConfig(max_age_days=args.max_age)
    result = run_blocklist_job(config)
    
    print(f"Version: {result['version']}")
    print(f"Total entries: {result['total_entries']}")
    print(f"Additions: {result['additions']}")
    print(f"Removals: {result['removals']}")