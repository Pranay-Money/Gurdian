"""
Retention Job - Data retention and privacy cleanup.

Implements:
- Daily cleanup of cases older than RETENTION_DAYS
- Cascade delete: signals, urls, url_intel, feedback
- Device wipe endpoint support
- Text storage opt-in handling
"""
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from sqlalchemy import select, delete, and_, func

# Add project paths
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from src.db.session import get_session_context
from src.db.models import (
    Case, Signal, Url, UrlIntel, Feedback, ReportedUrl, 
    Device, ApiUsage, StatsDaily, RiskLevel, ActionType
)
from guardian_ml.logger import logger


@dataclass
class RetentionConfig:
    """Configuration for data retention."""
    retention_days: int = 30
    batch_size: int = 1000
    dry_run: bool = False
    schedule_cron: str = "0 3 * * *"  # Daily 3 AM
    
    def __post_init__(self):
        pass


@dataclass
class RetentionResult:
    """Result of retention cleanup."""
    timestamp: str
    deleted_counts: Dict[str, int]
    oldest_remaining: Optional[str]
    newest_remaining: Optional[str]
    dry_run: bool
    duration_seconds: float


class RetentionJob:
    """
    Handles data retention cleanup.
    
    Deletes cases older than RETENTION_DAYS with cascade to:
    - signals
    - urls
    - url_intel
    - feedback
    """
    
    def __init__(self, config: Optional[RetentionConfig] = None):
        self.config = config or RetentionConfig()
    
    def run(self) -> RetentionResult:
        """Run retention cleanup."""
        logger.info("Running retention cleanup...")
        start_time = datetime.now(timezone.utc)
        
        cutoff = start_time - timedelta(days=self.config.retention_days)
        
        with get_session_context() as session:
            # Find cases to delete
            stmt = select(Case.id).where(Case.created_at < cutoff)
            case_ids = [row[0] for row in session.execute(stmt).fetchall()]
            
            if not case_ids:
                logger.info("No cases to delete")
                return RetentionResult(
                    timestamp=start_time.isoformat(),
                    deleted_counts={},
                    oldest_remaining=None,
                    newest_remaining=None,
                    dry_run=self.config.dry_run,
                    duration_seconds=0,
                )
            
            logger.info(f"Found {len(case_ids)} cases older than {self.config.retention_days} days")
            
            deleted_counts = {}
            
            if not self.config.dry_run:
                # Delete in batches to avoid lock contention
                for i in range(0, len(case_ids), self.config.batch_size):
                    batch = case_ids[i:i + self.config.batch_size]
                    
                    # Delete child tables first (FK constraints)
                    # UrlIntel
                    result = session.execute(
                        delete(UrlIntel).where(UrlIntel.url_id.in_(
                            select(Url.id).where(Url.case_id.in_(batch))
                        ))
                    )
                    deleted_counts["url_intel"] = deleted_counts.get("url_intel", 0) + result.rowcount
                    
                    # Urls
                    result = session.execute(delete(Url).where(Url.case_id.in_(batch)))
                    deleted_counts["urls"] = deleted_counts.get("urls", 0) + result.rowcount
                    
                    # Signals
                    result = session.execute(delete(Signal).where(Signal.case_id.in_(batch)))
                    deleted_counts["signals"] = deleted_counts.get("signals", 0) + result.rowcount
                    
                    # Feedback
                    result = session.execute(delete(Feedback).where(Feedback.case_id.in_(batch)))
                    deleted_counts["feedback"] = deleted_counts.get("feedback", 0) + result.rowcount
                    
                    # Cases
                    result = session.execute(delete(Case).where(Case.id.in_(batch)))
                    deleted_counts["cases"] = deleted_counts.get("cases", 0) + result.rowcount
                    
                    session.commit()
                    logger.debug(f"Deleted batch {i//self.config.batch_size + 1}: {len(batch)} cases")
            else:
                # Dry run - just count
                for batch in [case_ids[i:i + self.config.batch_size] for i in range(0, len(case_ids), self.config.batch_size)]:
                    # Count what would be deleted
                    url_intel_count = session.execute(
                        select(func.count(UrlIntel.id)).where(UrlIntel.url_id.in_(
                            select(Url.id).where(Url.case_id.in_(batch))
                        ))
                    ).scalar()
                    deleted_counts["url_intel"] = deleted_counts.get("url_intel", 0) + url_intel_count
                    
                    urls_count = session.execute(
                        select(func.count(Url.id)).where(Url.case_id.in_(batch))
                    ).scalar()
                    deleted_counts["urls"] = deleted_counts.get("urls", 0) + urls_count
                    
                    signals_count = session.execute(
                        select(func.count(Signal.id)).where(Signal.case_id.in_(batch))
                    ).scalar()
                    deleted_counts["signals"] = deleted_counts.get("signals", 0) + signals_count
                    
                    feedback_count = session.execute(
                        select(func.count(Feedback.id)).where(Feedback.case_id.in_(batch))
                    ).scalar()
                    deleted_counts["feedback"] = deleted_counts.get("feedback", 0) + feedback_count
                    
                    deleted_counts["cases"] = deleted_counts.get("cases", 0) + len(batch)
            
            # Get remaining case date range
            oldest = session.execute(
                select(func.min(Case.created_at))
            ).scalar()
            newest = session.execute(
                select(func.max(Case.created_at))
            ).scalar()
            
            session.commit()
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        result = RetentionResult(
            timestamp=start_time.isoformat(),
            deleted_counts=deleted_counts,
            oldest_remaining=oldest.isoformat() if oldest else None,
            newest_remaining=newest.isoformat() if newest else None,
            dry_run=self.config.dry_run,
            duration_seconds=duration,
        )
        
        logger.info(f"Retention cleanup complete in {duration:.2f}s")
        logger.info(f"  Deleted: {deleted_counts}")
        
        return result
    
    def wipe_device(self, device_id: str) -> Dict[str, int]:
        """
        Wipe all data for a specific device (GDPR/privacy).
        
        Hard deletes: device, cases, signals, urls, url_intel, feedback, reports, api_usage
        """
        import uuid
        device_uuid = uuid.UUID(device_id)
        
        logger.info(f"Wiping device {device_id}...")
        start_time = datetime.now(timezone.utc)
        
        with get_session_context() as session:
            # Verify device exists
            device = session.execute(
                select(Device).where(Device.id == device_uuid)
            ).scalar_one_or_none()
            
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Get case IDs for this device
            case_ids = [row[0] for row in session.execute(
                select(Case.id).where(Case.device_id == device_uuid)
            ).fetchall()]
            
            deleted_counts = {}
            
            # Delete child tables
            if case_ids:
                # UrlIntel
                result = session.execute(
                    delete(UrlIntel).where(UrlIntel.url_id.in_(
                        select(Url.id).where(Url.case_id.in_(case_ids))
                    ))
                )
                deleted_counts["url_intel"] = result.rowcount
                
                # Urls
                result = session.execute(delete(Url).where(Url.case_id.in_(case_ids)))
                deleted_counts["urls"] = result.rowcount
                
                # Signals
                result = session.execute(delete(Signal).where(Signal.case_id.in_(case_ids)))
                deleted_counts["signals"] = result.rowcount
                
                # Feedback
                result = session.execute(delete(Feedback).where(Feedback.case_id.in_(case_ids)))
                deleted_counts["feedback"] = result.rowcount
                
                # Cases
                result = session.execute(delete(Case).where(Case.id.in_(case_ids)))
                deleted_counts["cases"] = result.rowcount
            
            # Reports by this device
            result = session.execute(delete(ReportedUrl).where(ReportedUrl.reporter_device_id == device_uuid))
            deleted_counts["reported_urls"] = result.rowcount
            
            # API usage
            result = session.execute(delete(ApiUsage).where(ApiUsage.device_id == device_uuid))
            deleted_counts["api_usage"] = result.rowcount
            
            # Rate limit buckets
            from src.db.models import RateLimitBucket
            result = session.execute(delete(RateLimitBucket).where(RateLimitBucket.device_id == device_uuid))
            deleted_counts["rate_limit_buckets"] = result.rowcount
            
            # Device itself
            session.execute(delete(Device).where(Device.id == device_uuid))
            deleted_counts["device"] = 1
            
            session.commit()
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        logger.info(f"Device wipe complete in {duration:.2f}s: {deleted_counts}")
        
        return deleted_counts


def run_retention_job(config: Optional[RetentionConfig] = None) -> RetentionResult:
    """Convenience function to run retention job."""
    job = RetentionJob(config)
    return job.run()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Run retention cleanup")
    parser.add_argument("--days", type=int, default=30, help="Retention days")
    parser.add_argument("--dry-run", action="store_true", help="Dry run only")
    parser.add_argument("--wipe-device", type=str, help="Wipe specific device ID")
    args = parser.parse_args()
    
    if args.wipe_device:
        job = RetentionJob(RetentionConfig())
        result = job.wipe_device(args.wipe_device)
        print(f"Wiped device {args.wipe_device}: {result}")
    else:
        config = RetentionConfig(retention_days=args.days, dry_run=args.dry_run)
        result = run_retention_job(config)
        print(f"Deleted: {result.deleted_counts}")
        print(f"Duration: {result.duration_seconds:.2f}s")