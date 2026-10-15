"""
Scheduler - APScheduler setup for background jobs.
"""
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

# Add project paths
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from guardian_ml.logger import logger


class Scheduler:
    """
    Job scheduler using APScheduler.
    
    Manages:
    - Blocklist generation (every 5 min)
    - Retention cleanup (daily)
    - Drift monitoring (hourly)
    - Model retraining (weekly)
    """
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self._jobs_registered = False
    
    def register_jobs(self) -> None:
        """Register all scheduled jobs."""
        if self._jobs_registered:
            return
        
        # Import job functions
        from src.jobs.blocklist import run_blocklist_job, BlocklistConfig
        from src.jobs.retention import run_retention_job, RetentionConfig
        from src.jobs.drift_monitor import run_drift_monitor, DriftConfig
        from src.jobs.retrain import run_retrain_job, RetrainConfig
        
        # Blocklist - every 5 minutes
        self.scheduler.add_job(
            run_blocklist_job,
            CronTrigger.from_crontab("*/5 * * * *"),
            id="blocklist",
            name="Blocklist Generation",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        
        # Retention - daily at 3 AM
        self.scheduler.add_job(
            run_retention_job,
            CronTrigger.from_crontab("0 3 * * *"),
            id="retention",
            name="Data Retention Cleanup",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        
        # Drift Monitor - hourly
        self.scheduler.add_job(
            run_drift_monitor,
            CronTrigger.from_crontab("0 * * * *"),
            id="drift_monitor",
            name="Drift Monitoring",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        
        # Retrain - weekly Monday 2 AM
        self.scheduler.add_job(
            run_retrain_job,
            CronTrigger.from_crontab("0 2 * * 1"),
            id="retrain",
            name="Model Retraining",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        
        self._jobs_registered = True
        logger.info("All jobs registered with scheduler")
    
    def start(self) -> None:
        """Start the scheduler."""
        self.register_jobs()
        self.scheduler.start()
        logger.info("Scheduler started")
    
    def shutdown(self, wait: bool = True) -> None:
        """Shutdown the scheduler."""
        self.scheduler.shutdown(wait=wait)
        logger.info("Scheduler stopped")
    
    def get_job_status(self) -> dict:
        """Get status of all jobs."""
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                "trigger": str(job.trigger),
            })
        return {"jobs": jobs, "running": self.scheduler.running}


# Global scheduler instance
_scheduler: Optional[Scheduler] = None


def get_scheduler() -> Scheduler:
    """Get global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = Scheduler()
    return _scheduler


@asynccontextmanager
async def lifespan_scheduler():
    """Lifespan context manager for FastAPI."""
    scheduler = get_scheduler()
    scheduler.start()
    try:
        yield
    finally:
        scheduler.shutdown()


if __name__ == "__main__":
    import asyncio
    
    async def main():
        scheduler = get_scheduler()
        scheduler.start()
        
        print("Scheduler running. Press Ctrl+C to stop.")
        print("Jobs:")
        for job in scheduler.get_job_status()["jobs"]:
            print(f"  {job['id']}: {job['name']} - next: {job['next_run']}")
        
        try:
            while True:
                await asyncio.sleep(60)
        except KeyboardInterrupt:
            scheduler.shutdown()
    
    asyncio.run(main())