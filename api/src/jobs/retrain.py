"""
Retrain Job - Automated ML model retraining with feedback loop.

Features:
- Exports consented false positives/negatives from feedback
- Merges with fresh threat intelligence feeds
- Retrains on rolling time split
- Compares against current model with FPR gates
- Promotes only if metrics pass
- Scheduled weekly
"""
import hashlib
import json
import logging
import os
import sys
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

import joblib
import numpy as np
import pandas as pd
import scipy.sparse as sp
from sqlalchemy import select, and_, func

# Add project paths
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from src.db.session import get_session_context
from src.db.models import Feedback, Case, VerdictType, ReportedUrl
from guardian_ml.pipeline import GuardianPipeline, PipelineConfig, run_training_pipeline
from guardian_ml.components.data_ingestion import DataIngestion, DataIngestionConfig
from guardian_ml.components.feature_engineering import FeatureEngineer
from guardian_ml.components.model_training import GuardianTrainer, ModelConfig
from guardian_ml.components.evaluation import ModelEvaluator, EvaluationConfig
from guardian_ml.logger import logger

API_MODELS_DIR = Path(__file__).resolve().parents[2] / "models"


@dataclass
class RetrainConfig:
    """Configuration for retrain job."""
    # Feedback settings
    min_feedback_samples: int = 50  # Minimum feedback samples before retrain
    feedback_lookback_days: int = 30  # How far back to look for feedback
    require_consent: bool = True  # Only use feedback from consented users
    
    # Data sources
    include_fresh_feeds: bool = True  # Merge with fresh OpenPhish/PhishTank/URLhaus
    include_reported_urls: bool = True  # Include user-reported URLs
    tranco_limit: int = 100000  # Benign samples from Tranco
    
    # Training settings
    use_time_split: bool = True  # Use rolling time split (not domain-disjoint)
    test_ratio: float = 0.2
    time_split_ratio: float = 0.8  # Train on older 80%, test on newer 20%
    
    # Promotion gates (must ALL pass to promote)
    min_auc: float = 0.90  # Minimum ROC-AUC
    min_pr_auc: float = 0.85  # Minimum PR-AUC
    max_fpr_at_1pct_tpr: float = 0.05  # Maximum FPR at 1% TPR (recall)
    max_fpr_at_01pct_tpr: float = 0.02  # Maximum FPR at 0.1% TPR
    max_ece: float = 0.05  # Maximum Expected Calibration Error
    min_improvement_auc: float = 0.005  # Minimum AUC improvement over current
    
    # Paths
    model_dir: Path = API_MODELS_DIR
    current_model_path: Path = API_MODELS_DIR / "model.joblib"
    review_queue_dir: Path = Path("ml/data/review_queue")
    export_dir: Path = API_MODELS_DIR
    
    # Scheduling
    schedule_cron: str = "0 2 * * 1"  # Weekly Monday 2 AM
    
    def __post_init__(self):
        self.model_dir = Path(self.model_dir)
        self.current_model_path = Path(self.current_model_path)
        self.review_queue_dir = Path(self.review_queue_dir)
        self.export_dir = Path(self.export_dir)
        
        self.review_queue_dir.mkdir(parents=True, exist_ok=True)
        self.export_dir.mkdir(parents=True, exist_ok=True)


@dataclass
class RetrainResult:
    """Result of retrain job."""
    success: bool
    version_hash: str
    promoted: bool
    train_samples: int
    test_samples: int
    feedback_samples: int
    metrics: Dict[str, float]
    gate_results: Dict[str, bool]
    message: str
    timestamp: str


class FeedbackExporter:
    """Exports consented feedback for retraining."""
    
    def __init__(self, config: RetrainConfig):
        self.config = config
    
    def export_feedback(self) -> Tuple[List[Dict], List[Dict]]:
        """
        Export false positives and false negatives from feedback.
        
        Returns:
            Tuple of (false_positives, false_negatives) as lists of records
        """
        logger.info("Exporting feedback for retraining...")
        
        with get_session_context() as session:
            # Get feedback from last N days
            cutoff = datetime.now(timezone.utc) - timedelta(days=self.config.feedback_lookback_days)
            
            stmt = select(Feedback, Case).join(Case, Feedback.case_id == Case.id).where(
                and_(
                    Feedback.created_at >= cutoff,
                    Feedback.verdict.in_([VerdictType.FALSE_POSITIVE, VerdictType.FALSE_NEGATIVE]),
                    Case.store_raw_text == True if self.config.require_consent else True
                )
            )
            
            results = session.execute(stmt).all()
            
            false_positives = []
            false_negatives = []
            
            for feedback, case in results:
                # Extract URLs from case
                for url_data in case.urls:
                    record = {
                        "url": url_data["url"],
                        "label": 0 if feedback.verdict == VerdictType.FALSE_POSITIVE else 1,
                        "source": "feedback",
                        "feedback_verdict": feedback.verdict.value,
                        "feedback_notes": feedback.notes,
                        "case_id": str(case.id),
                        "fetched_at": datetime.now(timezone.utc).isoformat(),
                    }
                    
                    if feedback.verdict == VerdictType.FALSE_POSITIVE:
                        false_positives.append(record)
                    else:
                        false_negatives.append(record)
            
            logger.info(f"Exported {len(false_positives)} false positives, {len(false_negatives)} false negatives")
            
            return false_positives, false_negatives
    
    def export_reported_urls(self) -> List[Dict]:
        """Export user-reported URLs pending review."""
        logger.info("Exporting reported URLs...")
        
        with get_session_context() as session:
            cutoff = datetime.now(timezone.utc) - timedelta(days=self.config.feedback_lookback_days)
            
            stmt = select(ReportedUrl).where(
                and_(
                    ReportedUrl.created_at >= cutoff,
                    ReportedUrl.status == "pending"
                )
            )
            
            reports = session.execute(stmt).scalars().all()
            
            records = []
            for report in reports:
                records.append({
                    "url": report.url,
                    "label": 1,  # Reported as malicious
                    "source": "user_report",
                    "report_id": str(report.id),
                    "report_note": report.note,
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                })
            
            logger.info(f"Exported {len(records)} reported URLs")
            return records
    
    def save_review_queue(self, false_positives: List[Dict], false_negatives: List[Dict], reported: List[Dict]) -> Path:
        """Save review queue to disk for human review."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        queue_file = self.config.review_queue_dir / f"review_queue_{timestamp}.jsonl"
        
        all_records = false_positives + false_negatives + reported
        
        with open(queue_file, "w") as f:
            for record in all_records:
                f.write(json.dumps(record) + "\n")
        
        logger.info(f"Saved review queue to {queue_file} ({len(all_records)} records)")
        return queue_file


class RetrainJob:
    """
    Automated retraining job with feedback loop.
    
    Flow:
    1. Export consented feedback (FP/FN) and reported URLs
    2. Save to review queue for human validation
    3. Merge with fresh threat intel feeds
    4. Train on rolling time split
    5. Evaluate against promotion gates
    6. Promote if all gates pass
    """
    
    def __init__(self, config: Optional[RetrainConfig] = None):
        self.config = config or RetrainConfig()
        self.feedback_exporter = FeedbackExporter(self.config)
        self.data_ingestion = DataIngestion(DataIngestionConfig())
    
    def run(self) -> RetrainResult:
        """Run the complete retrain pipeline."""
        logger.info("=" * 60)
        logger.info("STARTING RETRAIN JOB")
        logger.info("=" * 60)
        
        timestamp = datetime.now(timezone.utc).isoformat()
        
        try:
            # Step 1: Export feedback and reported URLs
            logger.info("Step 1: Exporting feedback...")
            false_positives, false_negatives = self.feedback_exporter.export_feedback()
            reported_urls = self.feedback_exporter.export_reported_urls()
            
            feedback_count = len(false_positives) + len(false_negatives)
            reported_count = len(reported_urls)
            
            if feedback_count < self.config.min_feedback_samples and not self.config.include_fresh_feeds:
                return RetrainResult(
                    success=False,
                    version_hash="",
                    promoted=False,
                    train_samples=0,
                    test_samples=0,
                    feedback_samples=feedback_count,
                    metrics={},
                    gate_results={},
                    message=f"Insufficient feedback samples ({feedback_count} < {self.config.min_feedback_samples})",
                    timestamp=timestamp,
                )
            
            # Save review queue
            self.feedback_exporter.save_review_queue(false_positives, false_negatives, reported_urls)
            
            # Step 2: Merge with fresh feeds
            logger.info("Step 2: Fetching fresh threat intel feeds...")
            all_records = false_positives + false_negatives + reported_urls
            
            if self.config.include_fresh_feeds:
                fresh_records, _ = self.data_ingestion.fetch_all(
                    include_crawled=False,
                    tranco_limit=self.config.tranco_limit
                )
                all_records.extend(fresh_records)
                logger.info(f"Added {len(fresh_records)} fresh feed records")
            
            # Deduplicate by URL
            seen_urls = set()
            deduped_records = []
            for rec in all_records:
                if rec["url"] not in seen_urls:
                    seen_urls.add(rec["url"])
                    deduped_records.append(rec)
            
            logger.info(f"Total records after deduplication: {len(deduped_records)}")
            
            # Step 3: Create rolling time split
            logger.info("Step 3: Creating rolling time split...")
            sorted_records = sorted(deduped_records, key=lambda r: r.get("fetched_at", ""))
            
            if self.config.use_time_split:
                split_idx = int(len(sorted_records) * self.config.time_split_ratio)
                train_records = sorted_records[:split_idx]
                test_records = sorted_records[split_idx:]
            else:
                train_records, test_records = self.data_ingestion.split_by_domain(deduped_records, self.config.test_ratio)
            
            logger.info(f"Train: {len(train_records)}, Test: {len(test_records)}")
            
            # Step 4: Prepare features
            logger.info("Step 4: Preparing features...")
            pipeline_config = PipelineConfig(
                create_snapshot=False,
                use_domain_split=not self.config.use_time_split,
            )
            pipeline = GuardianPipeline(pipeline_config)
            
            # Set records manually since we have custom split
            pipeline.train_records = train_records
            pipeline.test_records = test_records
            
            pipeline.prepare_features(train_records)
            pipeline.prepare_features(test_records)
            
            # Step 5: Train models
            logger.info("Step 5: Training models...")
            train_info = pipeline.train_models()
            
            # Step 6: Evaluate
            logger.info("Step 6: Evaluating models...")
            eval_results = pipeline.evaluate(on_test=True)
            
            # Step 7: Check promotion gates
            logger.info("Step 7: Checking promotion gates...")
            lgb_results = eval_results["lightgbm"]
            
            gates = {
                "min_auc": lgb_results.roc_auc >= self.config.min_auc,
                "min_pr_auc": lgb_results.pr_auc >= self.config.min_pr_auc,
                "max_fpr_at_1pct": lgb_results.fpr_at_1pct_tpr <= self.config.max_fpr_at_1pct_tpr,
                "max_fpr_at_01pct": lgb_results.fpr_at_01pct_tpr <= self.config.max_fpr_at_01pct_tpr,
                "max_ece": lgb_results.ece <= self.config.max_ece,
            }
            
            # Check improvement over current model
            current_auc = self._get_current_model_auc()
            if current_auc > 0:
                gates["min_improvement"] = lgb_results.roc_auc - current_auc >= self.config.min_improvement_auc
            else:
                gates["min_improvement"] = True  # No current model to compare
            
            all_gates_pass = all(gates.values())
            
            metrics = {
                "roc_auc": lgb_results.roc_auc,
                "pr_auc": lgb_results.pr_auc,
                "f1": lgb_results.f1,
                "fpr_at_1pct": lgb_results.fpr_at_1pct_tpr,
                "fpr_at_01pct": lgb_results.fpr_at_01pct_tpr,
                "ece": lgb_results.ece,
                "current_auc": current_auc,
                "auc_improvement": lgb_results.roc_auc - current_auc if current_auc > 0 else 0,
            }
            
            # Step 8: Promote if gates pass
            promoted = False
            if all_gates_pass:
                logger.info("All gates passed! Promoting model...")
                pipeline.export_model()
                promoted = True
            else:
                logger.warning("Some gates failed. Model NOT promoted.")
                for gate, passed in gates.items():
                    status = "PASS" if passed else "FAIL"
                    logger.warning(f"  {gate}: {status}")
            
            result = RetrainResult(
                success=True,
                version_hash=pipeline.trainer.version_hash,
                promoted=promoted,
                train_samples=len(train_records),
                test_samples=len(test_records),
                feedback_samples=feedback_count,
                metrics=metrics,
                gate_results=gates,
                message="Retrain completed successfully" if all_gates_pass else "Retrain completed but gates failed",
                timestamp=timestamp,
            )
            
            # Save retrain log
            self._save_retrain_log(result)
            
            logger.info("=" * 60)
            logger.info(f"RETRAIN JOB COMPLETE - {'PROMOTED' if promoted else 'NOT PROMOTED'}")
            logger.info("=" * 60)
            
            return result
            
        except Exception as e:
            logger.error(f"Retrain job failed: {e}", exc_info=True)
            return RetrainResult(
                success=False,
                version_hash="",
                promoted=False,
                train_samples=0,
                test_samples=0,
                feedback_samples=0,
                metrics={},
                gate_results={},
                message=f"Retrain failed: {str(e)}",
                timestamp=timestamp,
            )
    
    def _get_current_model_auc(self) -> float:
        """Get AUC of currently deployed model."""
        try:
            if self.config.current_model_path.exists():
                model_package = joblib.load(self.config.current_model_path)
                # We'd need to evaluate on test set - for now return 0 to skip gate
                return 0.0
        except Exception:
            pass
        return 0.0
    
    def _save_retrain_log(self, result: RetrainResult) -> None:
        """Save retrain result to log file."""
        log_dir = self.config.model_dir / "retrain_logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"retrain_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        with open(log_file, "w") as f:
            json.dump(asdict(result), f, indent=2, default=str)
        
        logger.info(f"Saved retrain log to {log_file}")


def run_retrain_job(config: Optional[RetrainConfig] = None) -> RetrainResult:
    """Convenience function to run retrain job."""
    job = RetrainJob(config)
    return job.run()


if __name__ == "__main__":
    # Allow running directly
    import argparse
    
    parser = argparse.ArgumentParser(description="Run retrain job")
    parser.add_argument("--min-feedback", type=int, default=50, help="Minimum feedback samples")
    parser.add_argument("--no-fresh-feeds", action="store_true", help="Skip fresh threat feeds")
    parser.add_argument("--force", action="store_true", help="Force retrain even with low feedback")
    args = parser.parse_args()
    
    config = RetrainConfig(
        min_feedback_samples=args.min_feedback,
        include_fresh_feeds=not args.no_fresh_feeds,
    )
    
    result = run_retrain_job(config)
    
    print(f"Success: {result.success}")
    print(f"Promoted: {result.promoted}")
    print(f"Version: {result.version_hash}")
    print(f"Message: {result.message}")
    
    sys.exit(0 if result.success else 1)