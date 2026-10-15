"""
ML Pipeline Orchestrator

Ties together all components:
1. Data Ingestion -> fetch, deduplicate, snapshot, split
2. Feature Engineering -> fit transformers, extract features
3. Model Training -> train LR + LightGBM with calibration
4. Evaluation -> comprehensive metrics on held-out test set
5. Export -> model package for API consumption

Supports:
- make train: full pipeline from raw data to exported model
- make eval: evaluate existing model on test set
- Reproducible runs with version hashes
"""
import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

import joblib
import numpy as np
import pandas as pd
import scipy.sparse as sp

from guardian_ml.components.data_ingestion import DataIngestion, DataIngestionConfig
from guardian_ml.components.evaluation import EvaluationConfig, ModelEvaluator
from guardian_ml.components.feature_engineering import FeatureConfig, FeatureEngineer
from guardian_ml.components.model_exporter import export_for_api
from guardian_ml.components.model_training import GuardianTrainer, ModelConfig
from guardian_ml.exception import MLPipelineException
from guardian_ml.logger import logger


@dataclass
class PipelineConfig:
    """Master configuration for the entire ML pipeline."""
    # Data
    data_ingestion: DataIngestionConfig = None
    create_snapshot: bool = True
    include_crawled_benign: bool = True  # Enable by default for realistic benign URLs
    tranco_limit: int = 100000
    
    # Features
    feature_engineering: FeatureConfig = None
    
    # Model
    model_training: ModelConfig = None
    
    # Evaluation
    evaluation: EvaluationConfig = None
    
    # Pipeline
    use_domain_split: bool = True  # Domain-disjoint validation
    random_seed: int = 42
    allow_synthetic_export: bool = False
    
    # Output
    export_dir: Path = None
    
    def __post_init__(self):
        from guardian_ml.paths import get_api_models_dir
        if self.data_ingestion is None:
            self.data_ingestion = DataIngestionConfig()
        if self.feature_engineering is None:
            self.feature_engineering = FeatureConfig()
        if self.model_training is None:
            self.model_training = ModelConfig()
        if self.evaluation is None:
            self.evaluation = EvaluationConfig()
        if self.export_dir is None:
            self.export_dir = get_api_models_dir()
        
        # Ensure export directory exists
        self.export_dir.mkdir(parents=True, exist_ok=True)


class GuardianPipeline:
    """
    End-to-end ML pipeline for Guardian.
    
    Usage:
        pipeline = GuardianPipeline()
        pipeline.run()  # Full training pipeline
        
        # Or step by step:
        train_records, test_records = pipeline.ingest_data()
        X_train, y_train, domains_train = pipeline.prepare_features(train_records)
        pipeline.train_models(X_train, y_train, domains_train)
        results = pipeline.evaluate()
        pipeline.export_model()
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        self.config = config or PipelineConfig()
        self.config.export_dir.mkdir(parents=True, exist_ok=True)
        
        # Components
        self.data_ingestion = DataIngestion(self.config.data_ingestion)
        self.feature_engineer = FeatureEngineer(self.config.feature_engineering)
        self.trainer = GuardianTrainer(self.config.model_training)
        self.evaluator = ModelEvaluator(self.config.evaluation)
        
        # State
        self.train_records: List[Dict] = []
        self.test_records: List[Dict] = []
        self.X_train: Optional[sp.csr_matrix] = None
        self.y_train: Optional[np.ndarray] = None
        self.X_test: Optional[sp.csr_matrix] = None
        self.y_test: Optional[np.ndarray] = None
        self.train_domains: Optional[np.ndarray] = None
        self.test_domains: Optional[np.ndarray] = None
        self.test_tlds: Optional[List[str]] = None
        self.test_urls: Optional[List[str]] = None
        self.is_trained: bool = False
        self.is_synthetic: bool = False

    def _extract_domain_and_tld(self, records: List[Dict]) -> Tuple[np.ndarray, List[str]]:
        """Extract registrable domain and TLD for each record."""
        from guardian_ml.components.data_ingestion import DataIngestion
        ingestion = DataIngestion()
        domains = []
        tlds = []
        for rec in records:
            domain = ingestion._get_registrable_domain(rec["url"])
            domains.append(domain)
            # Extract TLD
            import tldextract
            ext = tldextract.extract(rec["url"])
            tlds.append(ext.suffix if ext.suffix else "unknown")
        return np.array(domains), tlds

    def ingest_data(self) -> Tuple[List[Dict], List[Dict]]:
        """
        Step 1: Ingest data from all sources.
        
        Returns:
            (train_records, test_records) - domain-disjoint split
        """
        logger.info("=" * 60)
        logger.info("STEP 1: DATA INGESTION")
        logger.info("=" * 60)
        
        # Fetch and snapshot
        train_records, test_records, metadata = self.data_ingestion.run(
            create_snapshot=self.config.create_snapshot,
            include_crawled=self.config.include_crawled_benign,
        )
        
        self.train_records = train_records
        self.test_records = test_records
        self.is_synthetic = (
            bool(metadata.get("source_counts", {}).get("synthetic"))
            or any(record.get("source") == "synthetic" for record in train_records + test_records)
        )
        
        logger.info(f"Train records: {len(train_records)}")
        logger.info(f"Test records: {len(test_records)}")
        logger.info(f"Snapshot metadata: {metadata}")
        
        return train_records, test_records

    def prepare_features(self, records: Optional[List[Dict]] = None) -> Tuple[sp.csr_matrix, np.ndarray, np.ndarray]:
        """
        Step 2: Prepare features for given records.
        
        If records is None, uses self.train_records.
        Fits feature engineer on training data only.
        
        Returns:
            (X, y, domains)
        """
        logger.info("=" * 60)
        logger.info("STEP 2: FEATURE ENGINEERING")
        logger.info("=" * 60)
        
        if records is None:
            records = self.train_records
        
        urls = [r["url"] for r in records]
        labels = np.array([r["label"] for r in records])
        domains, tlds = self._extract_domain_and_tld(records)
        
        # Fit on training data only
        if records is self.train_records:
            X = self.feature_engineer.fit_transform(urls, labels.tolist())
            self.X_train = X
            self.y_train = labels
            self.train_domains = domains
        else:
            X = self.feature_engineer.transform(urls)
            self.X_test = X
            self.y_test = labels
            self.test_domains = domains
            self.test_tlds = tlds
            self.test_urls = urls
        
        logger.info(f"Feature matrix shape: {X.shape}")
        logger.info(f"Feature groups: lexical={self.config.feature_engineering.use_lexical}, "
                   f"char_ngrams={self.config.feature_engineering.use_char_ngrams}, "
                   f"host_tokens={self.config.feature_engineering.use_host_tokens}")
        
        return X, labels, domains

    def train_models(self) -> Dict[str, Any]:
        """
        Step 3: Train both Logistic Regression and LightGBM models.
        
        Uses domain-disjoint or time-based validation split.
        """
        logger.info("=" * 60)
        logger.info("STEP 3: MODEL TRAINING")
        logger.info("=" * 60)
        
        if self.X_train is None or self.y_train is None:
            raise MLPipelineException("No training data. Call prepare_features() first.", sys)
        
        # Get timestamps for time-based split if needed
        timestamps = None
        if hasattr(self, 'train_records') and self.train_records:
            timestamps = np.array([
                pd.Timestamp(r.get("fetched_at", "1970-01-01")).timestamp() 
                for r in self.train_records
            ])
        
        train_info = self.trainer.train(
            self.X_train,
            self.y_train,
            self.feature_engineer.get_feature_names(),
            domain_labels=self.train_domains,
            timestamps=timestamps,
            split_method="domain" if self.config.use_domain_split else "time",
        )
        
        self.is_trained = True
        logger.info(f"Training complete. Version: {self.trainer.version_hash}")
        
        return train_info

    def evaluate(self, on_test: bool = True) -> Dict[str, Any]:
        """
        Step 4: Evaluate models on held-out test set (domain-disjoint split).
        
        Args:
            on_test: If True, evaluate on test set. If False, use validation split from training.
        """
        logger.info("=" * 60)
        logger.info("STEP 4: MODEL EVALUATION (Domain-Disjoint)")
        logger.info("=" * 60)
        
        if not self.is_trained:
            raise MLPipelineException("Models not trained. Call train_models() first.", sys)
        
        if on_test:
            if self.X_test is None:
                self.prepare_features(self.test_records)
            X_eval, y_eval = self.X_test, self.y_test
            tlds = self.test_tlds
            urls = self.test_urls
        else:
            raise NotImplementedError("Validation evaluation not implemented. Use on_test=True.")
        
        # Evaluate both models
        results = self.evaluator.compare_models(
            {
                "logistic_regression": self.trainer.lr_model,
                "lightgbm": self.trainer.lgb_model,
            },
            X_eval,
            y_eval,
            tlds,
        )
        
        # Print summary for LightGBM (primary model)
        from guardian_ml.components.evaluation import print_evaluation_summary
        print_evaluation_summary(results["lightgbm"], "LightGBM (Domain-Disjoint Test Set)")
        print_evaluation_summary(results["logistic_regression"], "Logistic Regression (Domain-Disjoint Test Set)")
        
        return results
    
    def evaluate_time_based(self) -> Dict[str, Any]:
        """
        Evaluate models on time-based split (older train, newer test).
        
        This simulates real-world temporal deployment where model sees older data first.
        """
        logger.info("=" * 60)
        logger.info("STEP 4b: MODEL EVALUATION (Time-Based Split)")
        logger.info("=" * 60)
        
        if not self.is_trained:
            raise MLPipelineException("Models not trained. Call train_models() first.", sys)
        
        # Get all records and split by time
        all_records = self.train_records + self.test_records
        from guardian_ml.components.data_ingestion import DataIngestion
        ingestion = DataIngestion()
        train_records, test_records = ingestion.split_by_time(all_records, test_ratio=0.2)
        
        logger.info(f"Time-based split: {len(train_records)} train, {len(test_records)} test")
        
        # Prepare features for time-based test set
        urls = [r["url"] for r in test_records]
        labels = np.array([r["label"] for r in test_records])
        domains, tlds = self._extract_domain_and_tld(test_records)
        
        X_test = self.feature_engineer.transform(urls)
        
        # Evaluate both models
        results = self.evaluator.compare_models(
            {
                "logistic_regression": self.trainer.lr_model,
                "lightgbm": self.trainer.lgb_model,
            },
            X_test,
            labels,
            tlds,
        )
        
        # Print summary
        from guardian_ml.components.evaluation import print_evaluation_summary
        print_evaluation_summary(results["lightgbm"], "LightGBM (Time-Based Test Set)")
        print_evaluation_summary(results["logistic_regression"], "Logistic Regression (Time-Based Test Set)")
        
        return results
    
    def run_shortcut_check(self) -> Dict[str, float]:
        """
        Run shortcut detection check on training data.
        
        Trains single-feature-group models to detect if any group
        trivially separates data sources rather than learning general patterns.
        
        Returns:
            Dictionary with AUC scores for each feature group and individual features
        """
        logger.info("=" * 60)
        logger.info("SHORTCUT DETECTION CHECK")
        logger.info("=" * 60)
        
        results = {}
        
        if self.feature_engineer.config.run_shortcut_check:
            logger.info("Running shortcut check on training data...")
            results = self.feature_engineer._run_shortcut_check(
                [r["url"] for r in self.train_records],
                [r["label"] for r in self.train_records]
            )
            
            # Log summary
            logger.info("Shortcut check results:")
            for key, val in results.items():
                if val > 0.7:
                    logger.warning(f"  ⚠ {key}: AUC={val:.4f} (potential shortcut)")
                else:
                    logger.info(f"    {key}: AUC={val:.4f}")
        else:
            logger.warning("Shortcut check was not run (disabled in config)")
        
        return results

    def export_model(self) -> Path:
        """
        Step 5: Export model package for API consumption.
        
        Creates:
        - model.joblib: Both models + feature engineer
        - feature_schema.json: Feature extraction spec
        - version.txt: Model version hash
        """
        logger.info("=" * 60)
        logger.info("STEP 5: MODEL EXPORT")
        logger.info("=" * 60)
        
        if not self.is_trained:
            raise MLPipelineException("Models not trained. Call train_models() first.", sys)
        
        # Prepare config dict for export
        trainer_config = {
            "synthetic": self.is_synthetic,
            "lr": {
                "C": self.config.model_training.lr_C,
                "max_iter": self.config.model_training.lr_max_iter,
                "class_weight": "balanced",
            },
            "lgb": {
                "n_estimators": self.config.model_training.lgb_n_estimators,
                "learning_rate": self.config.model_training.lgb_learning_rate,
                "max_depth": self.config.model_training.lgb_max_depth,
                "num_leaves": self.config.model_training.lgb_num_leaves,
                "min_child_samples": self.config.model_training.lgb_min_child_samples,
                "subsample": self.config.model_training.lgb_subsample,
                "colsample_bytree": self.config.model_training.lgb_colsample_bytree,
                "reg_alpha": self.config.model_training.lgb_reg_alpha,
                "reg_lambda": self.config.model_training.lgb_reg_lambda,
            },
            "calibration": {
                "method": self.config.model_training.calibration_method,
                "cv": self.config.model_training.calibration_cv,
            },
        }
        
        # Export
        export_info = export_for_api(
            self.trainer,
            self.feature_engineer,
            self.feature_engineer.get_feature_names(),
            trainer_config,
            str(self.config.export_dir),
            allow_synthetic=self.config.allow_synthetic_export,
        )
        
        logger.info(f"Model exported to {export_info['model_path']}")
        logger.info(f"Version: {self.trainer.version_hash}")
        
        return Path(export_info['model_path'])

    def run(self) -> Dict[str, Any]:
        """
        Run the complete pipeline end-to-end.
        
        Returns:
            Dictionary with all results and metadata
        """
        logger.info("Starting Guardian ML Pipeline")
        logger.info(f"Config: {asdict(self.config)}")
        
        # Step 1: Ingest data
        self.ingest_data()
        
        # Step 2: Prepare features (train)
        self.prepare_features(self.train_records)
        
        # Step 2b: Prepare features (test)
        self.prepare_features(self.test_records)
        
        # Step 3: Train models
        train_info = self.train_models()
        
        # Step 4: Evaluate (domain-disjoint)
        eval_results = self.evaluate(on_test=True)
        
        # Step 4b: Evaluate (time-based)
        time_eval_results = self.evaluate_time_based()
        
        # Step 4c: Shortcut detection check
        self.run_shortcut_check()
        
        # Step 5: Export
        export_path = self.export_model()
        
        # Summary
        summary = {
            "version_hash": self.trainer.version_hash,
            "train_info": train_info,
            "eval_results": {
                name: {
                    "roc_auc": res.roc_auc,
                    "pr_auc": res.pr_auc,
                    "f1": res.f1,
                    "fpr_at_1pct": res.fpr_at_1pct_tpr,
                    "fpr_at_01pct": res.fpr_at_01pct_tpr,
                    "ece": res.ece,
                    "brier_score": res.brier_score,
                }
                for name, res in eval_results.items()
            },
            "time_based_eval_results": {
                name: {
                    "roc_auc": res.roc_auc,
                    "pr_auc": res.pr_auc,
                    "f1": res.f1,
                    "fpr_at_1pct": res.fpr_at_1pct_tpr,
                    "fpr_at_01pct": res.fpr_at_01pct_tpr,
                    "ece": res.ece,
                    "brier_score": res.brier_score,
                }
                for name, res in time_eval_results.items()
            },
            "export_path": str(export_path),
            "feature_count": len(self.feature_engineer.get_feature_names()),
        }
        
        # Save pipeline summary
        summary_path = self.config.export_dir / "pipeline_summary.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        
        logger.info("=" * 60)
        logger.info("PIPELINE COMPLETE")
        logger.info("=" * 60)
        logger.info(f"Version: {self.trainer.version_hash}")
        logger.info(f"Export: {export_path}")
        logger.info(f"Summary: {summary_path}")
        
        return summary


def run_training_pipeline(config: Optional[PipelineConfig] = None) -> Dict[str, Any]:
    """Convenience function to run full training pipeline."""
    pipeline = GuardianPipeline(config)
    return pipeline.run()


def run_evaluation_only(model_path: Path, test_data_path: Path) -> Dict[str, Any]:
    """
    Run evaluation on existing model with test data.
    
    Useful for CI/CD and regression testing.
    """
    logger.info(f"Loading model from {model_path}")
    model_package = joblib.load(model_path)
    
    lgb_model = model_package["lgb_model"]
    lr_model = model_package["lr_model"]
    feature_engineer = model_package["feature_engineer"]
    feature_names = model_package["feature_names"]
    
    logger.info(f"Loading test data from {test_data_path}")
    test_records = []
    with open(test_data_path) as f:
        for line in f:
            test_records.append(json.loads(line))
    
    urls = [r["url"] for r in test_records]
    labels = np.array([r["label"] for r in test_records])
    
    # Transform
    X_test = feature_engineer.transform(urls)
    
    # Evaluate
    evaluator = ModelEvaluator()
    results = evaluator.compare_models(
        {"logistic_regression": lr_model, "lightgbm": lgb_model},
        X_test,
        labels,
    )
    
    return results


if __name__ == "__main__":
    # Run full pipeline
    import argparse
    
    parser = argparse.ArgumentParser(description="Guardian ML Pipeline")
    parser.add_argument("--eval-only", action="store_true", help="Run evaluation only")
    parser.add_argument("--model-path", type=Path, help="Path to model for eval-only")
    parser.add_argument("--test-data", type=Path, help="Path to test data for eval-only")
    parser.add_argument("--no-snapshot", action="store_true", help="Don't create data snapshot")
    parser.add_argument("--tranco-limit", type=int, default=100000, help="Tranco top-N limit")
    args = parser.parse_args()
    
    if args.eval_only:
        if not args.model_path or not args.test_data:
            parser.error("--eval-only requires --model-path and --test-data")
        run_evaluation_only(args.model_path, args.test_data)
    else:
        config = PipelineConfig()
        config.create_snapshot = not args.no_snapshot
        config.tranco_limit = args.tranco_limit
        run_training_pipeline(config)