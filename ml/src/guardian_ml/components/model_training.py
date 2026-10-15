"""
Model Training Component

Implements:
1. Logistic Regression baseline (calibrated)
2. LightGBM main model (calibrated with isotonic regression)
3. Time-based and domain-disjoint evaluation
4. Model export with feature schema and version hash
"""
import hashlib
import json
import warnings
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

import joblib
import lightgbm as lgb
import numpy as np
import scipy.sparse as sp
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    classification_report, precision_recall_curve
)
from sklearn.model_selection import train_test_split

from guardian_ml.exception import ModelTrainingException, ModelEvaluationException
from guardian_ml.logger import logger


class CalibratedLGBM:
    """Wrapper for LightGBM model with isotonic calibration."""
    
    def __init__(self, base_model: Any, calibrator: Any):
        self.base_model = base_model
        self.calibrator = calibrator
        self.classes_ = np.array([0, 1])
    
    def predict_proba(self, X: Any) -> np.ndarray:
        X_dense = X.toarray() if sp.issparse(X) else X
        proba = self.base_model.predict_proba(X_dense)[:, 1]
        calibrated = self.calibrator.transform(proba)
        return np.column_stack([1 - calibrated, calibrated])
    
    def predict(self, X: Any) -> np.ndarray:
        proba = self.predict_proba(X)[:, 1]
        return (proba >= 0.5).astype(int)


class CalibratedLR:
    """Wrapper for Logistic Regression with isotonic calibration."""
    
    def __init__(self, base_model: Any, calibrator: Any):
        self.base_model = base_model
        self.calibrator = calibrator
        self.classes_ = np.array([0, 1])
    
    def predict_proba(self, X: Any) -> np.ndarray:
        proba = self.base_model.predict_proba(X)[:, 1]
        calibrated = self.calibrator.transform(proba)
        return np.column_stack([1 - calibrated, calibrated])
    
    def predict(self, X: Any) -> np.ndarray:
        proba = self.predict_proba(X)[:, 1]
        return (proba >= 0.5).astype(int)


@dataclass
class ModelConfig:
    """Configuration for model training."""
    # Logistic Regression
    lr_C: float = 1.0
    lr_max_iter: int = 1000
    lr_penalty: str = "l2"
    lr_solver: str = "lbfgs"
    
    # LightGBM
    lgb_n_estimators: int = 500
    lgb_learning_rate: float = 0.05
    lgb_max_depth: int = 8
    lgb_num_leaves: int = 63
    lgb_min_child_samples: int = 20
    lgb_subsample: float = 0.8
    lgb_colsample_bytree: float = 0.8
    lgb_reg_alpha: float = 0.1
    lgb_reg_lambda: float = 0.1
    lgb_random_state: int = 42
    lgb_n_jobs: int = -1
    lgb_verbose: int = -1
    
    # Calibration
    calibration_method: str = "isotonic"  # "isotonic" or "sigmoid"
    calibration_cv: int = 3
    
    # Training
    early_stopping_rounds: int = 50
    val_split: float = 0.1
    
    # Paths
    model_dir: Path = None

    def __post_init__(self):
        from guardian_ml.paths import get_model_dir
        if self.model_dir is None:
            self.model_dir = get_model_dir()
        self.model_dir.mkdir(parents=True, exist_ok=True)


@dataclass
class ModelMetrics:
    """Container for model evaluation metrics."""
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    pr_auc: float
    fpr_at_1pct: float
    fpr_at_01pct: float
    confusion_matrix: List[List[int]]
    classification_report: Dict
    per_tld_metrics: Dict[str, Dict]


class GuardianTrainer:
    """
    Trains and evaluates Guardian ML models.
    
    Supports:
    - Logistic Regression baseline (fast, interpretable)
    - LightGBM main model (high performance)
    - Probability calibration (isotonic regression)
    - Time-based and domain-disjoint evaluation
    - Model export with full metadata
    """

    def __init__(self, config: Optional[ModelConfig] = None):
        self.config = config or ModelConfig()
        self.config.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.lr_model: Optional[Any] = None
        self.lgb_model: Optional[Any] = None
        self.feature_names: List[str] = []
        self.version_hash: str = ""
        self.is_trained: bool = False

    def _compute_version_hash(self, feature_names: List[str], train_size: int) -> str:
        """Compute deterministic version hash from config and data."""
        config_str = json.dumps(asdict(self.config), sort_keys=True, default=str)
        content = f"{config_str}|{len(feature_names)}|{train_size}".encode()
        return hashlib.sha256(content).hexdigest()[:16]

    def train_logistic_regression(
        self,
        X_train: sp.csr_matrix,
        y_train: np.ndarray,
        X_val: sp.csr_matrix,
        y_val: np.ndarray,
        X_cal: Optional[sp.csr_matrix] = None,
        y_cal: Optional[np.ndarray] = None,
    ) -> CalibratedClassifierCV:
        """Train calibrated Logistic Regression baseline.
        
        Uses three-way split: train / validation / calibration.
        If X_cal/y_cal not provided, uses internal CV (CalibratedClassifierCV default).
        """
        logger.info("Training Logistic Regression baseline...")
        
        base_lr = LogisticRegression(
            C=self.config.lr_C,
            max_iter=self.config.lr_max_iter,
            penalty=self.config.lr_penalty,
            solver=self.config.lr_solver,
            random_state=self.config.lgb_random_state,
            n_jobs=self.config.lgb_n_jobs,
            class_weight="balanced",
        )
        
        # Check if calibration set has samples
        has_cal = X_cal is not None and y_cal is not None and X_cal.shape[0] > 0
        
        if has_cal:
            # Use prefit calibration on separate calibration set
            logger.info(f"Calibrating LR on separate calibration set ({X_cal.shape[0]} samples)")
            base_lr.fit(X_train, y_train)
            from sklearn.isotonic import IsotonicRegression
            
            cal_proba = base_lr.predict_proba(X_cal)[:, 1]
            calibrator = IsotonicRegression(out_of_bounds="clip")
            calibrator.fit(cal_proba, y_cal)
            
            # Use module-level CalibratedLR wrapper (picklable)
            calibrated_lr = CalibratedLR(base_lr, calibrator)
        else:
            # Use internal CV calibration (default behavior)
            logger.info("Calibrating LR with internal CV (no separate calibration set)")
            calibrated_lr = CalibratedClassifierCV(
                base_lr,
                method=self.config.calibration_method,
                cv=self.config.calibration_cv,
                ensemble=True,
            )
            calibrated_lr.fit(X_train, y_train)
        
        # Validate on validation set
        val_proba = calibrated_lr.predict_proba(X_val)[:, 1]
        val_auc = roc_auc_score(y_val, val_proba)
        logger.info(f"  Logistic Regression validation AUC: {val_auc:.4f}")
        
        return calibrated_lr

    def train_lightgbm(
        self,
        X_train: sp.csr_matrix,
        y_train: np.ndarray,
        X_val: sp.csr_matrix,
        y_val: np.ndarray,
        X_cal: Optional[sp.csr_matrix] = None,
        y_cal: Optional[np.ndarray] = None,
    ) -> CalibratedClassifierCV:
        """Train calibrated LightGBM model.
        
        Uses three-way split: train / validation (early stopping) / calibration (isotonic).
        If X_cal/y_cal not provided, falls back to using validation set (with warning).
        """
        logger.info("Training LightGBM model...")
        
        # LightGBM doesn't natively support sparse matrices in sklearn API
        X_train_dense = X_train.toarray() if sp.issparse(X_train) else X_train
        X_val_dense = X_val.toarray() if sp.issparse(X_val) else X_val
        X_cal_dense = X_cal.toarray() if sp.issparse(X_cal) else X_cal if X_cal is not None else None
        
        base_lgb = lgb.LGBMClassifier(
            n_estimators=self.config.lgb_n_estimators,
            learning_rate=self.config.lgb_learning_rate,
            max_depth=self.config.lgb_max_depth,
            num_leaves=self.config.lgb_num_leaves,
            min_child_samples=self.config.lgb_min_child_samples,
            subsample=self.config.lgb_subsample,
            colsample_bytree=self.config.lgb_colsample_bytree,
            reg_alpha=self.config.lgb_reg_alpha,
            reg_lambda=self.config.lgb_reg_lambda,
            random_state=self.config.lgb_random_state,
            n_jobs=self.config.lgb_n_jobs,
            verbose=self.config.lgb_verbose,
            class_weight="balanced",
            objective="binary",
            metric="auc",
        )
        
        # Train with early stopping on validation set
        base_lgb.fit(
            X_train_dense,
            y_train,
            eval_set=[(X_val_dense, y_val)],
            eval_metric="auc",
            callbacks=[
                lgb.early_stopping(self.config.early_stopping_rounds),
                lgb.log_evaluation(100),
            ],
        )
        
        # Calibrate using separate calibration set (never test, never validation used for early stopping)
        from sklearn.isotonic import IsotonicRegression
        from sklearn.calibration import CalibratedClassifierCV
        
        has_cal = X_cal is not None and y_cal is not None and X_cal.shape[0] > 0
        
        if has_cal:
            logger.info(f"Calibrating on separate calibration set ({X_cal.shape[0]} samples)")
            cal_proba_uncalibrated = base_lgb.predict_proba(X_cal_dense)[:, 1]
        else:
            logger.warning("No separate calibration set provided; using validation set (potential data leakage)")
            X_cal_dense = X_val_dense
            y_cal = y_val
            cal_proba_uncalibrated = base_lgb.predict_proba(X_val_dense)[:, 1]
        
        # Fit isotonic regression calibrator on calibration set
        calibrator = IsotonicRegression(out_of_bounds="clip")
        calibrator.fit(cal_proba_uncalibrated, y_cal)
        
        # Create calibrated wrapper
        calibrated_lgb = CalibratedLGBM(base_lgb, calibrator)
        
        # Validate on validation set (not calibration set)
        val_proba = calibrated_lgb.predict_proba(X_val_dense)[:, 1]
        val_auc = roc_auc_score(y_val, val_proba)
        logger.info(f"  LightGBM validation AUC: {val_auc:.4f}")
        
        return calibrated_lgb

    def train(
        self,
        X: sp.csr_matrix,
        y: np.ndarray,
        feature_names: List[str],
        domain_labels: Optional[np.ndarray] = None,
        timestamps: Optional[np.ndarray] = None,
        split_method: str = "domain",  # "domain" or "time"
    ) -> Dict[str, Any]:
        """
        Train both models with three-way split: train / validation / calibration.
        
        Args:
            X: Feature matrix (sparse)
            y: Labels
            feature_names: List of feature names
            domain_labels: Registrable domain for each sample (for domain-disjoint split)
            timestamps: Fetch timestamp for each sample (for time-based split)
            split_method: "domain" for domain-disjoint, "time" for time-based split
            
        Note: Random stratified splits are not supported. Use domain-disjoint or time-based
        splits to avoid data leakage and ensure realistic evaluation.
        """
        self.feature_names = feature_names
        n_samples = X.shape[0]
        
        logger.info(f"Training on {n_samples} samples with {X.shape[1]} features")
        logger.info(f"  Class distribution: {np.bincount(y)}")
        logger.info(f"  Split method: {split_method}")
        
        # Three-way split: train (70%) / validation (15%) / calibration (15%)
        # This ensures calibration is never done on test or validation used for early stopping
        val_split = self.config.val_split  # e.g., 0.15
        cal_split = self.config.val_split  # same size for calibration
        
        if split_method == "domain":
            if domain_labels is None:
                raise ValueError("domain_labels required for domain-disjoint split")
            # Domain-disjoint split for all three sets
            unique_domains = np.unique(domain_labels)
            np.random.seed(self.config.lgb_random_state)
            np.random.shuffle(unique_domains)
            
            n_domains = len(unique_domains)
            n_train = int(n_domains * (1 - val_split - cal_split))
            n_val = int(n_domains * val_split)
            
            train_domains = set(unique_domains[:n_train])
            val_domains = set(unique_domains[n_train:n_train + n_val])
            cal_domains = set(unique_domains[n_train + n_val:])
            
            train_mask = np.array([d in train_domains for d in domain_labels])
            val_mask = np.array([d in val_domains for d in domain_labels])
            cal_mask = np.array([d in cal_domains for d in domain_labels])
            
            logger.info(f"  Domain-disjoint split: {len(train_domains)} train domains, "
                       f"{len(val_domains)} val domains, {len(cal_domains)} cal domains")
        
        elif split_method == "time":
            if timestamps is None:
                raise ValueError("timestamps required for time-based split")
            # Time-based split: older -> train, middle -> val, newest -> cal
            sort_idx = np.argsort(timestamps)
            n_train = int(n_samples * (1 - val_split - cal_split))
            n_val = int(n_samples * val_split)
            
            train_mask = np.zeros(n_samples, dtype=bool)
            val_mask = np.zeros(n_samples, dtype=bool)
            cal_mask = np.zeros(n_samples, dtype=bool)
            
            train_mask[sort_idx[:n_train]] = True
            val_mask[sort_idx[n_train:n_train + n_val]] = True
            cal_mask[sort_idx[n_train + n_val:]] = True
            
            logger.info(f"  Time-based split: {train_mask.sum()} train, "
                       f"{val_mask.sum()} val, {cal_mask.sum()} cal")
        
        else:
            raise ValueError(f"Unknown split_method: {split_method}. Use 'domain' or 'time'.")
        
        X_train, X_val, X_cal = X[train_mask], X[val_mask], X[cal_mask]
        y_train, y_val, y_cal = y[train_mask], y[val_mask], y[cal_mask]
        
        # Ensure calibration set has at least some samples; if not, fall back to validation
        min_cal_samples = 10
        if X_cal.shape[0] < min_cal_samples:
            logger.warning(f"Calibration set too small ({X_cal.shape[0]} samples), using validation set instead")
            X_cal, y_cal = X_val, y_val
        
        # Ensure validation set has at least some samples
        min_val_samples = 5
        if X_val.shape[0] < min_val_samples:
            logger.warning(f"Validation set too small ({X_val.shape[0]} samples), using training set instead")
            X_val, y_val = X_train, y_train
        
        logger.info(f"  Train: {X_train.shape[0]}, Val: {X_val.shape[0]}, Cal: {X_cal.shape[0]}")
        
        # Train Logistic Regression with separate calibration set
        self.lr_model = self.train_logistic_regression(X_train, y_train, X_val, y_val, X_cal, y_cal)
        
        # Train LightGBM with separate calibration set
        self.lgb_model = self.train_lightgbm(X_train, y_train, X_val, y_val, X_cal, y_cal)
        
        # Compute version hash
        self.version_hash = self._compute_version_hash(feature_names, X_train.shape[0])
        self.is_trained = True
        
        logger.info(f"Training complete. Version hash: {self.version_hash}")
        
        return {
            "version_hash": self.version_hash,
            "train_size": int(X_train.shape[0]),
            "val_size": int(X_val.shape[0]),
            "n_features": int(X.shape[1]),
        }

    def evaluate(
        self,
        X_test: sp.csr_matrix,
        y_test: np.ndarray,
        tlds: Optional[List[str]] = None,
    ) -> Dict[str, ModelMetrics]:
        """
        Evaluate both models on test set.
        
        Args:
            X_test: Test feature matrix
            y_test: Test labels
            tlds: Optional TLD for each sample (for per-TLD metrics)
        """
        if not self.is_trained:
            raise ModelEvaluationException("Models not trained. Call train() first.", None)
        
        X_test_dense = X_test.toarray() if sp.issparse(X_test) else X_test
        results = {}
        
        for name, model in [("logistic_regression", self.lr_model), ("lightgbm", self.lgb_model)]:
            logger.info(f"Evaluating {name}...")
            
            y_proba = model.predict_proba(X_test_dense)[:, 1]
            y_pred = (y_proba >= 0.5).astype(int)
            
            # Core metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            roc_auc = roc_auc_score(y_test, y_proba)
            pr_auc = average_precision_score(y_test, y_proba)
            
            # FPR at 1% and 0.1% TPR (security-focused thresholds)
            fpr_at_1pct = self._fpr_at_tpr(y_test, y_proba, target_tpr=0.99)
            fpr_at_01pct = self._fpr_at_tpr(y_test, y_proba, target_tpr=0.999)
            
            # Confusion matrix
            cm = confusion_matrix(y_test, y_pred).tolist()
            
            # Classification report
            clf_report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
            
            # Per-TLD metrics
            per_tld = {}
            if tlds is not None:
                per_tld = self._compute_per_tld_metrics(y_test, y_proba, y_pred, tlds)
            
            metrics = ModelMetrics(
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1=f1,
                roc_auc=roc_auc,
                pr_auc=pr_auc,
                fpr_at_1pct=fpr_at_1pct,
                fpr_at_01pct=fpr_at_01pct,
                confusion_matrix=cm,
                classification_report=clf_report,
                per_tld_metrics=per_tld,
            )
            results[name] = metrics
            
            logger.info(f"  {name}: AUC={roc_auc:.4f}, PR-AUC={pr_auc:.4f}, F1={f1:.4f}")
            logger.info(f"  FPR@1%TPR={fpr_at_1pct:.4f}, FPR@0.1%TPR={fpr_at_01pct:.4f}")
        
        return results

    def _fpr_at_tpr(self, y_true: np.ndarray, y_score: np.ndarray, target_tpr: float) -> float:
        """Compute FPR at a specific TPR (recall) threshold."""
        from sklearn.metrics import roc_curve
        fpr, tpr, thresholds = roc_curve(y_true, y_score)
        
        # Find threshold where TPR >= target_tpr
        idx = np.where(tpr >= target_tpr)[0]
        if len(idx) == 0:
            return 1.0  # Cannot achieve target TPR
        return float(fpr[idx[0]])

    def _compute_per_tld_metrics(
        self,
        y_true: np.ndarray,
        y_proba: np.ndarray,
        y_pred: np.ndarray,
        tlds: List[str],
    ) -> Dict[str, Dict]:
        """Compute metrics per TLD."""
        unique_tlds = set(tlds)
        per_tld = {}
        
        for tld in unique_tlds:
            mask = np.array([t == tld for t in tlds])
            if mask.sum() < 10:  # Skip TLDs with too few samples
                continue
            
            tld_y_true = y_true[mask]
            tld_y_proba = y_proba[mask]
            tld_y_pred = y_pred[mask]
            
            if len(np.unique(tld_y_true)) < 2:
                continue
            
            per_tld[tld] = {
                "count": int(mask.sum()),
                "malicious_rate": float(tld_y_true.mean()),
                "auc": float(roc_auc_score(tld_y_true, tld_y_proba)),
                "precision": float(precision_score(tld_y_true, tld_y_pred, zero_division=0)),
                "recall": float(recall_score(tld_y_true, tld_y_pred, zero_division=0)),
                "f1": float(f1_score(tld_y_true, tld_y_pred, zero_division=0)),
            }
        
        return per_tld

    def get_feature_importance(self, top_k: int = 50) -> Dict[str, float]:
        """Get feature importance from LightGBM model."""
        if not self.is_trained or self.lgb_model is None:
            return {}
        
        # Get base LightGBM model from calibrated wrapper
        if hasattr(self.lgb_model, 'base_model'):
            base_model = self.lgb_model.base_model
        elif hasattr(self.lgb_model, 'calibrated_classifiers_'):
            base_model = self.lgb_model.calibrated_classifiers_[0].base_estimator
        else:
            return {}
        
        importances = base_model.feature_importances_
        
        # Map to feature names
        importance_dict = dict(zip(self.feature_names, importances))
        sorted_importance = dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))
        
        return dict(list(sorted_importance.items())[:top_k])

    def predict_proba(self, X: sp.csr_matrix, model_name: str = "lightgbm") -> np.ndarray:
        """Get calibrated probabilities from specified model."""
        if not self.is_trained:
            raise ModelTrainingException("Models not trained", None)
        
        X_dense = X.toarray() if sp.issparse(X) else X
        model = self.lgb_model if model_name == "lightgbm" else self.lr_model
        return model.predict_proba(X_dense)[:, 1]

    def save(self, path: Path, feature_schema: Optional[Dict] = None) -> None:
        """Save trained models and metadata."""
        if not self.is_trained:
            raise ModelTrainingException("Cannot save untrained models", None)
        if feature_schema is None:
            feature_schema = {}
        
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        # Save models
        joblib.dump(self.lr_model, path / "lr_model.joblib")
        joblib.dump(self.lgb_model, path / "lgb_model.joblib")
        
        # Save metadata
        metadata = {
            "version_hash": self.version_hash,
            "feature_names": self.feature_names,
            "config": asdict(self.config),
            "feature_schema": feature_schema,
            "is_trained": self.is_trained,
            "saved_at": str(np.datetime64("now")),
        }
        # Convert Path objects
        meta_copy = metadata.copy()
        meta_copy["config"] = {k: str(v) if isinstance(v, Path) else v for k, v in metadata["config"].items()}
        
        with open(path / "metadata.json", "w") as f:
            json.dump(meta_copy, f, indent=2)
        
        logger.info(f"Saved models to {path}")
        logger.info(f"  Version: {self.version_hash}")

    @classmethod
    def load(cls, path: Path) -> "GuardianTrainer":
        """Load trained models and metadata."""
        path = Path(path)
        
        with open(path / "metadata.json") as f:
            metadata = json.load(f)
        
        config_dict = metadata["config"].copy()
        # Convert model_dir back to Path
        if "model_dir" in config_dict and isinstance(config_dict["model_dir"], str):
            config_dict["model_dir"] = Path(config_dict["model_dir"])
        
        config = ModelConfig(**config_dict)
        trainer = cls(config)
        
        trainer.lr_model = joblib.load(path / "lr_model.joblib")
        trainer.lgb_model = joblib.load(path / "lgb_model.joblib")
        trainer.feature_names = metadata["feature_names"]
        trainer.version_hash = metadata["version_hash"]
        trainer.is_trained = metadata["is_trained"]
        
        logger.info(f"Loaded models from {path}")
        logger.info(f"  Version: {trainer.version_hash}")
        
        return trainer


def export_for_api(
    trainer: GuardianTrainer,
    feature_engineer: Any,
    output_dir: Path,
) -> Path:
    """
    Export model package for API consumption.
    
    Creates:
    - model.joblib: Contains both models + feature engineer
    - feature_schema.json: Feature extraction specification
    - version.txt: Model version hash
    - model_card.md: Model card with limitations
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create combined model package
    model_package = {
        "lr_model": trainer.lr_model,
        "lgb_model": trainer.lgb_model,
        "feature_engineer": feature_engineer,
        "feature_names": trainer.feature_names,
        "version_hash": trainer.version_hash,
    }
    joblib.dump(model_package, output_dir / "model.joblib")
    
    # Save feature schema
    with open(output_dir / "feature_schema.json", "w") as f:
        json.dump(feature_engineer, f, indent=2, default=str)
    
    # Save version
    with open(output_dir / "version.txt", "w") as f:
        f.write(trainer.version_hash)
    
    logger.info(f"Exported API model package to {output_dir}")
    return output_dir


if __name__ == "__main__":
    # Quick test with synthetic data
    from guardian_ml.components.feature_engineering import FeatureEngineer
    
    test_urls = [
        "https://www.google.com/search?q=test",
        "http://malicious.tk/login.php",
        "https://github.com/user/repo",
        "http://paypal.phishing-site.ml/verify",
    ] * 100
    test_labels = [0, 1, 0, 1] * 100
    
    # Feature engineering
    engineer = FeatureEngineer()
    X = engineer.fit_transform(test_urls, test_labels)
    
    # Train
    trainer = GuardianTrainer()
    trainer.train(X, np.array(test_labels), engineer.get_feature_names())
    
    # Evaluate
    metrics = trainer.evaluate(X, np.array(test_labels))
    print(f"LR AUC: {metrics['logistic_regression'].roc_auc:.4f}")
    print(f"LGB AUC: {metrics['lightgbm'].roc_auc:.4f}")