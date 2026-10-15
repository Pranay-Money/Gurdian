"""
Model Training Component
Trains logistic regression baseline and LightGBM main model.
Calibrates probabilities with isotonic regression.
"""
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
from scipy.sparse import csr_matrix

from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score,
    confusion_matrix, classification_report
)
import lightgbm as lgb

from src.logger import logger
from src.exception import ModelTrainingException, MLPipelineException


@dataclass
class ModelConfig:
    """Configuration for model training."""
    # Logistic Regression
    lr_C: float = 1.0
    lr_max_iter: int = 1000
    lr_class_weight: str = "balanced"

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
    calibration_method: str = "isotonic"
    calibration_cv: int = 3

    # Early stopping
    early_stopping_rounds: int = 50
    eval_metric: str = "auc"

    # Output
    model_dir: str = "ml/models"


class ModelTrainer:
    """Trains and evaluates ML models."""

    def __init__(self, config: Optional[ModelConfig] = None):
        self.config = config or ModelConfig()
        self.model_dir = Path(self.config.model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        self.lr_model = None
        self.lgb_model = None
        self.calibrated_lr = None
        self.calibrated_lgb = None

    def train_logistic_regression(
        self,
        X_train: csr_matrix,
        y_train: np.ndarray,
        X_val: Optional[csr_matrix] = None,
        y_val: Optional[np.ndarray] = None
    ) -> LogisticRegression:
        """Train logistic regression baseline."""
        logger.info("Training Logistic Regression baseline...")

        self.lr_model = LogisticRegression(
            C=self.config.lr_C,
            max_iter=self.config.lr_max_iter,
            class_weight=self.config.lr_class_weight,
            random_state=42,
            n_jobs=self.config.lgb_n_jobs
        )

        self.lr_model.fit(X_train, y_train)

        # Calibrate
        logger.info("Calibrating Logistic Regression...")
        self.calibrated_lr = CalibratedClassifierCV(
            self.lr_model,
            method=self.config.calibration_method,
            cv=self.config.calibration_cv
        )
        self.calibrated_lr.fit(X_train, y_train)

        return self.lr_model

    def train_lightgbm(
        self,
        X_train: csr_matrix,
        y_train: np.ndarray,
        X_val: csr_matrix,
        y_val: np.ndarray
    ) -> lgb.LGBMClassifier:
        """Train LightGBM model with early stopping."""
        logger.info("Training LightGBM...")

        self.lgb_model = lgb.LGBMClassifier(
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
            objective="binary",
            metric=self.config.eval_metric,
            class_weight="balanced"
        )

        self.lgb_model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            eval_metric=self.config.eval_metric,
            callbacks=[
                lgb.early_stopping(self.config.early_stopping_rounds),
                lgb.log_evaluation(100)
            ]
        )

        # Calibrate
        logger.info("Calibrating LightGBM...")
        self.calibrated_lgb = CalibratedClassifierCV(
            self.lgb_model,
            method=self.config.calibration_method,
            cv=self.config.calibration_cv
        )
        self.calibrated_lgb.fit(X_train, y_train)

        return self.lgb_model

    def evaluate(
        self,
        model: Any,
        X_test: csr_matrix,
        y_test: np.ndarray,
        model_name: str
    ) -> Dict[str, Any]:
        """Evaluate model and return metrics."""
        logger.info(f"Evaluating {model_name}...")

        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]

        metrics = {
            "model": model_name,
            "precision": float(precision_score(y_test, y_pred, zero_division=0)),
            "recall": float(recall_score(y_test, y_pred, zero_division=0)),
            "f1": float(f1_score(y_test, y_pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_test, y_proba)),
            "pr_auc": float(average_precision_score(y_test, y_proba)),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "classification_report": classification_report(y_test, y_pred, output_dict=True)
        }

        # FPR at 1% and 0.1%
        fpr_1, fpr_01 = self._fpr_at_recall(y_test, y_proba, [0.99, 0.999])
        metrics["fpr_at_1pct"] = fpr_1
        metrics["fpr_at_0_1pct"] = fpr_01

        logger.info(f"{model_name} metrics: AUC={metrics['roc_auc']:.4f}, "
                    f"PR-AUC={metrics['pr_auc']:.4f}, F1={metrics['f1']:.4f}")

        return metrics

    def _fpr_at_recall(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        recall_targets: List[float]
    ) -> List[float]:
        """Calculate FPR at specific recall levels."""
        from sklearn.metrics import roc_curve
        fpr, tpr, thresholds = roc_curve(y_true, y_scores)
        results = []
        for target in recall_targets:
            idx = np.where(tpr >= target)[0]
            if len(idx) > 0:
                results.append(float(fpr[idx[0]]))
            else:
                results.append(1.0)
        return results

    def evaluate_per_tld(
        self,
        model: Any,
        X_test: csr_matrix,
        y_test: np.ndarray,
        urls: List[str],
        feature_names: List[str]
    ) -> Dict[str, Dict[str, float]]:
        """Evaluate model performance per TLD."""
        import tldextract

        tlds = [tldextract.extract(url).suffix for url in urls]
        unique_tlds = set(tlds)

        results = {}
        for tld in unique_tlds:
            if tld == "":
                continue
            mask = [t == tld for t in tlds]
            if sum(mask) < 10:  # Skip small samples
                continue

            X_tld = X_test[mask]
            y_tld = y_test[mask]
            y_proba = model.predict_proba(X_tld)[:, 1]

            if len(np.unique(y_tld)) < 2:
                continue

            results[tld] = {
                "count": int(sum(mask)),
                "malicious_rate": float(np.mean(y_tld)),
                "roc_auc": float(roc_auc_score(y_tld, y_proba)),
                "pr_auc": float(average_precision_score(y_tld, y_proba))
            }

        return results

    def get_feature_importance(
        self,
        feature_names: List[str],
        top_k: int = 50
    ) -> List[Dict[str, Any]]:
        """Get feature importance from LightGBM."""
        if self.lgb_model is None:
            return []

        importance = self.lgb_model.feature_importances_
        indices = np.argsort(importance)[::-1][:top_k]

        return [
            {
                "feature": feature_names[i],
                "importance": float(importance[i]),
                "rank": idx + 1
            }
            for idx, i in enumerate(indices)
        ]

    def save_models(self, feature_names: List[str]):
        """Save trained models and metadata."""
        self.model_dir.mkdir(parents=True, exist_ok=True)

        # Save models
        if self.calibrated_lr:
            joblib.dump(self.calibrated_lr, self.model_dir / "lr_calibrated.joblib")
        if self.lr_model:
            joblib.dump(self.lr_model, self.model_dir / "lr_raw.joblib")
        if self.calibrated_lgb:
            joblib.dump(self.calibrated_lgb, self.model_dir / "lgb_calibrated.joblib")
        if self.lgb_model:
            joblib.dump(self.lgb_model, self.model_dir / "lgb_raw.joblib")

        # Save feature names
        with open(self.model_dir / "feature_names.json", "w") as f:
            json.dump(feature_names, f)

        # Save config
        config_dict = {
            "lr": {
                "C": self.config.lr_C,
                "max_iter": self.config.lr_max_iter,
                "class_weight": self.config.lr_class_weight
            },
            "lgb": {
                "n_estimators": self.config.lgb_n_estimators,
                "learning_rate": self.config.lgb_learning_rate,
                "max_depth": self.config.lgb_max_depth,
                "num_leaves": self.config.lgb_num_leaves,
                "min_child_samples": self.config.lgb_min_child_samples,
                "subsample": self.config.lgb_subsample,
                "colsample_bytree": self.config.lgb_colsample_bytree,
                "reg_alpha": self.config.lgb_reg_alpha,
                "reg_lambda": self.config.lgb_reg_lambda
            },
            "calibration": {
                "method": self.config.calibration_method,
                "cv": self.config.calibration_cv
            }
        }
        with open(self.model_dir / "model_config.json", "w") as f:
            json.dump(config_dict, f, indent=2)

        logger.info(f"Saved models to {self.model_dir}")

    def load_models(self):
        """Load trained models."""
        lr_cal_path = self.model_dir / "lr_calibrated.joblib"
        lgb_cal_path = self.model_dir / "lgb_calibrated.joblib"
        lr_raw_path = self.model_dir / "lr_raw.joblib"
        lgb_raw_path = self.model_dir / "lgb_raw.joblib"

        if lr_cal_path.exists():
            self.calibrated_lr = joblib.load(lr_cal_path)
        if lgb_cal_path.exists():
            self.calibrated_lgb = joblib.load(lgb_cal_path)
        if lr_raw_path.exists():
            self.lr_model = joblib.load(lr_raw_path)
        if lgb_raw_path.exists():
            self.lgb_model = joblib.load(lgb_raw_path)

        logger.info(f"Loaded models from {self.model_dir}")


def train_models(
    X_train: csr_matrix,
    y_train: np.ndarray,
    X_val: csr_matrix,
    y_val: np.ndarray,
    config: Optional[ModelConfig] = None
) -> Tuple[ModelTrainer, Dict[str, Any]]:
    """Train both models and return trainer with metrics."""
    trainer = ModelTrainer(config)

    # Train LR
    trainer.train_logistic_regression(X_train, y_train)

    # Train LightGBM
    trainer.train_lightgbm(X_train, y_train, X_val, y_val)

    return trainer


if __name__ == "__main__":
    # Quick test
    from scipy.sparse import csr_matrix
    X = csr_matrix(np.random.rand(100, 20))
    y = np.random.randint(0, 2, 100)
    X_val = csr_matrix(np.random.rand(20, 20))
    y_val = np.random.randint(0, 2, 20)

    trainer = ModelTrainer()
    trainer.train_logistic_regression(X, y)
    trainer.train_lightgbm(X, y, X_val, y_val)
    print("Models trained successfully")