"""
Model Evaluation Component

Comprehensive evaluation including:
- Time-based and domain-disjoint splits
- Precision, recall, F1, PR-AUC, FPR at 1%/0.1%
- Confusion matrix, per-TLD error analysis
- Calibration curves and reliability diagrams
- Failure mode analysis
"""
import json
import warnings
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import scipy.sparse as sp
from sklearn.calibration import calibration_curve
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix,
    classification_report, precision_recall_curve, roc_curve,
    brier_score_loss
)

from guardian_ml.exception import ModelEvaluationException
from guardian_ml.logger import logger


@dataclass
class EvaluationConfig:
    """Configuration for evaluation."""
    output_dir: Path = None
    save_plots: bool = True
    save_predictions: bool = True
    bootstrap_samples: int = 1000
    confidence_level: float = 0.95

    def __post_init__(self):
        from guardian_ml.paths import get_evaluation_dir
        if self.output_dir is None:
            self.output_dir = get_evaluation_dir()
        self.output_dir.mkdir(parents=True, exist_ok=True)


@dataclass
class EvaluationResults:
    """Container for all evaluation results."""
    # Core metrics
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    pr_auc: float
    
    # Security-focused metrics
    # FPR at specific TPR thresholds (recall levels)
    fpr_at_95_tpr: float      # FPR at TPR >= 95%
    fpr_at_99_tpr: float      # FPR at TPR >= 99%
    fpr_at_999_tpr: float     # FPR at TPR >= 99.9% (aka FPR@0.1%TPR)
    
    # TPR at specific FPR thresholds (fallout levels)
    tpr_at_1pct_fpr: float    # TPR at FPR <= 1%
    tpr_at_01pct_fpr: float   # TPR at FPR <= 0.1%
    
    # Legacy metric names (for backward compatibility)
    fpr_at_1pct_tpr: float    # Alias for fpr_at_99_tpr
    fpr_at_01pct_tpr: float   # Alias for fpr_at_999_tpr
    
    brier_score: float
    
    # Confusion matrix
    confusion_matrix: List[List[int]]
    classification_report: Dict
    
    # Per-TLD metrics
    per_tld_metrics: Dict[str, Dict]
    
    # Calibration
    calibration_curve: Dict[str, List[float]]
    ece: float  # Expected Calibration Error
    
    # Bootstrap confidence intervals
    bootstrap_ci: Dict[str, Tuple[float, float]]
    
    # Predictions (optional)
    predictions: Optional[List[Dict]] = None


class ModelEvaluator:
    """
    Comprehensive model evaluation with statistical rigor.
    
    Evaluates on held-out test sets with:
    - Multiple metrics relevant to security (FPR at low TPR)
    - Per-TLD breakdown to identify blind spots
    - Calibration assessment
    - Bootstrap confidence intervals
    - Visualization outputs
    """

    def __init__(self, config: Optional[EvaluationConfig] = None):
        self.config = config or EvaluationConfig()
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

    def evaluate(
        self,
        model: Any,
        X_test: sp.csr_matrix,
        y_test: np.ndarray,
        tlds: Optional[List[str]] = None,
        urls: Optional[List[str]] = None,
        feature_names: Optional[List[str]] = None,
        model_name: str = "model",
    ) -> EvaluationResults:
        """
        Run comprehensive evaluation.
        
        Args:
            model: Trained model with predict_proba method
            X_test: Test feature matrix
            y_test: Test labels
            tlds: Optional TLD for each sample
            urls: Optional original URLs for prediction export
            feature_names: Feature names for importance analysis
            model_name: Name for output files
        """
        logger.info(f"Running comprehensive evaluation for {model_name}...")
        
        X_test_dense = X_test.toarray() if sp.issparse(X_test) else X_test
        
        # Get predictions
        y_proba = model.predict_proba(X_test_dense)[:, 1]
        y_pred = (y_proba >= 0.5).astype(int)
        
        # Core metrics
        results = self._compute_core_metrics(y_test, y_pred, y_proba)
        
        # Per-TLD metrics
        results.per_tld_metrics = self._compute_per_tld_metrics(y_test, y_proba, y_pred, tlds)
        
        # Calibration analysis
        results.calibration_curve, results.ece = self._compute_calibration(y_test, y_proba)
        
        # Bootstrap confidence intervals
        results.bootstrap_ci = self._bootstrap_confidence_intervals(y_test, y_proba)
        
        # Save predictions if requested
        if self.config.save_predictions and urls is not None:
            results.predictions = self._prepare_predictions(
                urls, y_test, y_pred, y_proba, tlds
            )
            self._save_predictions(results.predictions, model_name)
        
        # Save plots
        if self.config.save_plots:
            self._save_plots(y_test, y_proba, y_pred, model_name, tlds)
        
        # Save results
        self._save_results(results, model_name)
        
        logger.info(f"Evaluation complete for {model_name}")
        logger.info(f"  AUC: {results.roc_auc:.4f}, PR-AUC: {results.pr_auc:.4f}")
        logger.info(f"  FPR@1%TPR: {results.fpr_at_1pct_tpr:.4f}, FPR@0.1%TPR: {results.fpr_at_01pct_tpr:.4f}")
        logger.info(f"  ECE: {results.ece:.4f}")
        
        return results

    def _compute_core_metrics(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_proba: np.ndarray,
    ) -> EvaluationResults:
        """Compute core classification metrics."""
        # Standard metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_true, y_proba)
        pr_auc = average_precision_score(y_true, y_proba)
        brier = brier_score_loss(y_true, y_proba)
        
        # FPR at specific TPR thresholds (security-focused)
        fpr_at_95_tpr = self._fpr_at_tpr(y_true, y_proba, 0.95)
        fpr_at_99_tpr = self._fpr_at_tpr(y_true, y_proba, 0.99)
        fpr_at_999_tpr = self._fpr_at_tpr(y_true, y_proba, 0.999)
        
        # TPR at specific FPR thresholds
        tpr_at_1pct_fpr = self._tpr_at_fpr(y_true, y_proba, 0.01)
        tpr_at_01pct_fpr = self._tpr_at_fpr(y_true, y_proba, 0.001)
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred).tolist()
        
        # Classification report
        clf_report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
        
        return EvaluationResults(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            roc_auc=roc_auc,
            pr_auc=pr_auc,
            fpr_at_95_tpr=fpr_at_95_tpr,
            fpr_at_99_tpr=fpr_at_99_tpr,
            fpr_at_999_tpr=fpr_at_999_tpr,
            tpr_at_1pct_fpr=tpr_at_1pct_fpr,
            tpr_at_01pct_fpr=tpr_at_01pct_fpr,
            # Legacy aliases
            fpr_at_1pct_tpr=fpr_at_99_tpr,
            fpr_at_01pct_tpr=fpr_at_999_tpr,
            brier_score=brier,
            confusion_matrix=cm,
            classification_report=clf_report,
            per_tld_metrics={},
            calibration_curve={},
            ece=0.0,
            bootstrap_ci={},
        )

    def _fpr_at_tpr(self, y_true: np.ndarray, y_score: np.ndarray, target_tpr: float) -> float:
        """Compute FPR at a specific TPR threshold."""
        fpr, tpr, _ = roc_curve(y_true, y_score)
        idx = np.where(tpr >= target_tpr)[0]
        if len(idx) == 0:
            return 1.0
        return float(fpr[idx[0]])

    def _tpr_at_fpr(self, y_true: np.ndarray, y_score: np.ndarray, target_fpr: float) -> float:
        """Compute TPR at a specific FPR threshold."""
        fpr, tpr, _ = roc_curve(y_true, y_score)
        idx = np.where(fpr <= target_fpr)[0]
        if len(idx) == 0:
            return 0.0
        return float(tpr[idx[-1]])

    def _compute_per_tld_metrics(
        self,
        y_true: np.ndarray,
        y_proba: np.ndarray,
        y_pred: np.ndarray,
        tlds: Optional[List[str]],
    ) -> Dict[str, Dict]:
        """Compute metrics broken down by TLD."""
        if tlds is None:
            return {}
        
        unique_tlds = set(tlds)
        per_tld = {}
        
        for tld in sorted(unique_tlds):
            mask = np.array([t == tld for t in tlds])
            count = int(mask.sum())
            
            if count < 10:
                continue
            
            tld_y_true = y_true[mask]
            tld_y_proba = y_proba[mask]
            tld_y_pred = y_pred[mask]
            
            if len(np.unique(tld_y_true)) < 2:
                continue
            
            per_tld[tld] = {
                "count": count,
                "malicious_rate": float(tld_y_true.mean()),
                "auc": float(roc_auc_score(tld_y_true, tld_y_proba)),
                "pr_auc": float(average_precision_score(tld_y_true, tld_y_proba)),
                "precision": float(precision_score(tld_y_true, tld_y_pred, zero_division=0)),
                "recall": float(recall_score(tld_y_true, tld_y_pred, zero_division=0)),
                "f1": float(f1_score(tld_y_true, tld_y_pred, zero_division=0)),
                "fpr_at_1pct": self._fpr_at_tpr(tld_y_true, tld_y_proba, 0.99),
                "brier_score": float(brier_score_loss(tld_y_true, tld_y_proba)),
            }
        
        return per_tld

    def _compute_calibration(
        self,
        y_true: np.ndarray,
        y_proba: np.ndarray,
        n_bins: int = 10,
    ) -> Tuple[Dict[str, List[float]], float]:
        """Compute calibration curve and Expected Calibration Error (ECE)."""
        prob_true, prob_pred = calibration_curve(y_true, y_proba, n_bins=n_bins, strategy="uniform")
        
        # Expected Calibration Error
        bin_edges = np.linspace(0, 1, n_bins + 1)
        bin_indices = np.digitize(y_proba, bin_edges) - 1
        bin_indices = np.clip(bin_indices, 0, n_bins - 1)
        
        ece = 0.0
        for i in range(n_bins):
            mask = bin_indices == i
            if mask.sum() > 0:
                bin_accuracy = y_true[mask].mean()
                bin_confidence = y_proba[mask].mean()
                bin_weight = mask.mean()
                ece += bin_weight * abs(bin_accuracy - bin_confidence)
        
        calibration_data = {
            "prob_true": prob_true.tolist(),
            "prob_pred": prob_pred.tolist(),
            "bin_edges": bin_edges.tolist(),
        }
        
        return calibration_data, float(ece)

    def _bootstrap_confidence_intervals(
        self,
        y_true: np.ndarray,
        y_proba: np.ndarray,
    ) -> Dict[str, Tuple[float, float]]:
        """Compute bootstrap confidence intervals for key metrics."""
        n_samples = len(y_true)
        metrics_samples = {
            "roc_auc": [],
            "pr_auc": [],
            "accuracy": [],
            "f1": [],
            "brier_score": [],
        }
        
        np.random.seed(42)
        for _ in range(self.config.bootstrap_samples):
            indices = np.random.choice(n_samples, n_samples, replace=True)
            y_sample = y_true[indices]
            p_sample = y_proba[indices]
            y_pred_sample = (p_sample >= 0.5).astype(int)
            
            if len(np.unique(y_sample)) < 2:
                continue
            
            try:
                metrics_samples["roc_auc"].append(roc_auc_score(y_sample, p_sample))
                metrics_samples["pr_auc"].append(average_precision_score(y_sample, p_sample))
                metrics_samples["accuracy"].append(accuracy_score(y_sample, y_pred_sample))
                metrics_samples["f1"].append(f1_score(y_sample, y_pred_sample, zero_division=0))
                metrics_samples["brier_score"].append(brier_score_loss(y_sample, p_sample))
            except:
                pass
        
        alpha = (1 - self.config.confidence_level) / 2
        ci = {}
        for metric, values in metrics_samples.items():
            if values:
                ci[metric] = (float(np.percentile(values, alpha * 100)),
                             float(np.percentile(values, (1 - alpha) * 100)))
        
        return ci

    def _prepare_predictions(
        self,
        urls: List[str],
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_proba: np.ndarray,
        tlds: Optional[List[str]],
    ) -> List[Dict]:
        """Prepare detailed predictions for export."""
        predictions = []
        for i, url in enumerate(urls):
            pred = {
                "url": url,
                "true_label": int(y_true[i]),
                "predicted_label": int(y_pred[i]),
                "probability": float(y_proba[i]),
                "correct": bool(y_true[i] == y_pred[i]),
            }
            if tlds:
                pred["tld"] = tlds[i]
            predictions.append(pred)
        return predictions

    def _save_predictions(self, predictions: List[Dict], model_name: str) -> None:
        """Save predictions to JSONL."""
        output_path = self.config.output_dir / f"{model_name}_predictions.jsonl"
        with open(output_path, "w") as f:
            for pred in predictions:
                f.write(json.dumps(pred) + "\n")
        logger.info(f"Saved predictions to {output_path}")

    def _save_plots(
        self,
        y_true: np.ndarray,
        y_proba: np.ndarray,
        y_pred: np.ndarray,
        model_name: str,
        tlds: Optional[List[str]] = None,
    ) -> None:
        """Save evaluation plots."""
        try:
            fig, axes = plt.subplots(2, 3, figsize=(15, 10))
            
            # 1. ROC Curve
            ax = axes[0, 0]
            fpr, tpr, _ = roc_curve(y_true, y_proba)
            ax.plot(fpr, tpr, label=f'ROC (AUC={roc_auc_score(y_true, y_proba):.3f})')
            ax.plot([0, 1], [0, 1], 'k--', alpha=0.5)
            ax.set_xlabel('FPR')
            ax.set_ylabel('TPR')
            ax.set_title('ROC Curve')
            ax.legend()
            ax.grid(True, alpha=0.3)
            
            # 2. PR Curve
            ax = axes[0, 1]
            prec, rec, _ = precision_recall_curve(y_true, y_proba)
            ax.plot(rec, prec, label=f'PR (AUC={average_precision_score(y_true, y_proba):.3f})')
            ax.set_xlabel('Recall')
            ax.set_ylabel('Precision')
            ax.set_title('Precision-Recall Curve')
            ax.legend()
            ax.grid(True, alpha=0.3)
            
            # 3. Calibration Curve
            ax = axes[0, 2]
            prob_true, prob_pred = calibration_curve(y_true, y_proba, n_bins=10)
            ax.plot(prob_pred, prob_true, 'o-', label='Model')
            ax.plot([0, 1], [0, 1], 'k--', label='Perfect')
            ax.set_xlabel('Mean Predicted Probability')
            ax.set_ylabel('Fraction of Positives')
            ax.set_title('Calibration Curve')
            ax.legend()
            ax.grid(True, alpha=0.3)
            
            # 4. Score Distribution
            ax = axes[1, 0]
            ax.hist(y_proba[y_true == 0], bins=50, alpha=0.5, label='Benign', density=True)
            ax.hist(y_proba[y_true == 1], bins=50, alpha=0.5, label='Malicious', density=True)
            ax.set_xlabel('Predicted Probability')
            ax.set_ylabel('Density')
            ax.set_title('Score Distribution')
            ax.legend()
            ax.grid(True, alpha=0.3)
            
            # 5. Confusion Matrix
            ax = axes[1, 1]
            cm = confusion_matrix(y_true, y_pred)
            im = ax.imshow(cm, cmap='Blues')
            ax.set_xticks([0, 1])
            ax.set_yticks([0, 1])
            ax.set_xticklabels(['Benign', 'Malicious'])
            ax.set_yticklabels(['Benign', 'Malicious'])
            ax.set_xlabel('Predicted')
            ax.set_ylabel('True')
            ax.set_title('Confusion Matrix')
            for i in range(2):
                for j in range(2):
                    ax.text(j, i, str(cm[i, j]), ha='center', va='center')
            plt.colorbar(im, ax=ax)
            
            # 6. Per-TLD AUC (if available)
            ax = axes[1, 2]
            if tlds:
                tld_aucs = {}
                for tld in set(tlds):
                    mask = np.array([t == tld for t in tlds])
                    if mask.sum() >= 10 and len(np.unique(y_true[mask])) > 1:
                        tld_aucs[tld] = roc_auc_score(y_true[mask], y_proba[mask])
                if tld_aucs:
                    sorted_tlds = sorted(tld_aucs.items(), key=lambda x: x[1])
                    tld_names = [x[0] for x in sorted_tlds[-15:]]  # Top 15 worst
                    tld_values = [x[1] for x in sorted_tlds[-15:]]
                    ax.barh(range(len(tld_names)), tld_values)
                    ax.set_yticks(range(len(tld_names)))
                    ax.set_yticklabels(tld_names)
                    ax.set_xlabel('AUC')
                    ax.set_title('Per-TLD AUC (Worst 15)')
                    ax.grid(True, alpha=0.3)
            else:
                ax.text(0.5, 0.5, 'TLD data not available', ha='center', va='center')
            
            plt.tight_layout()
            plot_path = self.config.output_dir / f"{model_name}_evaluation_plots.png"
            plt.savefig(plot_path, dpi=150, bbox_inches='tight')
            plt.close()
            logger.info(f"Saved plots to {plot_path}")
            
        except Exception as e:
            logger.warning(f"Failed to save plots: {e}")

    def _save_results(self, results: EvaluationResults, model_name: str) -> None:
        """Save evaluation results to JSON."""
        # Convert to serializable dict
        results_dict = asdict(results)
        
        # Convert numpy types
        def convert(obj):
            if isinstance(obj, (np.integer, np.floating)):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, dict):
                return {k: convert(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert(v) for v in obj]
            return obj
        
        results_dict = convert(results_dict)
        
        output_path = self.config.output_dir / f"{model_name}_evaluation.json"
        with open(output_path, "w") as f:
            json.dump(results_dict, f, indent=2)
        logger.info(f"Saved evaluation results to {output_path}")

    def compare_models(
        self,
        models: Dict[str, Any],
        X_test: sp.csr_matrix,
        y_test: np.ndarray,
        tlds: Optional[List[str]] = None,
    ) -> Dict[str, EvaluationResults]:
        """Evaluate and compare multiple models."""
        results = {}
        for name, model in models.items():
            results[name] = self.evaluate(model, X_test, y_test, tlds, model_name=name)
        
        # Save comparison summary
        comparison = {}
        for name, res in results.items():
            comparison[name] = {
                "roc_auc": res.roc_auc,
                "pr_auc": res.pr_auc,
                "f1": res.f1,
                "fpr_at_95_tpr": res.fpr_at_95_tpr,
                "fpr_at_99_tpr": res.fpr_at_99_tpr,
                "fpr_at_999_tpr": res.fpr_at_999_tpr,
                "tpr_at_1pct_fpr": res.tpr_at_1pct_fpr,
                "tpr_at_01pct_fpr": res.tpr_at_01pct_fpr,
                "ece": res.ece,
                "brier_score": res.brier_score,
            }
        
        with open(self.config.output_dir / "model_comparison.json", "w") as f:
            json.dump(comparison, f, indent=2)
        
        logger.info("Model comparison:")
        for name, metrics in comparison.items():
            logger.info(f"  {name}: AUC={metrics['roc_auc']:.4f}, PR-AUC={metrics['pr_auc']:.4f}, "
                       f"F1={metrics['f1']:.4f}, FPR@99%TPR={metrics['fpr_at_99_tpr']:.4f}, "
                       f"TPR@1%FPR={metrics['tpr_at_1pct_fpr']:.4f}, ECE={metrics['ece']:.4f}")
        
        return results


def print_evaluation_summary(results: EvaluationResults, model_name: str = "Model") -> None:
    """Print formatted evaluation summary."""
    print(f"\n{'='*60}")
    print(f"{model_name} Evaluation Summary")
    print(f"{'='*60}")
    print(f"Accuracy:         {results.accuracy:.4f}")
    print(f"Precision:        {results.precision:.4f}")
    print(f"Recall:           {results.recall:.4f}")
    print(f"F1 Score:         {results.f1:.4f}")
    print(f"ROC-AUC:          {results.roc_auc:.4f}")
    print(f"PR-AUC:           {results.pr_auc:.4f}")
    print(f"Brier Score:      {results.brier_score:.4f}")
    print(f"ECE:              {results.ece:.4f}")
    print(f"\nSecurity-Focused Metrics:")
    print(f"  FPR @ TPR>=95%:   {results.fpr_at_95_tpr:.4f}")
    print(f"  FPR @ TPR>=99%:   {results.fpr_at_99_tpr:.4f}")
    print(f"  FPR @ TPR>=99.9%: {results.fpr_at_999_tpr:.4f}")
    print(f"  TPR @ FPR<=1%:    {results.tpr_at_1pct_fpr:.4f}")
    print(f"  TPR @ FPR<=0.1%:  {results.tpr_at_01pct_fpr:.4f}")
    print(f"\nConfusion Matrix:")
    print(f"  TN={results.confusion_matrix[0][0]}  FP={results.confusion_matrix[0][1]}")
    print(f"  FN={results.confusion_matrix[1][0]}  TP={results.confusion_matrix[1][1]}")
    print(f"\nBootstrap 95% CIs:")
    for metric, (low, high) in results.bootstrap_ci.items():
        print(f"  {metric}: [{low:.4f}, {high:.4f}]")
    
    if results.per_tld_metrics:
        print(f"\nPer-TLD Metrics (worst 10 by AUC):")
        sorted_tlds = sorted(results.per_tld_metrics.items(), key=lambda x: x[1]["auc"])
        for tld, metrics in sorted_tlds[:10]:
            print(f"  {tld}: AUC={metrics['auc']:.4f}, count={metrics['count']}, "
                  f"mal_rate={metrics['malicious_rate']:.3f}")


if __name__ == "__main__":
    # Quick test
    from guardian_ml.components.feature_engineering import FeatureEngineer
    from guardian_ml.components.model_training import GuardianTrainer
    
    test_urls = [
        "https://www.google.com/search?q=test",
        "http://malicious.tk/login.php",
        "https://github.com/user/repo",
        "http://paypal.phishing-site.ml/verify",
    ] * 250
    test_labels = [0, 1, 0, 1] * 250
    test_tlds = ["com", "tk", "com", "ml"] * 250
    
    engineer = FeatureEngineer()
    X = engineer.fit_transform(test_urls, test_labels)
    
    trainer = GuardianTrainer()
    trainer.train(X, np.array(test_labels), engineer.get_feature_names())
    
    evaluator = ModelEvaluator()
    results = evaluator.evaluate(trainer.lgb_model, X, np.array(test_labels), test_tlds)
    print_evaluation_summary(results, "LightGBM")