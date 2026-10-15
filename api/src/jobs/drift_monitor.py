"""
Drift Monitor Job - Monitors model performance drift in production.

Tracks:
- Score distribution shifts (PSI - Population Stability Index)
- Block rate changes
- Feature distribution shifts
- Prediction confidence calibration
- Alerts on significant shifts
"""
import json
import logging
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from collections import defaultdict

import joblib
import numpy as np
import scipy.stats as stats
from scipy.spatial.distance import jensenshannon
from sqlalchemy import select, func, and_, desc

# Add project paths
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from src.db.session import get_session_context
from src.db.models import Case, RiskLevel, ActionType
from guardian_ml.logger import logger


@dataclass
class DriftConfig:
    """Configuration for drift monitoring."""
    # Time windows
    reference_window_days: int = 7  # Reference period (stable baseline)
    current_window_days: int = 1    # Current period to compare
    min_samples_per_window: int = 100  # Minimum samples for reliable stats
    
    # Thresholds for alerts
    psi_threshold: float = 0.2  # Population Stability Index threshold
    ks_threshold: float = 0.05  # Kolmogorov-Smirnov test p-value threshold
    block_rate_change_threshold: float = 0.15  # 15% relative change in block rate
    score_mean_shift_threshold: float = 0.1  # 10% shift in mean score
    calibration_ece_threshold: float = 0.1  # Expected Calibration Error threshold
    
    # Feature drift
    feature_psi_threshold: float = 0.2
    max_features_to_check: int = 20
    
    # Alerting
    alert_on_drift: bool = True
    alert_webhook_url: Optional[str] = None
    alert_email: Optional[str] = None
    
    # Output
    output_dir: Path = Path("ml/drift_reports")
    save_detailed_reports: bool = True
    
    # Schedule
    schedule_cron: str = "0 * * * *"  # Hourly
    
    def __post_init__(self):
        self.output_dir = Path(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)


@dataclass
class DriftMetrics:
    """Container for drift detection metrics."""
    timestamp: str
    reference_period: Tuple[str, str]
    current_period: Tuple[str, str]
    reference_samples: int
    current_samples: int
    
    # Score distribution
    score_psi: float
    score_ks_statistic: float
    score_ks_pvalue: float
    score_js_divergence: float
    score_mean_ref: float
    score_mean_curr: float
    score_mean_shift: float
    score_std_ref: float
    score_std_curr: float
    
    # Block rate
    block_rate_ref: float
    block_rate_curr: float
    block_rate_change: float
    block_rate_relative_change: float
    
    # Level distribution
    level_dist_ref: Dict[str, int]
    level_dist_curr: Dict[str, int]
    level_psi: float
    
    # Feature drift (top features)
    feature_drift: Dict[str, float]
    
    # Calibration
    ece_ref: float
    ece_curr: float
    ece_change: float
    
    # Overall drift flag
    drift_detected: bool
    alert_triggered: bool


class DriftMonitor:
    """
    Monitors model drift in production by comparing
    current predictions against a reference baseline.
    """
    
    def __init__(self, config: Optional[DriftConfig] = None):
        self.config = config or DriftConfig()
    
    def _get_cases_in_window(self, days_back: int, days_forward: int = 0) -> List[Case]:
        """Get cases within a time window."""
        end_time = datetime.now(timezone.utc) - timedelta(days=days_forward)
        start_time = end_time - timedelta(days=days_back)
        
        with get_session_context() as session:
            stmt = select(Case).where(
                and_(
                    Case.created_at >= start_time,
                    Case.created_at < end_time,
                )
            ).order_by(Case.created_at)
            
            result = session.execute(stmt)
            return result.scalars().all()
    
    def _extract_scores_and_metadata(self, cases: List[Case]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Extract scores, levels, and actions from cases."""
        scores = []
        levels = []
        actions = []
        
        for case in cases:
            scores.append(case.score)
            levels.append(case.level.value)
            actions.append(case.action.value)
        
        return np.array(scores), np.array(levels), np.array(actions)
    
    def _compute_psi(self, ref_values: np.ndarray, curr_values: np.ndarray, bins: int = 10) -> float:
        """
        Compute Population Stability Index (PSI).
        
        PSI = Σ (actual_i - expected_i) * ln(actual_i / expected_i)
        
        Values:
        - PSI < 0.1: No significant drift
        - 0.1 <= PSI < 0.2: Moderate drift
        - PSI >= 0.2: Significant drift
        """
        # Create bins based on reference distribution
        _, bin_edges = np.histogram(ref_values, bins=bins, range=(0, 100))
        bin_edges[0] = -np.inf
        bin_edges[-1] = np.inf
        
        ref_hist, _ = np.histogram(ref_values, bins=bin_edges)
        curr_hist, _ = np.histogram(curr_values, bins=bin_edges)
        
        # Convert to proportions
        ref_prop = ref_hist / len(ref_values) if len(ref_values) > 0 else np.zeros(bins)
        curr_prop = curr_hist / len(curr_values) if len(curr_values) > 0 else np.zeros(bins)
        
        # Avoid division by zero
        ref_prop = np.maximum(ref_prop, 1e-6)
        curr_prop = np.maximum(curr_prop, 1e-6)
        
        psi = np.sum((curr_prop - ref_prop) * np.log(curr_prop / ref_prop))
        return float(psi)
    
    def _compute_js_divergence(self, ref_values: np.ndarray, curr_values: np.ndarray, bins: int = 20) -> float:
        """Compute Jensen-Shannon divergence between distributions."""
        _, bin_edges = np.histogram(ref_values, bins=bins, range=(0, 100))
        bin_edges[0] = -np.inf
        bin_edges[-1] = np.inf
        
        ref_hist, _ = np.histogram(ref_values, bins=bin_edges)
        curr_hist, _ = np.histogram(curr_values, bins=bin_edges)
        
        ref_prob = ref_hist / len(ref_values) if len(ref_values) > 0 else np.zeros(bins)
        curr_prob = curr_hist / len(curr_values) if len(curr_values) > 0 else np.zeros(bins)
        
        # Add small epsilon
        ref_prob = np.maximum(ref_prob, 1e-10)
        curr_prob = np.maximum(curr_prob, 1e-10)
        
        # Normalize
        ref_prob = ref_prob / ref_prob.sum()
        curr_prob = curr_prob / curr_prob.sum()
        
        return float(jensenshannon(ref_prob, curr_prob))
    
    def _compute_level_psi(self, ref_levels: np.ndarray, curr_levels: np.ndarray) -> float:
        """Compute PSI for categorical risk level distribution."""
        level_order = ["Low", "Medium", "High", "Critical"]
        
        ref_counts = np.array([np.sum(ref_levels == l) for l in level_order])
        curr_counts = np.array([np.sum(curr_levels == l) for l in level_order])
        
        ref_prop = ref_counts / len(ref_levels) if len(ref_levels) > 0 else np.zeros(4)
        curr_prop = curr_counts / len(curr_levels) if len(curr_levels) > 0 else np.zeros(4)
        
        ref_prop = np.maximum(ref_prop, 1e-6)
        curr_prop = np.maximum(curr_prop, 1e-6)
        
        psi = np.sum((curr_prop - ref_prop) * np.log(curr_prop / ref_prop))
        return float(psi)
    
    def _check_feature_drift(self, ref_cases: List[Case], curr_cases: List[Case]) -> Dict[str, float]:
        """Check feature drift by extracting signals from cases."""
        # Extract signal patterns as features
        def extract_signal_features(cases: List[Case]) -> Dict[str, np.ndarray]:
            feature_values = defaultdict(list)
            
            for case in cases:
                for signal in case.signals:
                    key = signal.get("key", "unknown")
                    feature_values[f"signal_{key}"].append(signal.get("points", 0))
            
            # Convert to mean per case
            case_features = defaultdict(list)
            for case in cases:
                signal_points = defaultdict(int)
                for signal in case.signals:
                    key = signal.get("key", "unknown")
                    signal_points[key] += signal.get("points", 0)
                
                for key in feature_values.keys():
                    short_key = key.replace("signal_", "")
                    case_features[key].append(signal_points.get(short_key, 0))
            
            return {k: np.array(v) for k, v in case_features.items()}
        
        ref_features = extract_signal_features(ref_cases)
        curr_features = extract_signal_features(curr_cases)
        
        drift = {}
        for feature_name in list(ref_features.keys())[:self.config.max_features_to_check]:
            if feature_name in curr_features:
                ref_vals = ref_features[feature_name]
                curr_vals = curr_features[feature_name]
                
                if len(ref_vals) > 10 and len(curr_vals) > 10:
                    psi = self._compute_psi(ref_vals, curr_vals, bins=10)
                    drift[feature_name] = psi
        
        return drift
    
    def _compute_calibration_ece(self, cases: List[Case]) -> float:
        """Compute Expected Calibration Error from cases with ground truth.
        
        Since we don't have ground truth for all cases, we use high-confidence
        predictions as proxy. This is a simplified approximation.
        """
        # Group by score bins and check consistency
        scores = np.array([c.score for c in cases])
        levels = np.array([c.level.value for c in cases])
        
        # For cases with very high scores, expect High/Critical
        # For cases with very low scores, expect Low
        high_conf = scores >= 80
        low_conf = scores <= 20
        
        if np.sum(high_conf) > 10 and np.sum(low_conf) > 10:
            # High scores should be High/Critical
            high_expected = np.array([1 if l in ["High", "Critical"] else 0 for l in levels[high_conf]])
            high_pred = scores[high_conf] / 100.0
            
            # Low scores should be Low
            low_expected = np.array([1 if l == "Low" else 0 for l in levels[low_conf]])
            low_pred = 1 - (scores[low_conf] / 100.0)
            
            # Compute ECE
            all_pred = np.concatenate([high_pred, low_pred])
            all_exp = np.concatenate([high_expected, low_expected])
            
            # Simple binning
            n_bins = 10
            bin_edges = np.linspace(0, 1, n_bins + 1)
            bin_indices = np.digitize(all_pred, bin_edges) - 1
            bin_indices = np.clip(bin_indices, 0, n_bins - 1)
            
            ece = 0.0
            for i in range(n_bins):
                mask = bin_indices == i
                if mask.sum() > 0:
                    bin_acc = all_exp[mask].mean()
                    bin_conf = all_pred[mask].mean()
                    bin_weight = mask.mean()
                    ece += bin_weight * abs(bin_acc - bin_conf)
            
            return float(ece)
        
        return 0.0
    
    def run(self) -> DriftMetrics:
        """Run drift detection and return metrics."""
        logger.info("Running drift monitor...")
        
        # Get reference and current windows
        ref_cases = self._get_cases_in_window(
            self.config.reference_window_days + self.config.current_window_days,
            self.config.current_window_days
        )
        
        curr_cases = self._get_cases_in_window(self.config.current_window_days)
        
        if len(ref_cases) < self.config.min_samples_per_window:
            logger.warning(f"Insufficient reference samples: {len(ref_cases)} < {self.config.min_samples_per_window}")
            return self._empty_metrics("Insufficient reference samples")
        
        if len(curr_cases) < self.config.min_samples_per_window:
            logger.warning(f"Insufficient current samples: {len(curr_cases)} < {self.config.min_samples_per_window}")
            return self._empty_metrics("Insufficient current samples")
        
        # Extract data
        ref_scores, ref_levels, ref_actions = self._extract_scores_and_metadata(ref_cases)
        curr_scores, curr_levels, curr_actions = self._extract_scores_and_metadata(curr_cases)
        
        # Score distribution drift
        score_psi = self._compute_psi(ref_scores, curr_scores)
        score_js = self._compute_js_divergence(ref_scores, curr_scores)
        
        # KS test
        ks_stat, ks_pval = stats.ks_2samp(ref_scores, curr_scores)
        
        # Mean/std shift
        score_mean_ref = float(np.mean(ref_scores))
        score_mean_curr = float(np.mean(curr_scores))
        score_std_ref = float(np.std(ref_scores))
        score_std_curr = float(np.std(curr_scores))
        score_mean_shift = abs(score_mean_curr - score_mean_ref) / (score_std_ref + 1e-6)
        
        # Block rate
        ref_blocked = np.sum(ref_actions == "block")
        curr_blocked = np.sum(curr_actions == "block")
        block_rate_ref = ref_blocked / len(ref_actions) if len(ref_actions) > 0 else 0
        block_rate_curr = curr_blocked / len(curr_actions) if len(curr_actions) > 0 else 0
        block_rate_change = block_rate_curr - block_rate_ref
        block_rate_rel_change = abs(block_rate_change) / (block_rate_ref + 1e-6)
        
        # Level distribution
        level_order = ["Low", "Medium", "High", "Critical"]
        level_dist_ref = {l: int(np.sum(ref_levels == l)) for l in level_order}
        level_dist_curr = {l: int(np.sum(curr_levels == l)) for l in level_order}
        level_psi = self._compute_level_psi(ref_levels, curr_levels)
        
        # Feature drift
        feature_drift = self._check_feature_drift(ref_cases, curr_cases)
        
        # Calibration (approximate)
        ece_ref = self._compute_calibration_ece(ref_cases)
        ece_curr = self._compute_calibration_ece(curr_cases)
        ece_change = abs(ece_curr - ece_ref)
        
        # Determine if drift detected
        drift_flags = {
            "score_psi": score_psi >= self.config.psi_threshold,
            "score_ks": ks_pval < self.config.ks_threshold,
            "score_mean_shift": score_mean_shift >= self.config.score_mean_shift_threshold,
            "block_rate": block_rate_rel_change >= self.config.block_rate_change_threshold,
            "level_psi": level_psi >= self.config.psi_threshold,
            "feature_drift": any(v >= self.config.feature_psi_threshold for v in feature_drift.values()),
            "calibration": ece_curr >= self.config.calibration_ece_threshold,
        }
        
        drift_detected = any(drift_flags.values())
        alert_triggered = drift_detected and self.config.alert_on_drift
        
        # Create metrics object
        metrics = DriftMetrics(
            timestamp=datetime.now(timezone.utc).isoformat(),
            reference_period=(
                (datetime.now(timezone.utc) - timedelta(days=self.config.reference_window_days + self.config.current_window_days)).isoformat(),
                (datetime.now(timezone.utc) - timedelta(days=self.config.current_window_days)).isoformat()
            ),
            current_period=(
                (datetime.now(timezone.utc) - timedelta(days=self.config.current_window_days)).isoformat(),
                datetime.now(timezone.utc).isoformat()
            ),
            reference_samples=len(ref_cases),
            current_samples=len(curr_cases),
            
            score_psi=score_psi,
            score_ks_statistic=float(ks_stat),
            score_ks_pvalue=float(ks_pval),
            score_js_divergence=score_js,
            score_mean_ref=score_mean_ref,
            score_mean_curr=score_mean_curr,
            score_mean_shift=score_mean_shift,
            score_std_ref=score_std_ref,
            score_std_curr=score_std_curr,
            
            block_rate_ref=block_rate_ref,
            block_rate_curr=block_rate_curr,
            block_rate_change=block_rate_change,
            block_rate_relative_change=block_rate_rel_change,
            
            level_dist_ref=level_dist_ref,
            level_dist_curr=level_dist_curr,
            level_psi=level_psi,
            
            feature_drift=feature_drift,
            
            ece_ref=ece_ref,
            ece_curr=ece_curr,
            ece_change=ece_change,
            
            drift_detected=drift_detected,
            alert_triggered=alert_triggered,
        )
        
        # Save detailed report
        if self.config.save_detailed_reports:
            self._save_report(metrics)
        
        # Log summary
        logger.info(f"Drift check complete: drift_detected={drift_detected}")
        logger.info(f"  Score PSI: {score_psi:.4f} (threshold: {self.config.psi_threshold})")
        logger.info(f"  Block rate: {block_rate_ref:.2%} -> {block_rate_curr:.2%} (change: {block_rate_change:+.2%})")
        logger.info(f"  Level PSI: {level_psi:.4f}")
        
        if drift_detected:
            logger.warning("DRIFT DETECTED!")
            for flag, triggered in drift_flags.items():
                if triggered:
                    logger.warning(f"  {flag}: TRIGGERED")
            
            if alert_triggered:
                self._send_alert(metrics, drift_flags)
        
        return metrics
    
    def _empty_metrics(self, message: str) -> DriftMetrics:
        """Return empty metrics when insufficient data."""
        return DriftMetrics(
            timestamp=datetime.now(timezone.utc).isoformat(),
            reference_period=("", ""),
            current_period=("", ""),
            reference_samples=0,
            current_samples=0,
            score_psi=0.0,
            score_ks_statistic=0.0,
            score_ks_pvalue=1.0,
            score_js_divergence=0.0,
            score_mean_ref=0.0,
            score_mean_curr=0.0,
            score_mean_shift=0.0,
            score_std_ref=0.0,
            score_std_curr=0.0,
            block_rate_ref=0.0,
            block_rate_curr=0.0,
            block_rate_change=0.0,
            block_rate_relative_change=0.0,
            level_dist_ref={},
            level_dist_curr={},
            level_psi=0.0,
            feature_drift={},
            ece_ref=0.0,
            ece_curr=0.0,
            ece_change=0.0,
            drift_detected=False,
            alert_triggered=False,
        )
    
    def _save_report(self, metrics: DriftMetrics) -> None:
        """Save detailed drift report."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_file = self.config.output_dir / f"drift_report_{timestamp}.json"
        
        with open(report_file, "w") as f:
            json.dump(asdict(metrics), f, indent=2, default=str)
        
        logger.info(f"Saved drift report to {report_file}")
    
    def _send_alert(self, metrics: DriftMetrics, drift_flags: Dict[str, bool]) -> None:
        """Send alert notification (webhook/email)."""
        # TODO: Implement webhook/email alerting
        logger.info("Alert would be sent here (webhook/email not configured)")


class DriftMonitorJob:
    """Wrapper for scheduled drift monitoring job."""
    
    def __init__(self, config: Optional[DriftConfig] = None):
        self.config = config or DriftConfig()
        self.monitor = DriftMonitor(self.config)
    
    def run(self) -> DriftMetrics:
        """Run drift monitoring job."""
        return self.monitor.run()


def run_drift_monitor(config: Optional[DriftConfig] = None) -> DriftMetrics:
    """Convenience function to run drift monitor."""
    job = DriftMonitorJob(config)
    return job.run()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Run drift monitor")
    parser.add_argument("--reference-days", type=int, default=7, help="Reference window days")
    parser.add_argument("--current-days", type=int, default=1, help="Current window days")
    parser.add_argument("--psi-threshold", type=float, default=0.2, help="PSI threshold")
    args = parser.parse_args()
    
    config = DriftConfig(
        reference_window_days=args.reference_days,
        current_window_days=args.current_days,
        psi_threshold=args.psi_threshold,
    )
    
    metrics = run_drift_monitor(config)
    
    print(f"Drift detected: {metrics.drift_detected}")
    print(f"Score PSI: {metrics.score_psi:.4f}")
    print(f"Block rate change: {metrics.block_rate_change:+.4f}")
    print(f"Level PSI: {metrics.level_psi:.4f}")
    
    sys.exit(1 if metrics.drift_detected else 0)