"""
Tests for evaluation component.
"""
import pytest
import numpy as np
import scipy.sparse as sp

from guardian_ml.components.evaluation import ModelEvaluator, EvaluationConfig, print_evaluation_summary
from guardian_ml.components.model_training import GuardianTrainer, ModelConfig
from guardian_ml.components.feature_engineering import FeatureEngineer, FeatureConfig


class TestModelEvaluator:
    """Test model evaluation."""

    def setup_method(self):
        """Create test data and trained model."""
        urls = [
            "https://www.google.com/search?q=test",
            "http://malicious.tk/login.php",
            "https://github.com/user/repo",
            "http://paypal.phishing-site.ml/verify",
        ] * 100
        labels = [0, 1, 0, 1] * 100

        self.engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=True,
            use_host_tokens=True,
            char_ngram_max_features=50,
            host_token_max_features=50,
        ))
        self.X = self.engineer.fit_transform(urls, labels)
        self.y = np.array(labels)

        self.trainer = GuardianTrainer(ModelConfig(
            lgb_n_estimators=10,
            early_stopping_rounds=5,
            val_split=0.2,
        ))
        
        import time
        timestamps = np.array([time.time() - i * 86400 for i in range(len(labels))])
        self.trainer.train(self.X, self.y, self.engineer.get_feature_names(), split_method="time", timestamps=timestamps)

    def test_evaluate_single_model(self):
        """Test evaluating a single model."""
        evaluator = ModelEvaluator(EvaluationConfig(save_plots=False))

        results = evaluator.evaluate(
            self.trainer.lgb_model,
            self.X,
            self.y,
            model_name="test_model"
        )

        assert hasattr(results, 'roc_auc')
        assert hasattr(results, 'pr_auc')
        assert hasattr(results, 'f1')
        assert hasattr(results, 'fpr_at_1pct_tpr')
        assert hasattr(results, 'fpr_at_01pct_tpr')
        assert hasattr(results, 'brier_score')
        assert hasattr(results, 'ece')
        assert hasattr(results, 'confusion_matrix')
        assert hasattr(results, 'classification_report')
        assert hasattr(results, 'per_tld_metrics')
        assert hasattr(results, 'calibration_curve')
        assert hasattr(results, 'bootstrap_ci')

        assert 0 <= results.roc_auc <= 1
        assert 0 <= results.pr_auc <= 1
        assert 0 <= results.f1 <= 1
        assert 0 <= results.ece <= 1

    def test_evaluate_compare_models(self):
        """Test comparing multiple models."""
        evaluator = ModelEvaluator(EvaluationConfig(save_plots=False))

        results = evaluator.compare_models(
            {
                "lightgbm": self.trainer.lgb_model,
                "logistic_regression": self.trainer.lr_model,
            },
            self.X,
            self.y,
        )

        assert "lightgbm" in results
        assert "logistic_regression" in results

    def test_evaluate_with_tlds(self):
        """Test evaluation with TLD breakdown."""
        evaluator = ModelEvaluator(EvaluationConfig(save_plots=False))

        # Use TLDs that have both classes for AUC computation
        tlds = ["com", "tk", "com", "tk"] * 50 + ["ml", "ml"] * 100  # 400 total

        results = evaluator.evaluate(
            self.trainer.lgb_model,
            self.X,
            self.y,
            tlds=tlds,
            model_name="test_tld"
        )

        assert len(results.per_tld_metrics) > 0
        for tld, metrics in results.per_tld_metrics.items():
            assert "count" in metrics
            assert "auc" in metrics
            assert "malicious_rate" in metrics

    def test_calibration_curve(self):
        """Test calibration curve computation."""
        evaluator = ModelEvaluator(EvaluationConfig(save_plots=False))

        # Perfect calibration
        y_true = np.array([0, 0, 1, 1])
        y_proba = np.array([0.1, 0.2, 0.8, 0.9])

        cal_curve, ece = evaluator._compute_calibration(y_true, y_proba)

        assert "prob_true" in cal_curve
        assert "prob_pred" in cal_curve
        assert "bin_edges" in cal_curve
        assert ece >= 0

    def test_fpr_at_tpr(self):
        """Test FPR at specific TPR."""
        evaluator = ModelEvaluator(EvaluationConfig(save_plots=False))

        # Perfect separation
        y_true = np.array([0] * 100 + [1] * 100)
        y_score = np.array([0.1] * 100 + [0.9] * 100)

        fpr_99 = evaluator._fpr_at_tpr(y_true, y_score, 0.99)
        fpr_999 = evaluator._fpr_at_tpr(y_true, y_score, 0.999)

        assert fpr_99 == 0.0
        assert fpr_999 == 0.0

        # No separation
        y_score_random = np.random.RandomState(42).rand(200)
        fpr_random = evaluator._fpr_at_tpr(y_true, y_score_random, 0.99)
        assert fpr_random > 0

    def test_print_summary(self, capsys):
        """Test printing evaluation summary."""
        evaluator = ModelEvaluator(EvaluationConfig(save_plots=False))
        results = evaluator.evaluate(
            self.trainer.lgb_model,
            self.X,
            self.y,
            model_name="test"
        )

        print_evaluation_summary(results, "Test Model")

        captured = capsys.readouterr()
        assert "Test Model Evaluation Summary" in captured.out
        assert "ROC-AUC" in captured.out
        assert "Confusion Matrix" in captured.out


if __name__ == "__main__":
    pytest.main([__file__, "-v"])