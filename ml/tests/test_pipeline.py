"""
Tests for pipeline orchestrator.
"""
import pytest
import numpy as np

from guardian_ml.pipeline import GuardianPipeline, PipelineConfig, run_training_pipeline
from guardian_ml.components.feature_engineering import FeatureConfig
from guardian_ml.components.model_training import ModelConfig
from guardian_ml.components.evaluation import EvaluationConfig


class TestGuardianPipeline:
    """Test pipeline orchestrator."""

    def test_pipeline_config(self):
        """Test pipeline configuration."""
        config = PipelineConfig()
        config.feature_engineering = FeatureConfig(
            use_lexical=True,
            use_char_ngrams=False,
            use_host_tokens=False,
        )
        config.model_training = ModelConfig(
            lgb_n_estimators=5,
            early_stopping_rounds=3,
        )
        config.evaluation = EvaluationConfig(save_plots=False)

        assert config.feature_engineering.use_lexical is True
        assert config.feature_engineering.use_char_ngrams is False
        assert config.model_training.lgb_n_estimators == 5

    def test_pipeline_initialization(self):
        """Test pipeline can be initialized."""
        config = PipelineConfig()
        config.feature_engineering = FeatureConfig(
            use_lexical=True,
            use_char_ngrams=False,
            use_host_tokens=False,
        )
        config.model_training = ModelConfig(
            lgb_n_estimators=5,
            early_stopping_rounds=3,
        )
        config.evaluation = EvaluationConfig(save_plots=False)

        pipeline = GuardianPipeline(config)

        assert pipeline.data_ingestion is not None
        assert pipeline.feature_engineer is not None
        assert pipeline.trainer is not None
        assert pipeline.evaluator is not None


class TestSyntheticPipeline:
    """Test pipeline with synthetic data (mocked ingestion)."""

    def test_pipeline_with_synthetic_data(self, tmp_path, monkeypatch):
        """Test full pipeline with synthetic data by mocking ingestion."""
        from guardian_ml.components.data_ingestion import DataIngestion

        # Mock data ingestion to return synthetic data
        def mock_run(self, create_snapshot=True, include_crawled=False):
            urls = [
                "https://www.google.com/search?q=test",
                "http://malicious.tk/login.php",
                "https://github.com/user/repo",
                "http://paypal.phishing-site.ml/verify",
            ] * 50
            labels = [0, 1, 0, 1] * 50
            records = [
                {"url": u, "label": l, "source": "synthetic", "fetched_at": "2024-01-01T00:00:00"}
                for u, l in zip(urls, labels)
            ]
            # Split by domain
            train = records[:120]
            test = records[120:]
            return train, test, {"source_counts": {"synthetic": len(records)}}

        monkeypatch.setattr(DataIngestion, "run", mock_run)

        config = PipelineConfig()
        config.feature_engineering = FeatureConfig(
            use_lexical=True,
            use_char_ngrams=True,
            use_host_tokens=True,
            char_ngram_max_features=50,
            host_token_max_features=50,
        )
        config.model_training = ModelConfig(
            lgb_n_estimators=10,
            early_stopping_rounds=5,
            val_split=0.2,
        )
        config.evaluation = EvaluationConfig(save_plots=False)
        config.export_dir = tmp_path / "models"
        config.create_snapshot = False
        config.allow_synthetic_export = True

        pipeline = GuardianPipeline(config)
        summary = pipeline.run()

        assert "version_hash" in summary
        assert "eval_results" in summary
        assert "lightgbm" in summary["eval_results"]
        assert "logistic_regression" in summary["eval_results"]
        assert summary["eval_results"]["lightgbm"]["roc_auc"] > 0
        assert (config.export_dir / "model.joblib").exists()
        assert (config.export_dir / "feature_schema.json").exists()
        assert (config.export_dir / "version.txt").exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])