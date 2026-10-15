"""
Tests for model training component.
"""
import pytest
import numpy as np
import scipy.sparse as sp
from unittest.mock import MagicMock, patch

from guardian_ml.components.model_training import GuardianTrainer, ModelConfig
from guardian_ml.components.feature_engineering import FeatureEngineer, FeatureConfig


class TestGuardianTrainer:
    """Test model training."""

    def setup_method(self):
        """Create test data."""
        self.urls = [
            "https://www.google.com/search?q=test",
            "http://malicious.tk/login.php",
            "https://github.com/user/repo",
            "http://paypal.phishing-site.ml/verify",
        ] * 100
        self.labels = np.array([0, 1, 0, 1] * 100)

        self.engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=True,
            use_host_tokens=True,
            char_ngram_max_features=50,
            host_token_max_features=50,
        ))
        self.X = self.engineer.fit_transform(self.urls, self.labels.tolist())
        self.feature_names = self.engineer.get_feature_names()

    def test_train_both_models(self):
        """Test training both LR and LightGBM."""
        trainer = GuardianTrainer(ModelConfig(
            lgb_n_estimators=10,
            early_stopping_rounds=5,
            val_split=0.2,
        ))
        
        # Use time-based split for tests
        import time
        timestamps = np.array([time.time() - i * 86400 for i in range(len(self.labels))])
        info = trainer.train(self.X, self.labels, self.feature_names, split_method="time", timestamps=timestamps)

        assert trainer.is_trained
        assert trainer.lr_model is not None
        assert trainer.lgb_model is not None
        assert "version_hash" in info
        assert len(trainer.version_hash) == 16

    def test_evaluate(self):
        """Test evaluation on test set."""
        trainer = GuardianTrainer(ModelConfig(
            lgb_n_estimators=10,
            early_stopping_rounds=5,
            val_split=0.2,
        ))
        
        import time
        timestamps = np.array([time.time() - i * 86400 for i in range(len(self.labels))])
        trainer.train(self.X, self.labels, self.feature_names, split_method="time", timestamps=timestamps)

        # Create test data
        test_urls = [
            "https://www.example.com/page",
            "http://evil.ml/phish",
        ] * 50
        test_labels = np.array([0, 1] * 50)
        X_test = self.engineer.transform(test_urls)

        results = trainer.evaluate(X_test, test_labels)

        assert "logistic_regression" in results
        assert "lightgbm" in results

        for name, metrics in results.items():
            assert hasattr(metrics, 'roc_auc')
            assert hasattr(metrics, 'pr_auc')
            assert hasattr(metrics, 'f1')
            assert hasattr(metrics, 'fpr_at_1pct')
            assert hasattr(metrics, 'fpr_at_01pct')
            assert 0 <= metrics.roc_auc <= 1
            assert 0 <= metrics.pr_auc <= 1

    def test_predict_proba(self):
        """Test probability prediction."""
        trainer = GuardianTrainer(ModelConfig(
            lgb_n_estimators=10,
            early_stopping_rounds=5,
        ))
        
        import time
        timestamps = np.array([time.time() - i * 86400 for i in range(len(self.labels))])
        trainer.train(self.X, self.labels, self.feature_names, split_method="time", timestamps=timestamps)

        test_urls = ["https://example.com/test"] * 10
        X_test = self.engineer.transform(test_urls)

        proba_lgb = trainer.predict_proba(X_test, "lightgbm")
        proba_lr = trainer.predict_proba(X_test, "logistic_regression")

        assert proba_lgb.shape == (10,)
        assert proba_lr.shape == (10,)
        assert np.all(proba_lgb >= 0) and np.all(proba_lgb <= 1)
        assert np.all(proba_lr >= 0) and np.all(proba_lr <= 1)

    def test_get_feature_importance(self):
        """Test feature importance extraction."""
        trainer = GuardianTrainer(ModelConfig(
            lgb_n_estimators=10,
            early_stopping_rounds=5,
        ))
        
        import time
        timestamps = np.array([time.time() - i * 86400 for i in range(len(self.labels))])
        trainer.train(self.X, self.labels, self.feature_names, split_method="time", timestamps=timestamps)

        importance = trainer.get_feature_importance(top_k=10)

        assert isinstance(importance, dict)
        assert len(importance) <= 10
        # Values should be sorted descending
        values = list(importance.values())
        assert values == sorted(values, reverse=True)

    def test_save_load(self, tmp_path):
        """Test model save and load."""
        from guardian_ml.components.feature_engineering import create_feature_schema

        trainer = GuardianTrainer(ModelConfig(
            lgb_n_estimators=10,
            early_stopping_rounds=5,
        ))
        
        import time
        timestamps = np.array([time.time() - i * 86400 for i in range(len(self.labels))])
        trainer.train(self.X, self.labels, self.feature_names, split_method="time", timestamps=timestamps)

        feature_schema = create_feature_schema(self.engineer)
        trainer.save(tmp_path / "models", feature_schema)

        # Load
        trainer2 = GuardianTrainer.load(tmp_path / "models")

        assert trainer2.is_trained
        assert trainer2.version_hash == trainer.version_hash
        assert trainer2.feature_names == trainer.feature_names

        # Predictions should match
        test_urls = ["https://example.com/test"] * 10
        X_test = self.engineer.transform(test_urls)

        proba1 = trainer.predict_proba(X_test)
        proba2 = trainer2.predict_proba(X_test)

        assert np.allclose(proba1, proba2)


class TestExportForAPI:
    """Test model export for API."""

    def setup_method(self):
        """Create test data."""
        self.urls = [
            "https://www.google.com/search?q=test",
            "http://malicious.tk/login.php",
            "https://github.com/user/repo",
            "http://paypal.phishing-site.ml/verify",
        ] * 100
        self.labels = np.array([0, 1, 0, 1] * 100)

        self.engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=True,
            use_host_tokens=True,
            char_ngram_max_features=50,
            host_token_max_features=50,
        ))
        self.X = self.engineer.fit_transform(self.urls, self.labels.tolist())
        self.feature_names = self.engineer.get_feature_names()

    def test_export_creates_files(self, tmp_path):
        """Test export creates all required files."""
        from guardian_ml.components.model_training import export_for_api
        from guardian_ml.components.feature_engineering import create_feature_schema
        
        trainer = GuardianTrainer(ModelConfig(
            lgb_n_estimators=10,
            early_stopping_rounds=5,
        ))
        
        import time
        timestamps = np.array([time.time() - i * 86400 for i in range(len(self.labels))])
        trainer.train(self.X, self.labels, self.feature_names, split_method="time", timestamps=timestamps)

        feature_schema = create_feature_schema(self.engineer)
        export_path = export_for_api(trainer, feature_schema, tmp_path / "export")

        assert export_path.exists()
        assert (export_path / "model.joblib").exists()
        assert (export_path / "feature_schema.json").exists()
        assert (export_path / "version.txt").exists()

        # Verify version
        with open(export_path / "version.txt") as f:
            version = f.read().strip()
        assert version == trainer.version_hash

    def test_exported_model_loadable(self, tmp_path):
        """Test exported model can be loaded and used."""
        from guardian_ml.components.model_training import export_for_api
        from guardian_ml.components.feature_engineering import create_feature_schema
        import joblib

        trainer = GuardianTrainer(ModelConfig(
            lgb_n_estimators=10,
            early_stopping_rounds=5,
        ))
        
        import time
        timestamps = np.array([time.time() - i * 86400 for i in range(len(self.labels))])
        trainer.train(self.X, self.labels, self.feature_names, split_method="time", timestamps=timestamps)

        feature_schema = create_feature_schema(self.engineer)
        export_path = export_for_api(trainer, feature_schema, tmp_path / "export")

        # Load exported package
        package = joblib.load(export_path / "model.joblib")

        assert "lr_model" in package
        assert "lgb_model" in package
        assert "feature_engineer" in package
        assert "feature_names" in package
        assert "version_hash" in package


if __name__ == "__main__":
    pytest.main([__file__, "-v"])