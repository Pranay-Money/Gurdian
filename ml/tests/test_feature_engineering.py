"""
Tests for feature engineering component.
"""
import pytest
import numpy as np
import scipy.sparse as sp

from guardian_ml.components.feature_engineering import FeatureEngineer, FeatureConfig


class TestFeatureEngineer:
    """Test feature engineering pipeline."""

    def test_fit_transform_basic(self):
        """Test basic fit and transform."""
        urls = [
            "https://www.google.com/search?q=test",
            "http://malicious.tk/login.php",
            "https://github.com/user/repo",
            "http://paypal.phishing-site.ml/verify",
        ] * 25
        labels = [0, 1, 0, 1] * 25

        engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=True,
            use_host_tokens=True,
            char_ngram_max_features=100,
            host_token_max_features=100,
            run_shortcut_check=False,  # Disable for speed
        ))

        X = engineer.fit_transform(urls, labels)

        assert sp.issparse(X)
        assert X.shape[0] == len(urls)
        assert X.shape[1] > 0

    def test_lexical_only(self):
        """Test with only lexical features."""
        urls = ["https://example.com/test", "http://evil.tk/phish"] * 5
        labels = [0, 1] * 5

        engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=False,
            use_host_tokens=False,
            run_shortcut_check=False,
        ))

        X = engineer.fit_transform(urls, labels)

        assert X.shape[1] == 29  # Only lexical features (29 features)

    def test_transform_before_fit_raises(self):
        """Test that transform before fit raises error."""
        engineer = FeatureEngineer()
        urls = ["https://example.com"]

        with pytest.raises(Exception):
            engineer.transform(urls)

    def test_get_feature_names(self):
        """Test feature names retrieval."""
        urls = ["https://example.com/test", "http://evil.tk/phish"] * 5
        labels = [0, 1] * 5

        engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=True,
            use_host_tokens=True,
            char_ngram_max_features=10,
            host_token_max_features=10,
            run_shortcut_check=False,
        ))

        X = engineer.fit_transform(urls, labels)
        names = engineer.get_feature_names()

        assert len(names) == X.shape[1]
        assert names[:29] == engineer.lexical_feature_names

    def test_save_load(self, tmp_path):
        """Test saving and loading feature engineer."""
        urls = [
            "https://www.google.com/search?q=test",
            "http://malicious.tk/login.php",
        ] * 50
        labels = [0, 1] * 50

        engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=True,
            use_host_tokens=True,
            char_ngram_max_features=50,
            host_token_max_features=50,
            run_shortcut_check=False,
        ))

        X1 = engineer.fit_transform(urls, labels)
        engineer.save(tmp_path / "features")

        # Load
        engineer2 = FeatureEngineer.load(tmp_path / "features")
        X2 = engineer2.transform(urls)

        # Results should be identical
        assert np.allclose(X1.toarray(), X2.toarray())

    def test_extract_host_tokens(self):
        """Test host token extraction."""
        engineer = FeatureEngineer()

        assert engineer._extract_host_tokens("https://www.google.com/search") == "www google com"
        # tldextract treats co.uk as a single suffix
        assert engineer._extract_host_tokens("https://sub.domain.co.uk/path") == "sub domain co.uk"
        assert engineer._extract_host_tokens("https://example.com") == "example com"

    def test_shortcut_check_runs(self):
        """Test that shortcut check runs without error."""
        urls = [
            "https://www.google.com/search?q=test",
            "http://malicious.tk/login.php",
        ] * 50
        labels = [0, 1] * 50

        engineer = FeatureEngineer(FeatureConfig(
            run_shortcut_check=True,
            shortcut_threshold_auc=0.99,  # High threshold to avoid warnings in test
        ))

        # Should not raise
        X = engineer.fit_transform(urls, labels)
        assert X.shape[0] == len(urls)


class TestCreateFeatureSchema:
    """Test feature schema creation."""

    def test_schema_structure(self):
        """Test schema has expected structure."""
        from guardian_ml.components.feature_engineering import create_feature_schema

        urls = ["https://example.com/test", "http://evil.tk/phish"] * 5
        labels = [0, 1] * 5

        engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=True,
            use_host_tokens=True,
            run_shortcut_check=False,
        ))
        engineer.fit(urls, labels)

        schema = create_feature_schema(engineer)

        assert "version" in schema
        assert "feature_groups" in schema
        assert "lexical" in schema["feature_groups"]
        assert "char_ngrams" in schema["feature_groups"]
        assert "host_tokens" in schema["feature_groups"]
        assert "total_features" in schema
        assert "extraction_functions" in schema


if __name__ == "__main__":
    pytest.main([__file__, "-v"])