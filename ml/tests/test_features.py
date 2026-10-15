"""
Tests for feature extraction.
"""
import pytest
import numpy as np

from guardian_ml.features import (
    URLFeatures, extract_features, features_to_array, get_feature_names,
    SUSPICIOUS_TLDS, URL_SHORTENERS, SUSPICIOUS_KEYWORDS, MAJOR_BRANDS
)


class TestFeatureExtraction:
    """Test URL feature extraction."""

    def test_benign_url(self):
        """Test features for a benign URL."""
        url = "https://www.google.com/search?q=test"
        features = extract_features(url)

        assert features.is_https == 1
        assert features.has_ip == 0
        assert features.url_shortener == 0
        assert features.punycode == 0
        assert features.brand_in_subdomain == 0
        assert features.brand_in_path == 0
        assert features.url_length == len(url)

    def test_malicious_ip_url(self):
        """Test features for URL with IP address."""
        url = "http://192.168.1.1/login.php"
        features = extract_features(url)

        assert features.has_ip == 1
        assert features.is_https == 0

    def test_malicious_shortener(self):
        """Test features for URL shortener."""
        url = "https://bit.ly/malicious"
        features = extract_features(url)

        assert features.url_shortener == 1

    def test_malicious_suspicious_tld(self):
        """Test features for suspicious TLD."""
        url = "http://phishing.tk/login"
        features = extract_features(url)

        assert features.suspicious_tld == 1

    def test_malicious_brand_in_subdomain(self):
        """Test features for brand in subdomain (typosquatting)."""
        url = "https://google.phishing-site.com/login"
        features = extract_features(url)

        assert features.brand_in_subdomain == 1

    def test_malicious_brand_in_path(self):
        """Test features for brand in path."""
        url = "https://evil.com/google/login"
        features = extract_features(url)

        assert features.brand_in_path == 1

    def test_brand_in_subdomain_official_domain(self):
        """Test brand_in_subdomain is 0 on official brand domains."""
        # mail.google.com - Google's official domain
        features = extract_features("https://mail.google.com/")
        assert features.brand_in_subdomain == 0, "mail.google.com should not trigger brand_in_subdomain"
        
        # github.com/google/x - GitHub's official domain
        features = extract_features("https://github.com/google/x")
        assert features.brand_in_subdomain == 0, "github.com should not trigger brand_in_subdomain for google"
        
        # paypal.com.evil.top - NOT PayPal's official domain (evil.top is the registrable domain)
        features = extract_features("https://paypal.com.evil.top/login")
        assert features.brand_in_subdomain == 1, "paypal.com.evil.top should trigger brand_in_subdomain"
        
        # google.phishing-site.com - NOT Google's official domain
        features = extract_features("https://google.phishing-site.com/login")
        assert features.brand_in_subdomain == 1, "google.phishing-site.com should trigger brand_in_subdomain"

    def test_brand_in_path_official_domain(self):
        """Test brand_in_path is 0 on official brand domains."""
        # google.com/login - Google's official domain
        features = extract_features("https://google.com/login")
        assert features.brand_in_path == 0, "google.com/login should not trigger brand_in_path"
        
        # github.com/user/repo - GitHub's official domain
        features = extract_features("https://github.com/user/repo")
        assert features.brand_in_path == 0, "github.com should not trigger brand_in_path"
        
        # evil.com/google/login - NOT Google's official domain
        features = extract_features("https://evil.com/google/login")
        assert features.brand_in_path == 1, "evil.com/google/login should trigger brand_in_path"

    def test_malicious_suspicious_keywords(self):
        """Test features for suspicious keywords."""
        url = "https://example.com/verify-account-update-password"
        features = extract_features(url)

        assert features.suspicious_keywords >= 3

    def test_malicious_redirect_param(self):
        """Test features for redirect parameter."""
        url = "https://example.com/login?redirect=https://evil.com"
        features = extract_features(url)

        assert features.has_redirect_param == 1

    def test_malicious_punycode(self):
        """Test features for punycode domain."""
        url = "https://xn--exmple-cua.com/"
        features = extract_features(url)

        assert features.punycode == 1

    def test_excessive_subdomains(self):
        """Test features for excessive subdomains."""
        url = "https://a.b.c.d.e.example.com/path"
        features = extract_features(url)

        assert features.subdomain_count >= 4

    def test_high_entropy(self):
        """Test features for high entropy hostname."""
        url = "https://a1b2c3d4e5f6g7h8i9j0.example.com/"
        features = extract_features(url)

        assert features.entropy > 3.5

    def test_long_url(self):
        """Test features for long URL."""
        url = "https://example.com/" + "a" * 200
        features = extract_features(url)

        assert features.url_length > 150

    def test_features_to_array(self):
        """Test conversion to array."""
        url = "https://example.com/test"
        features = extract_features(url)
        arr = features_to_array(features)

        assert isinstance(arr, list)
        assert len(arr) == 29
        assert all(isinstance(x, (int, float)) for x in arr)

    def test_feature_names(self):
        """Test feature names list."""
        names = get_feature_names()

        assert isinstance(names, list)
        assert len(names) == 29
        assert names[0] == "url_length"
        assert names[-1] == "punycode"

    def test_suspicious_tlds_defined(self):
        """Test suspicious TLDs list is populated."""
        assert len(SUSPICIOUS_TLDS) > 20
        assert "tk" in SUSPICIOUS_TLDS
        assert "ml" in SUSPICIOUS_TLDS

    def test_url_shorteners_defined(self):
        """Test URL shorteners list is populated."""
        assert len(URL_SHORTENERS) >= 20
        assert "bit.ly" in URL_SHORTENERS
        assert "tinyurl.com" in URL_SHORTENERS

    def test_suspicious_keywords_defined(self):
        """Test suspicious keywords list is populated."""
        assert len(SUSPICIOUS_KEYWORDS) > 30
        assert "login" in SUSPICIOUS_KEYWORDS
        assert "verify" in SUSPICIOUS_KEYWORDS

    def test_major_brands_defined(self):
        """Test major brands list is populated."""
        assert len(MAJOR_BRANDS) > 30
        assert "google" in MAJOR_BRANDS
        assert "paypal" in MAJOR_BRANDS


class TestEntropyCalculation:
    """Test entropy calculation."""

    def test_empty_string(self):
        from guardian_ml.features import calculate_entropy
        assert calculate_entropy("") == 0.0

    def test_uniform_string(self):
        from guardian_ml.features import calculate_entropy
        # All same character -> entropy 0
        assert calculate_entropy("aaaaa") == 0.0

    def test_random_string(self):
        from guardian_ml.features import calculate_entropy
        # High entropy string
        entropy = calculate_entropy("abcdefghijklmnopqrstuvwxyz")
        assert entropy > 4.0


class TestTLDExplanationBug:
    """Test the TLD explanation bug fix (uses actual URL's TLD, not hardcoded example)."""

    def test_suspicious_tld_signal_uses_actual_tld(self):
        """Test that suspicious TLD signal uses the actual URL's TLD."""
        from guardian_ml.features import extract_features
        from guardian_ml.model import GuardianModel
        import tempfile
        import os
        from guardian_ml.components.feature_engineering import FeatureEngineer, FeatureConfig
        from guardian_ml.components.model_training import GuardianTrainer, ModelConfig
        from guardian_ml.components.model_exporter import export_for_api
        import numpy as np
        
        # Create and train a model
        urls = [
            'https://www.google.com/search?q=test',
            'http://malicious.top/login.php',
            'https://github.com/user/repo',
            'http://paypal.phishing-site.ml/verify',
        ] * 50
        labels = [0, 1, 0, 1] * 50
        
        engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=True,
            use_host_tokens=True,
            char_ngram_max_features=50,
            host_token_max_features=50,
            run_shortcut_check=False,
        ))
        X = engineer.fit_transform(urls, labels)
        feature_names = engineer.get_feature_names()
        
        trainer = GuardianTrainer(ModelConfig(
            lgb_n_estimators=10,
            early_stopping_rounds=5,
            val_split=0.2,
        ))
        # Use time-based split with mock timestamps
        import time
        timestamps = np.array([time.time() - i * 86400 for i in range(len(labels))])
        trainer.train(X, np.array(labels), feature_names, split_method="time", timestamps=timestamps)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            export_info = export_for_api(trainer, engineer, feature_names, {
                'lr': {'C': 1.0, 'max_iter': 1000},
                'lgb': {'n_estimators': 10},
                'calibration': {'method': 'isotonic', 'cv': 3}
            }, tmpdir)
            
            model = GuardianModel.load(export_info['model_path'])
            
            # Test .top URL (suspicious TLD)
            result_top = model.predict('http://phishing.top/login')
            suspicious_tld_signals = [s for s in result_top.signals if s['label'] == 'Suspicious TLD']
            assert len(suspicious_tld_signals) == 1
            assert '.top' in suspicious_tld_signals[0]['reason']
            assert 'example' not in suspicious_tld_signals[0]['reason']
            
            # Test .com URL (not suspicious TLD)
            result_com = model.predict('https://example.com/page')
            suspicious_tld_signals_com = [s for s in result_com.signals if s['label'] == 'Suspicious TLD']
            assert len(suspicious_tld_signals_com) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])