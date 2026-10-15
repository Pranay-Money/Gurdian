"""
Tests for inference CLI and model loading from different working directories.
"""
import pytest
import tempfile
import os
import sys
import subprocess
import json
import numpy as np
from pathlib import Path

# Add ML src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "ml" / "src"))

from guardian_ml import GuardianModel
from guardian_ml.components.feature_engineering import FeatureEngineer, FeatureConfig
from guardian_ml.components.model_training import GuardianTrainer, ModelConfig
from guardian_ml.components.model_exporter import export_for_api


class TestInferenceCLI:
    """Test inference CLI functionality."""
    
    def setup_method(self):
        """Create a test model."""
        self.urls = [
            "https://www.google.com/search?q=test",
            "http://malicious.tk/login.php",
            "https://github.com/user/repo",
            "http://paypal.phishing-site.ml/verify",
        ] * 50
        self.labels = np.array([0, 1, 0, 1] * 50)
        
        self.engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=True,
            use_host_tokens=True,
            char_ngram_max_features=50,
            host_token_max_features=50,
            run_shortcut_check=False,
        ))
        self.X = self.engineer.fit_transform(self.urls, self.labels.tolist())
        self.feature_names = self.engineer.get_feature_names()
        
        self.trainer = GuardianTrainer(ModelConfig(
            lgb_n_estimators=10,
            early_stopping_rounds=5,
            val_split=0.2,
        ))
        
        import time
        timestamps = np.array([time.time() - i * 86400 for i in range(len(self.labels))])
        self.trainer.train(self.X, self.labels, self.feature_names, split_method="time", timestamps=timestamps)
    
    def test_model_load_from_different_cwd(self, tmp_path):
        """Test loading model from a different working directory."""
        # Export model to temp directory
        with tempfile.TemporaryDirectory() as export_dir:
            export_info = export_for_api(
                self.trainer, self.engineer, self.feature_names, {
                    "lr": {"C": 1.0, "max_iter": 1000},
                    "lgb": {"n_estimators": 10},
                    "calibration": {"method": "isotonic", "cv": 3}
                }, export_dir
            )
            
            model_path = Path(export_info['model_path'])
            
            # Change to a different directory and load model
            original_cwd = os.getcwd()
            try:
                os.chdir(tmp_path)
                
                # Load model using absolute path
                model = GuardianModel.load(model_path)
                assert model is not None
                # Version hash will differ because export config differs - just verify it loads
                assert model.version_hash is not None
                
                # Run prediction
                result = model.predict("https://example.com/test")
                assert result is not None
                assert 0 <= result.probability <= 1
                
            finally:
                os.chdir(original_cwd)
    
    def test_inference_cli_help(self):
        """Test inference CLI help output."""
        cli_path = Path(__file__).parent.parent / "src" / "guardian_ml" / "inference.py"
        result = subprocess.run(
            [sys.executable, str(cli_path), "--help"],
            capture_output=True, text=True
        )
        assert result.returncode == 0
        assert "Guardian ML inference" in result.stdout
        assert "--model" in result.stdout
        assert "--urls" in result.stdout
    
    def test_inference_cli_with_urls(self, tmp_path):
        """Test inference CLI with URL arguments."""
        with tempfile.TemporaryDirectory() as export_dir:
            export_info = export_for_api(
                self.trainer, self.engineer, self.feature_names, {
                    "lr": {"C": 1.0, "max_iter": 1000},
                    "lgb": {"n_estimators": 10},
                    "calibration": {"method": "isotonic", "cv": 3}
                }, export_dir
            )
            
            model_path = Path(export_info['model_path'])
            cli_path = Path(__file__).parent.parent / "src" / "guardian_ml" / "inference.py"
            
            result = subprocess.run(
                [sys.executable, str(cli_path), 
                 "--model", str(model_path),
                 "--urls", "https://example.com/test", "http://malicious.tk/login"],
                capture_output=True, text=True
            )
            assert result.returncode == 0
            assert "example.com" in result.stdout
            assert "malicious.tk" in result.stdout
    
    def test_inference_cli_with_input_file(self, tmp_path):
        """Test inference CLI with input JSONL file."""
        with tempfile.TemporaryDirectory() as export_dir:
            export_info = export_for_api(
                self.trainer, self.engineer, self.feature_names, {
                    "lr": {"C": 1.0, "max_iter": 1000},
                    "lgb": {"n_estimators": 10},
                    "calibration": {"method": "isotonic", "cv": 3}
                }, export_dir
            )
            
            model_path = Path(export_info['model_path'])
            cli_path = Path(__file__).parent.parent / "src" / "guardian_ml" / "inference.py"
            
            # Create input file
            input_file = tmp_path / "test_urls.jsonl"
            with open(input_file, 'w') as f:
                f.write('{"url": "https://example.com/test"}\n')
                f.write('{"url": "http://malicious.tk/login"}\n')
            
            result = subprocess.run(
                [sys.executable, str(cli_path), 
                 "--model", str(model_path),
                 "--input", str(input_file)],
                capture_output=True, text=True
            )
            assert result.returncode == 0
            assert "example.com" in result.stdout
            assert "malicious.tk" in result.stdout
    
    def test_inference_cli_output_json(self, tmp_path):
        """Test inference CLI JSON output."""
        with tempfile.TemporaryDirectory() as export_dir:
            export_info = export_for_api(
                self.trainer, self.engineer, self.feature_names, {
                    "lr": {"C": 1.0, "max_iter": 1000},
                    "lgb": {"n_estimators": 10},
                    "calibration": {"method": "isotonic", "cv": 3}
                }, export_dir
            )
            
            model_path = Path(export_info['model_path'])
            cli_path = Path(__file__).parent.parent / "src" / "guardian_ml" / "inference.py"
            output_file = tmp_path / "results.json"
            
            result = subprocess.run(
                [sys.executable, str(cli_path), 
                 "--model", str(model_path),
                 "--urls", "https://example.com/test",
                 "--format", "json",
                 "--output", str(output_file)],
                capture_output=True, text=True
            )
            assert result.returncode == 0
            
            # Check output file
            assert output_file.exists()
            with open(output_file) as f:
                data = json.load(f)
            assert len(data) == 1
            assert data[0]['url'] == "https://example.com/test"
            assert 'probability' in data[0]
            assert 'risk_level' in data[0]


class TestExporterRoundTrip:
    """Test model export and re-import round-trip."""
    
    def setup_method(self):
        """Create a test model."""
        self.urls = [
            "https://www.google.com/search?q=test",
            "http://malicious.tk/login.php",
            "https://github.com/user/repo",
            "http://paypal.phishing-site.ml/verify",
        ] * 50
        self.labels = np.array([0, 1, 0, 1] * 50)
        
        self.engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=True,
            use_host_tokens=True,
            char_ngram_max_features=50,
            host_token_max_features=50,
            run_shortcut_check=False,
        ))
        self.X = self.engineer.fit_transform(self.urls, self.labels.tolist())
        self.feature_names = self.engineer.get_feature_names()
        
        self.trainer = GuardianTrainer(ModelConfig(
            lgb_n_estimators=10,
            early_stopping_rounds=5,
            val_split=0.2,
        ))
        
        import time
        timestamps = np.array([time.time() - i * 86400 for i in range(len(self.labels))])
        self.trainer.train(self.X, self.labels, self.feature_names, split_method="time", timestamps=timestamps)
    
    def test_export_import_roundtrip(self, tmp_path):
        """Test export -> load -> predict produces same results."""
        with tempfile.TemporaryDirectory() as export_dir:
            export_info = export_for_api(
                self.trainer, self.engineer, self.feature_names, {
                    "lr": {"C": 1.0, "max_iter": 1000},
                    "lgb": {"n_estimators": 10},
                    "calibration": {"method": "isotonic", "cv": 3}
                }, export_dir
            )
            
            model_path = Path(export_info['model_path'])
            
            # Load original model
            model1 = GuardianModel.load(model_path)
            result1 = model1.predict("https://example.com/test")
            
            # Load again (simulating restart)
            model2 = GuardianModel.load(model_path)
            result2 = model2.predict("https://example.com/test")
            
            # Results should be identical
            assert abs(result1.probability - result2.probability) < 1e-6
            assert result1.risk_level == result2.risk_level
            assert result1.model_metadata['version_hash'] == result2.model_metadata['version_hash']
            
            # Check feature engineer works
            X1 = model1.feature_engineer.transform(["https://example.com/test"])
            X2 = model2.feature_engineer.transform(["https://example.com/test"])
            assert np.allclose(X1.toarray(), X2.toarray())
    
    def test_exported_model_has_all_components(self, tmp_path):
        """Test exported model contains all required components."""
        with tempfile.TemporaryDirectory() as export_dir:
            export_info = export_for_api(
                self.trainer, self.engineer, self.feature_names, {
                    "lr": {"C": 1.0, "max_iter": 1000},
                    "lgb": {"n_estimators": 10},
                    "calibration": {"method": "isotonic", "cv": 3}
                }, export_dir
            )
            
            model_path = Path(export_info['model_path'])
            
            import joblib
            package = joblib.load(model_path)
            
            # Check all required keys
            required_keys = ['lr_model', 'lgb_model', 'feature_engineer', 'feature_names', 'version_hash', 'metadata']
            for key in required_keys:
                assert key in package, f"Missing key: {key}"
            
            # Check metadata
            assert 'synthetic' in package['metadata']
            assert 'exported_at' in package['metadata']
            
            # Check feature schema exists
            schema_path = Path(export_dir) / "feature_schema.json"
            assert schema_path.exists()
            
            with open(schema_path) as f:
                schema = json.load(f)
            assert 'feature_names' in schema
            assert 'feature_count' in schema
            assert schema['feature_count'] == len(self.feature_names)
            
            # Check version.txt exists
            version_path = Path(export_dir) / "version.txt"
            assert version_path.exists()
            with open(version_path) as f:
                version = f.read().strip()
            assert version == export_info['version_hash']


class TestShortcutAudit:
    """Test shortcut detection functionality."""
    
    def test_shortcut_detection_runs(self):
        """Test that shortcut detection runs and returns results."""
        urls = [
            "https://www.google.com/search?q=test",
            "http://malicious.tk/login.php",
            "https://github.com/user/repo",
            "http://paypal.phishing-site.ml/verify",
        ] * 100
        labels = [0, 1, 0, 1] * 100
        
        engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=True,
            use_host_tokens=True,
            char_ngram_max_features=50,
            host_token_max_features=50,
            run_shortcut_check=True,
            shortcut_threshold_auc=0.9,
        ))
        
        results = engineer._run_shortcut_check(urls, labels)
        
        # Check expected keys in results
        assert 'lexical_auc' in results
        assert 'char_ngram_auc' in results
        assert 'host_token_auc' in results
        
        # Check individual feature checks
        for fname in ['path_length', 'query_length', 'path_depth', 'has_redirect_param', 'url_length', 'is_https']:
            assert f'{fname}_auc' in results
    
    def test_shortcut_detection_warnings(self, caplog):
        """Test that shortcut detection logs warnings for high AUC features."""
        # Create data where a single feature perfectly separates classes
        urls = []
        labels = []
        
        # Benign: all use .com
        for i in range(100):
            urls.append(f"https://site{i}.com/page")
            labels.append(0)
        
        # Malicious: all use .tk
        for i in range(100):
            urls.append(f"https://site{i}.tk/login")
            labels.append(1)
        
        engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=False,
            use_host_tokens=False,
            run_shortcut_check=True,
            shortcut_threshold_auc=0.85,
        ))
        
        with caplog.at_level("WARNING"):
            results = engineer._run_shortcut_check(urls, labels)
        
        # Should detect suspicious_tld as shortcut
        assert any("SHORTCUT" in msg or "shortcut" in msg.lower() for msg in caplog.messages)


class TestSyntheticExportRefusal:
    """Test that synthetic model export is refused without flag."""
    
    def setup_method(self):
        """Create a test model."""
        self.urls = [
            "https://www.google.com/search?q=test",
            "http://malicious.tk/login.php",
        ] * 50
        self.labels = np.array([0, 1] * 50)
        
        self.engineer = FeatureEngineer(FeatureConfig(
            use_lexical=True,
            use_char_ngrams=True,
            use_host_tokens=True,
            char_ngram_max_features=50,
            host_token_max_features=50,
            run_shortcut_check=False,
        ))
        self.X = self.engineer.fit_transform(self.urls, self.labels.tolist())
        self.feature_names = self.engineer.get_feature_names()
        
        self.trainer = GuardianTrainer(ModelConfig(
            lgb_n_estimators=10,
            early_stopping_rounds=5,
            val_split=0.2,
        ))
        
        import time
        timestamps = np.array([time.time() - i * 86400 for i in range(len(self.labels))])
        self.trainer.train(self.X, self.labels, self.feature_names, split_method="time", timestamps=timestamps)
    
    def test_synthetic_export_refused_by_default(self, tmp_path):
        """Test synthetic model export is refused without --allow-synthetic."""
        from guardian_ml.components.model_exporter import ModelExporter, ExportConfig
        from guardian_ml.exception import ModelExportException
        
        exporter = ModelExporter(ExportConfig(api_models_dir=tmp_path, allow_synthetic=False))
        
        with pytest.raises(ModelExportException) as exc_info:
            exporter.export(
                self.trainer, self.engineer, self.feature_names,
                {"synthetic": True}  # Mark as synthetic
            )
        assert "synthetic" in str(exc_info.value).lower()
    
    def test_synthetic_export_allowed_with_flag(self, tmp_path):
        """Test synthetic model export works with --allow-synthetic flag."""
        from guardian_ml.components.model_exporter import ModelExporter, ExportConfig
        
        exporter = ModelExporter(ExportConfig(api_models_dir=tmp_path, allow_synthetic=True))
        
        # Should not raise
        export_info = exporter.export(
            self.trainer, self.engineer, self.feature_names,
            {"synthetic": True}
        )
        
        assert export_info is not None
        assert 'model_path' in export_info
        
        # Check metadata includes synthetic flag
        import joblib
        package = joblib.load(export_info['model_path'])
        assert package['metadata']['synthetic'] == True
    
    def test_synthetic_model_load_refused(self, tmp_path):
        """Test loading synthetic model is refused without flag."""
        from guardian_ml.components.model_exporter import ModelExporter, ExportConfig
        
        # Export with synthetic flag
        exporter = ModelExporter(ExportConfig(api_models_dir=tmp_path, allow_synthetic=True))
        export_info = exporter.export(
            self.trainer, self.engineer, self.feature_names,
            {"synthetic": True}
        )
        
        model_path = Path(export_info['model_path'])
        
        # Should refuse to load without allow_synthetic
        with pytest.raises(ValueError) as exc_info:
            GuardianModel.load(model_path, allow_synthetic=False)
        assert "synthetic" in str(exc_info.value).lower()
        
        # Should load with allow_synthetic=True
        model = GuardianModel.load(model_path, allow_synthetic=True)
        assert model is not None
        
        # Should also load with env var
        import os
        os.environ['GUARDIAN_ALLOW_SYNTHETIC'] = '1'
        try:
            model = GuardianModel.load(model_path, allow_synthetic=False)
            assert model is not None
        finally:
            del os.environ['GUARDIAN_ALLOW_SYNTHETIC']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])