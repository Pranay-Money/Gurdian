"""
Pytest configuration for ML tests
"""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
import numpy as np
from scipy.sparse import csr_matrix


@pytest.fixture
def sample_urls():
    """Sample URLs for testing."""
    return [
        "https://www.google.com/search?q=test",
        "https://github.com/user/repo",
        "http://paypal-login.tk/verify",
        "https://xn--pple-43d.com/login",
        "https://bit.ly/3xYzK9",
        "http://192.168.1.1/admin",
        "https://amazon-security-update.ml/verify",
        "https://github.com/microsoft/vscode"
    ]


@pytest.fixture
def sample_labels():
    """Sample labels: 0=benign, 1=malicious."""
    return np.array([0, 0, 1, 1, 1, 1, 1, 0])


@pytest.fixture
def feature_matrix(sample_urls):
    """Create a simple feature matrix for testing."""
    from ml.src.components.feature_engineering import FeatureEngineer
    engineer = FeatureEngineer()
    X, names = engineer.build_feature_matrix(sample_urls, fit=True)
    return X, names


@pytest.fixture
def trained_lgb_model(feature_matrix, sample_labels):
    """Train a quick LightGBM model for testing."""
    from ml.src.components.model_trainer import ModelTrainer
    from sklearn.model_selection import train_test_split

    X, names = feature_matrix
    X_train, X_val, y_train, y_val = train_test_split(
        X, sample_labels, test_size=0.3, random_state=42, stratify=sample_labels
    )

    trainer = ModelTrainer()
    trainer.train_lightgbm(X_train, y_train, X_val, y_val)
    return trainer.calibrated_lgb