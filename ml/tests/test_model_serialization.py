from pathlib import PureWindowsPath

import joblib
import numpy as np
import pytest
from guardian_ml.components.feature_engineering import FeatureConfig, FeatureEngineer
from guardian_ml.model import GuardianModel
from sklearn.linear_model import LogisticRegression


def test_windows_path_in_feature_config_is_not_serialized(tmp_path):
    urls = [
        "https://example.com/about",
        "https://www.google.com/search",
        "http://malicious.test/login",
        "http://paypal.phishing.test/verify",
    ]
    labels = np.array([0, 0, 1, 1])
    feature_engineer = FeatureEngineer(
        FeatureConfig(
            use_char_ngrams=False,
            use_host_tokens=False,
            run_shortcut_check=False,
            feature_dir=tmp_path,
        )
    )
    features = feature_engineer.fit_transform(urls)
    classifier = LogisticRegression().fit(features.toarray(), labels)

    # PureWindowsPath represents a path written by a Windows exporter on every OS.
    feature_engineer.config.feature_dir = PureWindowsPath(r"D:\IEEE\ml\features")
    artifact_path = tmp_path / "windows-export.joblib"
    package = {
        "lr_model": classifier,
        "lgb_model": classifier,
        "feature_engineer": feature_engineer,
        "feature_names": feature_engineer.get_feature_names(),
        "version_hash": "cross-platform-test",
        "metadata": {"synthetic": False},
    }
    joblib.dump(package, artifact_path)

    loaded_model = GuardianModel.load(artifact_path)
    prediction = loaded_model.predict(urls[0])
    expected_probability = classifier.predict_proba(
        feature_engineer.transform([urls[0]]).toarray()
    )[0, 1]

    assert loaded_model.feature_engineer.config.feature_dir is None
    assert prediction.probability == pytest.approx(expected_probability)
