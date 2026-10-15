from pathlib import Path
from types import SimpleNamespace

from src import main
from src.core import config
from src.schemas import SignalCategory
from src.services import analyzer


def test_ml_contribution_signals_use_supported_category(monkeypatch):
    class PredictingModel:
        @staticmethod
        def predict(url):
            assert url == "https://example.com"
            return SimpleNamespace(
                probability=0.4,
                top_contributions=[
                    {"feature": "url_length", "contribution": 0.2, "direction": "risk"}
                ],
                risk_score=40,
                risk_level="Medium",
            )

    monkeypatch.setattr(analyzer, "ML_AVAILABLE", False)
    service = analyzer.AnalyzerService()
    service.ml_model = PredictingModel()

    result = service.analyze(channel="url", urls=["https://example.com"])
    ml_signals = [signal for signal in result.signals if signal["key"].startswith("ml_contrib_")]

    assert ml_signals
    assert all(
        SignalCategory(signal["category"]) is SignalCategory.STRUCTURAL
        for signal in ml_signals
    )


def test_analyzer_uses_rule_based_fallback_when_model_is_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(analyzer, "ML_AVAILABLE", True)
    monkeypatch.setattr(
        config,
        "get_settings",
        lambda: SimpleNamespace(model_path=tmp_path / "missing-model.joblib"),
    )

    service = analyzer.AnalyzerService()

    assert service.get_ml_status() == {
        "available": False,
        "status": "model_not_found",
        "mode": "rule_based_fallback",
        "model_version": None,
    }


def test_analyzer_does_not_expose_invalid_model_details(monkeypatch, tmp_path):
    model_path = tmp_path / "invalid-model.joblib"
    model_path.touch()

    class InvalidModel:
        @staticmethod
        def load(path: Path):
            raise ValueError(f"invalid artifact at {path}")

    monkeypatch.setattr(analyzer, "ML_AVAILABLE", True)
    monkeypatch.setattr(analyzer, "GuardianModel", InvalidModel)
    monkeypatch.setattr(
        config,
        "get_settings",
        lambda: SimpleNamespace(model_path=model_path),
    )

    service = analyzer.AnalyzerService()

    assert service.get_ml_status() == {
        "available": False,
        "status": "model_load_failed",
        "mode": "rule_based_fallback",
        "model_version": None,
    }
    assert str(model_path) not in repr(service.get_ml_status())


def test_health_keeps_api_healthy_and_reports_ml_fallback(monkeypatch):
    class FallbackAnalyzer:
        @staticmethod
        def get_ml_status():
            return {
                "available": False,
                "status": "model_not_found",
                "mode": "rule_based_fallback",
                "model_version": None,
            }

    monkeypatch.setattr(main, "get_analyzer", lambda: FallbackAnalyzer())

    import asyncio

    response = asyncio.run(main.health_check())

    assert response["status"] == "healthy"
    assert response["ml"]["mode"] == "rule_based_fallback"
