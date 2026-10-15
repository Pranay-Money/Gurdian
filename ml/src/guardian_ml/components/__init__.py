"""ML components, imported on demand to keep inference imports lightweight."""

from importlib import import_module
from typing import Any

_LAZY_EXPORTS = {
    "DataIngestion": (".data_ingestion", "DataIngestion"),
    "DataIngestionConfig": (".data_ingestion", "DataIngestionConfig"),
    "FeatureEngineer": (".feature_engineering", "FeatureEngineer"),
    "FeatureConfig": (".feature_engineering", "FeatureConfig"),
    "create_feature_schema": (".feature_engineering", "create_feature_schema"),
    "GuardianTrainer": (".model_training", "GuardianTrainer"),
    "ModelConfig": (".model_training", "ModelConfig"),
    "ModelEvaluator": (".evaluation", "ModelEvaluator"),
    "EvaluationConfig": (".evaluation", "EvaluationConfig"),
    "EvaluationResults": (".evaluation", "EvaluationResults"),
    "print_evaluation_summary": (
        ".evaluation",
        "print_evaluation_summary",
    ),
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    """Import the component module only when one of its exports is requested."""
    try:
        module_name, attribute_name = _LAZY_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    value = getattr(import_module(module_name, __name__), attribute_name)
    globals()[name] = value
    return value
