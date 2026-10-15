"""Guardian ML inference API with lazily loaded training components."""

from importlib import import_module
from typing import Any

from .exception import (
    ConfigurationException,
    DataIngestionException,
    FeatureEngineeringException,
    MLPipelineException,
    ModelEvaluationException,
    ModelExportException,
    ModelTrainingException,
)
from .features import URLFeatures, extract_features, features_to_array, get_feature_names
from .logger import logger
from .model import GuardianModel, PredictionResult

_LAZY_EXPORTS = {
    "DataIngestion": (".components.data_ingestion", "DataIngestion"),
    "DataIngestionConfig": (".components.data_ingestion", "DataIngestionConfig"),
    "FeatureEngineer": (".components.feature_engineering", "FeatureEngineer"),
    "FeatureConfig": (".components.feature_engineering", "FeatureConfig"),
    "create_feature_schema": (".components.feature_engineering", "create_feature_schema"),
    "GuardianTrainer": (".components.model_training", "GuardianTrainer"),
    "TrainingModelConfig": (".components.model_training", "ModelConfig"),
    "ModelEvaluator": (".components.evaluation", "ModelEvaluator"),
    "EvaluationConfig": (".components.evaluation", "EvaluationConfig"),
    "EvaluationResults": (".components.evaluation", "EvaluationResults"),
    "print_evaluation_summary": (
        ".components.evaluation",
        "print_evaluation_summary",
    ),
    "ModelExporter": (".components.model_exporter", "ModelExporter"),
    "ExportConfig": (".components.model_exporter", "ExportConfig"),
    "export_for_api": (".components.model_exporter", "export_for_api"),
    "GuardianPipeline": (".pipeline", "GuardianPipeline"),
    "PipelineConfig": (".pipeline", "PipelineConfig"),
    "run_training_pipeline": (".pipeline", "run_training_pipeline"),
    "run_evaluation_only": (".pipeline", "run_evaluation_only"),
}

__all__ = [
    "URLFeatures",
    "extract_features",
    "features_to_array",
    "get_feature_names",
    "GuardianModel",
    "PredictionResult",
    "MLPipelineException",
    "DataIngestionException",
    "FeatureEngineeringException",
    "ModelTrainingException",
    "ModelEvaluationException",
    "ModelExportException",
    "ConfigurationException",
    "logger",
    *_LAZY_EXPORTS,
]

__version__ = "0.1.0"


def __getattr__(name: str) -> Any:
    """Load training and evaluation interfaces only when they are requested."""
    try:
        module_name, attribute_name = _LAZY_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    value = getattr(import_module(module_name, __name__), attribute_name)
    globals()[name] = value
    return value
