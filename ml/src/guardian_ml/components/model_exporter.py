"""
Model Export Component
Exports model.joblib + feature schema + version hash to api/models/.
Includes both LR and LightGBM models, feature engineer, and version metadata.
"""
import hashlib
import json
import joblib
import numpy as np
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

from guardian_ml.logger import logger
from guardian_ml.exception import ModelExportException, MLPipelineException


@dataclass
class ExportConfig:
    """Configuration for model export."""
    api_models_dir: Path = None
    include_shap: bool = True
    shap_sample_size: int = 1000
    export_format: str = "joblib"
    allow_synthetic: bool = False  # Allow export of synthetic models (CI only)

    def __post_init__(self):
        from guardian_ml.paths import get_api_models_dir
        if self.api_models_dir is None:
            self.api_models_dir = get_api_models_dir()
        elif isinstance(self.api_models_dir, str):
            from guardian_ml.paths import resolve_path
            self.api_models_dir = resolve_path(self.api_models_dir)
        elif not self.api_models_dir.is_absolute():
            from guardian_ml.paths import resolve_path
            self.api_models_dir = resolve_path(self.api_models_dir)
        self.api_models_dir.mkdir(parents=True, exist_ok=True)


class ModelExporter:
    """Exports trained models for API consumption."""

    def __init__(self, config: Optional[ExportConfig] = None):
        self.config = config or ExportConfig()
        self.api_models_dir = self.config.api_models_dir
        # Already a Path from ExportConfig.__post_init__
        self.api_models_dir.mkdir(parents=True, exist_ok=True)

    def compute_version_hash(
        self,
        feature_names: List[str],
        config: Dict[str, Any],
        trainer: Any = None
    ) -> str:
        """Compute deterministic version hash from features + config."""
        content = {
            "feature_names": feature_names,
            "config": config,
        }
        if trainer and hasattr(trainer, 'version_hash'):
            content["trainer_version"] = trainer.version_hash
        content_str = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(content_str.encode()).hexdigest()[:16]

    def export(
        self,
        trainer: Any,
        feature_engineer: Any,
        feature_names: List[str],
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Export model package for API.
        
        Creates:
        - model.joblib: Contains both models + feature engineer + metadata
        - feature_schema.json: Feature extraction specification
        - version.txt: Model version hash
        """
        # Check for synthetic data flag
        is_synthetic = config.get('synthetic', False)
        if is_synthetic and not self.config.allow_synthetic:
            raise ModelExportException(
                "Model trained on synthetic data. Export blocked. "
                "Use --allow-synthetic flag (CI smoke tests only) to override."
            )
        if is_synthetic:
            logger.warning("Exporting SYNTHETIC model - NOT FOR PRODUCTION USE")

        logger.info("Exporting model package...")

        version_hash = self.compute_version_hash(feature_names, config, trainer)

        # Create combined model package
        model_package = {
            "lr_model": trainer.lr_model,
            "lgb_model": trainer.lgb_model,
            "feature_engineer": feature_engineer,
            "feature_names": feature_names,
            "version_hash": version_hash,
            "trainer_version_hash": trainer.version_hash if hasattr(trainer, 'version_hash') else version_hash,
            "metadata": {
                "synthetic": is_synthetic,
                "exported_at": pd.Timestamp.now().isoformat() if PANDAS_AVAILABLE else str(np.datetime64("now")),
            },
        }
        
        model_path = self.api_models_dir / "model.joblib"
        joblib.dump(model_package, model_path)
        logger.info(f"Saved model package to {model_path}")

        # Save feature schema
        feature_schema = {
            "version": version_hash,
            "feature_names": feature_names,
            "feature_count": len(feature_names),
            "lexical_features": [f for f in feature_names if not f.startswith("char_") and not f.startswith("host_")],
            "char_ngram_features": [f for f in feature_names if f.startswith("char_")],
            "host_token_features": [f for f in feature_names if f.startswith("host_")],
            "config": config,
            "exported_at": pd.Timestamp.now().isoformat() if PANDAS_AVAILABLE else str(np.datetime64("now")),
        }

        schema_path = self.api_models_dir / "feature_schema.json"
        with open(schema_path, "w") as f:
            json.dump(feature_schema, f, indent=2, default=str)
        logger.info(f"Saved feature schema to {schema_path}")

        # Save version
        version_path = self.api_models_dir / "version.txt"
        with open(version_path, "w") as f:
            f.write(version_hash)

        # Save model card with metadata
        self._save_model_card(trainer, feature_engineer, feature_names, version_hash, config)

        export_info = {
            "version_hash": version_hash,
            "model_path": str(model_path),
            "schema_path": str(schema_path),
            "version_path": str(version_path),
            "feature_count": len(feature_names),
            "shap_available": SHAP_AVAILABLE
        }

        logger.info(f"Model export complete: version {version_hash}")
        return export_info

    def _save_model_card(
        self,
        trainer: Any,
        feature_engineer: Any,
        feature_names: List[str],
        version_hash: str,
        config: Dict[str, Any]
    ) -> None:
        """Save model card with metadata."""
        card_path = self.api_models_dir / "MODEL_CARD.md"
        
        # Get training snapshot dates if available
        snapshot_dates = "Unknown"
        if hasattr(trainer, 'config') and hasattr(trainer.config, 'data_ingestion'):
            # Try to get from data ingestion metadata
            pass
        
        # Get calibration method
        calibration_method = config.get('calibration_method', 'isotonic')
        if 'calibration' in config:
            calibration_method = config['calibration'].get('method', 'isotonic')
        
        card_content = f"""# Guardian ML Model Card

## Model Details
- **Model Name**: Guardian Phishing/URL Classifier
- **Version**: {version_hash}
- **Date**: {pd.Timestamp.now().isoformat() if PANDAS_AVAILABLE else 'Unknown'}
- **Type**: Binary classifier (malicious vs benign URLs)
- **Architecture**: LightGBM (primary) + Logistic Regression (baseline) with {calibration_method} calibration
- **Framework**: scikit-learn, LightGBM

## Training Data
See DATA.md for full source catalog.

### Splits Used
- **Domain-disjoint split (80/20, seed=42)**: Primary evaluation split. All URLs from the same registrable domain go to the same split to prevent domain leakage.
- **Time-based split (80/20 by fetch timestamp)**: Secondary evaluation split. Older records → train, newer records → test. Records without timestamps are excluded. Both classes must have dated records for a valid split.

### Handling of Undated Records in Time Split
- Records missing `fetched_at` timestamp are excluded from time-based split
- Both malicious and benign classes must have dated records
- If either class lacks dated records, time-based split raises an error
- This ensures temporal evaluation is not biased by missing data

## Features
- Total features: {len(feature_names)}
- Lexical: {len([f for f in feature_names if not f.startswith('char_') and not f.startswith('host_')])}
- Char n-grams: {len([f for f in feature_names if f.startswith('char_')])}
- Host tokens: {len([f for f in feature_names if f.startswith('host_')])}

## Exported Package Contents
- model.joblib: Both models + feature engineer + metadata
- feature_schema.json: Feature extraction specification
- version.txt: Model version hash

## Calibration
- Method: {calibration_method}
- Applied to: Both LR and LightGBM
- Calibration set: Separate held-out set (never test, never validation used for early stopping)

## API Integration
```python
from guardian_ml import GuardianModel
model = GuardianModel.load("api/models/model.joblib")
result = model.predict("https://example.com")
print(result.probability, result.top_contributions)
```

## Synthetic Data Warning
"""
        if config.get('synthetic', False):
            card_content += """
[WARNING] This model was trained on SYNTHETIC DATA ONLY.
- Not for production use
- Metrics do not reflect real-world performance
- Use only for CI smoke tests and development
"""
        else:
            card_content += """
This model was trained on real-world data from OpenPhish, PhishTank, URLhaus, and Tranco.
"""
        with open(card_path, "w", encoding="utf-8") as f:
            f.write(card_content)
        logger.info(f"Saved model card to {card_path}")

    def load_latest(self) -> Dict[str, Any]:
        """Load latest model package."""
        model_path = self.api_models_dir / "model.joblib"
        
        if not model_path.exists():
            raise ModelExportException("No model found")
        
        package = joblib.load(model_path)
        logger.info(f"Loaded model version {package.get('version_hash', 'unknown')}")
        return package


def export_for_api(
    trainer: Any,
    feature_engineer: Any,
    feature_names: List[str],
    config: Dict[str, Any],
    output_dir: str = "api/models",
    allow_synthetic: bool = False,
) -> Dict[str, Any]:
    """Convenience function to export model for API."""
    exporter = ModelExporter(ExportConfig(api_models_dir=output_dir, allow_synthetic=allow_synthetic))
    return exporter.export(trainer, feature_engineer, feature_names, config)


if __name__ == "__main__":
    print("ModelExporter ready")