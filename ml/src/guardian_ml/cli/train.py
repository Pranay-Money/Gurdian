"""Train and export Guardian URL models from labeled local data."""

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from guardian_ml.components.data_ingestion import DataIngestion
from guardian_ml.components.evaluation import EvaluationConfig, ModelEvaluator
from guardian_ml.components.feature_engineering import FeatureConfig, FeatureEngineer
from guardian_ml.components.model_exporter import ExportConfig, ModelExporter
from guardian_ml.components.model_training import GuardianTrainer, ModelConfig
from guardian_ml.paths import get_api_models_dir, get_model_dir
from guardian_ml.pipeline import PipelineConfig, run_training_pipeline


def load_labeled_records(data_path: Path) -> list[dict[str, Any]]:
    """Read and validate CSV/JSONL records containing URL and binary label fields."""
    path = Path(data_path)
    if path.suffix.lower() == ".csv":
        frame = pd.read_csv(path, dtype=object)
        records = frame.to_dict(orient="records")
    elif path.suffix.lower() == ".jsonl":
        records = []
        with path.open("r", encoding="utf-8") as data_file:
            for line_number, line in enumerate(data_file, start=1):
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid JSON on line {line_number}") from exc
    else:
        raise ValueError("Training data must be a .csv or .jsonl file")

    if not records:
        raise ValueError("Training data contains no records")

    deduplicated: dict[str, dict[str, Any]] = {}
    for row_number, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"Record {row_number} must be an object")
        url_value = record.get("url")
        label_value = record.get("label")
        if not isinstance(url_value, str) or not url_value.strip():
            raise ValueError(f"Record {row_number} has a missing URL")
        url = url_value.strip()
        parsed_url = urlsplit(url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
            raise ValueError(f"Record {row_number} URL must be an absolute HTTP(S) URL")
        if label_value is None or pd.isna(label_value) or isinstance(label_value, bool):
            raise ValueError(f"Record {row_number} has a missing or invalid label")
        try:
            label = int(label_value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Record {row_number} label must be 0 or 1") from exc
        if label not in (0, 1) or str(label_value).strip() not in (str(label), f"{label}.0"):
            raise ValueError(f"Record {row_number} label must be 0 or 1")

        previous = deduplicated.get(url)
        if previous is not None and previous["label"] != label:
            raise ValueError(f"Duplicate URL has conflicting labels at record {row_number}")
        deduplicated.setdefault(url, {"url": url, "label": label})

    validated = list(deduplicated.values())
    labels = {record["label"] for record in validated}
    if labels != {0, 1}:
        raise ValueError("Training data must contain both benign (0) and malicious (1) labels")
    return validated


def split_records_by_domain(
    records: list[dict[str, Any]],
    test_size: float = 0.2,
    random_state: int = 42,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Create a domain-disjoint holdout with both classes represented in each split."""
    if not 0 < test_size < 1:
        raise ValueError("test_size must be between 0 and 1")

    ingestion = DataIngestion()
    domains = np.asarray(
        [ingestion._get_registrable_domain(row["url"]) for row in records]
    )
    if np.any(domains == ""):
        raise ValueError("Every training URL must have a registrable domain")
    if len(np.unique(domains)) < 5:
        raise ValueError(
            "At least five distinct registrable domains are required for a domain-disjoint split"
        )

    labels = np.asarray([row["label"] for row in records])
    splitter = GroupShuffleSplit(n_splits=100, test_size=test_size, random_state=random_state)
    for train_indices, test_indices in splitter.split(
        np.zeros(len(records)), labels, groups=domains
    ):
        if set(labels[train_indices]) == {0, 1} and set(labels[test_indices]) == {0, 1}:
            train_domains = set(domains[train_indices])
            test_domains = set(domains[test_indices])
            if train_domains.isdisjoint(test_domains):
                return (
                    [records[index] for index in train_indices],
                    [records[index] for index in test_indices],
                )
    raise ValueError("Unable to create a domain-disjoint train/test split containing both classes")


def train_records(
    records: list[dict[str, Any]],
    model_dir: Path,
    *,
    n_estimators: int = 500,
    learning_rate: float = 0.05,
    max_features: int = 5000,
    synthetic: bool = False,
    allow_synthetic: bool = False,
) -> dict[str, Any]:
    """Fit on training domains, evaluate held-out domains, and export the API package."""
    if synthetic and not allow_synthetic:
        raise ValueError("Synthetic model export requires the explicit --allow-synthetic override")

    train_records, test_records = split_records_by_domain(records)
    train_urls = [row["url"] for row in train_records]
    train_labels = np.asarray([row["label"] for row in train_records])
    test_urls = [row["url"] for row in test_records]
    test_labels = np.asarray([row["label"] for row in test_records])
    ingestion = DataIngestion()
    domain_labels = np.asarray([
        ingestion._get_registrable_domain(row["url"]) for row in train_records
    ])

    engineer = FeatureEngineer(FeatureConfig(
        char_ngram_max_features=max_features,
        run_shortcut_check=True,
    ))
    train_matrix = engineer.fit_transform(train_urls, train_labels.tolist())
    test_matrix = engineer.transform(test_urls)

    trainer = GuardianTrainer(ModelConfig(
        lgb_n_estimators=n_estimators,
        lgb_learning_rate=learning_rate,
        val_split=0.15,
    ))
    trainer.train(
        train_matrix,
        train_labels,
        engineer.get_feature_names(),
        domain_labels=domain_labels,
        split_method="domain",
    )

    evaluator = ModelEvaluator(EvaluationConfig(save_plots=False))
    results = evaluator.compare_models(
        {"logistic_regression": trainer.lr_model, "lightgbm": trainer.lgb_model},
        test_matrix,
        test_labels,
    )
    for model_name, metrics in results.items():
        print(  # noqa: T201 - CLI metric output
            f"{model_name}: ROC-AUC={metrics.roc_auc:.4f}, "
            f"PR-AUC={metrics.pr_auc:.4f}, F1={metrics.f1:.4f}"
        )

    export_config = {
        "synthetic": synthetic,
        "input_format": "labeled_url_records",
        "split_method": "registrable_domain",
        "lr": {"C": trainer.config.lr_C, "max_iter": trainer.config.lr_max_iter},
        "lgb": {
            "n_estimators": trainer.config.lgb_n_estimators,
            "learning_rate": trainer.config.lgb_learning_rate,
        },
        "calibration": {
            "method": trainer.config.calibration_method,
            "cv": trainer.config.calibration_cv,
        },
    }
    exporter = ModelExporter(ExportConfig(
        api_models_dir=model_dir,
        allow_synthetic=allow_synthetic,
    ))
    export_info = exporter.export(
        trainer,
        engineer,
        engineer.get_feature_names(),
        export_config,
    )
    print(f"Exported model: {export_info['model_path']}")  # noqa: T201 - CLI status output
    if synthetic:
        print("WARNING: This synthetic-data model is for development/CI only.")  # noqa: T201
    return {"export": export_info, "metrics": results}


def generate_synthetic_records(sample_count: int) -> list[dict[str, Any]]:
    """Generate a small synthetic set solely for explicit development/CI smoke tests."""
    if sample_count < 20 or sample_count % 2:
        raise ValueError("Synthetic sample count must be an even number of at least 20")
    words = ["account", "verify", "support", "secure", "portal", "update", "billing", "service"]
    records = []
    for index in range(sample_count // 2):
        records.append({"url": f"https://benign-{index}.com/home", "label": 0})
        records.append({"url": f"http://{words[index % len(words)]}-{index}.xyz/login", "label": 1})
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description="Guardian ML training and model export")
    commands = parser.add_subparsers(dest="command", required=True)

    data_parser = commands.add_parser(
        "data",
        help="Train from labeled local CSV or JSONL data",
    )
    data_parser.add_argument(
        "--data",
        type=Path,
        required=True,
        help="CSV/JSONL with url,label fields",
    )
    data_parser.add_argument("--model-dir", type=Path, default=get_api_models_dir())
    data_parser.add_argument("--n-estimators", type=int, default=500)
    data_parser.add_argument("--learning-rate", type=float, default=0.05)
    data_parser.add_argument("--max-features", type=int, default=5000)

    synthetic_parser = commands.add_parser("synthetic", help="Development/CI smoke model only")
    synthetic_parser.add_argument("--samples", type=int, default=200)
    synthetic_parser.add_argument(
        "--model-dir",
        type=Path,
        default=get_model_dir() / "development-synthetic",
    )
    synthetic_parser.add_argument("--n-estimators", type=int, default=20)
    synthetic_parser.add_argument("--learning-rate", type=float, default=0.05)
    synthetic_parser.add_argument("--max-features", type=int, default=500)
    synthetic_parser.add_argument("--allow-synthetic", action="store_true")

    pipeline_parser = commands.add_parser(
        "pipeline",
        help="Explicitly download documented feed sources and train",
    )
    pipeline_parser.add_argument("--download-feeds", action="store_true", required=True)
    pipeline_parser.add_argument("--model-dir", type=Path, default=get_api_models_dir())
    pipeline_parser.add_argument("--tranco-limit", type=int, default=100000)
    pipeline_parser.add_argument("--n-estimators", type=int, default=500)
    pipeline_parser.add_argument("--learning-rate", type=float, default=0.05)
    pipeline_parser.add_argument("--allow-synthetic", action="store_true")

    args = parser.parse_args()
    if args.command == "data":
        records = load_labeled_records(args.data)
        train_records(
            records,
            args.model_dir,
            n_estimators=args.n_estimators,
            learning_rate=args.learning_rate,
            max_features=args.max_features,
        )
    elif args.command == "synthetic":
        if not args.allow_synthetic:
            parser.error(
                "synthetic export requires --allow-synthetic and is for development/CI only"
            )
        train_records(
            generate_synthetic_records(args.samples),
            args.model_dir,
            n_estimators=args.n_estimators,
            learning_rate=args.learning_rate,
            max_features=args.max_features,
            synthetic=True,
            allow_synthetic=True,
        )
    else:
        config = PipelineConfig(
            export_dir=args.model_dir,
            tranco_limit=args.tranco_limit,
            allow_synthetic_export=args.allow_synthetic,
            model_training=ModelConfig(
                lgb_n_estimators=args.n_estimators,
                lgb_learning_rate=args.learning_rate,
            ),
        )
        run_training_pipeline(config)


if __name__ == "__main__":
    main()
