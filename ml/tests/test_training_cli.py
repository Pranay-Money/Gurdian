import json
import sys
from pathlib import Path

import joblib
import pytest

from guardian_ml.cli import train as train_cli
from guardian_ml.cli.train import (
    generate_synthetic_records,
    load_labeled_records,
    split_records_by_domain,
    train_records,
)
from guardian_ml.components.data_ingestion import DataIngestion
from guardian_ml.model import GuardianModel
from guardian_ml.paths import get_api_models_dir, get_model_dir


def test_load_labeled_records_accepts_csv_and_jsonl(tmp_path):
    csv_path = tmp_path / "urls.csv"
    csv_path.write_text(
        "url,label\nhttps://benign-one.com/,0\nhttp://malicious-one.xyz/login,1\n",
        encoding="utf-8",
    )
    jsonl_path = tmp_path / "urls.jsonl"
    jsonl_path.write_text(
        "\n".join(
            [
                json.dumps({"url": "https://benign-one.com/", "label": 0}),
                json.dumps({"url": "http://malicious-one.xyz/login", "label": 1}),
            ]
        ),
        encoding="utf-8",
    )

    assert load_labeled_records(csv_path) == load_labeled_records(jsonl_path)


def test_load_labeled_records_rejects_conflicting_duplicate_labels(tmp_path):
    path = tmp_path / "urls.jsonl"
    path.write_text(
        '{"url":"https://same-domain.com/","label":0}\n'
        '{"url":"https://same-domain.com/","label":1}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="conflicting labels"):
        load_labeled_records(path)


def test_domain_split_keeps_registrable_domains_disjoint():
    records = generate_synthetic_records(40)

    train, test = split_records_by_domain(records)
    ingestion = DataIngestion()
    train_domains = {ingestion._get_registrable_domain(row["url"]) for row in train}
    test_domains = {ingestion._get_registrable_domain(row["url"]) for row in test}

    assert train_domains.isdisjoint(test_domains)
    assert {row["label"] for row in train} == {0, 1}
    assert {row["label"] for row in test} == {0, 1}


def test_synthetic_model_export_requires_explicit_override(tmp_path):
    with pytest.raises(ValueError, match="explicit --allow-synthetic"):
        train_records(
            generate_synthetic_records(40),
            tmp_path,
            synthetic=True,
        )


def test_model_loader_rejects_incompatible_artifact(tmp_path):
    model_path = tmp_path / "incompatible.joblib"
    joblib.dump({"lgb_model": object()}, model_path)

    with pytest.raises(ValueError, match="missing required key"):
        GuardianModel.load(model_path)


def test_synthetic_cli_defaults_to_separate_development_directory(monkeypatch):
    captured = {}

    def capture_training(records, model_dir, **kwargs):
        assert records
        assert kwargs["synthetic"]
        captured["model_dir"] = model_dir

    monkeypatch.setattr(train_cli, "train_records", capture_training)
    monkeypatch.setattr(
        sys,
        "argv",
        ["guardian_ml_train", "synthetic", "--allow-synthetic"],
    )

    train_cli.main()

    assert captured["model_dir"] == get_model_dir() / "development-synthetic"
    assert captured["model_dir"] != get_api_models_dir()


def test_canonical_model_directory_is_api_models(monkeypatch):
    monkeypatch.delenv("GUARDIAN_HOME", raising=False)
    expected_repo_root = Path(__file__).resolve().parents[2]

    assert get_api_models_dir() == expected_repo_root / "api" / "models"
