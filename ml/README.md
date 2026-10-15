# Guardian ML

Guardian ML is a phishing and malicious URL detection project designed to classify URLs as benign or malicious using a combination of handcrafted URL features and machine learning models.

This project contains both a lightweight direct model implementation and a more advanced end-to-end ML pipeline. It is intended for security use cases such as browser extension checks, API-based URL scanning, and phishing detection automation.

---

## 1. Project overview

The project answers a practical security question:

"Given a URL, is it likely malicious and why?"

To do that, it:

- fetches URL datasets from malicious and benign sources
- deduplicates and splits data safely
- extracts numeric features from the URL structure
- trains classifiers such as Logistic Regression and LightGBM
- evaluates the model on held-out data
- explains risky signals in the prediction output
- exports the trained model package for downstream use

The code is organized into two main layers:

1. Direct model layer
   - simple, readable, easy to run
   - implemented in src/guardian_ml/model.py

2. Full pipeline layer
   - modular training and evaluation flow
   - implemented in src/guardian_ml/components and src/guardian_ml/pipeline.py

---

## 2. Repository structure

```text
ml/
├── DATA.md
├── MODEL_CARD.md
├── pyproject.toml
├── README.md
├── data/
├── models/
├── ml/
│   ├── data/
│   ├── logs/
│   ├── models/
│   └── evaluation/
├── notebooks/
├── src/
│   └── guardian_ml/
│       ├── __init__.py
│       ├── exception.py
│       ├── features.py
│       ├── logger.py
│       ├── model.py
│       ├── pipeline.py
│       ├── train.py
│       ├── inference.py
│       ├── cli/
│       │   ├── __init__.py
│       │   └── train.py
│       └── components/
│           ├── __init__.py
│           ├── data_ingestion.py
│           ├── feature_engineering.py
│           ├── model_training.py
│           ├── evaluation.py
│           ├── model_evaluator.py
│           ├── model_exporter.py
├── tests/
│   ├── test_data_ingestion.py
│   ├── test_evaluation.py
│   ├── test_feature_engineering.py
│   ├── test_features.py
│   ├── test_model_training.py
│   ├── test_pipeline.py
│   └── conftest.py
```

---

## 3. High-level system flow

The full working pipeline is:

1. Ingest malicious and benign URLs
2. Deduplicate data
3. Split into train/test sets
4. Extract numeric features
5. Train models
6. Evaluate model performance
7. Export trained model package
8. Run inference on new URLs

This is implemented across several files, but the important flow is centered around:

- src/guardian_ml/features.py
- src/guardian_ml/model.py
- src/guardian_ml/components/data_ingestion.py
- src/guardian_ml/components/feature_engineering.py
- src/guardian_ml/components/model_training.py
- src/guardian_ml/components/evaluation.py
- src/guardian_ml/pipeline.py

---

## 4. Module-by-module explanation

## 4.1 src/guardian_ml/features.py

This file is the foundation of the classifier. It turns a raw URL string into a structured numeric representation.

### Purpose

The system needs a fixed feature vector for a machine learning model. This file creates that representation.

### Key pieces

#### URLFeatures dataclass

This dataclass stores all extracted URL attributes, including:

- url_length
- hostname_length
- path_length
- query_length
- number of dots, hyphens, underscores, slashes
- question marks, equals, ampersands, @ symbols
- digit and letter counts
- has_ip
- has_port
- is_https
- subdomain_count
- tld_length
- domain_length
- suspicious_tld
- url_shortener
- suspicious_keywords
- brand_in_subdomain
- brand_in_path
- entropy
- path_depth
- has_redirect_param
- punycode

These features help detect URL patterns commonly found in phishing or malware domains.

### Feature lists used as heuristics

The file defines:

- SUSPICIOUS_TLDS = common abusive TLDs like .tk, .ml, .ga, .cf, .xyz, .club, etc.
- URL_SHORTENERS = known shortener domains like bit.ly, tinyurl.com, t.co, goo.gl
- SUSPICIOUS_KEYWORDS = high-risk terms like login, verify, account, secure, urgent, password, prize, crypto, update, bank
- MAJOR_BRANDS = common brands used in brand impersonation checks like google, apple, paypal, microsoft, amazon, netflix, github, slack, etc.

These are used to flag risky URL structures and brand impersonation attempts.

### Functions

#### calculate_entropy(s)

Computes Shannon entropy for a given string. High entropy often indicates random-looking text, which can occur in suspicious domains and obfuscation attempts.

#### extract_features(url)

This is the main feature extraction function. It performs the following:

- parse the URL using urlparse
- extract domain/subdomain/TLD using tldextract
- detect IP addresses in hostnames
- detect port use
- check if the scheme is HTTPS
- count subdomains
- detect suspicious TLDs
- detect known URL shorteners
- look for suspicious keyword matches in the URL text
- look for major brands in the subdomain or path
- detect punycode domains using xn--
- detect redirect parameters in the query string
- calculate hostname entropy
- compute path depth

This function creates a URLFeatures instance from a raw URL.

#### features_to_array(features)

Converts the dataclass into a flat numeric list. This list is fed into the model.

#### get_feature_names()

Returns the ordered list of feature names. The order must match features_to_array() so that the ML model sees consistent feature vectors.

---

## 4.2 src/guardian_ml/model.py

This is the lightweight direct model implementation. It is easier to understand than the full pipeline and is useful for single-model training and inference.

### Data classes

#### ModelConfig

Defines hyperparameters for LightGBM:

- n_estimators
- learning_rate
- max_depth
- num_leaves
- min_child_samples
- subsample
- colsample_bytree
- reg_alpha
- reg_lambda
- random_state
- n_jobs
- verbose

#### PredictionResult

Stores the final output of a prediction:

- is_malicious
- confidence
- risk_score
- risk_level
- signals
- feature_importance

### GuardianModel

#### __init__

Initializes:

- the model config
- model object
- scaler
- feature names
- trained state flag

#### train(urls, labels, val_split, early_stopping_rounds)

This is the training method for the direct model. It:

1. Converts URL strings to feature vectors
2. Creates X and y arrays
3. Performs train/validation split
4. Fits the StandardScaler on the training set
5. Trains an LGBMClassifier
6. Uses early stopping and evaluation on the validation set
7. Computes accuracy and ROC AUC
8. Returns metrics including the classification report

#### predict(url)

This is the main inference function.

It:

1. checks that the model has been trained
2. extracts features for the passed URL
3. scales the features
4. calls predict_proba to get the probability of maliciousness
5. threshold-checks at 0.5
6. computes confidence and risk score
7. assigns a risk level: Low / Medium / High / Critical
8. builds risk signals via _generate_signals
9. extracts top feature importances
10. returns a PredictionResult object

#### _generate_signals(features, proba)

Creates a list of explainable signals. For example:

- IP address in hostname
- suspicious TLD
- URL shortener
- suspicious keywords
- redirect parameter
- punycode domain
- excessive subdomains
- long URL
- no HTTPS
- brand in path/subdomain

These make model output easier to interpret in a security tool.

#### save(path)

Serializes the trained model using joblib and stores:

- model
- scaler
- feature_names
- config

#### load(path)

Restores a saved trained model.

#### predict_batch(urls)

Runs prediction on a whole list of URLs.

---

## 4.3 src/guardian_ml/components/data_ingestion.py

This file handles data collection and dataset preparation.

### DataIngestionConfig

Stores directory paths and source URLs.

### DataIngestion

This class fetches URL data from public feeds and prepares a clean dataset.

#### _get_registrable_domain(url)

Extracts the registrable domain such as example.com.

#### _fetch_openphish()

Fetches malicious URLs from OpenPhish and sets label = 1.

#### _fetch_phishtank()

Fetches and filters verified online phishing URLs from PhishTank.

#### _fetch_urlhaus()

Fetches and filters active malicious URLs from URLhaus.

#### _fetch_tranco(limit)

Downloads the Tranco top domain list and converts those domains into benign URLs like https://example.com.

#### _crawl_benign_paths(domains, max_paths_per_domain)

Generates common benign URL paths for some domains, useful as additional benign examples.

#### fetch_all(include_crawled, tranco_limit)

Combines all fetched records and returns them with source metadata.

#### create_snapshot(records, source_counts)

Creates a timestamped snapshot folder containing:

- urls.jsonl
- metadata.json

The metadata includes source counts and a SHA256 hash for reproducibility.

#### load_latest_snapshot()

Loads the most recent snapshot for reuse or inspection.

#### split_by_domain(records, test_ratio, seed)

This is important for realistic evaluation. It keeps all URLs from the same domain either in train or test to prevent leakage.

#### split_by_time(records, test_ratio)

Creates an alternate chronological split for time-based evaluation.

#### run(create_snapshot, include_crawled)

Runs the ingestion process end-to-end and returns training/test records plus metadata.

---

## 4.4 src/guardian_ml/components/feature_engineering.py

This file builds the full feature matrix for the pipeline model.

### FeatureConfig

Controls which feature groups are active:

- lexical features
- char n-gram TF-IDF features
- host token TF-IDF features
- shortcut detection settings

### FeatureEngineer

This class manages fit/transform logic across multiple feature groups.

#### _extract_host_tokens(url)

Extracts hostname tokens to help TF-IDF capture suspicious host naming patterns.

#### _extract_url_text(url)

Creates the lowercase URL string used for character n-gram analysis.

#### fit(urls, labels)

Fits the three feature groups:

- lexical scaler
- char vectorizer
- host tokenizer vectorizer

It can also run shortcut detection to identify suspiciously easy-to-separate feature groups.

#### transform(urls)

Converts URL strings to a combined sparse feature matrix containing:

- lexical numeric features
- char n-gram TF-IDF values
- host-token TF-IDF values

#### fit_transform(urls, labels)

Fits the feature engineer and transforms the dataset in one step.

#### get_feature_names()

Returns the full ordered feature list for all enabled groups.

#### save(path)

Saves trained feature transformers and metadata.

#### load(path)

Reloads the fitted feature engineering configuration.

---

## 4.5 src/guardian_ml/components/model_training.py

This module trains the full pipeline models and handles calibration.

### CalibratedLGBM

A wrapper class that combines a LightGBM model with isotonic calibration. This helps convert raw model probabilities into more stable probability estimates.

### ModelConfig

Contains configuration for:

- Logistic Regression
- LightGBM
- calibration tuning
- validation split
- model directory

### GuardianTrainer

This class performs the model training workflow.

#### train_logistic_regression(X_train, y_train, X_val, y_val)

Trains a Logistic Regression model with calibration.

#### train_lightgbm(X_train, y_train, X_val, y_val)

Trains the main LightGBM model with early stopping and calibration.

#### train(X, y, feature_names, use_domain_split, domain_labels)

This is the central training method. It:

- creates a train/validation split
- optionally uses domain-disjoint validation
- trains both models
- stores the trained models and feature names
- computes a version hash for the model

#### evaluate(X_test, y_test, tlds)

Evaluates both the Logistic Regression and LightGBM model on test data.

It computes:

- accuracy
- precision
- recall
- F1
- ROC-AUC
- PR-AUC
- FPR at 1% and 0.1% TPR
- confusion matrix
- classification report
- per-TLD metrics

#### _fpr_at_tpr(...)

Computes the false positive rate at a selected target recall threshold. This metric is important in phishing detection because false positives can block legitimate traffic, while false negatives can let phishing through.

#### _compute_per_tld_metrics(...)

Breaks performance down by TLD so the team can identify weak or risky domain groups.

#### get_feature_importance(top_k)

Returns the top contribution features by model importance.

#### save(path, feature_schema)

Saves the model package and schema to a directory.

#### load(path)

Loads a trained trainer package back from disk.

---

## 4.6 src/guardian_ml/components/evaluation.py

This module performs the final quality assessment for the trained models.

### EvaluationConfig

Controls output directories and whether to save plots or prediction files.

### EvaluationResults

Stores result objects for a model:

- core metrics
- confusion matrix
- classification report
- calibration data
- ECE
- TLD metrics
- confidence intervals

### ModelEvaluator

This class generates a deeper evaluation result including:

- standard metrics
- class imbalance-sensitive metrics
- calibration analysis
- confidence intervals
- per-TLD performance
- optional saved predictions and plots

#### evaluate(...)

Runs the evaluation flow on the provided test set.

#### _compute_core_metrics(...)

Calculates the standard classification metrics.

#### _compute_per_tld_metrics(...)

Breaks down performance by TLD.

#### _compute_calibration(...)

Measures how trustworthy the model probabilities are.

#### _bootstrap_confidence_intervals(...)

Estimates variance and confidence intervals for key metrics.

---

## 4.7 src/guardian_ml/pipeline.py

This is the orchestration layer for the complete model-building process.

### PipelineConfig

Stores the configuration for all steps:

- data ingestion
- feature engineering
- model training
- evaluation
- export
- snapshot creation
- random seed

### GuardianPipeline

This pipeline orchestrates the entire workflow.

#### ingest_data()

Runs ingestion and stores records for training and testing.

#### prepare_features(records)

Constructs feature matrices and fits the feature engineer on the training subset.

#### train_models()

Trains the model stack.

#### evaluate(on_test)

Runs evaluation on a held-out test set.

#### export_model()

Exports a model package for deployment.

#### run()

Executes the full pipeline:

1. ingest data
2. prepare features
3. train models
4. evaluate models
5. export package
6. save summary JSON

This is the main end-to-end process for training a new production model version.

---

## 4.8 src/guardian_ml/train.py

This is a CLI script for direct model training.

### What it does

- loads a dataset from JSONL or CSV, or generates synthetic data
- trains GuardianModel
- prints accuracy and AUC
- saves the trained model to disk

It is a simpler, direct path than the full component pipeline.

---

## 4.9 src/guardian_ml/inference.py

This is the CLI script for predictions.

### What it does

- loads a trained model
- receives URLs from CLI arguments or a JSON/JSONL file
- runs model.predict_batch on all URLs
- prints human-readable output or saves JSON results

This is the most direct way to use the model after training.

---

## 4.10 src/guardian_ml/exception.py

This file defines the custom exceptions used across the system.

Examples:

- MLPipelineException
- DataIngestionException
- FeatureEngineeringException
- ModelTrainingException
- ModelEvaluationException
- ModelExportException
- ConfigurationException

These make debugging easier and help isolate training, evaluation, and export failures.

---

## 4.11 src/guardian_ml/logger.py

This file sets up logging for the project.

It:

- creates log files under ml/logs
- logs events at INFO level
- also writes to the console

This is used throughout ingestion, training, and model export.

---

## 5. End-to-end working flow in plain English

Here is the real project flow in simple terms:

1. The system gathers URLs from multiple sources.
   - malicious URLs are collected from phishing feeds
   - benign URLs are collected from reputable domain lists

2. The data is cleaned and deduplicated.
   - duplicate URLs are removed
   - domains are grouped to avoid train/test leakage

3. Each URL is converted into a feature vector.
   - letters, digits, dots, query parameters, suspicious keywords, subdomains, etc.

4. The model learns from these features.
   - a baseline Logistic Regression model is trained
   - a stronger LightGBM model is trained

5. The model is evaluated on held-out data.
   - AUC and accuracy are measured
   - FPR at strict recall thresholds is measured
   - the model is checked for calibration quality

6. A new URL is scored.
   - features extracted
   - probability generated
   - result classified as malicious or benign
   - risk score and reasons are returned

7. The trained model is exported.
   - ready for API or extension use

---

## 6. Example usage

### Install project dependencies

```bash
cd ml
pip install -e ".[training]"
```

### Run tests

```bash
cd ml
python -m pytest -q
```

### Train from labeled local data

Install the ML package from the `ml` directory, then train from a CSV or JSONL file:

```bash
cd ml
python -m pip install -e ".[training]"
python -m guardian_ml.cli.train data --data data/urls.csv
```

The `training` extra installs plotting support used by model evaluation.
Runtime inference does not import the evaluation or plotting modules.

The input must contain `url` and `label` fields. Labels are binary (`0` for benign,
`1` for malicious); URLs must be absolute HTTP(S) URLs. Duplicate URLs with
conflicting labels, missing values, and datasets that cannot produce a
domain-disjoint train/test split are rejected. CSV files need a header row;
JSONL files need one JSON object per line, for example:

```json
{"url":"https://www.example.com/","label":0}
{"url":"https://suspicious-example.net/login","label":1}
```

Provide real, appropriately licensed labeled data with enough distinct
registrable domains for both classes. The command validates and evaluates a
held-out domain split before export. It does not download or fabricate training
data. A successful export is written to the canonical `api/models/model.joblib`
path by default; use `--model-dir` to specify another output directory.

Synthetic training is available only for development/CI smoke checks and
requires an explicit override:

```bash
python -m guardian_ml.cli.train synthetic --samples 200 --allow-synthetic
```

Synthetic artifacts are marked in their metadata and are rejected by API model
loading. The command writes to `ml/models/development-synthetic/` by default,
not the API's canonical model directory. Never use synthetic artifacts as
production models.

The feed-based pipeline also downloads external data, but only when explicitly
requested:

```bash
python -m guardian_ml.cli.train pipeline --download-feeds
```

Review the configured sources, their terms, and data-handling implications
before running this command.

### Inference on one or more URLs

```bash
cd ml
python src/guardian_ml/inference.py --model models/guardian_model.joblib --urls "https://example.com/login" "http://evil.tk/verify"
```

### Inference from a file

```bash
cd ml
python src/guardian_ml/inference.py --model models/guardian_model.joblib --input data/sample_urls.jsonl --output results.json
```

### Run the full pipeline

```bash
cd ml
python -m guardian_ml.pipeline
```

The legacy full-pipeline command above may download configured data sources.
For reproducible local training without network fetching, use the labeled-data
CLI described above.

---

## 7. What the project does well

- clearly separates data gathering, feature engineering, model training, and evaluation
- includes explainable signals for malicious decisions
- supports both lightweight and full-pipeline workflows
- uses security-relevant evaluation metrics
- logs training and evaluation steps
- creates dataset snapshots for reproducibility

---

## 8. Current limitations and caveats

This is a strong prototype, but it is not fully production-grade yet.

- There are two overlapping architectures: the direct model and the full pipeline.
- Some import paths are inconsistent between guardian_ml.* and src.* usage.
- Some parts are more ambitious than the code actually wires together in a single canonical runtime.
- Some calibration logic and signals are partially implemented and may need cleanup.
- The project assumes a particular directory structure and working directory layout.

This means the code is usable and understandable, but a clean final deployment would benefit from unifying the architecture and tightening the build/runtime paths.

---

## 9. Summary

Guardian ML is a well-structured malicious URL classification project built around:

- URL feature extraction
- dataset ingestion and deduplication
- domain-aware train/test splitting
- feature engineering with lexical and TF-IDF signals
- Logistic Regression and LightGBM training
- evaluation with security-sensitive metrics
- explainable malicious signals
- model export for downstream use

It is a serious prototype and a good foundation for a security-focused URL detection system. With a little cleanup around architecture and runtime consistency, it can become a more polished real-world product.

---

## 10. Notes for contributors

If you are continuing work on this project, the most important files to focus on are:

- src/guardian_ml/features.py
- src/guardian_ml/model.py
- src/guardian_ml/components/feature_engineering.py
- src/guardian_ml/components/model_training.py
- src/guardian_ml/pipeline.py

These files define the actual model behavior and are the primary areas for feature updates, training improvements, and production hardening.
