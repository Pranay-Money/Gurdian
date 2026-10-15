# Guardian ML Model Card

## Model Details
- **Model Name**: Guardian Phishing/URL Classifier
- **Version**: ddb54ba61f2265cb
- **Date**: 2026-10-15T06:11:53.930032
- **Type**: Binary classifier (malicious vs benign URLs)
- **Architecture**: LightGBM (primary) + Logistic Regression (baseline) with isotonic calibration
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
- Total features: 8029
- Lexical: 29
- Char n-grams: 5000
- Host tokens: 3000

## Exported Package Contents
- model.joblib: Both models + feature engineer + metadata
- feature_schema.json: Feature extraction specification
- version.txt: Model version hash

## Calibration
- Method: isotonic
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

This model was trained on real-world data from OpenPhish, PhishTank, URLhaus, and Tranco.
