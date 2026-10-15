# Guardian ML Model Card

## Model Details
- **Model Name**: Guardian Phishing/URL Classifier
- **Version**: 9be9d155d04de8db (example from synthetic test run)
- **Date**: 2026-10-14 (example from synthetic test run)
- **Type**: Binary classifier (malicious vs benign URLs)
- **Architecture**: LightGBM (primary) + Logistic Regression (baseline) with isotonic calibration
- **Framework**: scikit-learn 1.3+, LightGBM 4.2+
- **License**: MIT (model weights), CC BY 4.0 (data derivatives)

## Intended Use
- **Primary**: Real-time URL classification in browser extension and API
- **Secondary**: Bulk URL scanning for security teams
- **Out of Scope**: 
  - Page content analysis (DOM, scripts, images)
  - Zero-day exploit detection
  - Non-URL threat vectors (file attachments, etc.)

## Training Data
See [DATA.md](DATA.md) for full source catalog.

### Summary
| Source | Type | Count (approx) | License |
|--------|------|----------------|---------|
| OpenPhish | Malicious | 15,000 | Community |
| PhishTank | Malicious | 50,000 | Research |
| URLhaus | Malicious | 60,000 | CC BY 4.0 |
| Tranco | Benign | 100,000 | Research |
| **Total** | | **~225,000** | |

### Preprocessing
- Deduplication by URL and registrable domain
- Domain-disjoint train/test split (80/20, seed=42)
- No query strings or fragments in features (privacy)

### Class Balance
- Training: ~50/50 (balanced via source selection)
- Test: Reflects natural distribution after domain split

## Features

### Feature Groups
1. **Lexical (39 features)**: Hand-crafted structural features
   - URL length, hostname length, path depth
   - Character counts (dots, hyphens, underscores, etc.)
   - IP in hostname, port, HTTPS, subdomain count
   - TLD risk, URL shortener detection
   - Suspicious keywords, brand impersonation signals
   - Entropy, punycode, redirect parameters

2. **Char n-grams (5,000 features)**: TF-IDF on character 3-5 grams
   - Applied to full URL string
   - Sublinear TF scaling

3. **Host tokens (3,000 features)**: TF-IDF on tokenized hostname
   - Tokens from subdomain, domain, TLD
   - Word n-grams (1-2)

### Shortcut Detection
Run at training time to flag features that separate data sources rather than learning general patterns:
- Threshold: AUC > 0.90 on single feature group
- Action: Logged as warning; feature group not automatically removed

## Model Configuration

### LightGBM (Primary)
```yaml
n_estimators: 500
learning_rate: 0.05
max_depth: 8
num_leaves: 63
min_child_samples: 20
subsample: 0.8
colsample_bytree: 0.8
reg_alpha: 0.1
reg_lambda: 0.1
class_weight: balanced
objective: binary
metric: auc
```

### Calibration
- **Method**: Isotonic regression (3-fold CV)
- **Applied to**: Both LR and LightGBM
- **Purpose**: Reliable probability estimates for risk scoring

### Logistic Regression (Baseline)
```yaml
C: 1.0
penalty: l2
solver: lbfgs
max_iter: 1000
class_weight: balanced
```
- Calibrated with same isotonic regression

## Evaluation Results

### Test Set Metrics (Domain-Disjoint Split)
*Metrics computed on held-out domains never seen during training*

| Metric | LightGBM | Logistic Regression |
|--------|----------|---------------------|
| ROC-AUC | 0.5000 | 1.0000 |
| PR-AUC | 0.5000 | 1.0000 |
| Accuracy | 0.5000 | 1.0000 |
| Precision | 0.5000 | 1.0000 |
| Recall | 1.0000 | 1.0000 |
| F1 | 0.6667 | 1.0000 |
| FPR @ 1% TPR | 1.0000 | 0.0000 |
| FPR @ 0.1% TPR | 1.0000 | 0.0000 |
| Brier Score | 0.2500 | 0.0000 |
| ECE | 0.0000 | 0.0000 |

*Note: These metrics are from a synthetic test run with limited data. Production metrics will differ.*

### Test Set Metrics (Time-Based Split)
*Metrics computed on newer data (20% newest by fetch timestamp)*

| Metric | LightGBM | Logistic Regression |
|--------|----------|---------------------|
| ROC-AUC | 0.5000 | 1.0000 |
| PR-AUC | 0.5000 | 1.0000 |
| F1 | 0.6667 | 1.0000 |
| FPR @ 1% TPR | 1.0000 | 0.0000 |
| FPR @ 0.1% TPR | 1.0000 | 0.0000 |
| ECE | 0.0000 | 0.0000 |
| Brier Score | 0.2500 | 0.0000 |

### Per-TLD Analysis
Worst-performing TLDs (by AUC) on test set:
| TLD | Count | Malicious Rate | AUC | Notes |
|-----|-------|----------------|-----|-------|
| tk | 20 | 0.50 | 0.50 | Suspicious TLD |
| ml | 20 | 0.50 | 0.50 | Suspicious TLD |
| com | 40 | 0.00 | 1.00 | Benign dominant |

### Confusion Matrix (LightGBM, threshold=0.5)
```
                Predicted
              Benign  Malicious
Actual Benign    0       40
Actual Malicious 0       40
```

### Calibration Check
Reliability diagram and calibration metrics computed on test set:
- **Method**: Isotonic regression (separate calibration split, never on test)
- **ECE (Expected Calibration Error)**: 0.0000 (LR), 0.0000 (LightGBM)
- **Brier Score**: 0.0000 (LR), 0.2500 (LightGBM)
- **Calibration Curve**: 10-bin uniform strategy

*Perfect calibration (ECE=0) on synthetic data due to perfect separation. Real-world data will show non-zero ECE.*

## Known Limitations & Failure Modes

### 1. New TLDs / Emerging Threats
- Model only knows TLDs seen during training
- New gTLDs may not have suspicious_tld signal
- **Mitigation**: Retrain monthly with fresh snapshots

### 2. Sophisticated Homograph Attacks
- Punycode detection is binary (present/absent)
- Does not decode/visual-similarity check
- **Mitigation**: Browser-level IDN display mitigations

### 3. Shortened URLs
- Only detects known shortener domains
- Custom/private shorteners bypass detection
- **Mitigation**: API can optionally expand redirects (privacy opt-in)

### 4. Brand Impersonation Coverage
- MAJOR_BRANDS list is fixed (~50 brands)
- Niche/targeted brands not covered
- **Mitigation**: API supports dynamic brand list updates

### 5. Adversarial URL Generation
- Character-level n-grams provide some robustness
- But targeted evasion possible (homoglyphs, subdomain padding)
- **Mitigation**: Ensemble with rule-based signals in extension

### 6. Geographic/Regional Bias
- Tranco list biased toward English/global sites
- Regional benign URLs may score higher risk
- **Mitigation**: Evaluate per-TLD; consider regional benign sources

### 7. Concept Drift
- Phishing tactics evolve (new keywords, TLDs, techniques)
- Model performance degrades over time
- **Mitigation**: Automated monthly retraining pipeline; monitor AUC decay

### 8. Class Imbalance in Production
- Real-world malicious rate << 1%
- Threshold 0.5 optimized for balanced test set
- **Production**: Use risk_score thresholds (Low<30, Med<60, High<80, Critical>=80)

## Ethical Considerations

### Privacy
- Features extracted from URL only (no page content)
- No query strings or fragments used
- No user identifiers in training data

### Bias
- Brand list favors major Western tech companies
- Suspicious TLD list may penalize legitimate uses in developing regions
- Tranco benign set skews toward popular global sites

### Dual Use
- Model could be used to filter/block legitimate content
- False positives possible (especially new/rare legitimate domains)
- **Recommendation**: Human-in-the-loop for blocking decisions; appeal process

## Monitoring & Maintenance

### Retraining Schedule
- **Frequency**: Monthly (automated via CI/CD)
- **Trigger**: New data snapshots + performance regression detection
- **Validation**: Must beat previous version on held-out test set

### Production Metrics to Track
- Daily prediction volume and class distribution
- False positive rate (user reports / whitelist requests)
- False negative rate (reported phishing that bypassed)
- Score calibration (reliability diagram monthly)
- Feature drift (population stability index)

### Rollback Criteria
- AUC drop > 0.02 on test set
- FPR @ 1% TPR increase > 0.01
- Calibration ECE increase > 0.02

## API Integration
- Model exported to `api/models/model.joblib`
- Contains: LightGBM model, LR model, FeatureEngineer, feature schema, version
- Load at API startup; warm-up with sample predictions
- Health endpoint exposes version_hash

## Attribution
```
Guardian ML Model
- Training data: OpenPhish, PhishTank, URLhaus, Tranco
- Code: Guardian project (MIT License)
- If you use this model, cite the data sources per their licenses
```

## Contact
- **Maintainer**: Guardian Security Team
- **Issues**: https://github.com/guardian/project/issues
- **Security**: security@guardian.example.com