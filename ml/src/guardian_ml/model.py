"""
Thin inference wrapper for Guardian ML.

Loads the exported model package (model.joblib) which contains:
- lgb_model: Calibrated LightGBM model (isotonic regression)
- lr_model: Calibrated Logistic Regression model (isotonic regression)
- feature_engineer: Fitted FeatureEngineer with all transformers
- feature_names: List of feature names in order
- version_hash: Model version hash
"""

import os
import joblib
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .features import URLFeatures, extract_features, features_to_array, get_feature_names
from .logger import logger


@dataclass
class PredictionResult:
    """Result of URL classification."""
    is_malicious: bool
    probability: float  # Calibrated probability of malicious class
    confidence: float   # Distance from decision boundary
    risk_score: int     # 0-100 integer score
    risk_level: str     # Low/Medium/High/Critical
    signals: List[Dict[str, Any]]  # Human-readable explanation signals
    top_contributions: List[Dict[str, Any]]  # Feature contributions (SHAP or LR coef)
    model_metadata: Optional[Dict[str, Any]] = None  # Model metadata including synthetic flag


class GuardianModel:
    """
    Inference-only wrapper for Guardian ML models.
    
    Usage:
        model = GuardianModel.load("api/models/model.joblib")
        result = model.predict("https://example.com/login")
        print(result.probability, result.top_contributions)
    """
    
    def __init__(
        self,
        lgb_model: Any,
        lr_model: Any,
        feature_engineer: Any,
        feature_names: List[str],
        version_hash: str,
        metadata: Optional[Dict[str, Any]] = None,
        allow_synthetic: bool = False,
    ):
        self.lgb_model = lgb_model
        self.lr_model = lr_model
        self.feature_engineer = feature_engineer
        self.feature_names = feature_names
        self.version_hash = version_hash
        self.metadata = metadata or {}
        self.allow_synthetic = allow_synthetic
        
        # Check for synthetic model
        is_synthetic = self.metadata.get('synthetic', False)
        if is_synthetic and not self.allow_synthetic:
            # Check environment variable as fallback for CI
            if not os.environ.get('GUARDIAN_ALLOW_SYNTHETIC', '').lower() in ('1', 'true', 'yes'):
                raise ValueError(
                    "Model trained on synthetic data. Loading blocked. "
                    "Set GUARDIAN_ALLOW_SYNTHETIC=1 or use allow_synthetic=True (CI smoke tests only)."
                )
            logger.warning("Loading SYNTHETIC model - NOT FOR PRODUCTION USE")
        elif is_synthetic:
            logger.warning("Loading SYNTHETIC model - NOT FOR PRODUCTION USE")
        
        # Try to get SHAP explainer for LightGBM
        self._shap_explainer = None
        self._init_shap()
    
    def _init_shap(self):
        """Initialize SHAP TreeExplainer for LightGBM if available."""
        try:
            import shap
            # Get base LightGBM model from calibrated wrapper
            base_model = self._get_base_lgb_model()
            if base_model is not None:
                self._shap_explainer = shap.TreeExplainer(base_model)
                logger.info("SHAP TreeExplainer initialized for LightGBM")
        except ImportError:
            logger.info("SHAP not available, using feature importance for explanations")
        except Exception as e:
            logger.warning(f"SHAP initialization failed: {e}")
    
    def _get_base_lgb_model(self) -> Any:
        """Extract base LightGBM model from calibrated wrapper."""
        model = self.lgb_model
        # CalibratedClassifierCV
        if hasattr(model, 'calibrated_classifiers_'):
            return model.calibrated_classifiers_[0].base_estimator
        # CalibratedLGBM wrapper
        if hasattr(model, 'base_model'):
            return model.base_model
        # Direct LightGBM model
        if hasattr(model, 'feature_importances_'):
            return model
        return None
    
    @classmethod
    def load(cls, path: Path, allow_synthetic: bool = False) -> 'GuardianModel':
        """
        Load model from exported package.
        
        Args:
            path: Path to model.joblib exported by pipeline
            allow_synthetic: Allow loading synthetic models (CI only)
            
        Returns:
            GuardianModel instance ready for inference
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")
        
        logger.info(f"Loading model from {path}")
        package = joblib.load(path)

        if not isinstance(package, dict):
            raise ValueError("Model package must be a mapping")

        required_keys = ['lgb_model', 'lr_model', 'feature_engineer', 'feature_names', 'version_hash']
        for key in required_keys:
            if key not in package:
                raise ValueError(f"Model package missing required key: {key}")

        metadata = package.get('metadata', {})
        if not isinstance(metadata, dict):
            raise ValueError("Model metadata must be a mapping")
        if not isinstance(package['feature_names'], list) or not package['feature_names']:
            raise ValueError("Model feature_names must be a non-empty list")
        if not isinstance(package['version_hash'], str) or not package['version_hash']:
            raise ValueError("Model version_hash must be a non-empty string")
        if not callable(getattr(package['feature_engineer'], 'transform', None)):
            raise ValueError("Model feature engineer does not support transform")
        if not getattr(package['feature_engineer'], 'is_fitted', False):
            raise ValueError("Model feature engineer is not fitted")
        for key in ('lgb_model', 'lr_model'):
            if not callable(getattr(package[key], 'predict_proba', None)):
                raise ValueError(f"Model {key} does not support predict_proba")

        sample_features = package['feature_engineer'].transform(["https://guardian.invalid/"])
        if getattr(sample_features, "shape", (None, None))[1] != len(package['feature_names']):
            raise ValueError("Model feature schema does not match the fitted feature engineer")

        return cls(
            lgb_model=package['lgb_model'],
            lr_model=package['lr_model'],
            feature_engineer=package['feature_engineer'],
            feature_names=package['feature_names'],
            version_hash=package['version_hash'],
            metadata=metadata,
            allow_synthetic=allow_synthetic,
        )
    
    def predict(self, url: str, model_name: str = "lightgbm") -> PredictionResult:
        """
        Classify a single URL.
        
        Args:
            url: URL to classify
            model_name: "lightgbm" (primary) or "logistic_regression" (baseline)
            
        Returns:
            PredictionResult with calibrated probability and explanations
        """
        model = self.lgb_model if model_name == "lightgbm" else self.lr_model
        
        # Extract features using the same feature engineer from training
        X = self.feature_engineer.transform([url])
        X_dense = X.toarray() if hasattr(X, 'toarray') else X
        
        # Get calibrated probability
        proba = float(model.predict_proba(X_dense)[0, 1])
        is_malicious = proba > 0.5
        confidence = float(proba if is_malicious else 1 - proba)
        risk_score = int(proba * 100)
        
        if risk_score >= 80:
            risk_level = "Critical"
        elif risk_score >= 60:
            risk_level = "High"
        elif risk_score >= 30:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        # Generate human-readable signals
        signals = self._generate_signals(url)
        
        # Get feature contributions (SHAP or coefficients)
        top_contributions = self._get_contributions(X, model_name)
        
        return PredictionResult(
            is_malicious=bool(is_malicious),
            probability=proba,
            confidence=confidence,
            risk_score=risk_score,
            risk_level=risk_level,
            signals=signals,
            top_contributions=top_contributions,
            model_metadata={"version_hash": self.version_hash, "synthetic": self.metadata.get('synthetic', False)},
        )
    
    def predict_batch(self, urls: List[str], model_name: str = "lightgbm") -> List[PredictionResult]:
        """Classify multiple URLs."""
        return [self.predict(url, model_name) for url in urls]
    
    def _generate_signals(self, url: str) -> List[Dict[str, Any]]:
        """Generate human-readable explanation signals from features."""
        features = extract_features(url)
        import tldextract
        extracted = tldextract.extract(url)
        
        signals = []
        
        if features.has_ip:
            signals.append({
                'key': 'ip_in_hostname',
                'category': 'structural',
                'label': 'IP Address in Hostname',
                'points': 25,
                'reason': 'Hostname is an IP address instead of a domain name',
                'evidence': [{'type': 'hostname', 'value': f'has_ip={features.has_ip}', 'description': 'Direct IP usage'}],
            })
        
        if features.url_shortener:
            signals.append({
                'key': 'url_shortener',
                'category': 'structural',
                'label': 'URL Shortener Detected',
                'points': 20,
                'reason': 'URL uses a known shortening service',
                'evidence': [{'type': 'domain', 'value': 'shortener', 'description': 'Known shortener domain'}],
            })
        
        if features.suspicious_tld:
            signals.append({
                'key': 'suspicious_tld',
                'category': 'metadata',
                'label': 'Suspicious TLD',
                'points': 15,
                'reason': f'TLD is commonly abused: .{extracted.suffix}',
                'evidence': [{'type': 'tld', 'value': 'suspicious', 'description': 'High-risk TLD'}],
            })
        
        if features.brand_in_subdomain:
            signals.append({
                'key': 'brand_in_subdomain',
                'category': 'behavioral',
                'label': 'Brand Name in Subdomain',
                'points': 25,
                'reason': 'Major brand name appears in subdomain (possible typosquatting)',
                'evidence': [{'type': 'subdomain', 'value': 'brand', 'description': 'Brand impersonation'}],
            })
        
        if features.brand_in_path:
            signals.append({
                'key': 'brand_in_path',
                'category': 'behavioral',
                'label': 'Brand Name in Path',
                'points': 15,
                'reason': 'Major brand name appears in URL path',
                'evidence': [{'type': 'path', 'value': 'brand', 'description': 'Brand in path'}],
            })
        
        if features.suspicious_keywords >= 3:
            signals.append({
                'key': 'multiple_suspicious_keywords',
                'category': 'linguistic',
                'label': 'Multiple Suspicious Keywords',
                'points': 20,
                'reason': f'Found {features.suspicious_keywords} suspicious keywords',
                'evidence': [{'type': 'keywords', 'value': str(features.suspicious_keywords), 'description': 'Urgency/credential keywords'}],
            })
        elif features.suspicious_keywords > 0:
            signals.append({
                'key': 'suspicious_keywords',
                'category': 'linguistic',
                'label': 'Suspicious Keywords Present',
                'points': 10,
                'reason': f'Found {features.suspicious_keywords} suspicious keyword(s)',
                'evidence': [{'type': 'keywords', 'value': str(features.suspicious_keywords), 'description': 'Urgency/credential keywords'}],
            })
        
        if features.has_redirect_param:
            signals.append({
                'key': 'redirect_parameter',
                'category': 'behavioral',
                'label': 'Redirect Parameter Detected',
                'points': 10,
                'reason': 'URL contains redirect/next/return parameter',
                'evidence': [{'type': 'query', 'value': 'redirect', 'description': 'Open redirect risk'}],
            })
        
        if features.punycode:
            signals.append({
                'key': 'punycode_domain',
                'category': 'structural',
                'label': 'Punycode Domain',
                'points': 15,
                'reason': 'Domain uses punycode encoding (possible homograph attack)',
                'evidence': [{'type': 'domain', 'value': 'punycode', 'description': 'Internationalized domain'}],
            })
        
        if features.subdomain_count >= 4:
            signals.append({
                'key': 'excessive_subdomains',
                'category': 'structural',
                'label': 'Excessive Subdomains',
                'points': 15,
                'reason': f'URL has {features.subdomain_count} subdomain levels',
                'evidence': [{'type': 'subdomain_count', 'value': str(features.subdomain_count), 'description': 'Deep subdomain nesting'}],
            })
        
        if features.entropy > 3.5:
            signals.append({
                'key': 'high_entropy_hostname',
                'category': 'structural',
                'label': 'High Entropy Hostname',
                'points': 10,
                'reason': f'Hostname entropy is {features.entropy:.2f} (random-looking)',
                'evidence': [{'type': 'entropy', 'value': f'{features.entropy:.2f}', 'description': 'Algorithmic domain generation'}],
            })
        
        if not features.is_https:
            signals.append({
                'key': 'no_https',
                'category': 'metadata',
                'label': 'No HTTPS',
                'points': 5,
                'reason': 'Connection is not encrypted',
                'evidence': [{'type': 'scheme', 'value': 'http', 'description': 'Unencrypted'}],
            })
        
        if features.url_length > 150:
            signals.append({
                'key': 'long_url',
                'category': 'structural',
                'label': 'Unusually Long URL',
                'points': 5,
                'reason': f'URL length is {features.url_length} characters',
                'evidence': [{'type': 'length', 'value': str(features.url_length), 'description': 'Obfuscation attempt'}],
            })
        
        return signals
    
    def _get_contributions(self, X: Any, model_name: str) -> List[Dict[str, Any]]:
        """
        Get top feature contributions for this prediction.
        
        Uses SHAP TreeExplainer for LightGBM, LR coefficients for Logistic Regression.
        """
        X_dense = X.toarray() if hasattr(X, 'toarray') else X
        
        if model_name == "lightgbm" and self._shap_explainer is not None:
            try:
                import shap
                shap_values = self._shap_explainer.shap_values(X_dense)
                if isinstance(shap_values, list):
                    shap_values = shap_values[1]  # Class 1 (malicious)
                contribs = shap_values[0]
            except Exception as e:
                logger.warning(f"SHAP failed, falling back to feature importance: {e}")
                contribs = self._get_feature_importance_contributions()
        else:
            # Use LR coefficients or feature importance
            contribs = self._get_feature_importance_contributions(model_name)
        
        # Get top 10 contributions by absolute value
        top_idx = np.argsort(np.abs(contribs))[::-1][:10]
        
        contributions = []
        for i in top_idx:
            if i < len(self.feature_names):
                contributions.append({
                    'feature': self.feature_names[i],
                    'contribution': float(contribs[i]),
                    'direction': 'malicious' if contribs[i] > 0 else 'benign',
                })
        
        return contributions
    
    def _get_feature_importance_contributions(self, model_name: str = "lightgbm") -> np.ndarray:
        """Get feature importance as proxy for contributions."""
        model = self.lgb_model if model_name == "lightgbm" else self.lr_model
        
        if model_name == "logistic_regression" and hasattr(model, 'coef_'):
            # LR: use coefficients directly
            return model.coef_.flatten()
        
        # LightGBM: use feature importance
        base_model = self._get_base_lgb_model()
        if base_model is not None and hasattr(base_model, 'feature_importances_'):
            return base_model.feature_importances_
        
        # Fallback: uniform
        return np.ones(len(self.feature_names))