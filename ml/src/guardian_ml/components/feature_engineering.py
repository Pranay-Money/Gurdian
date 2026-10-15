"""
Feature Engineering Component

Implements three feature groups:
1. Lexical features (from url_engine) - structural URL properties
2. Char n-gram TF-IDF (3-5) - sequence patterns in URL/hostname
3. Host-token features - tokenized hostname parts with TF-IDF

Includes shortcut detection to identify features that trivially separate data sources.
"""
import re
import math
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from urllib.parse import urlparse

import joblib
import numpy as np
import scipy.sparse as sp
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

from guardian_ml.features import URLFeatures, extract_features, features_to_array, get_feature_names, _tld_extract
from guardian_ml.exception import FeatureEngineeringException
from guardian_ml.logger import logger


@dataclass
class FeatureConfig:
    """Configuration for feature extraction."""
    # Lexical features
    use_lexical: bool = True
    
    # Char n-gram TF-IDF
    use_char_ngrams: bool = True
    char_ngram_range: Tuple[int, int] = (3, 5)
    char_ngram_max_features: int = 5000
    char_ngram_analyzer: str = "char"
    
    # Host token features
    use_host_tokens: bool = True
    host_token_max_features: int = 3000
    host_token_ngram_range: Tuple[int, int] = (1, 2)
    
    # Shortcut detection
    run_shortcut_check: bool = True
    shortcut_threshold_auc: float = 0.9  # Flag features with AUC > this
    
    # Output
    feature_dir: Path = None

    def __post_init__(self):
        from guardian_ml.paths import get_features_dir
        if self.feature_dir is None:
            self.feature_dir = get_features_dir()
        self.feature_dir.mkdir(parents=True, exist_ok=True)

    def __getstate__(self):
        state = self.__dict__.copy()
        state["feature_dir"] = None
        return state


class FeatureEngineer:
    """
    Extracts and manages all feature groups for URLs.
    
    Feature groups:
    1. Lexical: 39 hand-crafted structural features
    2. Char n-grams: TF-IDF on character 3-5 grams of full URL
    3. Host tokens: TF-IDF on tokenized hostname parts (subdomain, domain, TLD)
    
    All transformers are fitted on training data only and saved for inference.
    """

    def __init__(self, config: Optional[FeatureConfig] = None):
        self.config = config or FeatureConfig()
        self.config.feature_dir.mkdir(parents=True, exist_ok=True)
        
        # Transformers (fitted during fit())
        self.lexical_scaler: Optional[StandardScaler] = None
        self.char_vectorizer: Optional[TfidfVectorizer] = None
        self.host_vectorizer: Optional[TfidfVectorizer] = None
        
        # Feature metadata
        self.lexical_feature_names: List[str] = get_feature_names()
        self.char_feature_names: List[str] = []
        self.host_feature_names: List[str] = []
        self.is_fitted: bool = False

    def _extract_host_tokens(self, url: str) -> str:
        """
        Extract tokenized hostname for host-token features.
        
        Returns space-separated tokens from subdomain, domain, TLD.
        Example: "www.google.com" -> "www google com"
        """
        extracted = _tld_extract(url)
        tokens = []
        if extracted.subdomain:
            # Split subdomain by dots and hyphens
            for part in re.split(r'[.\-]', extracted.subdomain):
                if part:
                    tokens.append(part.lower())
        if extracted.domain:
            tokens.append(extracted.domain.lower())
        if extracted.suffix:
            tokens.append(extracted.suffix.lower())
        return " ".join(tokens)

    def _extract_url_text(self, url: str) -> str:
        """Extract text representation for char n-grams (full URL)."""
        return url.lower()

    def fit(self, urls: List[str], labels: Optional[List[int]] = None) -> "FeatureEngineer":
        """
        Fit all transformers on training URLs.
        
        Args:
            urls: List of URL strings
            labels: Optional labels for shortcut detection
        """
        logger.info(f"Fitting feature transformers on {len(urls)} URLs...")
        
        # 1. Lexical features - fit scaler
        if self.config.use_lexical:
            logger.info("Fitting lexical feature scaler...")
            lexical_matrix = np.array([features_to_array(extract_features(url)) for url in urls])
            self.lexical_scaler = StandardScaler()
            self.lexical_scaler.fit(lexical_matrix)
        
        # 2. Char n-gram TF-IDF
        if self.config.use_char_ngrams:
            logger.info("Fitting char n-gram TF-IDF vectorizer...")
            url_texts = [self._extract_url_text(url) for url in urls]
            self.char_vectorizer = TfidfVectorizer(
                analyzer=self.config.char_ngram_analyzer,
                ngram_range=self.config.char_ngram_range,
                max_features=self.config.char_ngram_max_features,
                sublinear_tf=True,
                dtype=np.float32,
            )
            self.char_vectorizer.fit(url_texts)
            self.char_feature_names = [f"char_{n}" for n in self.char_vectorizer.get_feature_names_out()]
            logger.info(f"  Char n-gram features: {len(self.char_feature_names)}")
        
        # 3. Host token TF-IDF
        if self.config.use_host_tokens:
            logger.info("Fitting host token TF-IDF vectorizer...")
            host_texts = [self._extract_host_tokens(url) for url in urls]
            self.host_vectorizer = TfidfVectorizer(
                analyzer="word",
                ngram_range=self.config.host_token_ngram_range,
                max_features=self.config.host_token_max_features,
                sublinear_tf=True,
                dtype=np.float32,
                token_pattern=r"(?u)\b\w+\b",  # Match word tokens
            )
            self.host_vectorizer.fit(host_texts)
            self.host_feature_names = [f"host_{n}" for n in self.host_vectorizer.get_feature_names_out()]
            logger.info(f"  Host token features: {len(self.host_feature_names)}")
        
        # 4. Shortcut detection
        if self.config.run_shortcut_check and labels is not None and len(set(labels)) > 1:
            self._run_shortcut_check(urls, labels)
        
        self.is_fitted = True
        logger.info("Feature engineering fit complete.")
        return self

    def _run_shortcut_check(self, urls: List[str], labels: List[int]) -> Dict[str, float]:
        """
        Train on single feature groups to detect shortcuts.
        
        A shortcut is a feature group that alone achieves suspiciously high AUC,
        indicating it may be separating data sources rather than learning general patterns.
        
        Also checks individual lexical features for shortcut behavior.
        """
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import cross_val_score
        from sklearn.pipeline import make_pipeline
        
        logger.info("Running shortcut detection...")
        y = np.array(labels)
        results = {}
        
        # Check lexical features alone
        if self.config.use_lexical:
            X_lex = np.array([features_to_array(extract_features(url)) for url in urls])
            pipe = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1))
            scores = cross_val_score(pipe, X_lex, y, cv=3, scoring="roc_auc", n_jobs=-1)
            auc = scores.mean()
            logger.info(f"  Lexical-only AUC: {auc:.4f}")
            results['lexical_auc'] = auc
            if auc > self.config.shortcut_threshold_auc:
                logger.warning(f"  ⚠ SHORTCUT DETECTED: Lexical features AUC={auc:.4f} > {self.config.shortcut_threshold_auc}")
        
        # Check char n-grams alone
        if self.config.use_char_ngrams:
            url_texts = [self._extract_url_text(url) for url in urls]
            vec = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=5000, sublinear_tf=True)
            X_char = vec.fit_transform(url_texts)
            pipe = make_pipeline(LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1))
            scores = cross_val_score(pipe, X_char, y, cv=3, scoring="roc_auc", n_jobs=-1)
            auc = scores.mean()
            logger.info(f"  Char n-gram-only AUC: {auc:.4f}")
            results['char_ngram_auc'] = auc
            if auc > self.config.shortcut_threshold_auc:
                logger.warning(f"  ⚠ SHORTCUT DETECTED: Char n-grams AUC={auc:.4f} > {self.config.shortcut_threshold_auc}")
        
        # Check host tokens alone
        if self.config.use_host_tokens:
            host_texts = [self._extract_host_tokens(url) for url in urls]
            vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), max_features=3000, sublinear_tf=True)
            X_host = vec.fit_transform(host_texts)
            pipe = make_pipeline(LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1))
            scores = cross_val_score(pipe, X_host, y, cv=3, scoring="roc_auc", n_jobs=-1)
            auc = scores.mean()
            logger.info(f"  Host token-only AUC: {auc:.4f}")
            results['host_token_auc'] = auc
            if auc > self.config.shortcut_threshold_auc:
                logger.warning(f"  ⚠ SHORTCUT DETECTED: Host tokens AUC={auc:.4f} > {self.config.shortcut_threshold_auc}")
        
        # Check individual lexical features for shortcuts
        if self.config.use_lexical:
            feature_names = get_feature_names()
            X_lex = np.array([features_to_array(extract_features(url)) for url in urls])
            logger.info("  Individual feature shortcut check:")
            for i, fname in enumerate(feature_names):
                if fname in ['path_length', 'query_length', 'path_depth', 'has_redirect_param', 'url_length', 'is_https']:
                    X_single = X_lex[:, i:i+1]
                    pipe = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=42, n_jobs=-1))
                    try:
                        scores = cross_val_score(pipe, X_single, y, cv=3, scoring="roc_auc", n_jobs=-1)
                        auc = scores.mean()
                        results[f'{fname}_auc'] = auc
                        logger.info(f"    {fname}: AUC={auc:.4f}")
                        if auc > 0.7:  # Lower threshold for individual features
                            logger.warning(f"    ⚠ POTENTIAL SHORTCUT: {fname} AUC={auc:.4f} > 0.70")
                    except Exception as e:
                        logger.warning(f"    {fname}: failed ({e})")
                        results[f'{fname}_auc'] = 0.0
        
        return results

    def transform(self, urls: List[str]) -> sp.csr_matrix:
        """
        Transform URLs to combined feature matrix.
        
        Returns sparse CSR matrix with columns in order:
        [lexical | char_ngrams | host_tokens]
        """
        if not self.is_fitted:
            raise FeatureEngineeringException("FeatureEngineer not fitted. Call fit() first.", None)
        
        matrices = []
        
        # Lexical features
        if self.config.use_lexical:
            lexical_matrix = np.array([features_to_array(extract_features(url)) for url in urls])
            lexical_scaled = self.lexical_scaler.transform(lexical_matrix)
            matrices.append(sp.csr_matrix(lexical_scaled))
        
        # Char n-grams
        if self.config.use_char_ngrams:
            url_texts = [self._extract_url_text(url) for url in urls]
            char_matrix = self.char_vectorizer.transform(url_texts)
            matrices.append(char_matrix)
        
        # Host tokens
        if self.config.use_host_tokens:
            host_texts = [self._extract_host_tokens(url) for url in urls]
            host_matrix = self.host_vectorizer.transform(host_texts)
            matrices.append(host_matrix)
        
        if not matrices:
            raise FeatureEngineeringException("No feature groups enabled", None)
        
        combined = sp.hstack(matrices, format="csr")
        logger.info(f"Transformed {len(urls)} URLs to feature matrix: {combined.shape}")
        return combined

    def fit_transform(self, urls: List[str], labels: Optional[List[int]] = None) -> sp.csr_matrix:
        """Fit and transform in one step."""
        self.fit(urls, labels)
        return self.transform(urls)

    def get_feature_names(self) -> List[str]:
        """Get all feature names in order matching transform() output."""
        names = []
        if self.config.use_lexical:
            names.extend(self.lexical_feature_names)
        if self.config.use_char_ngrams:
            names.extend(self.char_feature_names)
        if self.config.use_host_tokens:
            names.extend(self.host_feature_names)
        return names

    def save(self, path: Path) -> None:
        """Save all fitted transformers and metadata."""
        if not self.is_fitted:
            raise FeatureEngineeringException("Cannot save unfitted FeatureEngineer", None)
        
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        # Save transformers
        if self.lexical_scaler:
            joblib.dump(self.lexical_scaler, path / "lexical_scaler.joblib")
        if self.char_vectorizer:
            joblib.dump(self.char_vectorizer, path / "char_vectorizer.joblib")
        if self.host_vectorizer:
            joblib.dump(self.host_vectorizer, path / "host_vectorizer.joblib")
        
        # Save metadata
        metadata = {
            "config": asdict(self.config),
            "lexical_feature_names": self.lexical_feature_names,
            "char_feature_names": self.char_feature_names,
            "host_feature_names": self.host_feature_names,
            "is_fitted": self.is_fitted,
            "version": "1.0",
        }
        with open(path / "metadata.json", "w") as f:
            # Convert Path objects to strings for JSON serialization
            meta_copy = metadata.copy()
            meta_copy["config"] = {k: str(v) if isinstance(v, Path) else v for k, v in metadata["config"].items()}
            json.dump(meta_copy, f, indent=2)
        
        logger.info(f"Saved feature engineer to {path}")

    @classmethod
    def load(cls, path: Path) -> "FeatureEngineer":
        """Load fitted transformers and metadata."""
        path = Path(path)
        
        with open(path / "metadata.json") as f:
            metadata = json.load(f)
        
        # Convert feature_dir back to Path if it's a string
        config_dict = metadata["config"].copy()
        if "feature_dir" in config_dict and isinstance(config_dict["feature_dir"], str):
            config_dict["feature_dir"] = Path(config_dict["feature_dir"])
        
        config = FeatureConfig(**config_dict)
        engineer = cls(config)
        
        engineer.lexical_feature_names = metadata["lexical_feature_names"]
        engineer.char_feature_names = metadata["char_feature_names"]
        engineer.host_feature_names = metadata["host_feature_names"]
        engineer.is_fitted = metadata["is_fitted"]
        
        if engineer.config.use_lexical:
            engineer.lexical_scaler = joblib.load(path / "lexical_scaler.joblib")
        if engineer.config.use_char_ngrams:
            engineer.char_vectorizer = joblib.load(path / "char_vectorizer.joblib")
        if engineer.config.use_host_tokens:
            engineer.host_vectorizer = joblib.load(path / "host_vectorizer.joblib")
        
        logger.info(f"Loaded feature engineer from {path}")
        return engineer


def create_feature_schema(engineer: FeatureEngineer) -> Dict[str, Any]:
    """
    Create feature schema for model export.
    
    This schema is saved alongside the model and used by the API
    to validate and explain inputs.
    """
    return {
        "version": "1.0",
        "feature_groups": {
            "lexical": {
                "enabled": engineer.config.use_lexical,
                "count": len(engineer.lexical_feature_names),
                "names": engineer.lexical_feature_names,
                "description": "Hand-crafted structural URL features",
            },
            "char_ngrams": {
                "enabled": engineer.config.use_char_ngrams,
                "count": len(engineer.char_feature_names),
                "names": engineer.char_feature_names[:20],  # Sample
                "description": f"Character {engineer.config.char_ngram_range[0]}-{engineer.config.char_ngram_range[1]}-gram TF-IDF",
            },
            "host_tokens": {
                "enabled": engineer.config.use_host_tokens,
                "count": len(engineer.host_feature_names),
                "names": engineer.host_feature_names[:20],  # Sample
                "description": f"Hostname token {engineer.config.host_token_ngram_range[0]}-{engineer.config.host_token_ngram_range[1]}-gram TF-IDF",
            },
        },
        "total_features": len(engineer.get_feature_names()),
        "extraction_functions": {
            "lexical": "guardian_ml.features.extract_features",
            "char_ngrams": "FeatureEngineer._extract_url_text",
            "host_tokens": "FeatureEngineer._extract_host_tokens",
        },
    }


if __name__ == "__main__":
    # Quick test
    test_urls = [
        "https://www.google.com/search?q=test",
        "http://malicious.tk/login.php",
        "https://github.com/user/repo",
        "http://paypal.phishing-site.ml/verify",
    ]
    test_labels = [0, 1, 0, 1]
    
    engineer = FeatureEngineer()
    X = engineer.fit_transform(test_urls, test_labels)
    print(f"Feature matrix shape: {X.shape}")
    print(f"Feature names ({len(engineer.get_feature_names())}): {engineer.get_feature_names()[:10]}...")