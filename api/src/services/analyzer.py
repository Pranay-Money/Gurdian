"""
Analyzer Service - Orchestrates all detection engines
"""
import hashlib
import structlog
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass
import uuid

from ..engines import (
    TextEngine, URLEngine, ImpersonationEngine,
    ScoringEngine, ExplanationEngine,
    analyze_text, analyze_urls, analyze_impersonation,
    calculate_score, generate_explanation
)

logger = structlog.get_logger(__name__)

# Try to import ML model
try:
    from guardian_ml import GuardianModel
    ML_AVAILABLE = True
    ML_IMPORT_ERROR_TYPE: Optional[str] = None
    logger.info("Guardian ML package import succeeded", ml_package_available=True)
except ImportError as exc:
    ML_AVAILABLE = False
    GuardianModel = None
    ML_IMPORT_ERROR_TYPE = type(exc).__name__
    logger.warning(
        "Guardian ML package import failed; using rule-based fallback",
        ml_package_available=False,
        exception_type=ML_IMPORT_ERROR_TYPE,
    )


@dataclass
class AnalysisResult:
    case_id: str
    score: int
    level: str
    action: str
    signals: List[Dict[str, Any]]
    urls: List[Dict[str, Any]]
    model_version: str
    latency_ms: int
    explanation: Dict[str, Any]
    text_hash: Optional[str] = None
    # ML-specific fields
    ml_probability: Optional[float] = None
    ml_contributions: Optional[List[Dict[str, Any]]] = None
    ml_risk_score: Optional[int] = None
    ml_risk_level: Optional[str] = None


class AnalyzerService:
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path(__file__).parent.parent / "engines" / "config"
        self.text_engine = TextEngine(self.config_dir)
        self.url_engine = URLEngine(self.config_dir)
        self.impersonation_engine = ImpersonationEngine(self.config_dir)
        self.scoring_engine = ScoringEngine(self.config_dir)
        self.explanation_engine = ExplanationEngine(self.config_dir)
        self.model_version = "1.0.0"
        
        # Load ML model if available
        self.ml_model = None
        self.ml_status = "model_not_loaded"
        if ML_AVAILABLE:
            self._load_ml_model()
        else:
            self.ml_status = "package_import_failed"

    def _load_ml_model(self):
        """Load Guardian ML model for inference."""
        try:
            from src.core.config import get_settings
            settings = get_settings()
            model_path = Path(settings.model_path)
            if not model_path.is_absolute():
                model_path = Path(__file__).resolve().parents[2] / model_path
            if model_path.exists():
                self.ml_model = GuardianModel.load(model_path)
                self.model_version = self.ml_model.version_hash
                self.ml_status = "loaded"
                logger.info(
                    "Guardian ML model loaded",
                    ml_model_available=True,
                    model_version=self.model_version,
                )
            else:
                self.ml_status = "model_not_found"
                logger.warning(
                    "Guardian ML model not found; using rule-based fallback",
                    ml_model_available=False,
                    reason=self.ml_status,
                )
        except Exception as exc:
            self.ml_status = "model_load_failed"
            logger.error(
                "Guardian ML model could not be loaded; using rule-based fallback",
                ml_model_available=False,
                reason=self.ml_status,
                exception_type=type(exc).__name__,
            )
            self.ml_model = None

    def get_ml_status(self) -> Dict[str, Any]:
        """Return safe ML readiness information without exposing local paths or errors."""
        return {
            "available": self.ml_model is not None,
            "status": self.ml_status,
            "mode": "ml_and_rules" if self.ml_model is not None else "rule_based_fallback",
            "model_version": self.model_version if self.ml_model is not None else None,
        }

    def analyze(
        self,
        channel: str,
        sender: Optional[str] = None,
        text: Optional[str] = None,
        urls: Optional[List[str]] = None,
        deep: bool = False
    ) -> AnalysisResult:
        """Run full analysis pipeline."""
        import time
        start = time.perf_counter()

        # Extract URLs from text if not provided
        extracted_urls = []
        if text:
            extracted_urls = self.url_engine.extract_urls(text)

        all_urls = list(dict.fromkeys((urls or []) + extracted_urls))

        # Run rule-based engines
        text_signals = analyze_text(text or "", self.config_dir)
        url_signals = analyze_urls(text or "", deep=deep, config_dir=self.config_dir)
        impersonation_signals = analyze_impersonation(text or "", sender, all_urls, self.config_dir)

        all_signals = text_signals + url_signals + impersonation_signals

        # Check blocklist
        blocklist_hit = self._check_blocklist(all_urls)

        # Run ML model if available
        ml_probability = None
        ml_contributions = None
        ml_risk_score = None
        ml_risk_level = None
        
        if self.ml_model and all_urls:
            try:
                # Use the first URL for ML classification (or could aggregate)
                primary_url = all_urls[0]
                ml_result = self.ml_model.predict(primary_url)
                ml_probability = ml_result.probability
                ml_contributions = ml_result.top_contributions
                ml_risk_score = ml_result.risk_score
                ml_risk_level = ml_result.risk_level
                
                # Add ML contribution signals
                for contrib in ml_contributions[:5]:  # Top 5 contributions
                    all_signals.append({
                        'key': f'ml_contrib_{contrib["feature"]}',
                        'category': 'structural',
                        'label': f'ML: {contrib["feature"]}',
                        'points': int(abs(contrib["contribution"]) * 100),
                        'reason': f'ML feature contribution: {contrib["direction"]} ({contrib["contribution"]:.3f})',
                        'evidence': [{'type': 'ml', 'value': contrib["feature"], 'description': contrib["direction"]}]
                    })
            except Exception as exc:
                self.ml_status = "inference_failed"
                logger.error(
                    "Guardian ML inference failed; using rule-based fallback",
                    reason=self.ml_status,
                    exception_type=type(exc).__name__,
                )

        # Calculate score using rule-based engine (fallback/complement)
        score_result = calculate_score(all_signals, blocklist_hit, self.config_dir)

        # If ML is available, blend ML probability with rule-based score
        final_score = score_result["score"]
        final_level = score_result["level"]
        final_action = score_result["action"]
        
        if ml_probability is not None:
            # Blend: 70% ML, 30% rule-based (normalized)
            ml_score = int(ml_probability * 100)
            rule_score = score_result["score"]
            final_score = int(0.7 * ml_score + 0.3 * rule_score)
            
            # Determine level from ML probability (primary)
            if ml_probability >= 0.8:
                final_level = "Critical"
                final_action = "block"
            elif ml_probability >= 0.6:
                final_level = "High"
                final_action = "block"
            elif ml_probability >= 0.3:
                final_level = "Medium"
                final_action = "warn"
            else:
                final_level = "Low"
                final_action = "allow"
            
            # Override with rule-based if it's more severe (safety)
            rule_severity = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
            ml_severity = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
            if rule_severity.get(score_result["level"], 0) > ml_severity.get(final_level, 0):
                final_level = score_result["level"]
                final_action = score_result["action"]

        # Generate explanation
        explanation = generate_explanation(
            score_result["signals"],
            final_level,
            final_score,
            self.config_dir
        )

        # Build URL analysis objects
        url_analyses = []
        for url in all_urls:
            analysis = self.url_engine.analyze_url(url)
            url_analyses.append({
                "url": analysis.url,
                "host": analysis.host,
                "registrable_domain": analysis.registrable_domain,
                "tld": analysis.tld,
                "https": analysis.scheme == "https",
                "subdomains": analysis.subdomain.split(".") if analysis.subdomain else [],
                "length": analysis.length,
                "age_days": None,  # Would need WHOIS
                "redirects": analysis.redirects,
                "intel": None  # Would need external APIs
            })

        latency_ms = int((time.perf_counter() - start) * 1000)
        normalized_text = text or ""
        text_hash = hashlib.sha256(normalized_text.encode("utf-8")).hexdigest() if normalized_text else None

        return AnalysisResult(
            case_id=str(uuid.uuid4()),
            score=final_score,
            level=final_level,
            action=final_action,
            signals=score_result["signals"],
            urls=url_analyses,
            model_version=self.model_version,
            latency_ms=latency_ms,
            explanation=explanation,
            text_hash=text_hash,
            ml_probability=ml_probability,
            ml_contributions=ml_contributions,
            ml_risk_score=ml_risk_score,
            ml_risk_level=ml_risk_level
        )

    def _check_blocklist(self, urls: List[str]) -> bool:
        """Check if any URL is on blocklist. Placeholder for DB check."""
        # In production, check against database blocklist
        # For now, check suspicious TLDs as proxy
        for url in urls:
            try:
                from urllib.parse import urlparse
                import tldextract
                extracted = tldextract.extract(url)
                if extracted.suffix in ("tk", "ml", "ga", "cf", "gq"):
                    return True
            except Exception:
                pass
        return False


# Global instance
_analyzer: Optional[AnalyzerService] = None


def get_analyzer(config_dir: Optional[Path] = None) -> AnalyzerService:
    global _analyzer
    if _analyzer is None:
        _analyzer = AnalyzerService(config_dir)
    return _analyzer