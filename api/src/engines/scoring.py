"""
Scoring Engine
Weighted signals with category caps, combo bonuses, and risk level thresholds.
Weights loaded from YAML config.
"""
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class ScoredSignal:
    key: str
    category: str
    label: str
    points: int
    reason: str
    evidence: str


@dataclass
class ScoreResult:
    score: int
    level: str
    action: str
    signals: List[ScoredSignal]
    category_scores: Dict[str, int]
    combo_bonuses: List[Dict[str, Any]]


class ScoringEngine:
    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path(__file__).parent / "config"
        self.config = self._load_weights()

    def _load_weights(self) -> Dict[str, Any]:
        path = self.config_dir / "weights.yaml"
        if not path.exists():
            return self._default_config()
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or self._default_config()

    def _default_config(self) -> Dict[str, Any]:
        return {
            "weights": {"text": {}, "url": {}, "impersonation": {}, "reputation": {}},
            "category_caps": {},
            "combo_bonuses": {},
            "thresholds": {"low": 20, "medium": 20, "high": 45, "critical": 70},
            "blocklist_forces_critical": True,
            "score_min": 0,
            "score_max": 100
        }

    def calculate(self, signals: List[Dict[str, Any]], blocklist_hit: bool = False) -> ScoreResult:
        """Calculate final score from signals."""
        def normalize_evidence(raw: Any) -> str:
            if raw is None:
                return ""
            if isinstance(raw, str):
                return raw
            if isinstance(raw, dict):
                return raw.get("value") or raw.get("description") or ""
            if isinstance(raw, list):
                if not raw:
                    return ""
                if isinstance(raw[0], dict):
                    return raw[0].get("value") or raw[0].get("description") or ""
                return str(raw[0])
            return str(raw)

        # Convert to ScoredSignal
        scored_signals = [
            ScoredSignal(
                key=s["key"],
                category=s["category"],
                label=s["label"],
                points=s["points"],
                reason=s["reason"],
                evidence=normalize_evidence(s.get("evidence"))
            )
            for s in signals
        ]
        scored_signals.sort(key=lambda signal: signal.points, reverse=True)

        # Apply category caps
        category_scores = defaultdict(int)
        category_caps = self.config.get("category_caps", {})

        for signal in scored_signals:
            cat = signal.category
            weight_config = self._get_weight_config(signal.key)
            cap = category_caps.get(cat, 100)
            # Apply cap per signal category
            if category_scores[cat] + signal.points > cap:
                signal.points = max(0, cap - category_scores[cat])
            category_scores[cat] += signal.points

        # Calculate base score
        base_score = sum(category_scores.values())

        # Apply combo bonuses
        combo_bonuses = []
        triggered_categories = set(category_scores.keys())

        for combo_key, combo_config in self.config.get("combo_bonuses", {}).items():
            if self._check_combo(combo_config, triggered_categories, scored_signals):
                bonus = combo_config.get("bonus", 0)
                base_score += bonus
                combo_bonuses.append({
                    "key": combo_key,
                    "description": combo_config.get("description", ""),
                    "bonus": bonus
                })

        # Blocklist forces critical
        if blocklist_hit and self.config.get("blocklist_forces_critical", True):
            base_score = max(base_score, self.config.get("thresholds", {}).get("critical", 70))

        # Clamp score
        score_min = self.config.get("score_min", 0)
        score_max = self.config.get("score_max", 100)
        final_score = max(score_min, min(score_max, base_score))

        # Determine level and action
        thresholds = {
            "low": 20,
            "medium": 20,
            "high": 45,
            "critical": 70,
            **self.config.get("thresholds", {})
        }
        if final_score >= thresholds.get("critical", 70):
            level = "Critical"
            action = "block"
        elif final_score >= thresholds.get("high", 45):
            level = "High"
            action = "block"
        elif final_score >= thresholds.get("medium", 20):
            level = "Medium"
            action = "warn"
        else:
            level = "Low"
            action = "allow"

        return ScoreResult(
            score=final_score,
            level=level,
            action=action,
            signals=scored_signals,
            category_scores=dict(category_scores),
            combo_bonuses=combo_bonuses
        )

    def _get_weight_config(self, signal_key: str) -> Dict[str, Any]:
        """Get weight configuration for a signal key."""
        for cat in ["text", "url", "impersonation", "reputation"]:
            if signal_key in self.config.get("weights", {}).get(cat, {}):
                return self.config["weights"][cat][signal_key]
        return {}

    def _check_combo(
        self,
        combo_config: Dict[str, Any],
        triggered_categories: set,
        signals: List[ScoredSignal]
    ) -> bool:
        """Check if combo bonus conditions are met."""
        requires = combo_config.get("requires", [])
        signal_keys = {s.key for s in signals}

        for req in requires:
            if isinstance(req, str):
                # Prefer direct signal-key matching, then fall back to category matching.
                if req in signal_keys:
                    continue
                if req in triggered_categories:
                    continue
                return False
            elif isinstance(req, dict):
                # Complex requirement (e.g., count of signals in category)
                cat = req.get("category")
                count = req.get("count", 1)
                cat_signals = sum(1 for s in signals if s.category == cat)
                if cat_signals < count:
                    return False

        return True


# Backward compatibility function
def calculate_score(
    signals: List[Dict[str, Any]],
    blocklist_hit: bool = False,
    config_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """Calculate score and return as dict."""
    engine = ScoringEngine(config_dir)
    result = engine.calculate(signals, blocklist_hit)
    return {
        "score": result.score,
        "level": result.level,
        "action": result.action,
        "signals": [
            {
                "key": s.key,
                "category": s.category,
                "label": s.label,
                "points": s.points,
                "reason": s.reason,
                "evidence": [{"type": s.category, "value": s.evidence, "description": s.reason}]
            }
            for s in result.signals
        ],
        "category_scores": result.category_scores,
        "combo_bonuses": result.combo_bonuses
    }