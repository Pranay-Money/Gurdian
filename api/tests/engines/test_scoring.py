"""
Tests for Scoring Engine
"""
import pytest
from src.engines.scoring import ScoringEngine, calculate_score


@pytest.fixture
def engine():
    return ScoringEngine()


class TestScoringEngine:
    """Test scoring engine weighted signals and thresholds."""

    def test_low_risk_below_20(self, engine):
        """Test score < 20 = Low."""
        signals = [
            {"key": "generic_greeting", "category": "linguistic", "label": "Generic Greeting",
             "points": 5, "reason": "test", "evidence": "test"}
        ]
        result = engine.calculate(signals)
        assert result.score < 20
        assert result.level == "Low"
        assert result.action == "allow"

    def test_medium_risk_20_44(self, engine):
        """Test score 20-44 = Medium."""
        signals = [
            {"key": "urgency", "category": "linguistic", "label": "Urgency",
             "points": 8, "reason": "test", "evidence": "test"},
            {"key": "generic_greeting", "category": "linguistic", "label": "Generic Greeting",
             "points": 5, "reason": "test", "evidence": "test"},
            {"key": "suspicious_tld", "category": "structural", "label": "Suspicious TLD",
             "points": 10, "reason": "test", "evidence": "test"}
        ]
        result = engine.calculate(signals)
        assert 20 <= result.score <= 44
        assert result.level == "Medium"
        assert result.action == "warn"

    def test_high_risk_45_69(self, engine):
        """Test score 45-69 = High."""
        signals = [
            {"key": "credential_request", "category": "sensitive_request", "label": "Credential Request",
             "points": 15, "reason": "test", "evidence": "test"},
            {"key": "deadline_threat", "category": "linguistic", "label": "Deadline Threat",
             "points": 12, "reason": "test", "evidence": "test"},
            {"key": "brand_in_subdomain", "category": "impersonation", "label": "Brand in Subdomain",
             "points": 20, "reason": "test", "evidence": "test"}
        ]
        result = engine.calculate(signals)
        assert 45 <= result.score <= 69
        assert result.level == "High"
        assert result.action == "block"

    def test_critical_risk_70_plus(self, engine):
        """Test score >= 70 = Critical."""
        signals = [
            {"key": "credential_request", "category": "sensitive_request", "label": "Credential Request",
             "points": 15, "reason": "test", "evidence": "test"},
            {"key": "unusual_payment", "category": "sensitive_request", "label": "Unusual Payment",
             "points": 18, "reason": "test", "evidence": "test"},
            {"key": "typosquat", "category": "impersonation", "label": "Typosquat",
             "points": 25, "reason": "test", "evidence": "test"},
            {"key": "deadline_threat", "category": "linguistic", "label": "Deadline Threat",
             "points": 12, "reason": "test", "evidence": "test"}
        ]
        result = engine.calculate(signals)
        assert result.score >= 70
        assert result.level == "Critical"
        assert result.action == "block"

    def test_category_cap_linguistic(self, engine):
        """Test linguistic category cap at 40."""
        # 6 urgency signals = 48 points, but cap is 40
        signals = [
            {"key": "urgency", "category": "linguistic", "label": "Urgency",
             "points": 8, "reason": "test", "evidence": "test"}
            for _ in range(6)
        ]
        result = engine.calculate(signals)
        linguistic_score = result.category_scores.get("linguistic", 0)
        assert linguistic_score <= 40

    def test_category_cap_sensitive_request(self, engine):
        """Test sensitive_request category cap at 45."""
        signals = [
            {"key": "credential_request", "category": "sensitive_request", "label": "Credential Request",
             "points": 15, "reason": "test", "evidence": "test"},
            {"key": "unusual_payment", "category": "sensitive_request", "label": "Unusual Payment",
             "points": 18, "reason": "test", "evidence": "test"},
            {"key": "credential_request", "category": "sensitive_request", "label": "Credential Request 2",
             "points": 15, "reason": "test", "evidence": "test"}
        ]
        result = engine.calculate(signals)
        sensitive_score = result.category_scores.get("sensitive_request", 0)
        assert sensitive_score <= 45

    def test_combo_bonus_urgency_sensitive_link(self, engine):
        """Test combo bonus: urgency + sensitive_request + structural."""
        signals = [
            {"key": "urgency", "category": "linguistic", "label": "Urgency",
             "points": 8, "reason": "test", "evidence": "test"},
            {"key": "credential_request", "category": "sensitive_request", "label": "Credential Request",
             "points": 15, "reason": "test", "evidence": "test"},
            {"key": "suspicious_tld", "category": "structural", "label": "Suspicious TLD",
             "points": 10, "reason": "test", "evidence": "test"}
        ]
        result = engine.calculate(signals)
        # Base: 33, Combo bonus: 15 = 48
        combo_bonuses = [c for c in result.combo_bonuses if "urgency_plus_sensitive" in c["key"]]
        assert len(combo_bonuses) > 0

    def test_combo_bonus_urgency_impersonation(self, engine):
        """Test combo bonus: urgency + impersonation."""
        signals = [
            {"key": "urgency", "category": "linguistic", "label": "Urgency",
             "points": 8, "reason": "test", "evidence": "test"},
            {"key": "brand_in_subdomain", "category": "impersonation", "label": "Brand in Subdomain",
             "points": 20, "reason": "test", "evidence": "test"}
        ]
        result = engine.calculate(signals)
        combo_bonuses = [c for c in result.combo_bonuses if "urgency_plus_impersonation" in c["key"]]
        assert len(combo_bonuses) > 0

    def test_blocklist_forces_critical(self, engine):
        """Test blocklist hit forces Critical regardless of score."""
        signals = [
            {"key": "generic_greeting", "category": "linguistic", "label": "Generic Greeting",
             "points": 5, "reason": "test", "evidence": "test"}
        ]
        result = engine.calculate(signals, blocklist_hit=True)
        assert result.score >= 70
        assert result.level == "Critical"
        assert result.action == "block"

    def test_score_clamped_to_100(self, engine):
        """Test score never exceeds 100."""
        signals = [
            {"key": "blocklist_hit", "category": "reputation", "label": "Blocklist Hit",
             "points": 100, "reason": "test", "evidence": "test"},
            {"key": "typosquat", "category": "impersonation", "label": "Typosquat",
             "points": 25, "reason": "test", "evidence": "test"}
        ]
        result = engine.calculate(signals)
        assert result.score <= 100

    def test_score_never_negative(self, engine):
        """Test score never goes below 0."""
        signals = []
        result = engine.calculate(signals)
        assert result.score >= 0

    def test_signals_sorted_by_points(self, engine):
        """Test returned signals are sorted by points descending."""
        signals = [
            {"key": "a", "category": "linguistic", "label": "A",
             "points": 5, "reason": "test", "evidence": "test"},
            {"key": "b", "category": "linguistic", "label": "B",
             "points": 15, "reason": "test", "evidence": "test"},
            {"key": "c", "category": "linguistic", "label": "C",
             "points": 10, "reason": "test", "evidence": "test"}
        ]
        result = engine.calculate(signals)
        points = [s.points for s in result.signals]
        assert points == sorted(points, reverse=True)

    def test_category_scores_present(self, engine):
        """Test category_scores dict is present."""
        signals = [
            {"key": "urgency", "category": "linguistic", "label": "Urgency",
             "points": 8, "reason": "test", "evidence": "test"},
            {"key": "suspicious_tld", "category": "structural", "label": "Suspicious TLD",
             "points": 10, "reason": "test", "evidence": "test"}
        ]
        result = engine.calculate(signals)
        assert "category_scores" in result.__dict__
        assert "linguistic" in result.category_scores
        assert "structural" in result.category_scores


class TestCalculateScoreFunction:
    """Test the backward compatibility function."""

    def test_returns_dict_format(self):
        signals = [
            {"key": "urgency", "category": "linguistic", "label": "Urgency",
             "points": 8, "reason": "test", "evidence": "test"}
        ]
        result = calculate_score(signals)
        assert isinstance(result, dict)
        assert "score" in result
        assert "level" in result
        assert "action" in result
        assert "signals" in result
        assert "category_scores" in result
        assert "combo_bonuses" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])