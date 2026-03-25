"""Tests for the scorer module."""

import pytest

from core.scorer import (
    score_endpoint,
    score_targets,
    filter_by_score,
    filter_by_confidence,
    get_top_targets,
)


class TestScoreEndpoint:
    """Tests for score_endpoint function."""

    def test_scores_id_parameter_high(self):
        data = {
            "endpoint": "/api/users",
            "params": ["id"],
            "vulnerability": "IDOR",
            "risk": "medium",
        }
        score = score_endpoint(data)
        assert score > 10

    def test_scores_user_id_higher_than_id(self):
        base = {
            "endpoint": "/api/data",
            "params": [],
            "vulnerability": "IDOR",
            "risk": "medium",
        }
        base["params"] = ["id"]
        score_id = score_endpoint(base)

        base["params"] = ["user_id"]
        score_user_id = score_endpoint(base)

        assert score_user_id > score_id

    def test_scores_admin_endpoint_high(self):
        data = {
            "endpoint": "/api/admin/users",
            "params": [],
            "vulnerability": "PRIVESC",
            "risk": "high",
        }
        score = score_endpoint(data)
        assert score >= 15

    def test_scores_api_endpoint(self):
        data = {
            "endpoint": "/api/users",
            "params": [],
            "vulnerability": "NONE",
            "risk": "low",
        }
        score = score_endpoint(data)
        assert score >= 3

    def test_scores_user_endpoint(self):
        data = {
            "endpoint": "/api/users/profile",
            "params": [],
            "vulnerability": "IDOR",
            "risk": "medium",
        }
        score = score_endpoint(data)
        assert score >= 8

    def test_scores_org_endpoint(self):
        data = {
            "endpoint": "/api/orgs",
            "params": ["id"],
            "vulnerability": "IDOR",
            "risk": "medium",
        }
        score = score_endpoint(data)
        assert score >= 12

    def test_handles_empty_data(self):
        score = score_endpoint({})
        assert score >= 0


class TestScoreTargets:
    """Tests for score_targets function."""

    def test_returns_sorted_targets(self):
        targets = [
            {"endpoint": "/api/low", "params": [], "vulnerability": "NONE", "risk": "low"},
            {"endpoint": "/api/high", "params": ["id"], "vulnerability": "IDOR", "risk": "medium"},
        ]
        scored = score_targets(targets)

        assert scored[0]["score"] >= scored[1]["score"]
        assert "score" in scored[0]
        assert "score" in scored[1]

    def test_preserves_target_data(self):
        targets = [
            {"endpoint": "/api/test", "params": ["id"], "vulnerability": "IDOR", "risk": "medium"},
        ]
        scored = score_targets(targets)

        assert scored[0]["endpoint"] == "/api/test"
        assert scored[0]["score"] > 0


class TestFilterByScore:
    """Tests for filter_by_score function."""

    def test_filters_by_minimum_score(self):
        targets = [
            {"score": 5},
            {"score": 10},
            {"score": 15},
        ]
        filtered = filter_by_score(targets, min_score=10)

        assert len(filtered) == 2
        assert all(t["score"] >= 10 for t in filtered)

    def test_empty_list_returns_empty(self):
        assert filter_by_score([]) == []


class TestFilterByConfidence:
    """Tests for filter_by_confidence function."""

    def test_filters_by_minimum_confidence(self):
        targets = [
            {"confidence": 0.3},
            {"confidence": 0.6},
            {"confidence": 0.9},
        ]
        filtered = filter_by_confidence(targets, min_confidence=0.6)

        assert len(filtered) == 2
        assert all(t["confidence"] >= 0.6 for t in filtered)

    def test_handles_missing_confidence(self):
        targets = [{"score": 10}, {"confidence": 0.8}]
        filtered = filter_by_confidence(targets, min_confidence=0.5)

        assert len(filtered) == 1


class TestGetTopTargets:
    """Tests for get_top_targets function."""

    def test_returns_limited_count(self):
        targets = [{"endpoint": f"/api/test{i}"} for i in range(10)]
        top = get_top_targets(targets, limit=3)

        assert len(top) == 3

    def test_returns_all_if_less_than_limit(self):
        targets = [{"score": 1}, {"score": 2}]
        top = get_top_targets(targets, limit=5)

        assert len(top) == 2

    def test_empty_list_returns_empty(self):
        assert get_top_targets([]) == []
