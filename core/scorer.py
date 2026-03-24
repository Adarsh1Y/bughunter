"""Scoring engine for endpoint prioritization."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def score_endpoint(data: dict) -> int:
    """
    Calculate priority score for an endpoint.
    
    Args:
        data: Endpoint dict with endpoint, params, risk, vulnerability, etc.
    
    Returns:
        Numeric score (higher = more valuable target).
    """
    score = 0
    
    endpoint = data.get("endpoint", "").lower()
    params = data.get("params", [])
    risk = data.get("risk", "low")
    vuln = data.get("vulnerability", "NONE")
    
    if "api" in endpoint:
        score += 3
    
    if "user" in endpoint:
        score += 4
    
    if "admin" in endpoint:
        score += 6
    
    if "login" in endpoint:
        score += 3
    
    if "auth" in endpoint:
        score += 4
    
    if "token" in endpoint:
        score += 5
    
    if "id" in params:
        score += 5
    
    if "user_id" in params:
        score += 6
    
    if "token" in params:
        score += 5
    
    if "password" in params:
        score += 4
    
    if "search" in endpoint or "query" in params:
        score += 2
    
    if "file" in params or "upload" in params:
        score += 4
    
    risk_scores = {"high": 5, "medium": 3, "low": 1}
    score += risk_scores.get(risk, 1)
    
    vuln_scores = {
        "AUTH": 5, "IDOR": 4, "SQLI": 5, 
        "XSS": 3, "RCE": 6, "PRIVESC": 5, "NONE": 0
    }
    score += vuln_scores.get(vuln, 0)
    
    return score


def score_targets(targets: list) -> list:
    """
    Score and sort targets by priority.
    
    Args:
        targets: List of target dicts.
    
    Returns:
        Targets sorted by score (descending).
    """
    scored = []
    for t in targets:
        t["score"] = score_endpoint(t)
        scored.append(t)
    
    return sorted(scored, key=lambda x: x.get("score", 0), reverse=True)


def filter_by_score(targets: list, min_score: int = 7) -> list:
    """
    Filter targets by minimum score threshold.
    
    Args:
        targets: List of scored targets.
        min_score: Minimum score to keep.
    
    Returns:
        Filtered list of targets.
    """
    return [t for t in targets if t.get("score", 0) >= min_score]


def filter_by_confidence(targets: list, min_confidence: float = 0.6) -> list:
    """
    Filter targets by minimum confidence.
    
    Args:
        targets: List of target dicts.
        min_confidence: Minimum confidence (0.0-1.0).
    
    Returns:
        Filtered list of targets.
    """
    return [t for t in targets if t.get("confidence", 0) >= min_confidence]


def get_top_targets(targets: list, limit: int = 3) -> list:
    """
    Get top N targets by score.
    
    Args:
        targets: List of target dicts.
        limit: Maximum number to return.
    
    Returns:
        Top N targets.
    """
    return targets[:limit]
