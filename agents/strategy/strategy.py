"""Strategy agent for prioritizing targets - focused on real bug hunting."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.scorer import score_endpoint, score_targets, filter_by_score, filter_by_confidence


def _get_max_targets() -> int:
    """Get max targets from config."""
    try:
        from config import get
        result = get("max_targets", 3)
        return int(result) if result else 3
    except:
        return 3


def prioritize(analysis_results: list, limit: int | None = None) -> list:
    """
    Prioritize targets focusing on real vulnerabilities.
    
    Focus on:
    - IDOR (Insecure Direct Object Reference)
    - Auth bypass
    - Business logic flaws
    - Data exposure
    
    Ignore:
    - Low-value endpoints
    - Static content
    """
    if not analysis_results:
        return []
    
    if limit is None:
        limit = _get_max_targets()
    
    scored = score_targets(analysis_results)
    
    filtered = filter_by_score(scored, min_score=7)
    
    filtered = filter_by_confidence(filtered, min_confidence=0.6)
    
    high_value_vulns = ["IDOR", "AUTH", "SQLI", "PRIVESC", "RCE"]
    high_value = [t for t in filtered if t.get("vulnerability") in high_value_vulns]
    
    if high_value:
        filtered = high_value
    
    if not filtered:
        filtered = [t for t in scored if t.get("score", 0) >= 4][:limit]
        filtered = filter_by_confidence(filtered, min_confidence=0.5)
    
    return filtered[:limit]


def select_targets(analysis_results: list, vuln_type: str | None = None) -> list:
    """Select targets by vulnerability type."""
    if not analysis_results:
        return []
    
    if vuln_type:
        return [r for r in analysis_results if r.get("vulnerability") == vuln_type]
    
    return analysis_results


def get_test_recommendations(target: dict) -> list:
    """
    Get targeted testing recommendations.
    
    Focus on actionable steps, not generic advice.
    """
    vuln = target.get("vulnerability", "")
    endpoint = target.get("endpoint", "")
    params = target.get("params", [])
    
    recommendations = {
        "IDOR": [
            f"Test {endpoint} with different ID values",
            "Check if you can access OTHER users' data",
            "Test horizontal escalation (user A accessing user B)",
            "Check for vertical escalation (user accessing admin data)"
        ],
        "AUTH": [
            f"Test token handling in {endpoint}",
            "Check if token is exposed in URL",
            "Test token reuse after logout",
            "Check token expiration handling"
        ],
        "SQLI": [
            f"Test SQL injection on {endpoint}",
            "Try ' OR 1=1 --",
            "Check for error messages",
            "Test blind SQLi if no errors"
        ],
        "XSS": [
            f"Test XSS on {endpoint}",
            "Try <script>alert(1)</script>",
            "Check if input is sanitized",
            "Test reflected vs stored XSS"
        ],
        "RCE": [
            f"Test command injection on {endpoint}",
            "Try ; ls or | cat /etc/passwd",
            "Check file upload restrictions",
            "Test for path traversal"
        ],
        "PRIVESC": [
            f"Test privilege escalation on {endpoint}",
            "Try accessing admin features as regular user",
            "Check role manipulation vectors",
            "Test IDOR on role-related parameters"
        ],
        "NONE": [
            "Check for common vulnerabilities",
            "Test authorization on sensitive endpoints",
            "Look for information disclosure"
        ]
    }
    
    recs = recommendations.get(vuln, recommendations["NONE"])
    return recs
