"""Session comparison engine for multi-user vulnerability detection."""

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def compare_responses(resp1: dict, resp2: dict) -> dict:
    """
    Compare responses from different users on the same endpoint.
    
    Args:
        resp1: Response from user 1 (dict with status, length, body_preview, url, user)
        resp2: Response from user 2 (dict with status, length, body_preview, url, user)
    
    Returns:
        Dict with comparison results:
        {
            "issue": "idor"|"auth_bypass"|"data_leak"|"none",
            "evidence": "description of the issue",
            "confidence": 0.0-1.0,
            "severity": "high"|"medium"|"low"
        }
    """
    result = {
        "issue": "none",
        "evidence": "",
        "confidence": 0.0,
        "severity": "low",
        "details": {}
    }
    
    if not resp1 or not resp2:
        return result
    
    url1 = resp1.get("url", "")
    url2 = resp2.get("url", "")
    
    user1 = resp1.get("user", "unknown")
    user2 = resp2.get("user", "unknown")
    
    status1 = resp1.get("status", 0)
    status2 = resp2.get("status", 0)
    
    length1 = resp1.get("length", 0)
    length2 = resp2.get("length", 0)
    
    body1 = resp1.get("body_preview", "")
    body2 = resp2.get("body_preview", "")
    
    result["details"] = {
        "user1": {"status": status1, "length": length1, "user": user1},
        "user2": {"status": status2, "length": length2, "user": user2}
    }
    
    if status1 == 0 or status2 == 0:
        return result
    
    if status1 == 200 and status2 == 200:
        if _check_idor(resp1, resp2):
            result["issue"] = "idor"
            result["confidence"] = 0.85
            result["severity"] = "high"
            result["evidence"] = f"User '{user1}' accessed same resource as '{user2}'"
        
        elif _check_data_leak(body1, body2, length1, length2):
            result["issue"] = "data_leak"
            result["confidence"] = 0.75
            result["severity"] = "medium"
            result["evidence"] = f"Different data returned: {length1} vs {length2} bytes"
    
    if status1 == 403 and status2 == 200:
        result["issue"] = "auth_bypass"
        result["confidence"] = 0.9
        result["severity"] = "high"
        result["evidence"] = f"User '{user2}' bypassed authorization"
    
    if status1 == 401 and status2 == 200:
        result["issue"] = "auth_bypass"
        result["confidence"] = 0.85
        result["severity"] = "high"
        result["evidence"] = f"Unauthenticated user '{user1}' got access"
    
    if status1 == 200 and status2 == 401:
        result["issue"] = "authorization_issue"
        result["confidence"] = 0.6
        result["severity"] = "low"
        result["evidence"] = "Inconsistent auth handling"
    
    return result


def _check_idor(resp1: dict, resp2: dict) -> bool:
    """Check if same URL returns data for different users."""
    url1 = resp1.get("url", "")
    url2 = resp2.get("url", "")
    
    if url1 == url2:
        length1 = resp1.get("length", 0)
        length2 = resp2.get("length", 0)
        
        if length1 > 0 and length2 > 0 and abs(length1 - length2) < 100:
            return True
    
    return False


def _check_data_leak(body1: str, body2: str, length1: int, length2: int) -> bool:
    """Check if sensitive data is leaking between users."""
    if length1 == 0 or length2 == 0:
        return False
    
    if abs(length1 - length2) > 500:
        return True
    
    sensitive_keywords = ["password", "email", "phone", "address", "ssn", "credit"]
    body1_lower = body1.lower()
    body2_lower = body2.lower()
    
    for keyword in sensitive_keywords:
        if keyword in body1_lower and keyword in body2_lower:
            return True
    
    return False


def compare_multi_user(responses: list) -> list:
    """
    Compare multiple responses and find vulnerabilities.
    
    Args:
        responses: List of response dicts from different users.
    
    Returns:
        List of findings.
    """
    findings = []
    
    for i, resp1 in enumerate(responses):
        for resp2 in responses[i + 1:]:
            comparison = compare_responses(resp1, resp2)
            
            if comparison["issue"] != "none":
                comparison["resp1_user"] = resp1.get("user")
                comparison["resp2_user"] = resp2.get("user")
                comparison["url"] = resp1.get("url")
                findings.append(comparison)
    
    return findings


def analyze_cross_user_access(url: str, user1_resp: dict, user2_resp: dict) -> dict:
    """
    Analyze cross-user access vulnerability for a specific URL.
    
    Args:
        url: The endpoint being tested.
        user1_resp: Response from first user.
        user2_resp: Response from second user.
    
    Returns:
        Analysis dict.
    """
    if not user1_resp or not user2_resp:
        return {"issue": "none", "evidence": "No response data"}
    
    user1_resp["url"] = url
    user2_resp["url"] = url
    
    comparison = compare_responses(user1_resp, user2_resp)
    
    if comparison["issue"] == "idor":
        comparison["recommendation"] = "Test with user A's ID while logged in as user B"
        comparison["impact"] = "Horizontal privilege escalation - access other users' data"
    
    elif comparison["issue"] == "auth_bypass":
        comparison["recommendation"] = "Check authorization checks on this endpoint"
        comparison["impact"] = "Authentication/authorization bypass"
    
    elif comparison["issue"] == "data_leak":
        comparison["recommendation"] = "Verify data isolation between users"
        comparison["impact"] = "Information disclosure"
    
    return comparison
