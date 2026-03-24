"""Dedicated IDOR detection module - high priority vulnerability detection."""

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


IDOR_PATTERNS = {
    "id": {"type": "numeric_id", "risk": "high"},
    "user_id": {"type": "user_reference", "risk": "critical"},
    "account_id": {"type": "account_reference", "risk": "critical"},
    "order_id": {"type": "order_reference", "risk": "high"},
    "post_id": {"type": "post_reference", "risk": "medium"},
    "transaction_id": {"type": "transaction_reference", "risk": "critical"},
    "invoice_id": {"type": "invoice_reference", "risk": "high"},
    "payment_id": {"type": "payment_reference", "risk": "critical"},
    "profile_id": {"type": "profile_reference", "risk": "high"},
    "document_id": {"type": "document_reference", "risk": "high"},
}

IDOR_ENDPOINT_PATTERNS = [
    "/api/users/",
    "/api/orders/",
    "/api/profile/",
    "/api/invoices/",
    "/api/documents/",
    "/api/transactions/",
    "/api/payments/",
    "/api/data/",
    "/user/",
    "/order/",
    "/profile/",
]


def detect_idor_params(endpoint: str, params: list) -> list:
    """
    Detect which parameters are likely IDOR targets.
    
    Args:
        endpoint: API endpoint path.
        params: List of parameter names.
    
    Returns:
        List of IDOR-vulnerable parameters with metadata.
    """
    idor_params = []
    
    for param in params:
        param_lower = param.lower()
        
        if param_lower in IDOR_PATTERNS:
            pattern = IDOR_PATTERNS[param_lower]
            idor_params.append({
                "param": param,
                "type": pattern["type"],
                "risk": pattern["risk"],
                "confidence": 0.9 if pattern["risk"] == "critical" else 0.8
            })
        
        elif param_lower.endswith("_id") or param_lower.endswith("Id"):
            idor_params.append({
                "param": param,
                "type": "generic_id_reference",
                "risk": "high",
                "confidence": 0.75
            })
    
    return idor_params


def is_idor_suspect_endpoint(endpoint: str) -> bool:
    """Check if endpoint is likely IDOR-vulnerable."""
    endpoint_lower = endpoint.lower()
    
    for pattern in IDOR_ENDPOINT_PATTERNS:
        if pattern in endpoint_lower:
            return True
    
    return False


def test_idor_vulnerability(
    base_url: str,
    endpoint: str,
    param: str,
    user1: str,
    user2: str,
    own_id: str = "1",
    other_id: str = "2"
) -> dict:
    """
    Test for IDOR vulnerability between two users.
    
    Tests:
    1. User1 accesses their own resource (baseline)
    2. User1 tries to access User2's resource (should fail)
    3. User2 tries to access User1's resource (should fail if IDOR)
    
    Args:
        base_url: Target base URL.
        endpoint: API endpoint.
        param: Parameter to test (e.g., "id").
        user1: First user.
        user2: Second user.
        own_id: User1's own resource ID.
        other_id: User2's resource ID.
    
    Returns:
        IDOR vulnerability assessment.
    """
    from core.burp import send_request_as_user
    from agents.stateful import compare_responses
    
    results = {
        "endpoint": endpoint,
        "param": param,
        "tests": [],
        "idor_detected": False,
        "severity": "none",
        "confidence": 0.0,
        "explanation": ""
    }
    
    base = base_url.rstrip('/')
    
    print(f"\n[IDOR Test] {endpoint}?{param}=...")
    
    print(f"  Test 1: {user1} accesses own resource ({param}={own_id})...")
    url_own = f"{base}{endpoint}?{param}={own_id}"
    resp_user1_own = send_request_as_user(url_own, user1)
    results["tests"].append({
        "test": "user1_accesses_own",
        "url": url_own,
        "status": resp_user1_own.get("status"),
        "length": resp_user1_own.get("length")
    })
    
    print(f"  Test 2: {user2} tries same resource ({param}={own_id})...")
    resp_user2_own = send_request_as_user(url_own, user2)
    results["tests"].append({
        "test": "user2_accesses_user1_resource",
        "url": url_own,
        "status": resp_user2_own.get("status"),
        "length": resp_user2_own.get("length")
    })
    
    url_other = f"{base}{endpoint}?{param}={other_id}"
    print(f"  Test 3: {user1} tries other resource ({param}={other_id})...")
    resp_user1_other = send_request_as_user(url_other, user1)
    results["tests"].append({
        "test": "user1_accesses_other",
        "url": url_other,
        "status": resp_user1_other.get("status"),
        "length": resp_user1_other.get("length")
    })
    
    comparison1 = compare_responses(resp_user2_own, resp_user1_own)
    comparison2 = compare_responses(resp_user1_other, resp_user1_own)
    
    if comparison1["issue"] == "idor" or comparison2["issue"] == "idor":
        results["idor_detected"] = True
        results["severity"] = "critical" if comparison1["confidence"] > 0.85 else "high"
        results["confidence"] = max(comparison1["confidence"], comparison2["confidence"])
        results["explanation"] = (
            f"User2 accessed User1's resource OR User1 accessed unauthorized resource. "
            f"Endpoint lacks proper authorization checks."
        )
        print(f"  [!] IDOR VULNERABILITY DETECTED (Severity: {results['severity']})")
    
    elif resp_user2_own.get("status") == 200 and resp_user1_own.get("status") == 200:
        if resp_user2_own.get("length", 0) > 0:
            results["idor_detected"] = True
            results["severity"] = "high"
            results["confidence"] = 0.8
            results["explanation"] = "Both users accessed same resource successfully - possible IDOR"
            print(f"  [!] POSSIBLE IDOR (both users got 200)")
    
    else:
        results["explanation"] = "Proper authorization checks appear to be in place"
        print(f"  [+] No IDOR detected")
    
    return results


def scan_endpoints_for_idor(
    base_url: str,
    endpoints: list,
    user1: str,
    user2: str
) -> dict:
    """
    Scan multiple endpoints for IDOR vulnerabilities.
    
    Args:
        base_url: Target base URL.
        endpoints: List of endpoints to test.
        user1: First user.
        user2: Second user.
    
    Returns:
        Scan results with all findings.
    """
    results = {
        "endpoints_tested": len(endpoints),
        "vulnerabilities_found": 0,
        "findings": []
    }
    
    print(f"\n[IDOR Scan] Testing {len(endpoints)} endpoints...")
    
    for endpoint in endpoints:
        if is_idor_suspect_endpoint(endpoint):
            print(f"\n  Scanning: {endpoint}")
            
            idor_params = detect_idor_params(endpoint, ["id"])
            if not idor_params:
                idor_params = [{"param": "id", "type": "generic", "risk": "medium", "confidence": 0.7}]
            
            for idor_param in idor_params:
                result = test_idor_vulnerability(
                    base_url, endpoint,
                    param=idor_param["param"],
                    user1=user1, user2=user2,
                    own_id="1", other_id="2"
                )
                
                results["findings"].append(result)
                
                if result["idor_detected"]:
                    results["vulnerabilities_found"] += 1
    
    print(f"\n[IDOR Scan Complete] Found {results['vulnerabilities_found']} vulnerabilities")
    
    return results


def assess_idor_risk(endpoint: str, param: str) -> dict:
    """
    Quick IDOR risk assessment for an endpoint.
    
    Args:
        endpoint: API endpoint.
        param: Parameter name.
    
    Returns:
        Risk assessment dict.
    """
    risk = "low"
    confidence = 0.5
    
    if is_idor_suspect_endpoint(endpoint):
        risk = "medium"
        confidence = 0.6
    
    param_lower = param.lower()
    if param_lower in IDOR_PATTERNS:
        risk = IDOR_PATTERNS[param_lower]["risk"]
        confidence = 0.85
    
    elif param_lower.endswith("_id"):
        risk = "high"
        confidence = 0.75
    
    return {
        "endpoint": endpoint,
        "param": param,
        "risk": risk,
        "confidence": confidence,
        "recommendation": "Test for IDOR" if risk in ("high", "critical") else "Low priority"
    }
