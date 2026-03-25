"""Cross-user testing for IDOR and privilege escalation detection."""

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def test_same_endpoint_different_users(
    base_url: str, endpoint: str, user1: str, user2: str, param: str = "id", param_value: str = "1"
) -> dict:
    """
    Test if user2 can access the same resource as user1.

    Args:
        base_url: Target base URL.
        endpoint: API endpoint (e.g., "/api/orders").
        user1: First user (should have legitimate access).
        user2: Second user (testing for unauthorized access).
        param: Parameter name (default: "id").
        param_value: Parameter value to test.

    Returns:
        Dict with test results and vulnerability findings.
    """
    from core.burp import send_request_as_user
    from agents.stateful import compare_responses

    url = f"{base_url.rstrip('/')}{endpoint}?{param}={param_value}"

    print(f"\n[Cross-User Test] {endpoint}")
    print(f"  User1 ({user1}) accessing {param}={param_value}...")

    resp1 = send_request_as_user(url, user1)

    print(f"  User2 ({user2}) attempting same request...")

    resp2 = send_request_as_user(url, user2)

    comparison = compare_responses(resp1, resp2)

    result = {
        "endpoint": endpoint,
        "param": param,
        "param_value": param_value,
        "url": url,
        "user1": {"user": user1, "status": resp1.get("status"), "length": resp1.get("length")},
        "user2": {"user": user2, "status": resp2.get("status"), "length": resp2.get("length")},
        "comparison": comparison,
        "idor_detected": comparison["issue"] == "idor",
        "auth_bypass_detected": comparison["issue"] == "auth_bypass",
    }

    if result["idor_detected"]:
        print(f"  [!] IDOR POSSIBLE")
        print(f"      {comparison['evidence']}")
    elif result["auth_bypass_detected"]:
        print(f"  [!] AUTH BYPASS POSSIBLE")
        print(f"      {comparison['evidence']}")
    else:
        print(f"  [+] No issue detected")

    return result


def test_horizontal_escalation(
    base_url: str, user1: str, user2: str, resource: str = "/api/profile"
) -> dict:
    """
    Test horizontal privilege escalation.
    User2 tries to access user1's resources.

    Args:
        base_url: Target base URL.
        user1: Victim user.
        user2: Attacker user.
        resource: Resource endpoint to test.

    Returns:
        Test results.
    """
    return test_same_endpoint_different_users(
        base_url, resource, user1, user2, param="id", param_value="1"
    )


def test_vertical_escalation(
    base_url: str, regular_user: str, admin_user: str, admin_endpoint: str = "/api/admin"
) -> dict:
    """
    Test vertical privilege escalation.
    Regular user tries to access admin endpoints.

    Args:
        base_url: Target base URL.
        regular_user: Non-admin user.
        admin_user: Admin user.
        admin_endpoint: Admin endpoint to test.

    Returns:
        Test results.
    """
    from core.burp import send_request_as_user
    from agents.stateful import compare_responses

    url = f"{base_url.rstrip('/')}{admin_endpoint}"

    print(f"\n[Vertical Escalation Test] {admin_endpoint}")
    print(f"  Regular user ({regular_user}) attempting admin access...")

    resp_regular = send_request_as_user(url, regular_user)

    print(f"  Admin user ({admin_user}) accessing...")

    resp_admin = send_request_as_user(url, admin_user)

    comparison = compare_responses(resp_regular, resp_admin)

    result = {
        "endpoint": admin_endpoint,
        "regular_user": {
            "user": regular_user,
            "status": resp_regular.get("status"),
            "length": resp_regular.get("length"),
        },
        "admin_user": {
            "user": admin_user,
            "status": resp_admin.get("status"),
            "length": resp_admin.get("length"),
        },
        "comparison": comparison,
        "privesc_detected": (resp_regular.get("status") == 200 and resp_admin.get("status") == 200),
    }

    if result["privesc_detected"]:
        print(f"  [!] PRIVILEGE ESCALATION DETECTED")
        print(f"      Regular user accessed admin endpoint")
    else:
        print(f"  [+] No privilege escalation (403 expected for regular user)")

    return result


def test_batch_idor(
    base_url: str, endpoint: str, user1: str, user2: str, param: str = "id", values: list = None
) -> dict:
    """
    Test IDOR across multiple resource IDs.

    Args:
        base_url: Target base URL.
        endpoint: API endpoint.
        user1: First user.
        user2: Second user.
        param: Parameter name.
        values: List of IDs to test.

    Returns:
        Dict with all test results.
    """
    if values is None:
        values = ["1", "2", "3", "999", "admin"]

    results = {
        "endpoint": endpoint,
        "param": param,
        "tests": [],
        "vulnerabilities_found": 0,
        "summary": "",
    }

    print(f"\n[Batch IDOR Test] {endpoint}")
    print(f"  Testing {len(values)} values: {values}")

    for value in values:
        print(f"\n  Testing {param}={value}...")
        result = test_same_endpoint_different_users(
            base_url, endpoint, user1, user2, param=param, param_value=value
        )
        results["tests"].append(result)

        if result["idor_detected"] or result["auth_bypass_detected"]:
            results["vulnerabilities_found"] += 1

    results["summary"] = (
        f"Found {results['vulnerabilities_found']} vulnerabilities out of {len(values)} tests"
    )

    print(f"\n{results['summary']}")

    return results


def test_multi_user_all_endpoints(base_url: str, endpoints: list, user1: str, user2: str) -> dict:
    """
    Test multiple endpoints for cross-user vulnerabilities.

    Args:
        base_url: Target base URL.
        endpoints: List of endpoint strings.
        user1: First user.
        user2: Second user.

    Returns:
        Summary of all tests.
    """
    results = {"tests": [], "vulnerabilities_found": 0, "endpoints_tested": len(endpoints)}

    print(f"\n[Multi-Endpoint Test] Testing {len(endpoints)} endpoints")

    for endpoint in endpoints:
        print(f"\n  Testing: {endpoint}")
        result = test_same_endpoint_different_users(base_url, endpoint, user1, user2)
        results["tests"].append(result)

        if result["idor_detected"] or result["auth_bypass_detected"]:
            results["vulnerabilities_found"] += 1
            print(f"    [!] ANOMALY DETECTED")

    print(
        f"\n[Summary] {results['vulnerabilities_found']}/{len(endpoints)} endpoints show anomalies"
    )

    return results
