"""Basic response analyzer for detecting anomalies - optimized for low RAM."""

import sys
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def _get_max_response_size() -> int:
    """Get max response size from config."""
    try:
        from config import get

        result = get("low_ram.max_response_size", 200)
        return int(result) if result else 200
    except:
        return 200


def create_lightweight_response(
    status: int, length: int, body: str = "", payload: str = ""
) -> dict:
    """
    Create a lightweight response dict.

    Args:
        status: HTTP status code.
        length: Response body length.
        body: Response body (truncated to max size).
        payload: The payload used.

    Returns:
        Lightweight response dict.
    """
    max_size = _get_max_response_size()
    truncated_body = body[:max_size] if body else ""

    return {"status": status, "length": length, "body_preview": truncated_body, "payload": payload}


def analyze_responses(responses: list) -> list:
    """
    Analyze responses for anomalies.

    Args:
        responses: List of response dicts from Burp proxy.

    Returns:
        List of anomaly dicts.
    """
    if not responses or len(responses) < 2:
        return []

    anomalies = []
    baseline = responses[0]

    if baseline.get("status") == 0:
        return []

    for i, resp in enumerate(responses[1:], 1):
        anomaly = detect_anomaly(baseline, resp, i)
        if anomaly:
            anomalies.append(anomaly)

    return anomalies


def detect_anomaly(baseline: dict, response: dict, index: int) -> dict | None:
    """
    Detect anomaly between baseline and a response with confidence scoring.

    Args:
        baseline: Baseline response.
        response: Response to compare.
        index: Index of response in list.

    Returns:
        Anomaly dict with confidence score or None.
    """
    if response.get("status") == 0:
        return {
            "index": index,
            "type": "error",
            "description": f"Request failed: {response.get('error', 'unknown')}",
            "severity": "info",
            "confidence": 0.0,
            "next_step": "N/A - request failed",
        }

    confidence = 0.0
    status_diff = response.get("status", 0) - baseline.get("status", 0)

    if status_diff > 0:
        confidence += 0.4
        vuln_type = "auth_bypass" if response.get("status") == 200 else "status_injection"
        return {
            "index": index,
            "type": "status_change",
            "vulnerability": vuln_type,
            "baseline_status": baseline.get("status"),
            "new_status": response.get("status"),
            "description": f"Status changed: {baseline.get('status')} -> {response.get('status')}",
            "severity": "high",
            "confidence": min(confidence + 0.4, 1.0),
            "payload": response.get("payload", ""),
            "next_step": "Test with different session/token to confirm auth bypass",
        }

    length_diff = response.get("length", 0) - baseline.get("length", 0)
    baseline_length = baseline.get("length", 1)

    if baseline_length > 0 and abs(length_diff) > 150:
        confidence += 0.3

        if abs(length_diff) > 500:
            confidence += 0.2

        body1 = baseline.get("body_preview", "")
        body2 = response.get("body_preview", "")
        if body1 and body2 and body1 != body2:
            confidence += 0.5

        vuln_type = "possible_idor" if length_diff > 0 else "data_manipulation"

        return {
            "index": index,
            "type": "size_difference",
            "vulnerability": vuln_type,
            "baseline_size": baseline.get("length"),
            "new_size": response.get("length"),
            "difference": length_diff,
            "description": f"Size changed by {length_diff} bytes ({baseline.get('length')} -> {response.get('length')})",
            "severity": "high" if abs(length_diff) > 500 else "medium",
            "confidence": min(confidence, 1.0),
            "payload": response.get("payload", ""),
            "next_step": "Try changing the ID parameter to access another user's resource",
        }

    return None


def filter_by_confidence(anomalies: list, min_confidence: float = 0.5) -> list:
    """
    Filter anomalies by minimum confidence threshold.

    Args:
        anomalies: List of anomaly dicts.
        min_confidence: Minimum confidence to include (default: 0.5).

    Returns:
        Filtered list of anomalies.
    """
    return [a for a in anomalies if a.get("confidence", 0) >= min_confidence]


def summarize_anomalies(anomalies: list) -> str:
    """
    Create a summary of detected anomalies.
    """
    if not anomalies:
        return "No anomalies detected."

    summary = f"Found {len(anomalies)} anomaly(s):\n"

    for a in anomalies:
        summary += f"\n- [{a['severity'].upper()}] {a['type']}: {a['description']}"
        if a.get("payload"):
            summary += f"\n  Payload: {a['payload']}"

    return summary


SENSITIVE_DATA_PATTERNS = [
    "password",
    "passwd",
    "pwd",
    "email",
    "phone",
    "address",
    "ssn",
    "credit_card",
    "card_number",
    "cvv",
    "api_key",
    "secret_key",
    "token",
    "session_id",
    "auth_token",
]


def detect_sensitive_data(body: str) -> list:
    """
    Detect sensitive data in response body.

    Args:
        body: Response body text.

    Returns:
        List of detected sensitive fields.
    """
    detected = []
    body_lower = body.lower()

    for pattern in SENSITIVE_DATA_PATTERNS:
        if pattern in body_lower:
            detected.append(pattern)

    return detected


def analyze_cross_user_responses(responses: list) -> list:
    """
    Analyze responses from multiple users to detect cross-user vulnerabilities.

    Args:
        responses: List of response dicts with 'user' field.

    Returns:
        List of cross-user vulnerability findings.
    """
    findings = []

    for i, resp1 in enumerate(responses):
        for resp2 in responses[i + 1 :]:
            finding = compare_user_responses(resp1, resp2)
            if finding:
                findings.append(finding)

    return findings


def compare_user_responses(resp1: dict, resp2: dict) -> dict | None:
    """
    Compare responses from two different users on same endpoint.

    Args:
        resp1: Response from user 1.
        resp2: Response from user 2.

    Returns:
        Finding dict or None.
    """
    user1 = resp1.get("user", "unknown")
    user2 = resp2.get("user", "unknown")

    if user1 == user2:
        return None

    url1 = resp1.get("url", "")
    url2 = resp2.get("url", "")

    status1 = resp1.get("status", 0)
    status2 = resp2.get("status", 0)

    length1 = resp1.get("length", 0)
    length2 = resp2.get("length", 0)

    body1 = resp1.get("body_preview", "")
    body2 = resp2.get("body_preview", "")

    finding = None

    if status1 == 200 and status2 == 200:
        if abs(length1 - length2) < 50 and length1 > 100:
            finding = {
                "type": "data_exposure",
                "severity": "high",
                "issue": "idor",
                "confidence": 0.85,
                "description": f"Users '{user1}' and '{user2}' received same data",
                "user1": {"user": user1, "status": status1, "length": length1},
                "user2": {"user": user2, "status": status2, "length": length2},
                "url": url1,
            }

    if status1 == 200 and status2 == 403:
        finding = {
            "type": "permission_bypass",
            "severity": "high",
            "issue": "auth_bypass",
            "confidence": 0.9,
            "description": f"User '{user2}' bypassed authorization (got 200 vs 403)",
            "user1": {"user": user1, "status": status1},
            "user2": {"user": user2, "status": status2},
            "url": url1,
        }

    if status1 == 403 and status2 == 200:
        finding = {
            "type": "permission_bypass",
            "severity": "high",
            "issue": "auth_bypass",
            "confidence": 0.9,
            "description": f"User '{user1}' bypassed authorization (got 200 vs 403)",
            "user1": {"user": user1, "status": status1},
            "user2": {"user": user2, "status": status2},
            "url": url1,
        }

    sensitive1 = detect_sensitive_data(body1)
    sensitive2 = detect_sensitive_data(body2)

    if sensitive1 or sensitive2:
        common = set(sensitive1) & set(sensitive2)
        if common:
            finding = {
                "type": "sensitive_data_leak",
                "severity": "critical",
                "issue": "data_exposure",
                "confidence": 0.95,
                "description": f"Sensitive data detected: {', '.join(common)}",
                "exposed_fields": list(common),
                "user1": {"user": user1, "status": status1},
                "user2": {"user": user2, "status": status2},
                "url": url1,
            }

    return finding


def analyze_multi_user_access(responses: list) -> dict:
    """
    Comprehensive multi-user access analysis.

    Args:
        responses: List of responses from multiple users.

    Returns:
        Analysis summary dict.
    """
    users = set(r.get("user", "unknown") for r in responses)

    findings = analyze_cross_user_responses(responses)

    idor_findings = [f for f in findings if f.get("issue") == "idor"]
    auth_findings = [f for f in findings if f.get("issue") == "auth_bypass"]
    data_findings = [f for f in findings if f.get("issue") == "data_exposure"]

    return {
        "users_tested": list(users),
        "total_responses": len(responses),
        "total_findings": len(findings),
        "findings_by_type": {
            "idor": len(idor_findings),
            "auth_bypass": len(auth_findings),
            "data_exposure": len(data_findings),
        },
        "findings": findings,
        "severity_summary": _summarize_severity(findings),
    }


def _summarize_severity(findings: list) -> dict:
    """Summarize findings by severity."""
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        if sev in summary:
            summary[sev] += 1
    return summary
