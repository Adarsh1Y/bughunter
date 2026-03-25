"""Response validation engine - compare responses and validate findings."""

import re
from typing import Optional


def validate_response(response_a: str, response_b: str) -> dict:
    """
    Compare two responses and return validation result.

    Args:
        response_a: Baseline/control response
        response_b: Test response to compare

    Returns:
        dict with:
        - changed: bool
        - difference_score: 0.0-1.0
        - reason: str describing the difference
        - details: dict with specific comparisons
    """
    if not response_a or not response_b:
        return {
            "changed": False,
            "difference_score": 0.0,
            "reason": "empty response",
            "details": {},
        }

    details = {}
    reasons = []
    score = 0.0

    len_a = len(response_a)
    len_b = len(response_b)
    details["length_a"] = len_a
    details["length_b"] = len_b

    if len_a != len_b:
        diff_pct = abs(len_a - len_b) / max(len_a, len_b)
        details["length_diff_pct"] = round(diff_pct, 2)
        if diff_pct > 0.1:
            score += 0.3
            reasons.append("response length changed")

    if response_a != response_b:
        score += 0.2
        details["content_changed"] = True
        if "content_changed" not in reasons:
            reasons.append("content differs")

    response_a_lower = response_a.lower()
    response_b_lower = response_b.lower()

    if response_a_lower == response_b_lower:
        details["case_sensitive_diff"] = True
        score += 0.1
        reasons.append("case difference only")

    return {
        "changed": len_a != len_b or response_a != response_b,
        "difference_score": min(score, 1.0),
        "reason": "; ".join(reasons) if reasons else "no difference",
        "details": details,
    }


def validate_idor(response_a: str, response_b: str) -> dict:
    """
    Validate IDOR vulnerability.

    Mark as POSSIBLE only if:
    - response_a != response_b
    - AND content suggests different user data

    Args:
        response_a: Baseline response (your user)
        response_b: Test response (different user)

    Returns:
        dict with status and details
    """
    result = validate_response(response_a, response_b)

    if not result["changed"]:
        return {
            "status": "NO ISSUE",
            "confidence": None,
            "reason": "No response change detected",
            "details": result,
        }

    result["confidence"] = "LOW"
    result["reason"] = "Response changed"
    result["details"]["vuln_type"] = "IDOR"

    user_patterns = [
        r'"user"\s*:\s*"([^"]+)"',
        r'"username"\s*:\s*"([^"]+)"',
        r'"id"\s*:\s*(\d+)',
        r'"email"\s*:\s*"([^"]+)"',
        r'"name"\s*:\s*"([^"]+)"',
    ]

    users_a = set()
    users_b = set()

    for pattern in user_patterns:
        matches_a = re.findall(pattern, response_a, re.IGNORECASE)
        matches_b = re.findall(pattern, response_b, re.IGNORECASE)
        users_a.update(matches_a)
        users_b.update(matches_b)

    if users_a and users_b and users_a != users_b:
        result["confidence"] = "HIGH"
        result["status"] = "POSSIBLE"
        result["reason"] = f"Different user data detected: {users_a} vs {users_b}"
        result["details"]["users_a"] = list(users_a)
        result["details"]["users_b"] = list(users_b)
    elif result["difference_score"] > 0.2:
        result["confidence"] = "MEDIUM"
        result["status"] = "POSSIBLE"
        result["reason"] = "Response changed but no clear user difference"
    else:
        result["status"] = "NO ISSUE"
        result["reason"] = "Minor response change, likely normal variation"

    return result


def validate_path_traversal(response: str) -> dict:
    """
    Validate path traversal vulnerability.

    Mark as POSSIBLE only if response contains real file content.

    Args:
        response: Response from the test request

    Returns:
        dict with status and details
    """
    file_patterns = [
        r"root:x:\d+:\d+:",
        r"daemon:x:\d+:\d+:",
        r"bin:x:\d+:\d+:",
        r"nobody:x:\d+:\d+:",
        r"^[a-z_][a-z0-9_-]*\[\d+\]:",
        r"^\s*\d+\s+\S+\s+\S+",
        r"#.*\n.*:\s*/",
    ]

    linux_patterns = [
        r"root:x:0:0:",
        r"/bin/bash",
        r"/usr/bin/",
        r"uid=\d+",
    ]

    file_indicators = 0
    matched_pattern = None

    for pattern in file_patterns + linux_patterns:
        if re.search(pattern, response, re.MULTILINE):
            file_indicators += 1
            matched_pattern = pattern
            break

    if file_indicators == 0:
        return {
            "status": "NO ISSUE",
            "confidence": None,
            "reason": "No file content patterns detected",
            "details": {"checked_patterns": len(file_patterns) + len(linux_patterns)},
        }

    content_snippet = response[:500] if len(response) > 500 else response
    return {
        "status": "POSSIBLE",
        "confidence": "HIGH",
        "reason": f"File content pattern detected (matched: {matched_pattern})",
        "details": {
            "vuln_type": "PATH_TRAVERSAL",
            "pattern_matched": matched_pattern,
            "response_size": len(response),
            "snippet": content_snippet,
        },
    }


def validate_rce(response: str, command: str = "id") -> dict:
    """
    Validate command injection / RCE vulnerability.

    Mark as POSSIBLE only if response contains actual command output.

    Args:
        response: Response from the test request
        command: The command that was injected

    Returns:
        dict with status and details
    """
    command_output_patterns = [
        (r"uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)", "Linux uid/gid"),
        (r"uid=\d+", "UID found"),
        (r"root|daemon|bin|nobody", "System users"),
        (r"groups=\d+", "Group information"),
        (r"Windows", "Windows system"),
        (r"Microsoft Windows", "Windows"),
        (r"NT AUTHORITY", "Windows AD"),
    ]

    matched = []
    for pattern, description in command_output_patterns:
        if re.search(pattern, response, re.IGNORECASE):
            matched.append(description)

    if not matched:
        return {
            "status": "NO ISSUE",
            "confidence": None,
            "reason": "No command output patterns detected",
            "details": {"checked_patterns": len(command_output_patterns)},
        }

    output_snippet = response[:300] if len(response) > 300 else response
    return {
        "status": "POSSIBLE",
        "confidence": "HIGH",
        "reason": f"Command output detected: {', '.join(matched)}",
        "details": {
            "vuln_type": "RCE",
            "indicators": matched,
            "response_size": len(response),
            "snippet": output_snippet,
        },
    }


def validate_lfi(response: str) -> dict:
    """
    Validate LFI vulnerability.

    Mark as POSSIBLE only if actual file content is returned.

    Args:
        response: Response from the test request

    Returns:
        dict with status and details
    """
    content_indicators = [
        r"[a-z]+\s*:\s*[^<>{}|$]+",  # key: value format
        r"^\s*[a-z_][a-z0-9_-]+\s*=",  # VARIABLE= format
        r"^#.*\n",  # Comments
        r"\d+\.\d+\.\d+\.\d+",  # IP addresses
        r"localhost|127\.0\.0\.1",  # Localhost
    ]

    matched = []
    for pattern in content_indicators:
        if re.search(pattern, response, re.MULTILINE):
            matched.append(pattern[:30])

    if len(matched) < 2:
        return {
            "status": "NO ISSUE",
            "confidence": None,
            "reason": "No clear file content patterns",
            "details": {"matched_indicators": len(matched)},
        }

    return {
        "status": "POSSIBLE",
        "confidence": "MEDIUM",
        "reason": f"File-like content patterns detected ({len(matched)} indicators)",
        "details": {
            "vuln_type": "LFI",
            "indicators": matched,
            "response_size": len(response),
            "snippet": response[:300],
        },
    }


def validate_admin_bypass(response: str) -> dict:
    """
    Validate admin/authentication bypass.

    Args:
        response: Response from admin endpoint

    Returns:
        dict with status and details
    """
    if not response:
        return {"status": "NO ISSUE", "confidence": None, "reason": "Empty response", "details": {}}

    admin_indicators = [
        r'"admin"\s*:\s*true',
        r'"role"\s*:\s*"\s*admin',
        r'"privileged"\s*:\s*true',
        r'"superuser"\s*:\s*true',
    ]

    matched = []
    for pattern in admin_indicators:
        if re.search(pattern, response, re.IGNORECASE):
            matched.append(pattern)

    if not matched:
        return {
            "status": "NO ISSUE",
            "confidence": None,
            "reason": "No admin indicators found",
            "details": {},
        }

    return {
        "status": "POSSIBLE",
        "confidence": "HIGH",
        "reason": "Admin/privileged indicators found in response",
        "details": {"vuln_type": "AUTH_BYPASS", "indicators": matched, "snippet": response[:200]},
    }


def format_validation_result(result: dict) -> str:
    """Format validation result for display."""
    output = []
    output.append(f"\nStatus: {result.get('status', 'UNKNOWN')}")

    if result.get("confidence"):
        output.append(f"Confidence: {result['confidence']}")

    output.append(f"\nReason: {result.get('reason', 'No reason provided')}")

    if "snippet" in result.get("details", {}):
        snippet = result["details"]["snippet"]
        if len(snippet) > 200:
            snippet = snippet[:200] + "..."
        output.append(f"\nResponse snippet:\n{snippet}")

    output.append("\n[Manual verification required]")

    return "\n".join(output)
