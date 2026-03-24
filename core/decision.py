"""Decision engine for vulnerability findings."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def decide(finding: dict) -> str:
    """
    Decide what action to take based on a finding.
    
    Args:
        finding: Anomaly/finding dict with confidence score.
    
    Returns:
        Decision: "likely_vulnerable", "needs_manual_test", or "ignore"
    """
    if not finding:
        return "ignore"
    
    confidence = finding.get("confidence", 0.0)
    vuln_type = finding.get("vulnerability", "")
    
    if confidence >= 0.75:
        return "likely_vulnerable"
    elif confidence >= 0.5:
        return "needs_manual_test"
    else:
        return "ignore"


def get_action_for_vulnerability(vuln_type: str) -> str:
    """
    Get suggested next action for a vulnerability type.
    
    Args:
        vuln_type: Type of vulnerability.
    
    Returns:
        Action suggestion string.
    """
    actions = {
        "idor": "Try accessing another user's resource by changing the ID parameter",
        "auth_bypass": "Test removing or modifying the session token to confirm auth bypass",
        "possible_idor": "Change ID to access other users' data - check for horizontal escalation",
        "status_injection": "Test with different payloads to confirm status code manipulation",
        "data_manipulation": "Try modifying the parameter value to alter data",
        "sensitive_data_leak": "Verify what data is exposed and assess impact",
        "permission_bypass": "Test accessing resources from different user accounts"
    }
    
    return actions.get(vuln_type.lower(), "Manual testing required to confirm vulnerability")


def evaluate_findings(findings: list) -> dict:
    """
    Evaluate all findings and return categorized results.
    
    Args:
        findings: List of finding dicts.
    
    Returns:
        Dict with categorized findings and summary.
    """
    likely_vuln = []
    manual_test = []
    ignored = []
    
    for f in findings:
        decision = decide(f)
        f["decision"] = decision
        
        if decision == "likely_vulnerable":
            likely_vuln.append(f)
        elif decision == "needs_manual_test":
            manual_test.append(f)
        else:
            ignored.append(f)
    
    return {
        "likely_vulnerable": likely_vuln,
        "needs_manual_test": manual_test,
        "ignored": ignored,
        "summary": {
            "total": len(findings),
            "likely_count": len(likely_vuln),
            "manual_count": len(manual_test),
            "ignored_count": len(ignored)
        }
    }


def format_finding_output(finding: dict) -> str:
    """
    Format a finding for display.
    
    Args:
        finding: Finding dict.
    
    Returns:
        Formatted string.
    """
    vuln = finding.get("vulnerability", "unknown")
    confidence = finding.get("confidence", 0.0)
    decision = decide(finding)
    next_step = finding.get("next_step", get_action_for_vulnerability(vuln))
    
    decision_symbol = {
        "likely_vulnerable": "[!]",
        "needs_manual_test": "[?]",
        "ignore": "[ ]"
    }.get(decision, "[ ]")
    
    output = f"{decision_symbol} {vuln.upper()} detected"
    output += f"\n    Confidence: {confidence:.0%}"
    output += f"\n    Decision: {decision.replace('_', ' ')}"
    output += f"\n    Next Step: {next_step}"
    
    if finding.get("description"):
        output += f"\n    Details: {finding['description']}"
    
    return output


def filter_and_decide(findings: list, min_confidence: float = 0.5) -> dict:
    """
    Filter findings by confidence and return decisions.
    
    Args:
        findings: List of findings.
        min_confidence: Minimum confidence threshold.
    
    Returns:
        Evaluated findings dict.
    """
    filtered = [f for f in findings if f.get("confidence", 0) >= min_confidence]
    return evaluate_findings(filtered)
