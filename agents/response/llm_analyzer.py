"""LLM-based response analyzer for vulnerability explanation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.llm import call_ollama


def _get_model() -> str:
    """Get model from config."""
    try:
        from config import get
        return get("llm_models.response", "llama3.2:1b")
    except:
        return "llama3.2:1b"


def analyze_with_llm(responses: list, anomaly: dict) -> str:
    """
    Use LLM to analyze an anomaly and suggest vulnerability.
    
    Args:
        responses: List of response dicts.
        anomaly: Anomaly dict from basic analyzer.
    
    Returns:
        LLM explanation of the anomaly.
    """
    if not anomaly:
        return "No anomaly to analyze."
    
    vuln = anomaly.get('vulnerability', anomaly.get('type', 'unknown'))
    prompt = f"""You are a bug bounty hunter. Analyze this test result:

Anomaly Type: {anomaly.get('type')}
Vulnerability: {vuln}
Payload: {anomaly.get('payload')}
Description: {anomaly.get('description')}

Return JSON with:
- issue: vulnerability name
- reason: why this is exploitable
- severity: critical/high/medium/low
- evidence: what confirms this

Under 100 words total."""

    try:
        return call_ollama(prompt, model=_get_model())
    except Exception as e:
        return f"LLM analysis failed: {e}"


def suggest_exploitation(anomaly: dict, vuln_type: str) -> str:
    """
    Suggest exploitation steps for an anomaly.
    """
    payload = anomaly.get('payload', 'unknown')
    vuln = anomaly.get('vulnerability', vuln_type)
    
    prompt = f"""Bug bounty hunter context:
Vulnerability: {vuln}
Working Payload: {payload}

Return JSON with:
- next_step: specific follow-up action
- poc: one-line proof of concept
- impact: business impact

Under 60 words."""

    try:
        return call_ollama(prompt, model=_get_model())
    except Exception:
        return "next_step: Test with different payloads; poc: Manual verification needed; impact: Data exposure"


def generate_next_steps(anomalies: list) -> str:
    """
    Generate next testing steps based on anomalies.
    """
    if not anomalies:
        return "No anomalies to investigate."
    
    vulns = [a.get('vulnerability', a.get('type', 'unknown')) for a in anomalies]
    payloads = [a.get('payload', 'unknown') for a in anomalies if a.get('payload')][:3]
    
    prompt = f"""Bug bounty testing results:
Vulnerabilities: {vulns}
Working Payloads: {payloads}

Return JSON list with 3 actions:
[{{"action": "...", "priority": "high/medium/low"}}]

Under 30 words total."""

    try:
        return call_ollama(prompt, model=_get_model())
    except Exception:
        return "[{'action': 'Test identified payloads with different encodings', 'priority': 'high'}]"


def analyze_multi_user_with_llm(user1_resp: dict, user2_resp: dict) -> str:
    """
    Use LLM to analyze multi-user response comparison.
    
    Args:
        user1_resp: Response from first user.
        user2_resp: Response from second user.
    
    Returns:
        LLM analysis of cross-user vulnerability.
    """
    user1 = user1_resp.get('user', 'unknown')
    user2 = user2_resp.get('user', 'unknown')
    url = user1_resp.get('url', 'unknown')
    
    status1 = user1_resp.get('status', 0)
    status2 = user2_resp.get('status', 0)
    
    length1 = user1_resp.get('length', 0)
    length2 = user2_resp.get('length', 0)
    
    body1 = user1_resp.get('body_preview', '')[:200]
    body2 = user2_resp.get('body_preview', '')[:200]
    
    prompt = f"""You are analyzing multi-user responses.

Determine:
- if access control is broken
- if data belongs to another user
- if vulnerability is IDOR or privilege escalation

Be precise.

User1 ({user1}):
  Status: {status1}
  Length: {length1}
  Body: {body1}

User2 ({user2}):
  Status: {status2}
  Length: {length2}
  Body: {body2}

Endpoint: {url}

Return JSON with:
- issue: IDOR/priv_esc/auth_bypass/none
- reason: why vulnerability exists
- severity: critical/high/medium/low
- impact: business impact

Under 80 words."""

    try:
        return call_ollama(prompt, model=_get_model())
    except Exception as e:
        return f"LLM analysis failed: {e}"


def analyze_idor_with_llm(endpoint: str, user1: str, user2: str, finding: dict) -> str:
    """
    Use LLM to analyze IDOR vulnerability details.
    
    Args:
        endpoint: API endpoint.
        user1: First user.
        user2: Second user.
        finding: IDOR finding dict.
    
    Returns:
        LLM analysis of IDOR vulnerability.
    """
    prompt = f"""You are analyzing IDOR vulnerability.

Endpoint: {endpoint}
User1 ({user1}): accessed resource successfully
User2 ({user2}): accessed same resource

Finding:
- Type: {finding.get('type')}
- Severity: {finding.get('severity')}
- Confidence: {finding.get('confidence')}

Return JSON:
- issue: "idor" or "horizontal_escalation" or "vertical_escalation"
- explanation: technical explanation
- exploitation: how to exploit
- impact: business risk

Under 60 words."""

    try:
        return call_ollama(prompt, model=_get_model())
    except Exception as e:
        return f"LLM analysis failed: {e}"


def suggest_idor_tests(endpoint: str, param: str) -> str:
    """
    Suggest IDOR-specific test cases.
    
    Args:
        endpoint: API endpoint.
        param: Parameter name.
    
    Returns:
        Suggested test cases.
    """
    prompt = f"""As a bug bounty hunter, suggest 3 IDOR test cases for:
Endpoint: {endpoint}
Parameter: {param}

Consider:
- Modify ID values (1, 2, 999, -1)
- Test other users' resources
- Check for enumeration

Return JSON list:
[{{"test": "...", "expected": "...", "severity": "..."}}]

Under 50 words total."""

    try:
        return call_ollama(prompt, model=_get_model())
    except Exception:
        return "[{'test': 'Try id=999', 'expected': '403', 'severity': 'high'}]"
