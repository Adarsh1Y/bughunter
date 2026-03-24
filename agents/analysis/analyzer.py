"""Analysis agent for URL analysis - focused on high-value targets."""

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.llm import call_ollama

HIGH_VALUE_PATTERNS = {
    "id": {"vuln": "IDOR", "confidence": 0.8},
    "user_id": {"vuln": "IDOR", "confidence": 0.9},
    "post_id": {"vuln": "IDOR", "confidence": 0.8},
    "account_id": {"vuln": "IDOR", "confidence": 0.9},
    "token": {"vuln": "AUTH", "confidence": 0.9},
    "key": {"vuln": "AUTH", "confidence": 0.8},
    "secret": {"vuln": "AUTH", "confidence": 0.9},
    "password": {"vuln": "AUTH", "confidence": 0.7},
    "auth": {"vuln": "AUTH", "confidence": 0.8},
    "admin": {"vuln": "PRIVESC", "confidence": 0.8},
    "role": {"vuln": "PRIVESC", "confidence": 0.8},
    "sql": {"vuln": "SQLI", "confidence": 0.8},
    "order": {"vuln": "SQLI", "confidence": 0.7},
    "sort": {"vuln": "SQLI", "confidence": 0.7},
    "search": {"vuln": "XSS", "confidence": 0.7},
    "q": {"vuln": "XSS", "confidence": 0.7},
    "query": {"vuln": "XSS", "confidence": 0.7},
    "file": {"vuln": "RCE", "confidence": 0.7},
    "cmd": {"vuln": "RCE", "confidence": 0.8},
    "upload": {"vuln": "RCE", "confidence": 0.7},
}

LOW_VALUE_PATTERNS = ["about", "contact", "terms", "privacy", "static", "assets", "css", "js", "images", "img", "favicon"]

RISK_LEVELS = {
    "AUTH": "high",
    "IDOR": "medium",
    "PRIVESC": "high",
    "SQLI": "high",
    "XSS": "medium",
    "RCE": "high",
}


def _get_max_input_size() -> int:
    """Get max input size from config."""
    try:
        from config import get
        result = get("max_input_size", 1500)
        return int(result) if result else 1500
    except:
        return 1500


def is_low_value_endpoint(endpoint: str) -> bool:
    """Check if endpoint is low value."""
    endpoint_lower = endpoint.lower()
    for pattern in LOW_VALUE_PATTERNS:
        if pattern in endpoint_lower:
            return True
    return False


def analyze(urls: str) -> list:
    """
    Analyze URLs focusing on high-value targets.
    
    Args:
        urls: A string containing URLs to analyze.
    
    Returns:
        List of dicts with analysis results.
    """
    if not urls or not urls.strip():
        return []

    results = []
    
    for line in urls.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        
        if not line.startswith(('http://', 'https://')):
            continue
        
        analysis = analyze_single_url(line)
        if analysis:
            results.append(analysis)
    
    return results


def analyze_single_url(url: str) -> dict | None:
    """Analyze a single URL and return structured result."""
    try:
        parsed = urlparse(url)
        endpoint = parsed.path
        params = list(parse_qs(parsed.query).keys())
        
        if is_low_value_endpoint(endpoint):
            return None
        
        vuln_type = "NONE"
        confidence = 0.3
        
        for param in params:
            param_lower = param.lower()
            if param_lower in HIGH_VALUE_PATTERNS:
                info = HIGH_VALUE_PATTERNS[param_lower]
                vuln_type = info["vuln"]
                confidence = info["confidence"]
                break
        
        if vuln_type == "NONE" and any(p in params for p in HIGH_VALUE_PATTERNS):
            for p in params:
                if p.lower() in HIGH_VALUE_PATTERNS:
                    info = HIGH_VALUE_PATTERNS[p.lower()]
                    vuln_type = info["vuln"]
                    confidence = info["confidence"]
                    break
        
        issue_map = {
            "IDOR": "Insecure Direct Object Reference",
            "AUTH": "Authentication/Authorization Flaw",
            "SQLI": "SQL Injection",
            "XSS": "Cross-Site Scripting",
            "RCE": "Remote Code Execution",
            "PRIVESC": "Privilege Escalation",
        }
        
        return {
            "endpoint": endpoint,
            "params": params,
            "risk": RISK_LEVELS.get(vuln_type, "low"),
            "vulnerability": vuln_type,
            "confidence": confidence,
            "issue": issue_map.get(vuln_type, "Potential vulnerability"),
            "reason": f"Parameter '{params[0]}' suggests {vuln_type} risk",
            "next_step": f"Fuzz {endpoint} with {vuln_type} payloads"
        }
    except Exception:
        return None


def analyze_with_llm(urls: str) -> list:
    """Use LLM to enhance analysis (optional)."""
    if not urls or not urls.strip():
        return []
    
    max_size = _get_max_input_size()
    truncated_input = urls[:max_size]
    
    prompt = f"""You are a bug bounty expert.

Focus ONLY on:
- endpoints with user-controlled parameters
- endpoints involving IDs, tokens, authentication
- API endpoints that handle sensitive data

IGNORE:
- static content
- public pages without input
- low-value endpoints

Analyze these URLs and return JSON array:
[
  {{"endpoint": "/api/path", "params": ["id"], "risk": "high", "vulnerability": "IDOR", "confidence": 0.8}}
]

URLs:
{truncated_input}

Return ONLY valid JSON array:"""

    try:
        result = call_ollama(prompt)
        return parse_llm_analysis(result, urls)
    except Exception:
        return analyze(urls)


def parse_llm_analysis(text: str, original_urls: str) -> list:
    """Parse LLM text analysis into structured format."""
    results = analyze(original_urls)
    return results
