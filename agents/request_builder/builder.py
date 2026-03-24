"""Request builder for HTTP request generation."""

from urllib.parse import urlparse, urlencode, urlunparse


def build_request(base_url: str, endpoint: str, param: str, payload: str, method: str = "GET", user: str = None) -> dict:
    """
    Build an HTTP request from components.
    
    Args:
        base_url: Base URL (e.g., "https://example.com")
        endpoint: API endpoint (e.g., "/api/users")
        param: Parameter name to fuzz.
        payload: Payload value.
        method: HTTP method (GET or POST).
        user: Username for session-aware requests.
    
    Returns:
        Dict with request details.
    """
    full_url = base_url.rstrip('/') + endpoint
    
    if method == "GET":
        query = f"{param}={payload}"
        url = f"{full_url}?{query}"
        body = None
    else:
        url = full_url
        body = {param: payload}
    
    result = {
        "method": method,
        "url": url,
        "body": body,
        "param": param,
        "payload": payload
    }
    
    if user:
        result["user"] = user
        try:
            from agents.stateful import get_headers, get_cookies
            result["headers"] = get_headers(user)
            result["cookies"] = get_cookies(user)
        except ImportError:
            pass
    
    return result


def build_requests(base_url: str, endpoint: str, param: str, payloads: list, method: str = "GET", user: str = None) -> list:
    """
    Build multiple HTTP requests from payloads.
    
    Args:
        base_url: Base URL.
        endpoint: API endpoint.
        param: Parameter name to fuzz.
        payloads: List of payload strings.
        method: HTTP method.
        user: Username for session-aware requests.
    
    Returns:
        List of request dicts.
    """
    requests = []
    for payload in payloads:
        req = build_request(base_url, endpoint, param, payload, method, user=user)
        requests.append(req)
    return requests


def format_request(req: dict) -> str:
    """
    Format a request dict as a readable string.
    
    Args:
        req: Request dict from build_request.
    
    Returns:
        Formatted request string.
    """
    method = req["method"]
    url = req["url"]
    body = req["body"]
    
    if method == "GET":
        return f"{method} {url}"
    else:
        body_str = urlencode(body) if body else ""
        return f"{method} {url}\nBody: {body_str}"


def format_requests(requests: list) -> str:
    """
    Format multiple requests.
    
    Args:
        requests: List of request dicts.
    
    Returns:
        Formatted string of all requests.
    """
    return "\n".join(format_request(r) for r in requests)
