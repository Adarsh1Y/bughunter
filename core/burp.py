"""Burp Suite integration for proxy testing."""

import urllib.request
import urllib.error
import ssl

BURP_PROXY = "http://127.0.0.1:8080"


def _format_cookies(cookies: dict) -> str:
    """Format cookies dict as header string."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def send_via_proxy(request: dict) -> dict | None:
    """
    Send a single request through Burp proxy.
    
    Args:
        request: Request dict with method, url, body, optionally user/headers/cookies.
    
    Returns:
        Response dict or None if failed.
    """
    proxy_handler = urllib.request.ProxyHandler({
        'http': BURP_PROXY,
        'https': BURP_PROXY
    })
    
    try:
        req = urllib.request.Request(
            url=request["url"],
            data=request.get("body"),
            method=request.get("method", "GET")
        )
        
        user = request.get("user")
        if user:
            try:
                from agents.stateful import get_cookies, get_headers
                cookies = request.get("cookies", get_cookies(user))
                headers = request.get("headers", get_headers(user))
                
                if cookies:
                    req.add_header("Cookie", _format_cookies(cookies))
                if headers:
                    for k, v in headers.items():
                        if k not in ("Cookie",):
                            req.add_header(k, v)
            except ImportError:
                pass
        
        opener = urllib.request.build_opener(proxy_handler)
        response = opener.open(req, timeout=10)
        
        body = response.read()
        
        return {
            "status": response.status,
            "url": request["url"],
            "payload": request.get("payload"),
            "user": request.get("user"),
            "length": len(body),
            "body_preview": body[:200].decode('utf-8', errors='ignore')
        }
    except urllib.error.URLError as e:
        return {
            "status": 0,
            "url": request["url"],
            "payload": request.get("payload"),
            "user": request.get("user"),
            "error": str(e)
        }
    except Exception as e:
        return {
            "status": 0,
            "url": request["url"],
            "payload": request.get("payload"),
            "user": request.get("user"),
            "error": str(e)
        }


def check_burp_running() -> bool:
    """
    Check if Burp proxy is running.
    
    Returns:
        True if Burp is reachable.
    """
    try:
        proxy_handler = urllib.request.ProxyHandler({'http': BURP_PROXY})
        opener = urllib.request.build_opener(proxy_handler)
        opener.open("http://burp/check", timeout=3)
        return True
    except:
        pass
    
    try:
        urllib.request.urlopen("http://127.0.0.1:8080", timeout=3)
        return True
    except:
        return False


def send_requests(requests: list, prompt: bool = True) -> list:
    """
    Send multiple requests through Burp.
    
    Args:
        requests: List of request dicts.
        prompt: If True, ask before sending.
    
    Returns:
        List of response dicts.
    """
    if not requests:
        return []
    
    if prompt:
        print(f"\n[!] About to send {len(requests)} requests via Burp proxy ({BURP_PROXY})")
        response = input("Proceed? (y/n): ")
        if response.lower() != 'y':
            print("Aborted.")
            return []
    
    print(f"\n[+] Sending {len(requests)} requests via Burp...")
    
    results = []
    for i, req in enumerate(requests, 1):
        user = req.get("user", "")
        user_str = f" [{user}]" if user else ""
        print(f"  [{i}/{len(requests)}]{user_str} {req['method']} {req['url'][:70]}...")
        result = send_via_proxy(req)
        results.append(result)
    
    print(f"[+] Completed {len(results)} requests")
    return results


def send_request_as_user(url: str, user: str, method: str = "GET", body: dict = None) -> dict:
    """
    Send a request as a specific user.
    
    Args:
        url: Full URL.
        user: Username to use session from.
        method: HTTP method.
        body: Request body for POST.
    
    Returns:
        Response dict.
    """
    request = {
        "method": method,
        "url": url,
        "body": body,
        "user": user
    }
    return send_via_proxy(request)


def send_raw_request(method: str, url: str, headers: dict = None, body: str = None) -> dict:
    """
    Send raw HTTP request without proxy.
    
    Args:
        method: HTTP method.
        url: Full URL.
        headers: Request headers.
        body: Request body.
    
    Returns:
        Response dict.
    """
    try:
        req = urllib.request.Request(url, data=body, method=method)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        
        ctx = ssl.create_default_context()
        response = urllib.request.urlopen(req, timeout=15, context=ctx)
        resp_body = response.read()
        
        return {
            "status": response.status,
            "headers": dict(response.headers),
            "body": resp_body,
            "length": len(resp_body)
        }
    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "headers": dict(e.headers),
            "error": str(e)
        }
    except Exception as e:
        return {
            "status": 0,
            "error": str(e)
        }
