"""Multi-user login support for stateful testing."""

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from .session_manager import save_session, load_session, get_cookies, get_headers


def login_user(user: str, base_url: str, username: str, password: str) -> dict:
    """
    Simulate login for a user and store session.
    
    Args:
        user: Username identifier (e.g., "user1", "user2")
        base_url: Base URL of target
        username: Login username
        password: Login password
    
    Returns:
        Session dict with cookies and headers
    """
    from core.burp import send_raw_request
    
    login_url = f"{base_url.rstrip('/')}/login"
    
    post_data = f"username={username}&password={password}"
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "BugHunter/1.0"
    }
    
    response = send_raw_request(
        method="POST",
        url=login_url,
        headers=headers,
        body=post_data
    )
    
    if response and response.get("status") in (200, 302, 301):
        cookies = extract_cookies(response)
        
        save_session(user, cookies=cookies, headers={
            "Cookie": format_cookies(cookies),
            "User-Agent": "BugHunter/1.0"
        })
        
        return {
            "success": True,
            "user": user,
            "cookies": cookies,
            "status": response.get("status")
        }
    
    return {
        "success": False,
        "user": user,
        "error": response.get("error", "Login failed")
    }


def login_with_session(user: str, base_url: str, session_cookie: str) -> dict:
    """
    Store a pre-existing session for a user.
    
    Args:
        user: Username identifier
        base_url: Base URL
        session_cookie: Session cookie value
    
    Returns:
        Session dict
    """
    cookies = {"session": session_cookie}
    
    save_session(user, cookies=cookies, headers={
        "Cookie": f"session={session_cookie}",
        "User-Agent": "BugHunter/1.0"
    })
    
    return {
        "success": True,
        "user": user,
        "cookies": cookies
    }


def extract_cookies(response: dict) -> dict:
    """Extract cookies from response headers."""
    cookies = {}
    
    set_cookie = response.get("headers", {}).get("Set-Cookie", "")
    if set_cookie:
        for part in set_cookie.split(";"):
            part = part.strip()
            if "=" in part:
                name, value = part.split("=", 1)
                cookies[name.strip()] = value.strip()
    
    return cookies


def format_cookies(cookies: dict) -> str:
    """Format cookies dict as header string."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def simulate_login(user: str, role: str = "user") -> dict:
    """
    Simulate login with mock credentials for testing.
    
    Args:
        user: Username identifier
        role: "user" or "admin"
    
    Returns:
        Mock session dict
    """
    if role == "admin":
        cookies = {"session_id": f"admin_{user}_token", "role": "admin"}
    else:
        cookies = {"session_id": f"user_{user}_token", "role": "user"}
    
    save_session(user, cookies=cookies, headers={
        "Cookie": format_cookies(cookies),
        "User-Agent": "BugHunter/1.0"
    })
    
    return {
        "success": True,
        "user": user,
        "role": role,
        "cookies": cookies
    }


def get_user_session(user: str) -> dict:
    """
    Get full session for a user.
    
    Args:
        user: Username
    
    Returns:
        Session with user context
    """
    session = load_session(user)
    
    return {
        "user": user,
        "cookies": session.get("cookies", {}),
        "headers": session.get("headers", {}),
        "is_logged_in": bool(session.get("cookies"))
    }


def setup_test_users() -> dict:
    """
    Setup default test users (user1 and user2).
    
    Returns:
        Dict with both users' sessions
    """
    simulate_login("user1", role="user")
    simulate_login("user2", role="user")
    
    return {
        "user1": get_user_session("user1"),
        "user2": get_user_session("user2")
    }
