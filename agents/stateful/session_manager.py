"""Session manager for multi-user stateful testing."""

import json
from pathlib import Path
from typing import Optional

SESSIONS_FILE = Path(__file__).parent.parent.parent / "data" / "sessions.json"


def _load_sessions() -> dict:
    """Load sessions from file."""
    if SESSIONS_FILE.exists():
        try:
            with open(SESSIONS_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _save_sessions(sessions: dict) -> None:
    """Save sessions to file."""
    SESSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SESSIONS_FILE, 'w') as f:
        json.dump(sessions, f, indent=2)


def save_session(user: str, cookies: Optional[dict] = None, headers: Optional[dict] = None) -> None:
    """
    Save session for a user.
    
    Args:
        user: Username (e.g., "user1", "user2")
        cookies: Dict of cookies
        headers: Dict of headers
    """
    sessions = _load_sessions()
    
    if user not in sessions:
        sessions[user] = {"cookies": {}, "headers": {}}
    
    if cookies:
        sessions[user]["cookies"].update(cookies)
    
    if headers:
        sessions[user]["headers"].update(headers)
    
    _save_sessions(sessions)


def load_session(user: str) -> dict:
    """
    Load session for a user.
    
    Args:
        user: Username
    
    Returns:
        Session dict with cookies and headers
    """
    sessions = _load_sessions()
    return sessions.get(user, {"cookies": {}, "headers": {}})


def get_cookies(user: str) -> dict:
    """Get cookies for a user."""
    session = load_session(user)
    return session.get("cookies", {})


def get_headers(user: str) -> dict:
    """Get headers for a user."""
    session = load_session(user)
    return session.get("headers", {})


def delete_session(user: str) -> None:
    """Delete session for a user."""
    sessions = _load_sessions()
    if user in sessions:
        del sessions[user]
        _save_sessions(sessions)


def list_users() -> list:
    """List all users with saved sessions."""
    sessions = _load_sessions()
    return list(sessions.keys())


def clear_all_sessions() -> None:
    """Clear all saved sessions."""
    _save_sessions({})
