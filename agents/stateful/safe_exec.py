"""Safe execution guards for preventing spam and limiting requests."""

import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def _get_safe_config() -> dict:
    """Get safe execution config."""
    try:
        from config import get
        return get("safe_execution", {})
    except:
        return {}


def get_max_requests() -> int:
    """Get max requests per test."""
    config = _get_safe_config()
    return config.get("max_requests_per_test", 10)


def get_max_multi_user_tests() -> int:
    """Get max multi-user tests."""
    config = _get_safe_config()
    return config.get("max_multi_user_tests", 5)


def confirm_before_idor() -> bool:
    """Check if should confirm before IDOR test."""
    config = _get_safe_config()
    return config.get("confirm_before_idor_test", True)


def confirm_before_multi_user() -> bool:
    """Check if should confirm before multi-user test."""
    config = _get_safe_config()
    return config.get("confirm_before_multi_user", True)


def get_rate_limit() -> int:
    """Get rate limit in seconds."""
    config = _get_safe_config()
    return config.get("rate_limit_seconds", 1)


def dry_run_enabled() -> bool:
    """Check if dry-run option is enabled."""
    config = _get_safe_config()
    return config.get("dry_run_option", True)


def safe_request_count(count: int, operation: str = "request") -> bool:
    """
    Check if request count is within safe limits.
    
    Args:
        count: Number of requests planned.
        operation: Description of operation.
    
    Returns:
        True if within limits.
    """
    max_req = get_max_requests()
    
    if count > max_req:
        print(f"[!] WARNING: {operation} wants to send {count} requests")
        print(f"    Safe limit: {max_req} requests")
        print(f"    Use fewer payloads or targets to reduce count.")
        return False
    
    return True


def safe_multi_user_test(test_name: str) -> bool:
    """
    Check if multi-user test should proceed with confirmation.
    
    Args:
        test_name: Name of the test.
    
    Returns:
        True if should proceed.
    """
    if not confirm_before_multi_user():
        return True
    
    print(f"\n[*] Multi-user test: {test_name}")
    print(f"    This will make requests as multiple users.")
    
    try:
        response = input("    Proceed? (y/n): ").strip().lower()
        return response == 'y'
    except EOFError:
        return False


def safe_idor_test(endpoint: str, user1: str, user2: str) -> bool:
    """
    Check if IDOR test should proceed with confirmation.
    
    Args:
        endpoint: API endpoint being tested.
        user1: First user.
        user2: Second user.
    
    Returns:
        True if should proceed.
    """
    if not confirm_before_idor():
        return True
    
    print(f"\n[*] IDOR Test Confirmation")
    print(f"    Endpoint: {endpoint}")
    print(f"    Testing: {user1} vs {user2}")
    print(f"    This will attempt to access resources as different users.")
    
    try:
        response = input("    Proceed? (y/n): ").strip().lower()
        return response == 'y'
    except EOFError:
        return False


def rate_limit():
    """Apply rate limiting between requests."""
    delay = get_rate_limit()
    if delay > 0:
        time.sleep(delay)


def truncate_requests(requests: list, max_count: int = None) -> list:
    """
    Truncate request list to safe limit.
    
    Args:
        requests: List of requests.
        max_count: Maximum allowed (uses config if None).
    
    Returns:
        Truncated list.
    """
    if max_count is None:
        max_count = get_max_requests()
    
    if len(requests) > max_count:
        print(f"[!] Truncating {len(requests)} requests to {max_count}")
        return requests[:max_count]
    
    return requests


def dry_run_mode() -> tuple:
    """
    Check if running in dry-run mode.
    
    Returns:
        Tuple of (is_dry_run, should_proceed).
    """
    if not dry_run_enabled():
        return False, True
    
    print("\n[*] DRY RUN MODE")
    print("    No actual requests will be sent.")
    
    try:
        response = input("    Continue in dry-run? (y/n): ").strip().lower()
        if response == 'y':
            return True, True
        response = input("    Run actual requests? (y/n): ").strip().lower()
        return False, response == 'y'
    except EOFError:
        return True, False


def show_safe_summary(count: int, users: int, duration_sec: int) -> str:
    """Generate safe execution summary."""
    return f"Requests: {count} | Users: {users} | Est. time: {duration_sec}s"


def validate_safe_operation(
    request_count: int,
    multi_user: bool = False,
    idor_test: bool = False
) -> bool:
    """
    Validate if operation is safe to execute.
    
    Args:
        request_count: Number of requests.
        multi_user: If this is a multi-user test.
        idor_test: If this is an IDOR test.
    
    Returns:
        True if safe to proceed.
    """
    if not safe_request_count(request_count):
        return False
    
    if idor_test and not safe_idor_test("/api/test", "user1", "user2"):
        return False
    
    if multi_user and not safe_multi_user_test("cross-user test"):
        return False
    
    return True
