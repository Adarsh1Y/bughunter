"""Stateful testing modules for multi-user session management."""

from .session_manager import (
    save_session,
    load_session,
    get_cookies,
    get_headers,
    delete_session,
    list_users,
    clear_all_sessions
)
from .login import (
    login_user,
    login_with_session,
    simulate_login,
    get_user_session,
    setup_test_users
)
from .comparator import (
    compare_responses,
    compare_multi_user,
    analyze_cross_user_access
)
from .flow_engine import (
    execute_flow,
    execute_idor_flow,
    execute_auth_bypass_flow,
    run_preset_flow,
    list_preset_flows,
    PRESET_FLOWS
)
from .cross_user import (
    test_same_endpoint_different_users,
    test_horizontal_escalation,
    test_vertical_escalation,
    test_batch_idor,
    test_multi_user_all_endpoints
)
from .idor_detector import (
    detect_idor_params,
    is_idor_suspect_endpoint,
    test_idor_vulnerability,
    scan_endpoints_for_idor,
    assess_idor_risk
)
from .safe_exec import (
    get_max_requests,
    get_max_multi_user_tests,
    confirm_before_idor,
    confirm_before_multi_user,
    safe_request_count,
    safe_idor_test,
    safe_multi_user_test,
    truncate_requests,
    rate_limit,
    validate_safe_operation
)

__all__ = [
    "save_session",
    "load_session",
    "get_cookies",
    "get_headers",
    "delete_session",
    "list_users",
    "clear_all_sessions",
    "login_user",
    "login_with_session",
    "simulate_login",
    "get_user_session",
    "setup_test_users",
    "compare_responses",
    "compare_multi_user",
    "analyze_cross_user_access",
    "execute_flow",
    "execute_idor_flow",
    "execute_auth_bypass_flow",
    "run_preset_flow",
    "list_preset_flows",
    "PRESET_FLOWS",
    "test_same_endpoint_different_users",
    "test_horizontal_escalation",
    "test_vertical_escalation",
    "test_batch_idor",
    "test_multi_user_all_endpoints",
    "detect_idor_params",
    "is_idor_suspect_endpoint",
    "test_idor_vulnerability",
    "scan_endpoints_for_idor",
    "assess_idor_risk",
    "get_max_requests",
    "get_max_multi_user_tests",
    "confirm_before_idor",
    "confirm_before_multi_user",
    "safe_request_count",
    "safe_idor_test",
    "safe_multi_user_test",
    "truncate_requests",
    "rate_limit",
    "validate_safe_operation"
]
