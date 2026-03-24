"""Flow engine for multi-step attack simulation."""

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def _get_max_flow_steps() -> int:
    """Get max steps per flow from config."""
    try:
        from config import get
        result = get("max_flow_steps", 10)
        return int(result) if result else 10
    except:
        return 10


def execute_flow(flow: list, user: str, base_url: str) -> dict:
    """
    Execute a sequence of steps as a specific user.
    
    Args:
        flow: List of step dicts with type and params.
        user: Username for session.
        base_url: Base URL of target.
    
    Returns:
        Dict with results of all steps.
    """
    from core.burp import send_request_as_user
    from agents.request_builder import build_request
    
    results = {
        "user": user,
        "base_url": base_url,
        "steps": [],
        "completed": False,
        "final_state": {}
    }
    
    max_steps = _get_max_flow_steps()
    
    for i, step in enumerate(flow[:max_steps]):
        step_type = step.get("type", "")
        step_name = step.get("name", f"step_{i}")
        
        step_result = {
            "name": step_name,
            "type": step_type,
            "success": False,
            "response": None
        }
        
        try:
            if step_type == "login":
                resp = _do_login(base_url, user, step)
                step_result["response"] = resp
                step_result["success"] = resp.get("status") in (200, 302, 301)
            
            elif step_type == "fetch_profile":
                url = f"{base_url.rstrip('/')}/api/profile"
                resp = send_request_as_user(url, user)
                step_result["response"] = resp
                step_result["success"] = resp.get("status") == 200
            
            elif step_type == "fetch_orders":
                url = f"{base_url.rstrip('/')}/api/orders"
                resp = send_request_as_user(url, user)
                step_result["response"] = resp
                step_result["success"] = resp.get("status") == 200
            
            elif step_type == "fetch_specific":
                resource = step.get("resource", "/api/data")
                resource_id = step.get("id", "1")
                url = f"{base_url.rstrip('/')}{resource}?id={resource_id}"
                resp = send_request_as_user(url, user)
                step_result["response"] = resp
                step_result["success"] = resp.get("status") in (200, 403)
                step_result["resource_id"] = resource_id
            
            elif step_type == "modify":
                resource = step.get("resource", "/api/data")
                resource_id = step.get("id", "1")
                method = step.get("method", "PUT")
                url = f"{base_url.rstrip('/')}{resource}/{resource_id}"
                resp = send_request_as_user(url, user, method=method)
                step_result["response"] = resp
                step_result["success"] = resp.get("status") in (200, 204, 403)
            
            elif step_type == "custom":
                url = step.get("url", base_url)
                method = step.get("method", "GET")
                resp = send_request_as_user(url, user, method=method)
                step_result["response"] = resp
                step_result["success"] = resp.get("status") == 200
            
            else:
                step_result["error"] = f"Unknown step type: {step_type}"
        
        except Exception as e:
            step_result["error"] = str(e)
        
        results["steps"].append(step_result)
        
        if not step_result["success"] and step.get("critical", False):
            break
    
    results["completed"] = all(s["success"] for s in results["steps"])
    
    return results


def _do_login(base_url: str, user: str, step: dict) -> dict:
    """Execute a login step."""
    from core.burp import send_raw_request
    
    login_url = f"{base_url.rstrip('/')}/login"
    username = step.get("username", user)
    password = step.get("password", "password")
    
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    body = f"username={username}&password={password}"
    
    return send_raw_request("POST", login_url, headers=headers, body=body)


def execute_idor_flow(base_url: str, user1: str, user2: str, resource: str, resource_id: str) -> dict:
    """
    Execute IDOR testing flow: user1 accesses resource, user2 tries same.
    
    Args:
        base_url: Target base URL.
        user1: First user (should have access).
        user2: Second user (testing for unauthorized access).
        resource: API endpoint (e.g., "/api/orders").
        resource_id: Resource ID to test.
    
    Returns:
        Dict with both users' responses and IDOR detection result.
    """
    from core.burp import send_request_as_user
    from agents.stateful import compare_responses
    
    url = f"{base_url.rstrip('/')}{resource}?id={resource_id}"
    
    print(f"\n[IDOR Flow] Testing {url}")
    print(f"  User1 ({user1}) accessing...")
    
    resp1 = send_request_as_user(url, user1)
    
    print(f"  User2 ({user2}) attempting same...")
    
    resp2 = send_request_as_user(url, user2)
    
    comparison = compare_responses(resp1, resp2)
    
    return {
        "url": url,
        "user1_response": resp1,
        "user2_response": resp2,
        "idor_detected": comparison["issue"] == "idor",
        "comparison": comparison
    }


def execute_auth_bypass_flow(base_url: str, users: list, endpoint: str) -> dict:
    """
    Test authorization bypass across multiple users.
    
    Args:
        base_url: Target base URL.
        users: List of usernames to test.
        endpoint: Endpoint to test (e.g., "/api/admin").
    
    Returns:
        Dict with responses from all users and findings.
    """
    from core.burp import send_request_as_user
    from agents.stateful import compare_multi_user
    
    url = f"{base_url.rstrip('/')}{endpoint}"
    
    print(f"\n[Auth Bypass Flow] Testing {url}")
    
    responses = []
    for user in users:
        print(f"  Testing as {user}...")
        resp = send_request_as_user(url, user)
        resp["user"] = user
        responses.append(resp)
    
    findings = compare_multi_user(responses)
    
    return {
        "endpoint": endpoint,
        "responses": responses,
        "findings": findings
    }


PRESET_FLOWS = {
    "basic_idor": [
        {"type": "login", "name": "login", "critical": True},
        {"type": "fetch_specific", "name": "fetch_own_data", "resource": "/api/profile", "id": "1"}
    ],
    "order_idor": [
        {"type": "login", "name": "login", "critical": True},
        {"type": "fetch_orders", "name": "fetch_own_orders"},
        {"type": "fetch_specific", "name": "test_order_access", "resource": "/api/orders", "id": "999"}
    ],
    "horizontal_escalation": [
        {"type": "login", "name": "login_as_user1", "critical": True},
        {"type": "fetch_specific", "name": "get_user1_data", "resource": "/api/profile", "id": "1"}
    ],
    "vertical_escalation": [
        {"type": "login", "name": "login_as_user", "critical": True},
        {"type": "custom", "name": "try_admin_endpoint", "url": "/api/admin/users"}
    ]
}


def run_preset_flow(flow_name: str, user: str, base_url: str) -> dict:
    """
    Run a preset flow by name.
    
    Args:
        flow_name: Name of preset flow (e.g., "basic_idor").
        user: Username to execute as.
        base_url: Target base URL.
    
    Returns:
        Flow execution results.
    """
    if flow_name not in PRESET_FLOWS:
        return {"error": f"Unknown flow: {flow_name}. Available: {list(PRESET_FLOWS.keys())}"}
    
    flow = PRESET_FLOWS[flow_name]
    return execute_flow(flow, user, base_url)


def list_preset_flows() -> list:
    """List available preset flows."""
    return [
        {"name": name, "steps": len(flow)}
        for name, flow in PRESET_FLOWS.items()
    ]
