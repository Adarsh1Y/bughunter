"""Bug hunting orchestrator - semi-automatic workflow, optimized for low RAM."""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.analysis import analyze
from agents.strategy import prioritize, get_test_recommendations
from agents.fuzz import get_payloads_for_target
from agents.request_builder import build_requests, format_requests
from agents.response import (
    analyze_responses, summarize_anomalies,
    analyze_multi_user_access, compare_user_responses
)
from agents.response.llm_analyzer import (
    analyze_multi_user_with_llm, analyze_idor_with_llm
)
from agents.report import generate_report, save_report_markdown
from agents.stateful import (
    setup_test_users, simulate_login,
    test_same_endpoint_different_users,
    test_idor_vulnerability,
    execute_idor_flow
)
from core.burp import send_requests, check_burp_running

BANNER = """
╔═══════════════════════════════════════════════════════╗
║         BUG HUNTER - AI ASSISTED SYSTEM            ║
║         Semi-Automatic Security Testing              ║
║         + Multi-User Session Testing                ║
╚═══════════════════════════════════════════════════════╝
"""


def _is_low_ram() -> bool:
    """Check if low RAM mode is enabled."""
    try:
        from config import get
        return get("mode") == "low_ram"
    except:
        return False


def _get_max_payloads() -> int:
    """Get max payloads from config."""
    try:
        from config import get
        result = get("max_payloads", 5)
        return int(result) if result else 5
    except:
        return 5


def run_analysis(urls: str) -> list:
    """Run URL analysis."""
    print("\n[1] Analyzing URLs...")
    results = analyze(urls)
    print(f"  Found {len(results)} potential targets")
    return results


def run_strategy(analysis_results: list) -> list:
    """Run strategy and prioritize targets (only if needed)."""
    print("\n[2] Prioritizing targets...")
    
    # Smart: only prioritize if we have high-risk targets
    has_high_risk = any(t.get('risk') == 'high' for t in analysis_results)
    
    if not has_high_risk and _is_low_ram():
        print("  Skipping deep strategy (low RAM mode, no high-risk targets)")
        # Return first few targets
        return analysis_results[:3]
    
    targets = prioritize(analysis_results)
    print(f"  Top {len(targets)} targets identified")
    return targets


def select_target(targets: list) -> dict | None:
    """Let user select a target."""
    print("\n[3] Target Selection")
    print("-" * 40)
    for i, t in enumerate(targets, 1):
        vuln = t.get('vulnerability', 'NONE')
        risk = t.get('risk', 'low')
        params = ', '.join(t.get('params', []))
        issue = t.get('issue', vuln)
        print(f"  {i}. [{risk.upper()}] {t['endpoint']} - {issue}")
        print(f"     Why: {t.get('reason', 'Parameter suggests vulnerability')}")
        print(f"     Next: {t.get('next_step', 'Fuzz this endpoint')}")
    
    print("\nSelect target (1-3) or 'q' to quit: ", end="")
    try:
        choice = input().strip()
    except EOFError:
        choice = '1'
    
    if choice.lower() == 'q':
        return None
    
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(targets):
            return targets[idx]
    except ValueError:
        pass
    
    return targets[0] if targets else None


def generate_and_build(target: dict, base_url: str) -> list:
    """Generate payloads and build requests."""
    print("\n[4] Generating payloads...")
    payloads = get_payloads_for_target(target)
    
    # Smart: reduce payload count in low RAM mode
    max_payloads = _get_max_payloads()
    payloads = payloads[:max_payloads]
    print(f"  Generated {len(payloads)} payloads (limited for low RAM)")
    
    print("\n[5] Building requests...")
    param = target.get('params', ['id'])[0]
    requests = build_requests(base_url, target['endpoint'], param, payloads)
    print(f"  Built {len(requests)} requests")
    
    return requests


def send_to_proxy(requests: list) -> bool:
    """Ask user and send requests to proxy."""
    print("\n[6] Burp Integration")
    print("-" * 40)
    
    burp_running = check_burp_running()
    print(f"  Burp proxy: {'Running' if burp_running else 'Not detected'}")
    
    print("\n  Sample requests:")
    for r in requests[:3]:
        print(f"    {r['method']} {r['url'][:70]}...")
    
    print("\n  Send to Burp proxy? (y/n): ", end="")
    try:
        if input().strip().lower() != 'y':
            print("  Skipped.")
            return False
    except EOFError:
        return False
    
    results = send_requests(requests, prompt=False)
    return len(results) > 0


def analyze_test_responses() -> list:
    """Get response data from user for analysis."""
    print("\n[7] Response Analysis")
    print("-" * 40)
    print("  Paste response data or 's' to skip")
    print("  Format: status,length,payload")
    
    responses = []
    print("  > ", end="")
    
    while True:
        try:
            line = input().strip()
            if not line:
                break
            if line.lower() == 's':
                break
            parts = line.split(',')
            if len(parts) >= 2:
                responses.append({
                    'status': int(parts[0]),
                    'length': int(parts[1]),
                    'payload': parts[2] if len(parts) > 2 else ''
                })
        except (ValueError, EOFError):
            break
    
    return responses


def run_response_analysis(responses: list, target: dict):
    """Run response analysis."""
    if not responses:
        print("\n  No response data to analyze.")
        return [], None
    
    print("\n[8] Analyzing responses...")
    anomalies = analyze_responses(responses)
    
    if anomalies:
        print(f"  Found {len(anomalies)} anomaly(ies)!")
        print(summarize_anomalies(anomalies))
    else:
        print("  No anomalies detected.")
    
    llm_analysis = None
    if anomalies:
        # Smart: skip LLM analysis in low RAM mode unless high severity
        high_severity = any(a.get('severity') == 'high' for a in anomalies)
        
        if not _is_low_ram() or high_severity:
            print("\n[9] LLM Analysis...")
            from agents.response.llm_analyzer import analyze_with_llm
            for a in anomalies[:2]:  # Limit to 2
                llm_analysis = analyze_with_llm(responses, a)
                print(f"  {llm_analysis[:150]}...")
        else:
            print("  Skipping LLM analysis (low RAM mode, medium severity)")
    
    return anomalies, llm_analysis


def generate_findings_report(target: dict, anomalies: list, llm_analysis: str):
    """Generate vulnerability report."""
    if not anomalies:
        return
    
    print("\n[10] Generate Report? (y/n): ", end="")
    try:
        if input().strip().lower() != 'y':
            return
    except EOFError:
        return
    
    print("\n[11] Generating report...")
    
    for a in anomalies:
        report = generate_report(
            target=target,
            payload=a.get('payload', ''),
            anomaly=a,
            llm_analysis=llm_analysis or '',
            vuln_type=target.get('vulnerability', 'Unknown')
        )
        
        filename = f"report_{target['endpoint'].replace('/', '_')}_{a['type']}.md"
        filepath = Path('data/output') / filename
        filepath.parent.mkdir(exist_ok=True)
        
        save_report_markdown(report, str(filepath))
        print(f"  Saved: {filepath}")


def setup_sessions() -> tuple:
    """Setup test user sessions."""
    print("\n[*] Setting up test sessions...")
    
    try:
        users = setup_test_users()
        print(f"  Created {len(users)} test users")
        for user in users:
            print(f"    - {user}")
        return users
    except Exception as e:
        print(f"  Error: {e}")
        return {}


def run_cross_user_test(base_url: str, endpoint: str, user1: str, user2: str) -> dict:
    """Run cross-user testing for IDOR."""
    print(f"\n[*] Cross-User Test: {endpoint}")
    print(f"    Testing: {user1} vs {user2}")
    
    result = test_same_endpoint_different_users(
        base_url, endpoint, user1, user2
    )
    
    if result.get("idor_detected"):
        print(f"  [!] IDOR VULNERABILITY FOUND!")
        print(f"      Evidence: {result.get('comparison', {}).get('evidence', '')}")
    elif result.get("auth_bypass_detected"):
        print(f"  [!] AUTH BYPASS FOUND!")
    else:
        print(f"  [+] No vulnerability detected")
    
    return result


def run_idor_test(base_url: str, target: dict, user1: str = "user1", user2: str = "user2") -> dict:
    """Run dedicated IDOR test."""
    endpoint = target.get("endpoint", "/api/data")
    param = target.get("params", ["id"])[0]
    
    print(f"\n[*] IDOR Vulnerability Test")
    print(f"    Endpoint: {endpoint}")
    print(f"    Parameter: {param}")
    
    result = test_idor_vulnerability(
        base_url, endpoint, param,
        user1=user1, user2=user2
    )
    
    if result.get("idor_detected"):
        print(f"  [!] IDOR DETECTED!")
        print(f"      Severity: {result.get('severity', 'unknown')}")
        print(f"      Confidence: {result.get('confidence', 0):.0%}")
        print(f"      {result.get('explanation', '')}")
    else:
        print(f"  [+] No IDOR detected")
        print(f"      {result.get('explanation', 'Proper authorization in place')}")
    
    return result


def analyze_cross_user_responses(responses: list) -> dict:
    """Analyze responses from multiple users."""
    if not responses:
        return {"findings": [], "summary": "No responses to analyze"}
    
    print(f"\n[*] Analyzing {len(responses)} responses from {len(set(r.get('user') for r in responses))} users...")
    
    analysis = analyze_multi_user_access(responses)
    
    print(f"  Total findings: {analysis.get('total_findings', 0)}")
    
    by_type = analysis.get("findings_by_type", {})
    if by_type.get("idor"):
        print(f"    IDOR findings: {by_type['idor']}")
    if by_type.get("auth_bypass"):
        print(f"    Auth bypass findings: {by_type['auth_bypass']}")
    if by_type.get("data_exposure"):
        print(f"    Data exposure findings: {by_type['data_exposure']}")
    
    return analysis


def run_session_testing_menu(base_url: str, target: dict) -> dict:
    """Run session-aware multi-user testing menu."""
    results = {
        "cross_user_test": None,
        "idor_test": None,
        "multi_user_analysis": None
    }
    
    print("\n" + "=" * 50)
    print("SESSION TESTING MENU")
    print("=" * 50)
    print("1. Cross-User Test (user1 vs user2)")
    print("2. IDOR Vulnerability Test")
    print("3. Both (1 and 2)")
    print("4. Skip session testing")
    print("-" * 50)
    
    try:
        choice = input("Select option (1-4): ").strip()
    except EOFError:
        choice = "4"
    
    users = setup_sessions()
    
    if choice in ("1", "3"):
        print("\n[Cross-User Test]")
        results["cross_user_test"] = run_cross_user_test(
            base_url,
            target.get("endpoint", "/api/data"),
            "user1", "user2"
        )
    
    if choice in ("2", "3"):
        print("\n[IDOR Test]")
        results["idor_test"] = run_idor_test(
            base_url,
            target,
            "user1", "user2"
        )
    
    return results


def main():
    """Main orchestrator loop."""
    print(BANNER)
    print(f"Mode: {'LOW RAM' if _is_low_ram() else 'NORMAL'}")
    
    print("\nEnter target URLs (one per line, empty line to finish):")
    print("-" * 40)
    
    urls = []
    while True:
        try:
            line = input("  > ").strip()
            if not line:
                break
            if line.startswith(('http://', 'https://')):
                urls.append(line)
        except EOFError:
            break
    
    if not urls:
        print("No URLs provided. Exiting.")
        return
    
    url_input = '\n'.join(urls)
    print(f"\nLoaded {len(urls)} URLs")
    
    # Run pipeline
    analysis = run_analysis(url_input)
    if not analysis:
        print("No targets found. Exiting.")
        return
    
    targets = run_strategy(analysis)
    if not targets:
        print("No valid targets. Exiting.")
        return
    
    target = select_target(targets)
    if not target:
        print("Exiting.")
        return
    
    print(f"\n  Selected: {target['endpoint']} ({target.get('vulnerability')})")
    print("\n  Testing recommendations:")
    for rec in get_test_recommendations(target):
        print(f"    - {rec}")
    
    print("\n  Enter base URL (or Enter for https://target.com): ", end="")
    try:
        base_url = input().strip()
    except EOFError:
        base_url = "https://target.com"
    
    if not base_url:
        base_url = "https://target.com"
    
    # Ask about session testing
    print("\n" + "-" * 40)
    print("Enable session-aware multi-user testing?")
    print("This tests IDOR and cross-user vulnerabilities.")
    
    try:
        session_choice = input("Run session testing? (y/n): ").strip().lower()
    except EOFError:
        session_choice = "n"
    
    session_results = {}
    if session_choice == 'y':
        session_results = run_session_testing_menu(base_url, target)
    
    # Continue with standard fuzzing
    requests = generate_and_build(target, base_url)
    
    print("\n  Preview requests:")
    print(format_requests(requests[:5]))
    
    send_to_proxy(requests)
    
    responses = analyze_test_responses()
    
    # Analyze standard responses
    anomalies, llm_analysis = run_response_analysis(responses, target)
    
    # Analyze multi-user responses if we have them
    if session_results.get("cross_user_test"):
        print("\n[*] Session testing findings:")
        for key, result in session_results.items():
            if result and result.get("idor_detected"):
                print(f"    [!] {key}: IDOR detected")
    
    if anomalies:
        generate_findings_report(target, anomalies, llm_analysis or '')
    
    print("\n" + "=" * 50)
    print("Scan complete!")
    print("=" * 50)


if __name__ == "__main__":
    main()
