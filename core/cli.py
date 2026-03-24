"""CLI core module for BugHunter."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ''
    class Style:
        BRIGHT = RESET_ALL = ''

from agents.analysis import analyze
from agents.strategy import prioritize, get_test_recommendations
from agents.fuzz import generate_payloads
from agents.request_builder import build_requests, format_requests
from agents.response import analyze_responses, summarize_anomalies
from agents.response.llm_analyzer import analyze_with_llm
from agents.report import generate_report


BANNER = f"""{Fore.CYAN}
╔═══════════════════════════════════════════════════════╗
║              BUGHUNTER CLI TOOL                    ║
║              AI-Assisted Security Testing           ║
╚═══════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


def p_success(msg: str):
    """Print success message."""
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def p_error(msg: str):
    """Print error message."""
    print(f"{Fore.RED}[!]{Style.RESET_ALL} {msg}")


def p_warn(msg: str):
    """Print warning message."""
    print(f"{Fore.YELLOW}[-]{Style.RESET_ALL} {msg}")


def p_info(msg: str):
    """Print info message."""
    print(f"{Fore.CYAN}[i]{Style.RESET_ALL} {msg}")


def p_vuln(msg: str):
    """Print vulnerability detected message."""
    print(f"{Fore.RED}{Style.BRIGHT}[!] VULNERABILITY: {msg}{Style.RESET_ALL}")


def section(title: str):
    """Print a section header."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")


def p_target(target: dict, num: int = None):
    """Print a target nicely."""
    prefix = f"{num}. " if num else ""
    endpoint = target.get('endpoint', 'unknown')
    vuln = target.get('vulnerability', 'NONE')
    risk = target.get('risk', 'low').upper()
    confidence = target.get('confidence', 0)
    
    risk_color = Fore.RED if risk == 'HIGH' else Fore.YELLOW if risk == 'MEDIUM' else Fore.GREEN
    
    print(f"\n{prefix}{Fore.WHITE}{endpoint}{Style.RESET_ALL}")
    print(f"     {Fore.CYAN}Vulnerability:{Style.RESET_ALL} {Fore.YELLOW}{vuln}{Style.RESET_ALL}")
    print(f"     {Fore.CYAN}Risk:{Style.RESET_ALL} {risk_color}{risk}{Style.RESET_ALL}")
    print(f"     {Fore.CYAN}Confidence:{Style.RESET_ALL} {confidence:.0%}")
    
    if target.get('reason'):
        print(f"     {Fore.CYAN}Reason:{Style.RESET_ALL} {target.get('reason')}")


def p_payloads(payloads: list):
    """Print payloads nicely."""
    print(f"\n{Fore.CYAN}Payloads:{Style.RESET_ALL}")
    for p in payloads:
        print(f"  {Fore.YELLOW}•{Style.RESET_ALL} {p}")


def p_next_step(step: str):
    """Print next step."""
    print(f"\n{Fore.GREEN}Next Step:{Style.RESET_ALL} {step}")


def print_menu():
    """Print main menu."""
    print(f"\n{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}=== BugHunter CLI ==={Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}1.{Style.RESET_ALL} Run Analysis")
    print(f"{Fore.WHITE}2.{Style.RESET_ALL} Run Strategy")
    print(f"{Fore.WHITE}3.{Style.RESET_ALL} Generate Payloads")
    print(f"{Fore.WHITE}4.{Style.RESET_ALL} Build Requests")
    print(f"{Fore.WHITE}5.{Style.RESET_ALL} Analyze Responses")
    print(f"{Fore.WHITE}6.{Style.RESET_ALL} Generate Report")
    print(f"{Fore.WHITE}7.{Style.RESET_ALL} Run Full Pipeline")
    print(f"{Fore.WHITE}8.{Style.RESET_ALL} Load Last Session")
    print(f"{Fore.WHITE}9.{Style.RESET_ALL} Quick Test (Full Flow)")
    print(f"{Fore.WHITE}0.{Style.RESET_ALL} Exit")
    print(f"{Fore.CYAN}{'-' * 50}{Style.RESET_ALL}")


def get_input(prompt: str) -> str:
    """Get user input safely."""
    try:
        return input(f"{Fore.WHITE}{prompt}{Style.RESET_ALL}").strip()
    except EOFError:
        return ""


def run_analysis_cli():
    """Run URL analysis."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[*] RUNNING ANALYSIS...{Style.RESET_ALL}")
    print("Enter URLs (one per line, empty line to finish):")
    
    urls = []
    while True:
        line = get_input("  > ")
        if not line:
            break
        if line.startswith(('http://', 'https://')):
            urls.append(line)
    
    if not urls:
        p_warn("No URLs provided.")
        return []
    
    url_input = '\n'.join(urls)
    p_info(f"Analyzing {len(urls)} URLs...")
    time.sleep(0.3)
    
    results = analyze(url_input)
    
    section("ANALYSIS RESULTS")
    if results:
        p_success(f"Found {len(results)} potential target(s)")
        for i, r in enumerate(results, 1):
            p_target(r, i)
    else:
        p_warn("No valid targets found")
    
    return results


def run_strategy_cli(analysis_results: list):
    """Run strategy on analysis results."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[*] RUNNING STRATEGY...{Style.RESET_ALL}")
    
    if not analysis_results:
        p_error("No analysis results. Run analysis first (option 1).")
        return []
    
    targets = prioritize(analysis_results)
    
    section("STRATEGY RESULTS")
    p_success(f"{len(targets)} prioritized target(s)")
    
    for i, t in enumerate(targets, 1):
        p_target(t, i)
        recs = get_test_recommendations(t)
        if recs:
            p_next_step(recs[0])
    
    return targets


def generate_payloads_cli():
    """Generate payloads for a vulnerability type."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[*] GENERATING PAYLOADS...{Style.RESET_ALL}")
    print("Types: IDOR, XSS, SQLI, AUTH, RCE")
    
    vuln = get_input("Vulnerability type (default: IDOR): ") or "IDOR"
    vuln = vuln.upper()
    
    count = get_input("Number of payloads (default: 5): ")
    count = int(count) if count.isdigit() else 5
    
    section(f"PAYLOADS: {vuln}")
    payloads = generate_payloads(vuln, count)
    p_payloads(payloads)
    
    return payloads


def build_requests_cli():
    """Build HTTP requests."""
    print("\n[+] BUILD REQUESTS")
    print("-" * 40)
    
    base_url = get_input("Base URL (e.g., https://example.com): ")
    if not base_url:
        base_url = "https://example.com"
    
    endpoint = get_input("Endpoint (e.g., /api/users): ")
    if not endpoint:
        endpoint = "/api/data"
    
    param = get_input("Parameter name (default: id): ") or "id"
    
    payloads_input = get_input("Payloads (comma-separated, or Enter for defaults): ")
    
    if payloads_input:
        payloads = [p.strip() for p in payloads_input.split(',')]
    else:
        payloads = generate_payloads("IDOR", 3)
    
    requests = build_requests(base_url, endpoint, param, payloads)
    
    print(f"\n[+] Built {len(requests)} requests:")
    print(format_requests(requests[:5]))
    
    return requests


def analyze_responses_cli():
    """Analyze simulated responses."""
    print("\n[+] ANALYZE RESPONSES")
    print("-" * 40)
    print("Enter response data (status,length,payload):")
    print("Empty line to finish, 's' to skip")
    
    responses = []
    while True:
        line = get_input("  > ")
        if not line or line.lower() == 's':
            break
        
        parts = line.split(',')
        if len(parts) >= 2:
            try:
                responses.append({
                    'status': int(parts[0]),
                    'length': int(parts[1]),
                    'payload': parts[2] if len(parts) > 2 else ''
                })
            except ValueError:
                print("  Invalid format. Use: status,length,payload")
    
    if not responses:
        print("No responses to analyze.")
        return [], []
    
    print(f"\n[+] Analyzing {len(responses)} responses...")
    
    anomalies = analyze_responses(responses)
    
    if anomalies:
        print(f"\n[!] Found {len(anomalies)} anomaly(ies):")
        for a in anomalies:
            sev = a.get('severity', 'unknown').upper()
            vtype = a.get('type', 'unknown')
            vuln = a.get('vulnerability', '')
            print(f"  [{sev}] {vtype} - {vuln}")
            print(f"       {a.get('description', '')}")
    else:
        print("No anomalies detected.")
    
    llm_result = None
    if anomalies:
        print("\n[+] Running LLM analysis...")
        llm_result = analyze_with_llm(responses, anomalies[0])
        print(f"  LLM: {llm_result[:200]}...")
    
    return anomalies, llm_result


def generate_report_cli(anomalies: list, llm_analysis: str, target: dict = None):
    """Generate vulnerability report."""
    print("\n[+] GENERATE REPORT")
    print("-" * 40)
    
    if not anomalies:
        print("No anomalies to report. Run analysis first.")
        return
    
    if target is None:
        target = {
            'endpoint': '/api/test',
            'params': ['id'],
            'vulnerability': 'Unknown',
            'risk': 'medium'
        }
    
    print(f"Generating report for {len(anomalies)} finding(s)...")
    
    for i, a in enumerate(anomalies, 1):
        report = generate_report(
            target=target,
            payload=a.get('payload', ''),
            anomaly=a,
            llm_analysis=llm_analysis or '',
            vuln_type=target.get('vulnerability', 'Unknown')
        )
        
        print(f"\n--- Report {i} ---")
        print(report[:500] + "..." if len(report) > 500 else report)
    
    print("\n[+] Reports generated.")


def run_full_pipeline():
    """Run the complete analysis pipeline."""
    print("\n[+] RUNNING FULL PIPELINE")
    print("=" * 50)
    
    analysis = run_analysis_cli()
    if not analysis:
        return
    
    targets = run_strategy_cli(analysis)
    if not targets:
        return
    
    print("\n[+] Select a target:")
    choice = get_input("Enter number (default: 1): ") or "1"
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(targets):
            target = targets[idx]
        else:
            target = targets[0]
    except ValueError:
        target = targets[0]
    
    print(f"\n[+] Selected: {target.get('endpoint')}")
    
    endpoint = target.get('endpoint', '/api/data')
    param = target.get('params', ['id'])[0] if target.get('params') else 'id'
    
    payloads = generate_payloads(target.get('vulnerability', 'IDOR'), 3)
    requests = build_requests('https://example.com', endpoint, param, payloads)
    
    print(f"\n[+] Built {len(requests)} requests")
    
    print("\n[+] Simulated responses (using test data):")
    responses = [
        {'status': 200, 'length': 500, 'payload': '1'},
        {'status': 200, 'length': 510, 'payload': '2'},
        {'status': 200, 'length': 505, 'payload': '999'}
    ]
    
    anomalies, llm_result = analyze_responses_cli()
    
    if not anomalies:
        print("\n[+] Simulating some anomalies for demo...")
        anomalies = [
            {
                'type': 'size_difference',
                'vulnerability': 'possible_idor',
                'severity': 'high',
                'description': 'Response size changed significantly',
                'payload': '999'
            }
        ]
    
    generate_report_cli(anomalies, llm_result, target)
    
    print("\n[+] Pipeline complete!")


def run_cli():
    """Main CLI loop."""
    print(BANNER)
    
    analysis_results = []
    strategy_results = []
    current_anomalies = []
    current_llm = None
    current_target = None
    
    while True:
        print_menu()
        choice = get_input("Select option (0-9): ")
        
        try:
            if choice == '1':
                analysis_results = run_analysis_cli()
            
            elif choice == '2':
                strategy_results = run_strategy_cli(analysis_results)
            
            elif choice == '3':
                generate_payloads_cli()
            
            elif choice == '4':
                build_requests_cli()
            
            elif choice == '5':
                current_anomalies, current_llm = analyze_responses_cli()
            
            elif choice == '6':
                generate_report_cli(current_anomalies, current_llm, current_target)
            
            elif choice == '7':
                run_full_pipeline()
            
            elif choice == '8':
                load_session_cli()
            
            elif choice == '9':
                run_quick_test()
            
            elif choice == '0':
                p_success("Goodbye!")
                break
            
            else:
                p_warn("Invalid option. Select 0-9.")
        
        except KeyboardInterrupt:
            p_warn("Interrupted. Type '0' to exit.")
        except Exception as e:
            p_error(f"Error: {e}")


def load_session_cli():
    """Load and display last session."""
    print("\n[+] LOAD LAST SESSION")
    print("-" * 40)
    
    session = load_session()
    
    if not session:
        print("No previous session found.")
        return
    
    print(f"Timestamp: {session.get('timestamp', 'unknown')}")
    print(f"Selected Target: {session.get('selected_target', 'unknown')}")
    
    targets = session.get('targets', [])
    if targets:
        print(f"\nTargets ({len(targets)}):")
        for t in targets[:3]:
            print(f"  - {t.get('endpoint')} ({t.get('vulnerability')})")
    
    payloads = session.get('payloads', [])
    if payloads:
        print(f"\nPayloads:")
        for p in payloads[:5]:
            print(f"  - {p}")
    
    print(f"\nNotes: {session.get('notes', 'none')}")


if __name__ == "__main__":
    run_cli()


def save_session(targets: list, selected: dict, payloads: list, notes: str = "") -> str:
    """
    Save session results to JSON file.
    
    Args:
        targets: List of analyzed targets.
        selected: Selected target dict.
        payloads: List of generated payloads.
        notes: Optional notes.
    
    Returns:
        Path to saved file.
    """
    import json
    from datetime import datetime
    
    session = {
        "timestamp": datetime.now().isoformat(),
        "targets": targets,
        "selected_target": selected.get("endpoint", "unknown") if selected else None,
        "payloads": payloads,
        "notes": notes
    }
    
    output_path = Path(__file__).parent.parent / "data" / "output" / "session.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(session, f, indent=2)
    
    return str(output_path)


def load_session() -> dict:
    """
    Load last session from JSON file.
    
    Returns:
        Session dict or empty dict.
    """
    import json
    
    session_path = Path(__file__).parent.parent / "data" / "output" / "session.json"
    
    if session_path.exists():
        try:
            with open(session_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    
    return {}


def run_auto_mode(urls: list = None, focus: bool = False):
    """
    Run in auto mode - automatic pipeline execution.
    
    Args:
        urls: Optional list of URLs (else prompt).
        focus: If True, limit to top 1-2 targets.
    """
    print(BANNER)
    print(f"\n{Fore.GREEN}{Style.BRIGHT}[*] AUTO MODE{Style.RESET_ALL}")
    
    if not urls:
        print("\nEnter URLs (one per line, empty line to finish):")
        urls = []
        while True:
            line = get_input("  > ")
            if not line:
                break
            if line.startswith(('http://', 'https://')):
                urls.append(line)
    
    if not urls:
        p_error("No URLs provided.")
        return
    
    p_info(f"Analyzing {len(urls)} URLs...")
    time.sleep(0.3)
    
    url_input = '\n'.join(urls)
    analysis = analyze(url_input)
    
    if not analysis:
        p_error("No valid targets found.")
        return
    
    targets = prioritize(analysis)
    
    if focus:
        targets = targets[:2]
        p_warn(f"Focus mode: limiting to top {len(targets)} targets")
    
    if not targets:
        p_error("No valid targets after prioritization.")
        return
    
    section("ANALYSIS COMPLETE")
    p_success(f"Found {len(targets)} prioritized target(s)")
    
    for i, t in enumerate(targets, 1):
        p_target(t, i)
        recs = get_test_recommendations(t)
        if recs:
            p_next_step(recs[0])
    
    selected = targets[0]
    
    section("SELECTED TARGET")
    p_target(selected)
    
    vuln_type = selected.get('vulnerability', 'IDOR')
    payloads = generate_payloads(vuln_type, 5)
    p_payloads(payloads)
    
    endpoint = selected.get('endpoint', '/api/data')
    param = selected.get('params', ['id'])[0] if selected.get('params') else 'id'
    requests = build_requests('https://target.com', endpoint, param, payloads)
    
    print(f"\n{Fore.CYAN}Sample Requests:{Style.RESET_ALL}")
    print(format_requests(requests[:3]))
    
    save_session(targets, selected, payloads, notes="Auto mode session")
    
    section("AUTO MODE COMPLETE")
    p_success("Session saved to data/output/session.json")
    p_next_step("Send requests via Burp and analyze responses")


def run_focus_mode(urls: list = None):
    """
    Run in focus mode - top 1-2 targets only.
    
    Args:
        urls: Optional list of URLs.
    """
    print(BANNER)
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}[*] FOCUS MODE{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Showing only top 1-2 high-confidence targets{Style.RESET_ALL}")
    
    if not urls:
        print("\nEnter URLs (one per line, empty line to finish):")
        urls = []
        while True:
            line = get_input("  > ")
            if not line:
                break
            if line.startswith(('http://', 'https://')):
                urls.append(line)
    
    if not urls:
        p_error("No URLs provided.")
        return
    
    url_input = '\n'.join(urls)
    analysis = analyze(url_input)
    
    if not analysis:
        p_error("No valid targets found.")
        return
    
    targets = prioritize(analysis)
    targets = [t for t in targets if t.get('confidence', 0) >= 0.6]
    targets = targets[:2]
    
    if not targets:
        p_error("No high-confidence targets found.")
        return
    
    section("FOCUS: TOP TARGETS")
    for i, t in enumerate(targets, 1):
        p_target(t, i)
        recs = get_test_recommendations(t)
        if recs:
            p_next_step(recs[0])
    
    selected = targets[0]
    vuln_type = selected.get('vulnerability', 'IDOR')
    payloads = generate_payloads(vuln_type, 3)
    p_payloads(payloads)
    
    save_session(targets, selected, payloads, notes="Focus mode session")
    p_success("Session saved to data/output/session.json")


def run_quick_test():
    """Run quick test - full flow with minimal interaction."""
    print(BANNER)
    print(f"\n{Fore.GREEN}{Style.BRIGHT}[*] QUICK TEST MODE{Style.RESET_ALL}")
    
    print("\nEnter URLs (one per line, empty line to finish):")
    urls = []
    while True:
        line = get_input("  > ")
        if not line:
            break
        if line.startswith(('http://', 'https://')):
            urls.append(line)
    
    if not urls:
        p_error("No URLs provided.")
        return
    
    p_info(f"Analyzing {len(urls)} URLs...")
    
    url_input = '\n'.join(urls)
    analysis = analyze(url_input)
    
    if not analysis:
        p_error("No valid targets found.")
        return
    
    targets = prioritize(analysis)
    
    if not targets:
        p_error("No valid targets after prioritization.")
        return
    
    selected = targets[0]
    vuln_type = selected.get('vulnerability', 'IDOR')
    payloads = generate_payloads(vuln_type, 3)
    
    endpoint = selected.get('endpoint', '/api/data')
    param = selected.get('params', ['id'])[0] if selected.get('params') else 'id'
    requests = build_requests('https://target.com', endpoint, param, payloads)
    
    section("QUICK TEST RESULTS")
    p_target(selected)
    p_payloads(payloads)
    print(f"\n{Fore.CYAN}Built Requests:{Style.RESET_ALL}")
    print(format_requests(requests[:3]))
    
    save_session(targets, selected, payloads, notes="Quick test session")
    p_success("Session saved")
    p_next_step("Send requests via Burp and verify results")
