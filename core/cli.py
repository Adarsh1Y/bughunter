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
        GREEN = RED = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ""

    class Style:
        BRIGHT = RESET_ALL = ""


from agents.analysis import analyze
from agents.strategy import prioritize, get_test_recommendations
from agents.fuzz import generate_payloads
from agents.request_builder import build_requests, format_requests
from agents.response import analyze_responses, summarize_anomalies
from agents.response.llm_analyzer import analyze_with_llm
from agents.report import generate_report
from core.parser import (
    parse_traffic_file,
    get_endpoint,
    has_auth,
    is_static_file,
    is_api_endpoint,
    filter_traffic,
    filter_and_score,
    generate_request_pack,
    save_request_pack,
)


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
    """Print anomaly detected message."""
    print(f"{Fore.RED}{Style.BRIGHT}[!] ANOMALY: {msg}{Style.RESET_ALL}")


def section(title: str):
    """Print a section header."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}{title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")


def p_target(target: dict, num: int = None):
    """Print a target nicely with honest status."""
    prefix = f"{num}. " if num else ""
    endpoint = target.get("endpoint", "unknown")
    vuln = target.get("vulnerability", "NONE")
    risk = target.get("risk", "low").upper()
    score = target.get("score", 0)

    risk_color = Fore.RED if risk == "HIGH" else Fore.YELLOW if risk == "MEDIUM" else Fore.GREEN

    print(f"\n{prefix}{Fore.WHITE}{endpoint}{Style.RESET_ALL}")
    print(f"     {Fore.CYAN}Status:{Style.RESET_ALL} {Fore.YELLOW}UNVERIFIED{Style.RESET_ALL}")
    print(f"     {Fore.CYAN}Pattern:{Style.RESET_ALL} {vuln}")
    print(f"     {Fore.CYAN}Risk:{Style.RESET_ALL} {risk_color}{risk}{Style.RESET_ALL}")
    print(f"     {Fore.CYAN}Score:{Style.RESET_ALL} {score}")

    if target.get("reason"):
        print(f"     {Fore.CYAN}Pattern Match:{Style.RESET_ALL} {target.get('reason')}")

    print(f"\n     {Fore.YELLOW}Manual verification required before confirming{Style.RESET_ALL}")


def p_payloads(payloads: list):
    """Print payloads nicely."""
    print(f"\n{Fore.CYAN}Payloads:{Style.RESET_ALL}")
    for p in payloads:
        print(f"  {Fore.YELLOW}•{Style.RESET_ALL} {p}")


def print_test_plan(target: dict, payloads: list, requests: list):
    """
    Print clean test plan output with honest status.

    Args:
        target: Target dict with endpoint, score, etc.
        payloads: List of payload values.
        requests: List of request dicts.
    """
    print(f"\n{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[+] Target: {target.get('endpoint', 'unknown')}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Status: UNVERIFIED{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Score: {target.get('score', 0)}{Style.RESET_ALL}")

    payload_str = ", ".join(str(p) for p in payloads)
    print(f"\n{Fore.CYAN}Suggested Payloads:{Style.RESET_ALL} {payload_str}")

    request_strs = []
    for req in requests:
        method = req.get("method", "GET")
        url = req.get("url", "")
        request_strs.append(f"{method} {url}")

    print(f"\n{Fore.CYAN}Test Requests:{Style.RESET_ALL}")
    for req_str in request_strs:
        print(f"  {req_str}")

    vuln = target.get("vulnerability", "IDOR")
    what_to_test = {
        "IDOR": "Compare responses - look for different user data",
        "XSS": "Compare responses - look for reflected input",
        "SQLI": "Compare responses - look for SQL errors",
        "AUTH": "Compare responses - look for auth bypass",
        "RCE": "Compare responses - look for command output",
    }
    print(
        f"\n{Fore.CYAN}Next Step:{Style.RESET_ALL} {what_to_test.get(vuln, 'Compare responses for differences')}"
    )
    print(
        f"\n{Fore.YELLOW}This result is not confirmed. Manual verification required.{Style.RESET_ALL}"
    )
    print(f"{Fore.YELLOW}{'=' * 50}{Style.RESET_ALL}")


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
    print(f"{Fore.WHITE}A.{Style.RESET_ALL} Quick Retest (Fast)")
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
        if line.startswith(("http://", "https://")):
            urls.append(line)

    if not urls:
        p_warn("No URLs provided.")
        return []

    url_input = "\n".join(urls)
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
        payloads = [p.strip() for p in payloads_input.split(",")]
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
        if not line or line.lower() == "s":
            break

        parts = line.split(",")
        if len(parts) >= 2:
            try:
                responses.append(
                    {
                        "status": int(parts[0]),
                        "length": int(parts[1]),
                        "payload": parts[2] if len(parts) > 2 else "",
                    }
                )
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
            sev = a.get("severity", "unknown").upper()
            vtype = a.get("type", "unknown")
            vuln = a.get("vulnerability", "")
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
            "endpoint": "/api/test",
            "params": ["id"],
            "vulnerability": "Unknown",
            "risk": "medium",
        }

    print(f"Generating report for {len(anomalies)} finding(s)...")

    for i, a in enumerate(anomalies, 1):
        report = generate_report(
            target=target,
            payload=a.get("payload", ""),
            anomaly=a,
            llm_analysis=llm_analysis or "",
            vuln_type=target.get("vulnerability", "Unknown"),
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

    endpoint = target.get("endpoint", "/api/data")
    param = target.get("params", ["id"])[0] if target.get("params") else "id"

    payloads = generate_payloads(target.get("vulnerability", "IDOR"), 3)
    requests = build_requests("https://example.com", endpoint, param, payloads)

    print(f"\n[+] Built {len(requests)} requests")

    print("\n[+] Simulated responses (using test data):")
    responses = [
        {"status": 200, "length": 500, "payload": "1"},
        {"status": 200, "length": 510, "payload": "2"},
        {"status": 200, "length": 505, "payload": "999"},
    ]

    anomalies, llm_result = analyze_responses_cli()

    if not anomalies:
        print("\n[+] Simulating some anomalies for demo...")
        anomalies = [
            {
                "type": "size_difference",
                "vulnerability": "possible_idor",
                "severity": "high",
                "description": "Response size changed significantly",
                "payload": "999",
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
            if choice == "1":
                analysis_results = run_analysis_cli()

            elif choice == "2":
                strategy_results = run_strategy_cli(analysis_results)

            elif choice == "3":
                generate_payloads_cli()

            elif choice == "4":
                build_requests_cli()

            elif choice == "5":
                current_anomalies, current_llm = analyze_responses_cli()

            elif choice == "6":
                generate_report_cli(current_anomalies, current_llm, current_target)

            elif choice == "7":
                run_full_pipeline()

            elif choice == "8":
                load_session_cli()

            elif choice == "9":
                run_quick_test()

            elif choice.lower() == "a":
                run_retest_mode()

            elif choice == "0":
                p_success("Goodbye!")
                break

            else:
                p_warn("Invalid option. Select 0-9 or A.")

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

    targets = session.get("targets", [])
    if targets:
        print(f"\nTargets ({len(targets)}):")
        for t in targets[:3]:
            print(f"  - {t.get('endpoint')} ({t.get('vulnerability')})")

    payloads = session.get("payloads", [])
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
        "notes": notes,
    }

    output_path = Path(__file__).parent.parent / "data" / "output" / "session.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
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
            with open(session_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass

    return {}


def run_auto_mode(urls: list = None, focus: bool = False, input_file: str = None):
    """
    Run in auto mode - automatic pipeline execution.

    Args:
        urls: Optional list of URLs (else prompt).
        focus: If True, limit to top 1-2 targets.
        input_file: Optional path to traffic.json file.
    """
    print(BANNER)
    print(f"\n{Fore.GREEN}{Style.BRIGHT}[*] AUTO MODE{Style.RESET_ALL}")

    if input_file:
        p_info(f"Loading traffic from: {input_file}")
        try:
            traffic_data = parse_traffic_file(input_file)
            p_success(f"Parsed {len(traffic_data)} requests from traffic file")

            filtered_data = filter_traffic(traffic_data)
            p_info(f"Filtered to {len(filtered_data)} relevant requests (API + authenticated)")

            if not filtered_data:
                p_error("No relevant traffic after filtering.")
                return

            urls = [req["url"] for req in filtered_data]
            p_info(f"Extracted {len(urls)} URLs from filtered traffic")
        except Exception as e:
            p_error(f"Failed to parse traffic file: {e}")
            return
    elif not urls:
        print("\nEnter URLs (one per line, empty line to finish):")
        urls = []
        while True:
            line = get_input("  > ")
            if not line:
                break
            if line.startswith(("http://", "https://")):
                urls.append(line)

    if not urls:
        p_error("No URLs provided.")
        return

    p_info(f"Analyzing {len(urls)} URLs...")
    time.sleep(0.3)

    url_input = "\n".join(urls)
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

    vuln_type = selected.get("vulnerability", "IDOR")
    payloads = generate_payloads(vuln_type, 5)

    endpoint = selected.get("endpoint", "/api/data")
    param = selected.get("params", ["id"])[0] if selected.get("params") else "id"
    requests = build_requests("https://target.com", endpoint, param, payloads[:3])

    print_test_plan(selected, payloads[:3], requests)

    save_session(targets, selected, payloads, notes="Auto mode session")

    section("AUTO MODE COMPLETE")
    p_success("Session saved to data/output/session.json")
    p_next_step("Send requests via Burp and analyze responses")


def run_focus_mode(urls: list = None, input_file: str = None):
    """
    Run in focus mode - top 1-2 targets only.

    Args:
        urls: Optional list of URLs.
        input_file: Optional path to traffic.json file.
    """
    print(BANNER)
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}[*] FOCUS MODE{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Showing only top 1-2 high-confidence targets{Style.RESET_ALL}")

    if input_file:
        p_info(f"Loading traffic from: {input_file}")
        try:
            traffic_data = parse_traffic_file(input_file)
            p_success(f"Parsed {len(traffic_data)} requests from traffic file")

            filtered_data = filter_traffic(traffic_data)
            p_info(f"Filtered to {len(filtered_data)} relevant requests (API + authenticated)")

            if not filtered_data:
                p_error("No relevant traffic after filtering.")
                return

            urls = [req["url"] for req in filtered_data]
            p_info(f"Extracted {len(urls)} URLs from filtered traffic")
        except Exception as e:
            p_error(f"Failed to parse traffic file: {e}")
            return
    elif not urls:
        print("\nEnter URLs (one per line, empty line to finish):")
        urls = []
        while True:
            line = get_input("  > ")
            if not line:
                break
            if line.startswith(("http://", "https://")):
                urls.append(line)

    if not urls:
        p_error("No URLs provided.")
        return

    url_input = "\n".join(urls)
    analysis = analyze(url_input)

    if not analysis:
        p_error("No valid targets found.")
        return

    targets = prioritize(analysis)
    targets = [t for t in targets if t.get("confidence", 0) >= 0.6]
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
    vuln_type = selected.get("vulnerability", "IDOR")
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
        if line.startswith(("http://", "https://")):
            urls.append(line)

    if not urls:
        p_error("No URLs provided.")
        return

    p_info(f"Analyzing {len(urls)} URLs...")

    url_input = "\n".join(urls)
    analysis = analyze(url_input)

    if not analysis:
        p_error("No valid targets found.")
        return

    targets = prioritize(analysis)

    if not targets:
        p_error("No valid targets after prioritization.")
        return

    selected = targets[0]
    vuln_type = selected.get("vulnerability", "IDOR")
    payloads = generate_payloads(vuln_type, 3)

    endpoint = selected.get("endpoint", "/api/data")
    param = selected.get("params", ["id"])[0] if selected.get("params") else "id"
    requests = build_requests("https://target.com", endpoint, param, payloads)

    section("QUICK TEST RESULTS")
    p_target(selected)
    p_payloads(payloads)
    print(f"\n{Fore.CYAN}Built Requests:{Style.RESET_ALL}")
    print(format_requests(requests[:3]))

    save_session(targets, selected, payloads, notes="Quick test session")
    p_success("Session saved")
    p_next_step("Send requests via Burp and verify results")


def run_retest_mode(endpoint: str = None):
    """
    Quick retest mode - fast endpoint testing without full analysis.

    Args:
        endpoint: Optional endpoint string (e.g., "/api/user?id=1").
    """
    print(BANNER)
    print(f"\n{Fore.GREEN}{Style.BRIGHT}[*] QUICK RETEST MODE{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Fast testing without full analysis{Style.RESET_ALL}")

    if not endpoint:
        endpoint = get_input("\nEnter endpoint to retest (e.g., /api/user?id=1): ")

    if not endpoint:
        p_error("No endpoint provided.")
        return

    from urllib.parse import urlparse, parse_qs
    from agents.fuzz import generate_payloads
    from agents.request_builder import build_requests

    parsed = urlparse(endpoint if "://" in endpoint else f"http://example.com{endpoint}")
    path = parsed.path
    params = parse_qs(parsed.query)

    if not params:
        param_name = get_input("Parameter name (default: id): ") or "id"
        payloads = generate_payloads("IDOR", 3)
    else:
        param_name = list(params.keys())[0]
        existing_values = params[param_name]
        print(f"{Fore.CYAN}Detected parameter: {param_name} = {existing_values}{Style.RESET_ALL}")
        payloads = generate_payloads("IDOR", 3)

    section("RETEST TARGET")
    print(f"{Fore.WHITE}Endpoint:{Style.RESET_ALL} {path}")
    print(f"{Fore.WHITE}Parameter:{Style.RESET_ALL} {param_name}")

    print(f"\n{Fore.CYAN}Payloads:{Style.RESET_ALL}")
    for p in payloads:
        print(f"  {Fore.YELLOW}•{Style.RESET_ALL} {p}")

    base_url = get_input("\nBase URL (default: https://target.com): ") or "https://target.com"
    requests = build_requests(base_url, path, param_name, payloads)

    section("READY-TO-TEST REQUESTS")
    print(format_requests(requests))

    print(f"\n{Fore.GREEN}[+] {len(requests)} requests ready for testing{Style.RESET_ALL}")
    p_next_step("Copy requests to Burp Repeater and test")


def send_through_proxy(
    requests: list[dict], proxy: str = "http://127.0.0.1:8080", delay: int = 1
) -> list[dict]:
    """
    Send requests through proxy and capture responses.

    Args:
        requests: List of request dicts.
        proxy: Proxy URL.
        delay: Delay between requests in seconds.

    Returns:
        List of response dicts with status, length, snippet.
    """
    import time
    import urllib.request
    import urllib.error

    responses = []
    max_requests = 5

    p_info(f"Sending {min(len(requests), max_requests)} requests through {proxy}")
    p_info(f"Safety: delay={delay}s, max_requests={max_requests}")

    for i, req in enumerate(requests[:max_requests]):
        if i >= max_requests:
            p_warn(f"Safety limit reached ({max_requests} requests)")
            break

        try:
            url = req.get("url", "")
            method = req.get("method", "GET")
            headers = req.get("headers", {})

            req_obj = urllib.request.Request(url, method=method)
            for key, value in headers.items():
                req_obj.add_header(key, value)

            proxy_handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
            opener = urllib.request.build_opener(proxy_handler)

            time.sleep(delay)

            try:
                response = opener.open(req_obj, timeout=10)
                status = response.getcode()
                body = response.read().decode("utf-8", errors="ignore")
                length = len(body)
                snippet = body[:200]
            except urllib.error.HTTPError as e:
                status = e.code
                body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
                length = len(body)
                snippet = body[:200]
            except Exception as e:
                status = 0
                length = 0
                snippet = str(e)[:200]

            responses.append(
                {
                    "status": status,
                    "length": length,
                    "snippet": snippet,
                    "payload": req.get("payload", ""),
                    "url": url,
                }
            )

            print(f"  [{status}] {method} {url}")

        except Exception as e:
            p_warn(f"Request failed: {e}")
            responses.append(
                {
                    "status": 0,
                    "length": 0,
                    "snippet": str(e),
                    "payload": req.get("payload", ""),
                    "url": req.get("url", ""),
                }
            )

    return responses


def run_attack_ready_mode(input_file: str = None):
    """
    Run in attack-ready mode - prepare and optionally execute attacks.

    Args:
        input_file: Path to traffic.json file.
    """
    print(BANNER)
    print(f"\n{Fore.RED}{Style.BRIGHT}[*] ATTACK-READY MODE{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Safety: Confirmation required before any requests{Style.RESET_ALL}")

    if not input_file:
        p_error("No input file provided. Use --input traffic.json")
        return

    p_info(f"Loading traffic from: {input_file}")
    try:
        traffic_data = parse_traffic_file(input_file)
        p_success(f"Parsed {len(traffic_data)} requests from traffic file")

        filtered_data = filter_traffic(traffic_data)
        p_info(f"Filtered to {len(filtered_data)} relevant requests (API + authenticated)")

        if not filtered_data:
            p_error("No relevant traffic after filtering.")
            return

        urls = [req["url"] for req in filtered_data]
    except Exception as e:
        p_error(f"Failed to parse traffic file: {e}")
        return

    p_info(f"Analyzing {len(urls)} URLs...")
    url_input = "\n".join(urls)
    analysis = analyze(url_input)

    if not analysis:
        p_error("No valid targets found.")
        return

    targets = prioritize(analysis)
    targets = [t for t in targets if t.get("confidence", 0) >= 0.6]
    targets = targets[:2]

    if not targets:
        p_error("No high-confidence targets found.")
        return

    section("ATTACK-READY: TOP TARGETS")
    for i, t in enumerate(targets, 1):
        p_target(t, i)

    selected = targets[0]
    vuln_type = selected.get("vulnerability", "IDOR")
    payloads = generate_payloads(vuln_type, 3)

    section("GENERATING REQUEST PACK")
    request_pack = generate_request_pack(targets[:1], payloads, "https://target.com")
    save_path = save_request_pack(request_pack)
    p_success(f"Request pack saved to: {save_path}")

    section("PREVIEW: REQUESTS TO TEST")
    print(f"[+] Target: {selected.get('endpoint', 'unknown')}")
    print(f"[+] Requests to test: {len(request_pack)}")
    print()
    for req in request_pack:
        print(f"  {req['method']} {req['url']}")

    section("CONFIRMATION REQUIRED")
    confirm = get_input("Send these requests through proxy? (y/n): ")

    if confirm.lower() != "y":
        p_warn("Aborted. No requests sent.")
        p_info("Requests saved to data/output/requests.json for manual testing.")
        return

    p_info("User confirmed. Executing requests through proxy...")

    responses = send_through_proxy(request_pack)

    if not responses:
        p_error("No responses captured. Check proxy settings.")
        return

    section("RESPONSES CAPTURED")
    p_success(f"Captured {len(responses)} responses")

    for resp in responses:
        status = resp.get("status", "?")
        length = resp.get("length", 0)
        snippet = resp.get("snippet", "")[:50]
        print(f"  [{status}] len={length} | {snippet}...")

    from core.parser import save_responses

    resp_path = save_responses(responses)
    p_success(f"Responses saved to: {resp_path}")

    section("AUTO ANALYSIS")
    anomalies = analyze_responses(responses)

    if anomalies:
        for a in anomalies:
            print(f"\n{Fore.RED}{Style.BRIGHT}[!] Possible issue detected{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Confidence:{Style.RESET_ALL} {a.get('confidence', 0.5):.0%}")
            print(f"{Fore.CYAN}Reason:{Style.RESET_ALL} {a.get('description', 'Unknown')}")
            print(f"\n{Fore.GREEN}Next step:{Style.RESET_ALL} Verify with another account")
    else:
        p_info("No anomalies detected in responses.")


def run_live_mode():
    """Run in live mode - watch proxy traffic in real-time."""
    from core.live_listener import (
        listen_live,
        check_proxy_available,
        print_endpoint_detection,
        LiveListener,
    )

    print(BANNER)
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[*] LIVE MODE{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Safe mode: Observation only - no requests sent{Style.RESET_ALL}")
    print()

    if not check_proxy_available():
        print(f"{Fore.YELLOW}[!] Proxy not available on 127.0.0.1:8080{Style.RESET_ALL}")
        print(
            f"{Fore.YELLOW}[!] Make sure Burp Suite is running with proxy enabled{Style.RESET_ALL}"
        )
        print()
        print(f"{Fore.CYAN}Starting anyway - waiting for proxy...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Press Ctrl+C to exit{Style.RESET_ALL}")
        print()

    listener = LiveListener()
    listener.start()

    try:
        while listener.running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted{Style.RESET_ALL}")
    finally:
        listener.stop()

    results = listener.get_requests()

    section("LIVE SESSION SUMMARY")
    p_success(f"Captured {len(results)} endpoints")

    if results:
        for r in results:
            print_endpoint_detection(r)

    p_info("Session complete. Use --attack-ready to prepare actual tests.")
