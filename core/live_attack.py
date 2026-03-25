"""Live-Attack unified mode - continuous monitoring with attack execution."""

import time
import threading
from typing import Optional

from core.queue import EndpointQueue, get_queue
from core.live_listener import (
    LiveListener,
    check_proxy_available,
    filter_and_score,
    print_endpoint_detection,
)
from core.parser import save_responses
from agents.fuzz import generate_payloads
from agents.response import analyze_responses
from agents.request_builder import build_requests, format_requests


def process_attack(queued_endpoint, payloads, get_input_fn) -> tuple:
    """
    Process an attack for the given endpoint.

    Returns:
        (confirmed, responses, anomalies)
    """
    print(f"\n{'=' * 50}")
    print(f"{Fore.GREEN}[+] Ready to test: {queued_endpoint.normalized}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Score:{Style.RESET_ALL} {queued_endpoint.score}")
    print(f"{Fore.CYAN}Original:{Style.RESET_ALL} {queued_endpoint.method} {queued_endpoint.url}")
    print(f"\n{Fore.GREEN}Payloads:{Style.RESET_ALL} {', '.join(payloads)}")

    requests = build_requests("https://target.com", queued_endpoint.endpoint, "id", payloads)

    print(f"\n{Fore.CYAN}Requests to send:{Style.RESET_ALL}")
    print(format_requests(requests[:3]))

    confirm = get_input_fn("\nProceed? (y/n): ")

    if confirm.lower() != "y":
        return False, [], []

    from core.cli import send_through_proxy

    responses = send_through_proxy(requests)

    return True, responses, []


def analyze_results(responses, queued_endpoint):
    """Analyze attack results and output findings."""
    print(f"\n{'=' * 50}")
    print(f"{Fore.CYAN}ANALYSIS RESULTS{Style.RESET_ALL}")

    if not responses:
        print(f"{Fore.YELLOW}No responses captured{Style.RESET_ALL}")
        return

    anomalies = analyze_responses(responses)

    if anomalies:
        for a in anomalies:
            print(f"\n{Fore.RED}{Style.BRIGHT}[!] Possible vulnerability detected{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Confidence:{Style.RESET_ALL} {a.get('confidence', 0.5):.0%}")
            print(
                f"{Fore.CYAN}Reason:{Style.RESET_ALL} {a.get('description', 'Response anomaly detected')}"
            )
            print(f"\n{Fore.GREEN}Next step:{Style.RESET_ALL} Verify manually")
    else:
        print(f"{Fore.YELLOW}[-] No obvious anomalies detected{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Manual verification recommended{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}Response summary:{Style.RESET_ALL}")
    for resp in responses[:3]:
        status = resp.get("status", "?")
        length = resp.get("length", 0)
        print(f"  [{status}] len={length}")


def run_live_attack_mode():
    """
    Run in live-attack mode - continuous monitoring with attack execution.

    Features:
    - Monitor proxy traffic in real-time
    - Queue high-score endpoints
    - Prompt for attack execution
    - Execute attacks safely
    - Analyze results
    - Continue monitoring
    """
    try:
        from colorama import Fore, Style
        from core.cli import section, p_info, p_warn, p_success, get_input
    except ImportError:
        Fore = type(
            "obj",
            (object,),
            {
                "GREEN": "\033[92m",
                "RED": "\033[91m",
                "YELLOW": "\033[93m",
                "CYAN": "\033[96m",
                "WHITE": "",
            },
        )()
        Style = type("obj", (object,), {"BRIGHT": "\033[1m", "RESET_ALL": "\033[0m"})()

        def section(x):
            print(f"\n{'=' * 50}\n{x}\n{'=' * 50}")

        def p_info(x):
            print(f"[*] {x}")

        def p_warn(x):
            print(f"[-] {x}")

        def p_success(x):
            print(f"[+] {x}")

        def get_input(x):
            return input(x)

    print(f"\n{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}BugHunter LIVE-ATTACK MODE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Continuous monitoring with safe attack execution{Style.RESET_ALL}")
    print()

    if not check_proxy_available():
        print(f"{Fore.YELLOW}[!] Proxy not available on 127.0.0.1:8080{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Will continue monitoring when proxy is available{Style.RESET_ALL}")
        print()

    queue = get_queue()
    queue.clear()

    listener = LiveListener()
    listener.start()

    processed_count = 0
    max_processed = 5

    print(f"{Fore.CYAN}[*] Starting live monitoring...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Press Ctrl+C to stop{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Endpoints will be queued for testing{Style.RESET_ALL}")
    print()

    last_queue_check = time.time()
    queue_check_interval = 3

    try:
        while listener.running:
            time.sleep(0.5)

            elapsed = int(time.time() - last_queue_check)
            if elapsed >= queue_check_interval:
                last_queue_check = time.time()

                queued = queue.get_unprocessed()

                if queued:
                    queued_endpoint = queued[0]
                    queue.mark_processed(queued_endpoint.normalized)
                    processed_count += 1

                    print(f"\n{Fore.GREEN}{'=' * 50}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[*] Endpoint queued for testing{Style.RESET_ALL}")

                    payloads = generate_payloads("IDOR", 3)

                    confirmed, responses, anomalies = process_attack(
                        queued_endpoint, payloads, get_input
                    )

                    if confirmed and responses:
                        analyze_results(responses, queued_endpoint)

                        resp_path = save_responses(responses)
                        print(f"{Fore.CYAN}[+] Responses saved to: {resp_path}{Style.RESET_ALL}")

                    if processed_count >= max_processed:
                        print(
                            f"\n{Fore.YELLOW}[!] Max attacks reached ({max_processed}){Style.RESET_ALL}"
                        )
                        print(f"{Fore.YELLOW}[!] Continuing in observation mode{Style.RESET_ALL}")
                        queue.mark_all_processed()

                if check_proxy_available():
                    print(f"{Fore.GREEN}{Style.BRIGHT}[+] Proxy connected{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
    finally:
        listener.stop()

    print(f"\n{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] LIVE-ATTACK SESSION COMPLETE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Endpoints detected: {queue.count()}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Attacks executed: {processed_count}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
