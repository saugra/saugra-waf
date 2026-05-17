#!/usr/bin/env python3
"""
WAF Security Testing Framework
Description: A professional script to validate WAF rulesets against common attack vectors.
Usage: python waf_tester.py --url https://your-target-app.com
"""

import argparse
import logging
import sys
from datetime import datetime
import requests
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    filename=f"waf_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


class WafTester:

    def __init__(self, target_url, user_agent=None):
        self.target_url = target_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    user_agent
                    or "WAF-Validation-Engine/1.0 (SecOps Test Script)"
                )
            }
        )

        # Define test payloads categorized by attack type
        self.payloads = {
            "SQL Injection (SQLi)": [
                "' OR '1'='1",
                "1' UNION SELECT null, null, null--",
                "admin' --",
                "OR 1=1 --",
            ],
            "Cross-Site Scripting (XSS)": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                '"><script>confirm(1)</script>',
            ],
            "Path Traversal": [
                "../../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ],
            "Remote Code Execution (RCE)": [
                "; cat /etc/passwd",
                "&& ls -la",
                "| id",
                "`whoami`",
            ],
        }

    def print_status(self, category, payload, status_code, blocked):
        """Prints formatted results to the console and logs them to a file."""
        if blocked:
            result_text = f"{Fore.GREEN}[BLOCKED]{Style.RESET_ALL}"
            log_level = "INFO"
        else:
            result_text = f"{Fore.RED}[PASSED/NOT BLOCKED]{Style.RESET_ALL}"
            log_level = "WARNING"

        output = (
            f"{result_text} Category: {category} | Payload: {payload} | "
            f"Response Code: {status_code}"
        )
        print(output)
        logging.log(
            getattr(logging, log_level),
            f"Category: {category} | Payload: {payload} | Status: {status_code} | Blocked: {blocked}",
        )

    def run_tests(self):
        """Iterates through attack categories and sends payloads via GET and POST."""
        print(f"{Fore.BLUE}[*] Starting WAF validation against: {self.target_url}")
        print(f"[*] Results will be saved to the local log file.\n" + "-" * 80)

        total_tests = 0
        blocked_tests = 0

        for category, payloads in self.payloads.items():
            print(f"\n{Fore.CYAN}--- Testing Category: {category} ---")

            for payload in payloads:
                # 1. Test via GET Query Parameter
                total_tests += 1
                try:
                    # Encoding is handled automatically by requests
                    response = self.session.get(
                        self.target_url, params={"test_param": payload}, timeout=10
                    )
                    # Standard WAF blocks return 403 Forbidden, 406 Not Acceptable, or 418 I'm a teapot
                    is_blocked = response.status_code in [403, 406, 418, 501]
                    if is_blocked:
                        blocked_tests += 1
                    self.print_status(
                        category, f"?test_param={payload}", response.status_code, is_blocked
                    )
                except requests.exceptions.RequestException as e:
                    print(f"{Fore.YELLOW}[ERROR] Connection issue: {e}")
                    logging.error(f"Error testing GET payload {payload}: {e}")

                # 2. Test via POST Body
                total_tests += 1
                try:
                    response = self.session.post(
                        self.target_url, data={"test_param": payload}, timeout=10
                    )
                    is_blocked = response.status_code in [403, 406, 418, 501]
                    if is_blocked:
                        blocked_tests += 1
                    self.print_status(
                        category, f"POST body={payload}", response.status_code, is_blocked
                    )
                except requests.exceptions.RequestException as e:
                    print(f"{Fore.YELLOW}[ERROR] Connection issue: {e}")
                    logging.error(f"Error testing POST payload {payload}: {e}")

        # Summary
        print("\n" + "=" * 80)
        print(f"{Fore.BLUE}[*] Testing Complete.")
        print(f"Total Blocked: {blocked_tests}/{total_tests}")
        efficiency = (blocked_tests / total_tests) * 100 if total_tests > 0 else 0
        print(f"WAF Block Rate: {efficiency:.2f}%")
        print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="Professional WAF Testing Script"
    )
    parser.add_argument(
        "--url", required=True, help="Target URL to test (e.g., https://example.com)"
    )
    parser.add_argument(
        "--ua",
        required=False,
        help="Optional: Custom User-Agent string to use",
    )

    args = parser.parse_args()

    # Simple sanity check for URL format
    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        print(
            f"{Fore.RED}[!] Invalid URL scheme. URL must start with http:// or https://"
        )
        sys.exit(1)

    tester = WafTester(target_url=args.url, user_agent=args.ua)
    tester.run_tests()


if __name__ == "__main__":
    main()
