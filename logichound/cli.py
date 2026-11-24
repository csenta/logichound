#!/usr/bin/env python3
"""
CLI for LogicHound: Autonomous Business-Logic and Authorization Vulnerability Auditor.
"""

import argparse
import json
import sys
from logichound.models import AuthSession, HTTPRequest
from logichound.scanner import LogicScanner


def main():
    parser = argparse.ArgumentParser(
        description="LogicHound: Automated BOLA, IDOR & Privilege Escalation Auditor."
    )
    parser.add_argument("--url", required=True, help="Target URL / API endpoint to audit")
    parser.add_argument("--method", default="GET", help="HTTP Method (GET, POST, etc.)")
    parser.add_argument("--token-a", required=True, help="Auth token / header for Victim / High-Privilege session")
    parser.add_argument("--token-b", required=True, help="Auth token / header for Attacker / Low-Privilege session")
    parser.add_argument("--user-id-a", help="Victim user ID / identifier (e.g. usr_1001)")
    parser.add_argument("--role-a", default="admin", help="Role of session A (default: admin)")
    parser.add_argument("--role-b", default="user", help="Role of session B (default: user)")
    parser.add_argument("--body", help="Request body string or JSON")
    parser.add_argument("--out", help="Path to save output Markdown report")

    args = parser.parse_args()

    session_a = AuthSession(
        name="Session_A",
        headers={"Authorization": f"Bearer {args.token_a}"},
        user_id=args.user_id_a,
        role=args.role_a,
    )
    session_b = AuthSession(
        name="Session_B",
        headers={"Authorization": f"Bearer {args.token_b}"},
        role=args.role_b,
    )

    scanner = LogicScanner(session_victim=session_a, session_attacker=session_b)
    req = HTTPRequest(
        method=args.method.upper(),
        url=args.url,
        body=args.body,
    )

    print(f"[*] Starting LogicHound audit on {req.method} {req.url}...")
    findings = scanner.audit_endpoint(req)

    report = scanner.generate_markdown_report()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] Saved audit report to: {args.out}")
    else:
        print("\n" + report)

    if findings:
        sys.exit(2)  # Exit code 2 indicates vulnerabilities detected
    sys.exit(0)


if __name__ == "__main__":
    main()
