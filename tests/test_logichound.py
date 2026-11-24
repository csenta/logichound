"""
Unit tests for LogicHound Business-Logic and Authorization Scanner.
"""

import unittest
from logichound.models import AuthSession, HTTPRequest, HTTPResponse
from logichound.scanner import LogicScanner


class TestLogicHound(unittest.TestCase):

    def setUp(self):
        self.session_admin = AuthSession(
            name="AdminSession",
            user_id="usr_admin",
            role="admin",
            headers={"Authorization": "Bearer admin_secret_token"},
        )
        self.session_user = AuthSession(
            name="UserSession",
            user_id="usr_regular",
            role="user",
            headers={"Authorization": "Bearer user_token_123"},
        )
        self.session_victim = AuthSession(
            name="VictimSession",
            user_id="usr_victim_888",
            role="user",
            headers={"Authorization": "Bearer victim_token_888"},
        )

    def test_detect_bola_idor(self):
        # Mock API where attacker can access victim's order
        def mock_vulnerable_api(req: HTTPRequest) -> HTTPResponse:
            auth_header = req.headers.get("Authorization", "")
            if "victim" in auth_header or "user" in auth_header:
                return HTTPResponse(
                    status_code=200,
                    body='{"order_id": "ord_99", "owner": "usr_victim_888", "amount": 500}',
                    json_data={"order_id": "ord_99", "owner": "usr_victim_888", "amount": 500},
                )
            return HTTPResponse(status_code=401, body="Unauthorized")

        scanner = LogicScanner(
            session_victim=self.session_victim,
            session_attacker=self.session_user,
            requester_func=mock_vulnerable_api,
        )

        findings = scanner.audit_endpoint(
            HTTPRequest(method="GET", url="https://api.target.local/v1/orders/ord_99")
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "BOLA_IDOR")
        self.assertEqual(findings[0].severity, "High")
        self.assertIn("usr_victim_888", findings[0].evidence)

    def test_detect_bfla_privilege_escalation(self):
        # Admin endpoint that fails to check role
        def mock_admin_endpoint(req: HTTPRequest) -> HTTPResponse:
            auth_header = req.headers.get("Authorization", "")
            if auth_header:  # Any logged in user allowed
                return HTTPResponse(
                    status_code=200,
                    body='{"status": "success", "message": "all settings flushed"}',
                    json_data={"status": "success"},
                )
            return HTTPResponse(status_code=401, body="Login required")

        scanner = LogicScanner(
            session_victim=self.session_admin,
            session_attacker=self.session_user,
            requester_func=mock_admin_endpoint,
        )

        findings = scanner.audit_endpoint(
            HTTPRequest(method="POST", url="https://api.target.local/v1/admin/flush")
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "BFLA_PRIVILEGE_ESCALATION")
        self.assertEqual(findings[0].severity, "High")

    def test_properly_enforced_access_control(self):
        # Secure API properly rejecting cross-access
        def mock_secure_api(req: HTTPRequest) -> HTTPResponse:
            auth = req.headers.get("Authorization", "")
            if "victim" in auth:
                return HTTPResponse(status_code=200, body='{"data": "victim_profile"}')
            elif "user" in auth:
                return HTTPResponse(status_code=403, body='{"error": "Forbidden"}')
            return HTTPResponse(status_code=401, body="Unauthorized")

        scanner = LogicScanner(
            session_victim=self.session_victim,
            session_attacker=self.session_user,
            requester_func=mock_secure_api,
        )

        findings = scanner.audit_endpoint(
            HTTPRequest(method="GET", url="https://api.target.local/v1/profile")
        )
        self.assertEqual(len(findings), 0)

    def test_detect_unauthenticated_bypass(self):
        # Endpoint exposing private data to unauthenticated requests
        def mock_public_leak(req: HTTPRequest) -> HTTPResponse:
            return HTTPResponse(
                status_code=200,
                body='{"account": "acc_secret_44", "balance": 10000}',
                json_data={"account": "acc_secret_44", "balance": 10000},
            )

        scanner = LogicScanner(
            session_victim=self.session_victim,
            session_attacker=self.session_user,
            requester_func=mock_public_leak,
        )

        findings = scanner.audit_endpoint(
            HTTPRequest(method="GET", url="https://api.target.local/v1/billing")
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "AUTHENTICATION_BYPASS")
        self.assertEqual(findings[0].severity, "Critical")


if __name__ == "__main__":
    unittest.main()
