"""
Differential analysis engine for cross-session access correlation.
"""

import json
from logichound.models import HTTPResponse, AuthSession, Finding


class DifferentialOracle:

    @staticmethod
    def analyze_cross_access(
        method: str,
        url: str,
        victim_session: AuthSession,
        victim_resp: HTTPResponse,
        attacker_session: AuthSession,
        attacker_resp: HTTPResponse,
        anon_resp: HTTPResponse | None = None,
    ) -> Finding | None:
        """
        Evaluates whether an unauthorized attacker session successfully accessed
        a protected victim resource or privileged action.
        """
        # If victim was denied originally (401/403/404), baseline is invalid
        if victim_resp.status_code not in (200, 201, 204):
            return None

        # 1. Check for unauthenticated access (Anonymous bypass)
        if anon_resp and anon_resp.status_code in (200, 201):
            if anon_resp.body and len(anon_resp.body) > 10 and anon_resp.body == victim_resp.body:
                return Finding(
                    vuln_type="AUTHENTICATION_BYPASS",
                    severity="Critical",
                    endpoint=url,
                    method=method,
                    attacker_session="Anonymous",
                    victim_session=victim_session.name,
                    evidence=f"Endpoint returned HTTP {anon_resp.status_code} with full victim body without authentication.",
                    reproduction_curl=f"curl -X {method} '{url}'",
                )

        # 2. Check for BFLA / Privilege Escalation (Admin -> User)
        if victim_session.role == "admin" and attacker_session.role != "admin":
            if attacker_resp.status_code in (200, 201, 204):
                return Finding(
                    vuln_type="BFLA_PRIVILEGE_ESCALATION",
                    severity="High",
                    endpoint=url,
                    method=method,
                    attacker_session=attacker_session.name,
                    victim_session=victim_session.name,
                    evidence=f"Low-privileged role '{attacker_session.role}' successfully accessed administrative endpoint with HTTP {attacker_resp.status_code}.",
                    reproduction_curl=f"curl -X {method} '{url}' -H 'Authorization: <{attacker_session.name}_TOKEN>'",
                )

        # 3. Check for BOLA / IDOR (User B accessing User A resource)
        if attacker_resp.status_code in (200, 201):
            # Check if victim's specific identifier appears in attacker's response
            if victim_session.user_id and victim_session.user_id in attacker_resp.body:
                return Finding(
                    vuln_type="BOLA_IDOR",
                    severity="High",
                    endpoint=url,
                    method=method,
                    attacker_session=attacker_session.name,
                    victim_session=victim_session.name,
                    evidence=(
                        f"Attacker session received HTTP {attacker_resp.status_code} containing victim's private identifier "
                        f"'{victim_session.user_id}'."
                    ),
                    reproduction_curl=f"curl -X {method} '{url}' -H 'Authorization: <{attacker_session.name}_TOKEN>'",
                )

            # Check for structural identity match (same payload returned to both users)
            if victim_resp.json_data and attacker_resp.json_data:
                if victim_resp.json_data == attacker_resp.json_data and len(str(victim_resp.json_data)) > 20:
                    return Finding(
                        vuln_type="BOLA_IDOR",
                        severity="Medium",
                        endpoint=url,
                        method=method,
                        attacker_session=attacker_session.name,
                        victim_session=victim_session.name,
                        evidence=f"Attacker session received identical JSON response body as victim session ({len(victim_resp.body)} bytes).",
                        reproduction_curl=f"curl -X {method} '{url}' -H 'Authorization: <{attacker_session.name}_TOKEN>'",
                    )

        return None
