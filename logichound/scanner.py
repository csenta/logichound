"""
LogicHound Scan Orchestrator.
Manages the dual-session testing matrix, request execution, and report generation.
"""

import json
from typing import Callable
from logichound.models import AuthSession, HTTPRequest, HTTPResponse, Finding
from logichound.mutator import RequestMutator
from logichound.diff_engine import DifferentialOracle


class LogicScanner:
    def __init__(
        self,
        session_victim: AuthSession,
        session_attacker: AuthSession,
        requester_func: Callable[[HTTPRequest], HTTPResponse] | None = None,
    ):
        self.victim = session_victim
        self.attacker = session_attacker
        self.requester = requester_func or self._default_requester
        self.findings: list[Finding] = []

    def _default_requester(self, req: HTTPRequest) -> HTTPResponse:
        import requests
        try:
            resp = requests.request(
                method=req.method,
                url=req.url,
                headers=req.headers,
                params=req.params,
                data=req.body,
                timeout=10,
                allow_redirects=False,
            )
            try:
                json_data = resp.json()
            except Exception:
                json_data = None
            return HTTPResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                json_data=json_data,
            )
        except Exception as exc:
            return HTTPResponse(status_code=0, body=str(exc))

    def audit_endpoint(self, base_request: HTTPRequest) -> list[Finding]:
        """
        Runs the full cross-session verification loop for a single target request.
        """
        # 1. Baseline: Run as Victim
        req_victim = RequestMutator.apply_session(base_request, self.victim)
        resp_victim = self.requester(req_victim)

        # If victim request wasn't successful, skip
        if resp_victim.status_code not in (200, 201, 204):
            return []

        # 2. Cross-Access: Run as Attacker (with victim's resource URL)
        req_attacker = RequestMutator.apply_session(base_request, self.attacker)
        resp_attacker = self.requester(req_attacker)

        # 3. Anonymous: Run without auth headers
        anon_session = AuthSession(name="Anonymous")
        req_anon = RequestMutator.apply_session(base_request, anon_session)
        # Strip any residual authorization headers
        req_anon.headers.pop("Authorization", None)
        req_anon.headers.pop("Cookie", None)
        resp_anon = self.requester(req_anon)

        # 4. Analyze Differential
        finding = DifferentialOracle.analyze_cross_access(
            method=base_request.method,
            url=base_request.url,
            victim_session=self.victim,
            victim_resp=resp_victim,
            attacker_session=self.attacker,
            attacker_resp=resp_attacker,
            anon_resp=resp_anon,
        )

        if finding:
            self.findings.append(finding)
            return [finding]

        return []

    def generate_markdown_report(self) -> str:
        lines = [
            "# LogicHound Vulnerability Audit Report",
            f"**Victim Session**: `{self.victim.name}` ({self.victim.role})",
            f"**Attacker Session**: `{self.attacker.name}` ({self.attacker.role})",
            f"**Total Findings**: {len(self.findings)}",
            "",
            "---",
            "",
        ]
        if not self.findings:
            lines.append("No business logic or cross-session authorization vulnerabilities detected.")
            return "\n".join(lines)

        for i, f in enumerate(self.findings, 1):
            lines.extend([
                f"### {i}. [{f.severity}] {f.vuln_type} on `{f.method} {f.endpoint}`",
                f"- **Attacker**: `{f.attacker_session}`",
                f"- **Victim**: `{f.victim_session}`",
                f"- **Evidence**: {f.evidence}",
                f"- **Reproduction**:",
                f"```bash\n{f.reproduction_curl}\n```",
                "",
            ])

        return "\n".join(lines)
