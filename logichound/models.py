"""
Core data models for LogicHound.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AuthSession:
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    user_id: str | None = None
    role: str = "user"


@dataclass
class HTTPRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    params: dict[str, str] = field(default_factory=dict)


@dataclass
class HTTPResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    json_data: Any = None


@dataclass
class Finding:
    vuln_type: str  # BOLA, BFLA, IDOR, PRIVILEGE_ESCALATION
    severity: str   # Low, Medium, High, Critical
    endpoint: str
    method: str
    attacker_session: str
    victim_session: str
    evidence: str
    reproduction_curl: str
