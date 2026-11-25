# LogicHound: Autonomous Business-Logic & Authorization Vulnerability Auditor

> **Status:** prototype. A personal security-research project, not a production product. Expect rough edges; issues and pull requests are welcome.

Automated security scanner for detecting **Broken Object Level Authorization (BOLA/IDOR)**, **Broken Function Level Authorization (BFLA)**, and **Privilege Escalation** flaws across APIs and modern web applications.

---

## Why LogicHound?

Traditional vulnerability scanners (DAST/SAST) search for syntax errors, injection markers, or known CVE signatures. They cannot detect authorization flaws because **an IDOR response looks identical to a valid response**—the vulnerability lies purely in *who* is accessing *whose* data.

**LogicHound** solves this by establishing a multi-session testing matrix:
1. **Victim / High-Privilege Session** ($S_{A}$)
2. **Attacker / Low-Privilege Session** ($S_{B}$)
3. **Anonymous Baseline** ($S_{Anon}$)

It systematically executes cross-token replays and differential oracle analysis to detect when unauthorized identities gain access to private records or administrative endpoints.

---

## Vulnerabilities Detected

- **OWASP API1:2023 - Broken Object Level Authorization (BOLA / IDOR)**: User B accessing User A's private orders, invoices, or personal profiles.
- **OWASP API5:2023 - Broken Function Level Authorization (BFLA)**: Low-privileged users calling administrative endpoints (e.g. `/api/admin/users/delete`).
- **OWASP API2:2023 - Broken Authentication**: Sensitive data accessible to unauthenticated callers.

---

## Quick Start

### 1. Installation
```bash
pip install -r requirements.txt
```

### 2. Run an Audit on an API Endpoint
```bash
python3 -m logichound.cli \
  --url "https://api.example.com/v1/users/usr_1001/billing" \
  --method GET \
  --token-a "victim_jwt_token_here" \
  --token-b "attacker_jwt_token_here" \
  --user-id-a "usr_1001" \
  --out report.md
```

### 3. Generated Report Example
```markdown
### 1. [High] BOLA_IDOR on `GET https://api.example.com/v1/users/usr_1001/billing`
- **Attacker**: `Session_B`
- **Victim**: `Session_A`
- **Evidence**: Attacker session received HTTP 200 containing victim's private identifier 'usr_1001'.
- **Reproduction**:
curl -X GET 'https://api.example.com/v1/users/usr_1001/billing' -H 'Authorization: <Session_B_TOKEN>'
```

## License

MIT. See [LICENSE](LICENSE).
