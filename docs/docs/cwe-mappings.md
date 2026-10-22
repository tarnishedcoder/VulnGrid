# CWE Mappings

Common CWEs emitted by the scanner wrappers:

| CWE | Name | OWASP Top 10 | Example remediation |
|-----|------|--------------|---------------------|
| CWE-78 | OS Command Injection | A03 Injection | Avoid `shell=True`; whitelist input |
| CWE-89 | SQL Injection | A03 Injection | Parameterized queries / ORM |
| CWE-79 | Cross-Site Scripting (XSS) | A03 Injection | Output-encode, use safe templating |
| CWE-798 | Hardcoded Credentials | A07 Auth Failures | Vault / env secrets, rotate keys |
| CWE-918 | SSRF | A10 SSRF | Allow-list URLs, no internal access |
| CWE-502 | Deserialization of Untrusted Data | A08 Integrity | Sign payloads, avoid pickle |
| CWE-434 | Unrestricted File Upload | A04 Insecure Design | Validate type/size, store outside webroot |

Risk score used everywhere: `risk = CVSS × EPSS × 10` (0–100).
Gate threshold in CI: fail when `CVSS ≥ 7.0 and EPSS ≥ 0.2`.
