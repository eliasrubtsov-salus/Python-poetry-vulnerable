# Vulnerable Test Application

## ⚠️ WARNING ⚠️
This application intentionally contains multiple security vulnerabilities for testing purposes.
**DO NOT USE IN PRODUCTION OR EXPOSE TO THE INTERNET!**

## Purpose
This application is designed to test vulnerability detection and elimination agents. It includes:

### Package Vulnerabilities (in pyproject.toml)
1. **Flask 2.0.0** - CVE-2023-30861 (cookie parsing vulnerability)
2. **Requests 2.25.0** - CVE-2023-32681 (proxy-authorization header leak)
3. **PyYAML 5.3.1** - CVE-2020-14343 (arbitrary code execution)
4. **Jinja2 2.11.0** - CVE-2024-22195 (XSS vulnerability)
5. **Cryptography 3.3.0** - Multiple CVEs including CVE-2023-23931
6. **urllib3 1.26.4** - CVE-2023-43804 (cookie leak via redirect)
7. **Pillow 8.0.0** - CVE-2022-22817, CVE-2022-45198 (buffer overflow)
8. **Django 3.1.0** - CVE-2023-43665, CVE-2024-27351 (SQL injection)

### Code Vulnerabilities (in app.py and utils.py)

#### app.py
- SQL Injection (string formatting in queries)
- YAML Deserialization (arbitrary code execution)
- Server-Side Template Injection (SSTI)
- Command Injection (os.system with user input)
- Insecure Deserialization (pickle.loads)
- Path Traversal (unvalidated file paths)
- Hardcoded Secrets (API keys, passwords)
- Debug Mode Enabled in production

#### utils.py
- Weak Cryptographic Hash (MD5)
- Predictable Random Number Generation
- Insecure SSL Verification (verify=False)
- Weak Encryption (ECB mode)
- XML External Entity (XXE) vulnerability
- Open Redirect
- Information Disclosure (stack traces)

## Installation

```bash
cd vulnerable-app
poetry install
```

## Running the Application

```bash
poetry run python app.py
```

## Testing with Security Scanners

This application can be tested with various security tools:

- **Bandit**: `poetry run bandit -r .`
- **Safety**: `poetry run safety check`
- **Pip-audit**: `pip-audit`
- **Semgrep**: `semgrep --config=auto .`
- **Trivy**: `trivy fs .`

## Expected Findings

Your vulnerability elimination agent should detect and fix:
- Outdated packages with known CVEs
- Code-level security anti-patterns
- Hardcoded credentials
- Insecure cryptographic practices
- Injection vulnerabilities
- Insecure configurations

## Safe Fixes

The agent should upgrade packages to safe versions:
- Flask → 3.0.0+
- Requests → 2.31.0+
- PyYAML → 6.0.1+
- Jinja2 → 3.1.3+
- Cryptography → 41.0.0+
- urllib3 → 2.0.7+
- Pillow → 10.0.0+
- Django → 4.2.8+
